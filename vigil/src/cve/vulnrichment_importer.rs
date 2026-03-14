use std::{
    path::{Path, PathBuf},
    process::Command,
};

use serde_json::Value;

use crate::db::DbPool;

const REPO_URL: &str = "https://github.com/cisagov/vulnrichment.git";
const CISA_ORG_ID: &str = "134c704f-9b21-4f2e-91b3-4a467353bcc0";
const BATCH_SIZE: usize = 500;

pub struct VulnrichmentSyncResult {
    pub count: usize,
    pub repo_version: String,
}

pub async fn sync_vulnrichment(db: &DbPool, data_dir: &str) -> anyhow::Result<VulnrichmentSyncResult> {
    let repo_dir = PathBuf::from(data_dir).join("vulnrichment");
    let repo_dir_str = repo_dir.to_string_lossy().to_string();

    let db = db.clone();
    tokio::task::spawn_blocking(move || -> anyhow::Result<VulnrichmentSyncResult> {
        // Clone or pull
        if repo_dir.join(".git").exists() {
            tracing::info!("[vulnrichment] pulling latest changes");
            git_pull(&repo_dir_str)?;
        } else {
            tracing::info!("[vulnrichment] cloning repository (first time)");
            git_clone(REPO_URL, &repo_dir_str, &["--depth", "1"])?;
        }

        let repo_version = git_head(&repo_dir_str).unwrap_or_default();

        // Walk all JSON files
        let json_files = walk_json_files(&repo_dir);
        let synced_at = chrono::Utc::now().to_rfc3339();

        let mut count = 0usize;
        let mut batch: Vec<(String, Option<String>, Option<String>, Option<String>, Option<String>)> = Vec::new();

        let flush = |batch: &mut Vec<_>, synced_at: &str| -> anyhow::Result<()> {
            if batch.is_empty() { return Ok(()); }
            let conn = db.lock().unwrap();
            conn.execute_batch("BEGIN IMMEDIATE")?;
            let result: rusqlite::Result<()> = (|| {
                let mut stmt = conn.prepare_cached(
                    "INSERT OR REPLACE INTO cisa_ssvc
                     (cve_id, exploitation, automatable, technical_impact, timestamp, synced_at)
                     VALUES (?1,?2,?3,?4,?5,?6)",
                )?;
                for (cve_id, exploitation, automatable, technical_impact, timestamp) in batch.iter() {
                    stmt.execute(rusqlite::params![
                        cve_id, exploitation, automatable, technical_impact, timestamp, synced_at
                    ])?;
                }
                Ok(())
            })();
            batch.clear();
            match result {
                Ok(()) => { conn.execute_batch("COMMIT")?; Ok(()) }
                Err(e) => { conn.execute_batch("ROLLBACK")?; Err(e.into()) }
            }
        };

        for file_path in &json_files {
            let raw = match std::fs::read_to_string(file_path) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let record: Value = match serde_json::from_str(&raw) {
                Ok(v) => v,
                Err(_) => continue,
            };

            let ssvc = match extract_ssvc(&record) {
                Some(s) => s,
                None => continue,
            };

            // Extract CVE ID from filename
            let cve_id = file_path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.trim_end_matches(".json").to_string())
                .unwrap_or_default();
            if !cve_id.starts_with("CVE-") { continue; }

            batch.push((cve_id, ssvc.exploitation, ssvc.automatable, ssvc.technical_impact, ssvc.timestamp));

            if batch.len() >= BATCH_SIZE {
                count += batch.len();
                flush(&mut batch, &synced_at)?;
            }
        }

        count += batch.len();
        flush(&mut batch, &synced_at)?;

        tracing::info!(count, "[vulnrichment] upserted SSVC entries");
        Ok(VulnrichmentSyncResult { count, repo_version })
    })
    .await?
}

struct SsvcData {
    exploitation: Option<String>,
    automatable: Option<String>,
    technical_impact: Option<String>,
    timestamp: Option<String>,
}

fn extract_ssvc(record: &Value) -> Option<SsvcData> {
    let adp_list = record["containers"]["adp"].as_array()?;
    for adp in adp_list {
        let org_id = adp["providerMetadata"]["orgId"].as_str().unwrap_or("");
        if org_id != CISA_ORG_ID { continue; }
        let metrics = adp["metrics"].as_array()?;
        for metric in metrics {
            if metric["other"]["type"].as_str() != Some("ssvc") { continue; }
            let options = metric["other"]["content"]["options"].as_array()?;
            let mut exploitation: Option<String> = None;
            let mut automatable: Option<String> = None;
            let mut technical_impact: Option<String> = None;
            for opt in options {
                if let Some(v) = opt["Exploitation"].as_str() {
                    exploitation = Some(v.to_lowercase());
                }
                if let Some(v) = opt["Automatable"].as_str() {
                    automatable = Some(v.to_lowercase());
                }
                if let Some(v) = opt["Technical Impact"].as_str() {
                    technical_impact = Some(v.to_lowercase());
                }
            }
            if exploitation.is_none() && automatable.is_none() && technical_impact.is_none() {
                continue;
            }
            let timestamp = metric["other"]["content"]["timestamp"]
                .as_str()
                .map(|s| s.to_string());
            return Some(SsvcData { exploitation, automatable, technical_impact, timestamp });
        }
    }
    None
}

fn walk_json_files(dir: &Path) -> Vec<PathBuf> {
    let mut results = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return results,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            results.extend(walk_json_files(&path));
        } else if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name.ends_with(".json") && name.starts_with("CVE-") {
                results.push(path);
            }
        }
    }
    results
}

fn git_clone(url: &str, target: &str, extra_args: &[&str]) -> anyhow::Result<()> {
    let status = Command::new("git")
        .arg("clone")
        .args(extra_args)
        .arg(url)
        .arg(target)
        .env("GIT_TERMINAL_PROMPT", "0")
        .status()?;
    if !status.success() {
        anyhow::bail!("git clone failed for {}", url);
    }
    Ok(())
}

fn git_pull(repo_dir: &str) -> anyhow::Result<()> {
    let status = Command::new("git")
        .args(["pull"])
        .current_dir(repo_dir)
        .env("GIT_TERMINAL_PROMPT", "0")
        .status()?;
    if !status.success() {
        anyhow::bail!("git pull failed in {}", repo_dir);
    }
    Ok(())
}

fn git_head(repo_dir: &str) -> anyhow::Result<String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo_dir)
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()?;
    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}
