use std::{
    path::{Path, PathBuf},
    process::Command,
};

use rayon::prelude::*;
use serde_json::Value;

use crate::db::DbPool;

const REPO_URL: &str = "https://github.com/CVEProject/cvelistV5.git";
const BATCH_SIZE: usize = 500;

pub struct CvelistSyncResult {
    pub count: usize,
    pub repo_version: String,
}

struct CvelistRow {
    cve_id: String,
    state: String,
    cna_description: Option<String>,
    cna_title: Option<String>,
    date_published: Option<String>,
    date_updated: Option<String>,
    affected: Vec<AffectedEntry>,
}

struct AffectedEntry {
    vendor: Option<String>,
    product: String,
    versions_json: Option<String>,
    default_status: Option<String>,
}

pub async fn sync_cvelist(db: &DbPool, data_dir: &str) -> anyhow::Result<CvelistSyncResult> {
    let repo_dir = PathBuf::from(data_dir).join("cvelistV5");
    let repo_dir_str = repo_dir.to_string_lossy().to_string();

    let db = db.clone();
    tokio::task::spawn_blocking(move || -> anyhow::Result<CvelistSyncResult> {
        // Clone or pull
        let is_new_clone = !repo_dir.join(".git").exists();
        if is_new_clone {
            tracing::info!("[cvelist] cloning repository (blobless, may take a moment)");
            git_clone(REPO_URL, &repo_dir_str, &["--filter=blob:none", "--no-tags"])?;
        } else {
            tracing::info!("[cvelist] pulling latest changes");
            git_pull(&repo_dir_str)?;
        }

        let repo_version = git_head(&repo_dir_str).unwrap_or_default();

        // Check if already up to date
        let conn = db.lock().unwrap();
        let last_hash: Option<String> = conn
            .query_row(
                "SELECT sha256 FROM nvd_feed_state WHERE feed_name = 'cvelist'",
                [],
                |row| row.get(0),
            )
            .ok();
        drop(conn);

        if let Some(ref last) = last_hash {
            if !last.is_empty() && *last == repo_version {
                tracing::info!("[cvelist] already up to date, nothing to process");
                return Ok(CvelistSyncResult { count: 0, repo_version });
            }
        }

        // Determine files to process
        let files_to_process: Vec<PathBuf> = if let Some(ref last) = last_hash {
            if !last.is_empty() && !repo_version.is_empty() {
                match git_diff_files(&repo_dir_str, last) {
                    Ok(changed) => {
                        tracing::info!(
                            count = changed.len(),
                            "[cvelist] incremental: changed files"
                        );
                        changed
                            .into_iter()
                            .map(|f| repo_dir.join(f))
                            .filter(|p| {
                                p.extension().and_then(|e| e.to_str()) == Some("json")
                                    && p.file_name()
                                        .and_then(|n| n.to_str())
                                        .map(|n| n.starts_with("CVE-"))
                                        .unwrap_or(false)
                            })
                            .collect()
                    }
                    Err(_) => {
                        tracing::warn!("[cvelist] git diff failed, falling back to full walk");
                        walk_json_files(&repo_dir.join("cves"))
                    }
                }
            } else {
                walk_json_files(&repo_dir.join("cves"))
            }
        } else {
            walk_json_files(&repo_dir.join("cves"))
        };

        tracing::info!(count = files_to_process.len(), "[cvelist] files to process");

        // --- Rayon parallel parse ---
        let parsed: Vec<CvelistRow> = files_to_process
            .par_iter()
            .filter_map(|path| {
                let raw = std::fs::read_to_string(path).ok()?;
                let record: Value = serde_json::from_str(&raw).ok()?;
                extract_cvelist(&record)
            })
            .collect();

        tracing::info!(count = parsed.len(), "[cvelist] parsed CVE records — starting upsert");

        let synced_at = chrono::Utc::now().to_rfc3339();
        let conn = db.lock().unwrap();
        let mut count = 0usize;

        for chunk in parsed.chunks(BATCH_SIZE) {
            conn.execute_batch("BEGIN IMMEDIATE")?;
            let result: rusqlite::Result<()> = (|| {
                let mut stmt_cve = conn.prepare_cached(
                    "INSERT OR REPLACE INTO cvelist_cves
                     (cve_id, state, cna_description, cna_title, date_published, date_updated, synced_at)
                     VALUES (?1,?2,?3,?4,?5,?6,?7)",
                )?;
                let mut stmt_del = conn.prepare_cached(
                    "DELETE FROM cvelist_affected WHERE cve_id = ?1",
                )?;
                let mut stmt_aff = conn.prepare_cached(
                    "INSERT INTO cvelist_affected
                     (cve_id, vendor, product, versions_json, default_status)
                     VALUES (?1,?2,?3,?4,?5)",
                )?;
                for row in chunk {
                    stmt_cve.execute(rusqlite::params![
                        row.cve_id,
                        row.state,
                        row.cna_description,
                        row.cna_title,
                        row.date_published,
                        row.date_updated,
                        synced_at,
                    ])?;
                    stmt_del.execute(rusqlite::params![row.cve_id])?;
                    for aff in &row.affected {
                        stmt_aff.execute(rusqlite::params![
                            row.cve_id,
                            aff.vendor,
                            aff.product,
                            aff.versions_json,
                            aff.default_status,
                        ])?;
                    }
                }
                Ok(())
            })();
            match result {
                Ok(()) => conn.execute_batch("COMMIT")?,
                Err(e) => {
                    conn.execute_batch("ROLLBACK")?;
                    return Err(e.into());
                }
            }
            count += chunk.len();
        }

        // Update sync state
        conn.execute(
            "INSERT OR REPLACE INTO nvd_feed_state
             (feed_name, sha256, total_cves, imported_at)
             VALUES ('cvelist', ?1, ?2, ?3)",
            rusqlite::params![repo_version, count as i64, synced_at],
        )?;

        tracing::info!(count, "[cvelist] upserted CVE records");
        Ok(CvelistSyncResult { count, repo_version })
    })
    .await?
}

fn extract_cvelist(record: &Value) -> Option<CvelistRow> {
    let meta = &record["cveMetadata"];
    let cve_id = meta["cveId"].as_str()?.to_string();
    let state = meta["state"].as_str()?.to_string();
    if !cve_id.starts_with("CVE-") { return None; }

    let cna = &record["containers"]["cna"];
    let descriptions = cna["descriptions"].as_array();
    let cna_description = descriptions.and_then(|ds| {
        ds.iter()
            .find(|d| {
                d["lang"].as_str().map(|l| l == "en" || l.starts_with("en")).unwrap_or(false)
            })
            .and_then(|d| d["value"].as_str())
            .map(|s| s.to_string())
    });

    let cna_title = cna["title"].as_str().map(|s| s.to_string());
    let date_published = meta["datePublished"].as_str().map(|s| s.to_string());
    let date_updated = meta["dateUpdated"].as_str().map(|s| s.to_string());

    let affected = cna["affected"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|a| {
                    let product = a["product"].as_str()?.to_string();
                    let vendor = a["vendor"].as_str().map(|v| v.to_lowercase());
                    let versions_json = a.get("versions").and_then(|v| {
                        if v.is_array() { Some(v.to_string()) } else { None }
                    });
                    let default_status = a["defaultStatus"].as_str().map(|s| s.to_string());
                    Some(AffectedEntry {
                        vendor,
                        product: product.to_lowercase(),
                        versions_json,
                        default_status,
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    Some(CvelistRow { cve_id, state, cna_description, cna_title, date_published, date_updated, affected })
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
        .status()?;
    if !status.success() {
        anyhow::bail!("git clone failed for {}", url);
    }
    Ok(())
}

fn git_pull(repo_dir: &str) -> anyhow::Result<()> {
    let status = Command::new("git")
        .args(["-C", repo_dir, "pull"])
        .status()?;
    if !status.success() {
        anyhow::bail!("git pull failed in {}", repo_dir);
    }
    Ok(())
}

fn git_head(repo_dir: &str) -> anyhow::Result<String> {
    let output = Command::new("git")
        .args(["-C", repo_dir, "rev-parse", "HEAD"])
        .output()?;
    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

/// Returns relative file paths of changed JSON files since `from_hash`.
fn git_diff_files(repo_dir: &str, from_hash: &str) -> anyhow::Result<Vec<String>> {
    let output = Command::new("git")
        .args(["-C", repo_dir, "diff", "--name-only", from_hash, "HEAD"])
        .output()?;
    let lines = String::from_utf8(output.stdout)?;
    Ok(lines
        .lines()
        .filter(|f| f.ends_with(".json") && f.contains("CVE-"))
        .map(|f| f.to_string())
        .collect())
}
