use std::{
    path::{Path, PathBuf},
    process::Command,
    sync::{
        atomic::{AtomicUsize, Ordering as AtomicOrdering},
        Arc, Mutex,
    },
};

use rayon::prelude::*;
use serde::Deserialize;

use crate::{db::DbPool, types::SyncProgress};

const REPO_URL: &str = "https://github.com/cisagov/vulnrichment.git";
const CISA_ORG_ID: &str = "134c704f-9b21-4f2e-91b3-4a467353bcc0";
const BATCH_SIZE: usize = 500;

pub struct VulnrichmentSyncResult {
    pub count: usize,
}

// --- Typed deserialization structs ---

#[derive(Deserialize)]
struct VulnDoc {
    containers: VulnContainers,
}

#[derive(Deserialize)]
struct VulnContainers {
    adp: Option<Vec<Adp>>,
}

#[derive(Deserialize)]
struct Adp {
    #[serde(rename = "providerMetadata")]
    provider_metadata: ProviderMetadata,
    metrics: Option<Vec<Metric>>,
}

#[derive(Deserialize)]
struct ProviderMetadata {
    #[serde(rename = "orgId")]
    org_id: String,
}

#[derive(Deserialize)]
struct Metric {
    other: Option<MetricOther>,
}

#[derive(Deserialize)]
struct MetricOther {
    #[serde(rename = "type")]
    type_: String,
    content: Option<MetricContent>,
}

#[derive(Deserialize)]
struct MetricContent {
    timestamp: Option<String>,
    options: Option<Vec<serde_json::Value>>,
}

// --- Internal row type ---

struct SsvcRow {
    cve_id: String,
    exploitation: Option<String>,
    automatable: Option<String>,
    technical_impact: Option<String>,
    timestamp: Option<String>,
}

pub async fn sync_vulnrichment(
    db: &DbPool,
    data_dir: &str,
    progress: Arc<Mutex<Option<SyncProgress>>>,
) -> anyhow::Result<VulnrichmentSyncResult> {
    let repo_dir = PathBuf::from(data_dir).join("vulnrichment");
    let repo_dir_str = repo_dir.to_string_lossy().to_string();

    let db = db.clone();
    tokio::task::spawn_blocking(move || -> anyhow::Result<VulnrichmentSyncResult> {
        let set_progress = |stage: &str, message: String, files_done: usize, files_total: usize| {
            if let Ok(mut p) = progress.lock() {
                *p = Some(SyncProgress { stage: stage.to_string(), message, files_done, files_total });
            }
        };

        // Clone or pull
        if repo_dir.join(".git").exists() {
            tracing::info!("[vulnrichment] pulling latest changes");
            set_progress("git_pull", "Pulling latest Vulnrichment changes…".to_string(), 0, 0);
            git_pull(&repo_dir_str)?;
        } else {
            tracing::info!("[vulnrichment] cloning repository (first time)");
            set_progress("git_clone", "Cloning CISA Vulnrichment repository…".to_string(), 0, 0);
            git_clone(REPO_URL, &repo_dir_str, &["--depth", "1"])?;
        }

        let repo_version = git_head(&repo_dir_str).unwrap_or_default();

        // Check if already up to date
        let last_hash: Option<String> = {
            let conn = db.lock().unwrap();
            conn.query_row(
                "SELECT sha256 FROM nvd_feed_state WHERE feed_name = 'vulnrichment'",
                [],
                |row| row.get(0),
            )
            .ok()
        };
        if let Some(ref last) = last_hash {
            if !last.is_empty() && *last == repo_version {
                tracing::info!("[vulnrichment] already up to date, nothing to process");
                return Ok(VulnrichmentSyncResult { count: 0 });
            }
        }

        set_progress("scan", "Scanning Vulnrichment file index…".to_string(), 0, 0);

        // Build file list
        set_progress("scan", "Building file list…".to_string(), 0, 0);
        let json_files = walk_json_files(&repo_dir);
        let total_files = json_files.len();
        tracing::info!(count = total_files, "[vulnrichment] files to process");
        set_progress("parse", format!("Parsing {} SSVC files…", total_files), 0, total_files);

        // Parallel parse via Rayon
        let files_done_atomic = Arc::new(AtomicUsize::new(0));
        let files_done_clone = files_done_atomic.clone();

        let rows: Vec<SsvcRow> = json_files
            .par_iter()
            .filter_map(|path| {
                let cve_id = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.trim_end_matches(".json").to_string())?;
                if !cve_id.starts_with("CVE-") {
                    return None;
                }
                let raw = std::fs::read_to_string(path).ok()?;
                let doc = serde_json::from_str::<VulnDoc>(&raw).ok()?;
                let done = files_done_clone.fetch_add(1, AtomicOrdering::Relaxed) + 1;
                if done % 2_000 == 0 {
                    set_progress(
                        "parse",
                        format!("Parsing SSVC files… {}/{}", done, total_files),
                        done,
                        total_files,
                    );
                }
                extract_ssvc(cve_id, doc)
            })
            .collect();

        let total_parsed = rows.len();
        tracing::info!(count = total_parsed, "[vulnrichment] parsed SSVC records — starting upsert");
        set_progress("insert", format!("Inserting {} SSVC records…", total_parsed), 0, total_parsed);

        let synced_at = chrono::Utc::now().to_rfc3339();
        let mut count = 0usize;

        // Temporarily relax fsync for bulk import speed
        {
            let conn = db.lock().unwrap();
            conn.execute_batch("PRAGMA synchronous = OFF; PRAGMA cache_size = -131072;")?;
        }

        for chunk in rows.chunks(BATCH_SIZE) {
            // Explicit block so MutexGuard drops (lock released) before the yield.
            let batch_result: anyhow::Result<()> = {
                let conn = db.lock().unwrap();
                conn.execute_batch("BEGIN IMMEDIATE")?;
                let result: rusqlite::Result<()> = (|| {
                    let mut stmt = conn.prepare_cached(
                        "INSERT OR REPLACE INTO cisa_ssvc
                         (cve_id, exploitation, automatable, technical_impact, timestamp, synced_at)
                         VALUES (?1,?2,?3,?4,?5,?6)",
                    )?;
                    for row in chunk {
                        stmt.execute(rusqlite::params![
                            row.cve_id, row.exploitation, row.automatable,
                            row.technical_impact, row.timestamp, synced_at,
                        ])?;
                    }
                    Ok(())
                })();
                match result {
                    Ok(()) => { conn.execute_batch("COMMIT")?; Ok(()) }
                    Err(e) => {
                        conn.execute_batch("ROLLBACK")?;
                        Err(anyhow::anyhow!(e))
                    }
                }
                // conn (MutexGuard) drops here — lock released before yield
            };

            if let Err(e) = batch_result {
                if let Ok(conn) = db.lock() {
                    let _ = conn.execute_batch("PRAGMA synchronous = NORMAL; PRAGMA cache_size = -65536;");
                }
                return Err(e);
            }

            count += chunk.len();
            set_progress(
                "insert",
                format!("Inserting SSVC records… {}/{}", count, total_parsed),
                count,
                total_parsed,
            );

            // Yield briefly so status-endpoint threads can acquire the DB lock
            // between batches (prevents mutex barging on Windows).
            std::thread::sleep(std::time::Duration::from_millis(2));
        }

        // Restore pragmas after bulk import
        {
            let conn = db.lock().unwrap();
            conn.execute_batch("PRAGMA synchronous = NORMAL; PRAGMA cache_size = -65536;")?;
        }

        // Update sync state
        {
            let conn = db.lock().unwrap();
            conn.execute(
                "INSERT OR REPLACE INTO nvd_feed_state
                 (feed_name, sha256, total_cves, imported_at)
                 VALUES ('vulnrichment', ?1, ?2, ?3)",
                rusqlite::params![repo_version, count as i64, synced_at],
            )?;
        }

        tracing::info!(count, "[vulnrichment] upserted SSVC entries");
        Ok(VulnrichmentSyncResult { count })
    })
    .await?
}

fn extract_ssvc(cve_id: String, doc: VulnDoc) -> Option<SsvcRow> {
    let adp_list = doc.containers.adp?;
    for adp in adp_list {
        if adp.provider_metadata.org_id != CISA_ORG_ID {
            continue;
        }
        let Some(metrics) = adp.metrics else { continue };
        for metric in metrics {
            let Some(other) = metric.other else { continue };
            if other.type_ != "ssvc" {
                continue;
            }
            let Some(content) = other.content else { continue };
            let Some(options) = content.options else { continue };

            let mut exploitation: Option<String> = None;
            let mut automatable: Option<String> = None;
            let mut technical_impact: Option<String> = None;
            for opt in &options {
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
            return Some(SsvcRow {
                cve_id,
                exploitation,
                automatable,
                technical_impact,
                timestamp: content.timestamp,
            });
        }
    }
    None
}

fn walk_json_files(dir: &Path) -> Vec<PathBuf> {
    let mut results = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else { return results };
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
        .arg("clone").args(extra_args).arg(url).arg(target)
        .env("GIT_TERMINAL_PROMPT", "0")
        .status()?;
    if !status.success() { anyhow::bail!("git clone failed for {}", url); }
    Ok(())
}

fn git_pull(repo_dir: &str) -> anyhow::Result<()> {
    let status = Command::new("git")
        .args(["pull"]).current_dir(repo_dir)
        .env("GIT_TERMINAL_PROMPT", "0")
        .status()?;
    if !status.success() { anyhow::bail!("git pull failed in {}", repo_dir); }
    Ok(())
}

fn git_head(repo_dir: &str) -> anyhow::Result<String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"]).current_dir(repo_dir)
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()?;
    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}
