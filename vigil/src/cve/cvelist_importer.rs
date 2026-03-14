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

const REPO_URL: &str = "https://github.com/CVEProject/cvelistV5.git";
const BATCH_SIZE: usize = 500;

pub struct CvelistSyncResult {
    pub count: usize,
}

// --- Typed deserialization structs ---

#[derive(Deserialize)]
struct CveDoc {
    #[serde(rename = "cveMetadata")]
    cve_metadata: CveMetadata,
    containers: Containers,
}

#[derive(Deserialize)]
struct CveMetadata {
    #[serde(rename = "cveId")]
    cve_id: String,
    state: String,
    #[serde(rename = "datePublished")]
    date_published: Option<String>,
    #[serde(rename = "dateUpdated")]
    date_updated: Option<String>,
}

#[derive(Deserialize)]
struct Containers {
    cna: Cna,
}

#[derive(Deserialize)]
struct Cna {
    title: Option<String>,
    descriptions: Option<Vec<CveDescription>>,
    affected: Option<Vec<CveAffected>>,
}

#[derive(Deserialize)]
struct CveDescription {
    lang: Option<String>,
    value: Option<String>,
}

#[derive(Deserialize)]
struct CveAffected {
    vendor: Option<String>,
    product: Option<String>,
    versions: Option<serde_json::Value>,
    #[serde(rename = "defaultStatus")]
    default_status: Option<String>,
}

// --- Internal row types ---

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

pub async fn sync_cvelist(
    db: &DbPool,
    data_dir: &str,
    progress: Arc<Mutex<Option<SyncProgress>>>,
) -> anyhow::Result<CvelistSyncResult> {
    let repo_dir = PathBuf::from(data_dir).join("cvelistV5");
    let repo_dir_str = repo_dir.to_string_lossy().to_string();

    let db = db.clone();
    tokio::task::spawn_blocking(move || -> anyhow::Result<CvelistSyncResult> {
        let set_progress = |stage: &str, message: String, files_done: usize, files_total: usize| {
            if let Ok(mut p) = progress.lock() {
                *p = Some(SyncProgress { stage: stage.to_string(), message, files_done, files_total });
            }
        };

        // Clone or pull
        let is_new_clone = !repo_dir.join(".git").exists();
        if is_new_clone {
            tracing::info!("[cvelist] cloning repository (blobless, may take a moment)");
            set_progress("git_clone", "Cloning CVE Program repository (blobless)…".to_string(), 0, 0);
            git_clone(REPO_URL, &repo_dir_str, &["--filter=blob:none", "--no-tags"])?;
        } else {
            tracing::info!("[cvelist] pulling latest changes");
            set_progress("git_pull", "Pulling latest CVE list changes…".to_string(), 0, 0);
            git_pull(&repo_dir_str)?;
        }

        set_progress("scan", "Scanning CVE file index…".to_string(), 0, 0);

        let repo_version = git_head(&repo_dir_str).unwrap_or_default();

        // Check if already up to date
        let last_hash: Option<String> = {
            let conn = db.lock().unwrap();
            conn.query_row(
                "SELECT sha256 FROM nvd_feed_state WHERE feed_name = 'cvelist'",
                [],
                |row| row.get(0),
            )
            .ok()
        };

        if let Some(ref last) = last_hash {
            if !last.is_empty() && *last == repo_version {
                tracing::info!("[cvelist] already up to date, nothing to process");
                return Ok(CvelistSyncResult { count: 0 });
            }
        }

        // Determine files to process
        set_progress("scan", "Building file list…".to_string(), 0, 0);
        let files_to_process: Vec<PathBuf> = if let Some(ref last) = last_hash {
            if !last.is_empty() && !repo_version.is_empty() {
                match git_diff_files(&repo_dir_str, last) {
                    Ok(changed) => {
                        tracing::info!(count = changed.len(), "[cvelist] incremental: changed files");
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

        let total_files = files_to_process.len();
        tracing::info!(count = total_files, "[cvelist] files to process");
        set_progress("parse", format!("Parsing {} CVE files…", total_files), 0, total_files);

        // Parallel parse via Rayon
        let files_done_atomic = Arc::new(AtomicUsize::new(0));
        let files_done_clone = files_done_atomic.clone();

        let parsed: Vec<CvelistRow> = files_to_process
            .par_iter()
            .filter_map(|path| {
                let raw = std::fs::read_to_string(path).ok()?;
                let doc = serde_json::from_str::<CveDoc>(&raw).ok()?;
                let done = files_done_clone.fetch_add(1, AtomicOrdering::Relaxed) + 1;
                if done % 5_000 == 0 {
                    set_progress(
                        "parse",
                        format!("Parsing CVE files… {}/{}", done, total_files),
                        done,
                        total_files,
                    );
                }
                extract_cvelist(doc)
            })
            .collect();

        let total_parsed = parsed.len();
        tracing::info!(count = total_parsed, "[cvelist] parsed CVE records — starting upsert");
        set_progress("insert", format!("Inserting {} CVE records…", total_parsed), 0, total_parsed);

        let synced_at = chrono::Utc::now().to_rfc3339();
        let mut count = 0usize;

        // Temporarily relax fsync for bulk import speed
        {
            let conn = db.lock().unwrap();
            conn.execute_batch("PRAGMA synchronous = OFF; PRAGMA cache_size = -131072;")?;
        }

        for chunk in parsed.chunks(BATCH_SIZE) {
            // Explicit block so the MutexGuard drops (lock released) before the yield.
            let batch_result: anyhow::Result<()> = {
                let conn = db.lock().unwrap();
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
                            row.cve_id, row.state, row.cna_description, row.cna_title,
                            row.date_published, row.date_updated, synced_at,
                        ])?;
                        stmt_del.execute(rusqlite::params![row.cve_id])?;
                        for aff in &row.affected {
                            stmt_aff.execute(rusqlite::params![
                                row.cve_id, aff.vendor, aff.product,
                                aff.versions_json, aff.default_status,
                            ])?;
                        }
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
                // Restore pragmas before propagating the error
                if let Ok(conn) = db.lock() {
                    let _ = conn.execute_batch("PRAGMA synchronous = NORMAL; PRAGMA cache_size = -65536;");
                }
                return Err(e);
            }

            count += chunk.len();
            set_progress(
                "insert",
                format!("Inserting CVE records… {}/{}", count, total_parsed),
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
                 VALUES ('cvelist', ?1, ?2, ?3)",
                rusqlite::params![repo_version, count as i64, synced_at],
            )?;
        }

        tracing::info!(count, "[cvelist] upserted CVE records");
        Ok(CvelistSyncResult { count })
    })
    .await?
}

fn extract_cvelist(doc: CveDoc) -> Option<CvelistRow> {
    let meta = doc.cve_metadata;
    let cve_id = meta.cve_id;
    if !cve_id.starts_with("CVE-") {
        return None;
    }
    let state = meta.state;
    let cna = doc.containers.cna;

    let cna_description = cna.descriptions.as_deref().and_then(|ds| {
        ds.iter()
            .find(|d| d.lang.as_deref().map(|l| l == "en" || l.starts_with("en")).unwrap_or(false))
            .and_then(|d| d.value.clone())
    });

    let cna_title = cna.title;
    let date_published = meta.date_published;
    let date_updated = meta.date_updated;

    let affected = cna
        .affected
        .unwrap_or_default()
        .into_iter()
        .filter_map(|a| {
            let product = a.product?.to_lowercase();
            let vendor = a.vendor.map(|v| v.to_lowercase());
            let versions_json = a
                .versions
                .filter(|v| v.is_array())
                .map(|v| v.to_string());
            let default_status = a.default_status;
            Some(AffectedEntry { vendor, product, versions_json, default_status })
        })
        .collect();

    Some(CvelistRow { cve_id, state, cna_description, cna_title, date_published, date_updated, affected })
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

fn git_diff_files(repo_dir: &str, from_hash: &str) -> anyhow::Result<Vec<String>> {
    let output = Command::new("git")
        .args(["diff", "--name-only", from_hash, "HEAD"]).current_dir(repo_dir)
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()?;
    let lines = String::from_utf8(output.stdout)?;
    Ok(lines.lines()
        .filter(|f| f.ends_with(".json") && f.contains("CVE-"))
        .map(|f| f.to_string())
        .collect())
}
