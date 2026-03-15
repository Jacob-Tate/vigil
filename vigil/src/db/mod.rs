use std::{
    path::Path,
    sync::{Arc, Mutex},
};

use rusqlite::Connection;

pub type DbPool = Arc<Mutex<Connection>>;

/// Schema SQL embedded at compile time — avoids runtime path resolution.
const SCHEMA: &str = include_str!("schema.sql");

/// Opens the SQLite database, applies performance pragmas, initialises the
/// schema, and runs idempotent column-addition migrations.
pub fn init(db_path: &str) -> anyhow::Result<DbPool> {
    // Ensure parent directory exists
    if let Some(parent) = Path::new(db_path).parent() {
        std::fs::create_dir_all(parent)?;
    }

    let conn = Connection::open(db_path)?;

    // Performance and correctness pragmas
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA foreign_keys = ON;
         PRAGMA cache_size = -65536;
         PRAGMA synchronous = NORMAL;
         PRAGMA temp_store = MEMORY;",
    )?;

    // Create all tables (IF NOT EXISTS — safe to run repeatedly)
    conn.execute_batch(SCHEMA)?;

    // Idempotent column migrations — replicates database.ts lines 40-52.
    // Each ALTER TABLE is wrapped in an `.ok()` so a "duplicate column" error is ignored.
    let migrations: &[&str] = &[
        "ALTER TABLE servers ADD COLUMN ignore_patterns TEXT",
        "ALTER TABLE nvd_cve_cpes ADD COLUMN version_start_including TEXT",
        "ALTER TABLE nvd_cve_cpes ADD COLUMN version_start_excluding TEXT",
        "ALTER TABLE nvd_cve_cpes ADD COLUMN version_end_including TEXT",
        "ALTER TABLE nvd_cve_cpes ADD COLUMN version_end_excluding TEXT",
        "ALTER TABLE nvd_cves ADD COLUMN references_json TEXT",
        "ALTER TABLE cve_targets ADD COLUMN min_alert_cvss_score REAL NOT NULL DEFAULT 7.0",
        "ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'viewer'",
        "ALTER TABLE cve_findings ADD COLUMN enrichment_fingerprint TEXT",
        "ALTER TABLE cve_findings ADD COLUMN exploitation_alert_sent TEXT",
        "ALTER TABLE cve_findings ADD COLUMN rejection_alert_sent INTEGER DEFAULT 0",
    ];

    for sql in migrations {
        conn.execute_batch(sql).ok(); // ignore "duplicate column" errors
    }

    // Data migration: copy old min_cvss_score → min_alert_cvss_score if present
    conn.execute_batch(
        "UPDATE cve_targets SET min_alert_cvss_score = min_cvss_score \
         WHERE min_cvss_score IS NOT NULL",
    )
    .ok();

    Ok(Arc::new(Mutex::new(conn)))
}

/// Ensure all data subdirectories exist.
pub fn ensure_data_dirs(data_dir: &str) -> anyhow::Result<()> {
    for sub in &[
        "",
        "snapshots",
        "diffs",
        "screenshots",
        "ssl/snapshots",
        "ssl/history",
    ] {
        let path = if sub.is_empty() {
            data_dir.to_string()
        } else {
            format!("{}/{}", data_dir, sub)
        };
        std::fs::create_dir_all(&path)?;
    }
    Ok(())
}
