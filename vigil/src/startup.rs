use std::path::Path;

use crate::monitor::differ;

/// Delete diff files from `data/diffs/` that are older than `retention_days`.
/// Called once on startup — runs synchronously (disk I/O, no async needed at startup).
pub fn cleanup_old_diffs(data_dir: &str, retention_days: u64) {
    let diffs_dir = format!("{}/diffs", data_dir);
    let cutoff = std::time::SystemTime::now()
        .checked_sub(std::time::Duration::from_secs(retention_days * 86_400))
        .unwrap_or(std::time::SystemTime::UNIX_EPOCH);

    let entries = match std::fs::read_dir(&diffs_dir) {
        Ok(e) => e,
        Err(_) => return, // directory doesn't exist yet — nothing to clean up
    };

    let mut deleted = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        // Only touch .html diff files
        if path.extension().and_then(|e| e.to_str()) != Some("html") {
            continue;
        }
        if let Ok(meta) = entry.metadata() {
            if let Ok(modified) = meta.modified() {
                if modified < cutoff {
                    if std::fs::remove_file(&path).is_ok() {
                        deleted += 1;
                    } else {
                        tracing::warn!("[startup] failed to delete old diff: {:?}", path);
                    }
                }
            }
        }
    }

    if deleted > 0 {
        tracing::info!(
            deleted,
            retention_days,
            "[startup] cleaned up old diff files"
        );
    } else {
        tracing::debug!("[startup] no diff files needed cleanup");
    }
}

/// Re-prettify all HTML snapshot baselines using the Rust prettifier.
///
/// This is a one-time migration: Node.js used js-beautify to prettify HTML before
/// storing baselines; the Rust server uses a different (but consistent) prettifier.
/// If we don't normalise existing baselines, the first diff after cutover would always
/// show spurious whitespace changes rather than real content changes.
///
/// The migration is tracked with a marker file so it only runs once even after restarts.
pub fn reprettify_baselines(data_dir: &str) {
    let marker = format!("{}/.baseline_reprettified_v1", data_dir);

    if Path::new(&marker).exists() {
        tracing::debug!("[startup] baseline re-prettification already done — skipping");
        return;
    }

    let snapshots_dir = format!("{}/snapshots", data_dir);
    let entries = match std::fs::read_dir(&snapshots_dir) {
        Ok(e) => e,
        Err(_) => {
            // Snapshots dir doesn't exist yet — nothing to migrate; write marker so we
            // don't attempt again on every boot before any server is added.
            let _ = std::fs::write(&marker, "1");
            return;
        }
    };

    let mut migrated = 0usize;
    let mut skipped = 0usize;

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("html") {
            continue;
        }
        match std::fs::read_to_string(&path) {
            Ok(content) => {
                let reprettified = differ::prettify(&content);
                if reprettified != content {
                    if std::fs::write(&path, &reprettified).is_ok() {
                        migrated += 1;
                    } else {
                        tracing::warn!("[startup] failed to write reprettified snapshot: {:?}", path);
                    }
                } else {
                    skipped += 1;
                }
            }
            Err(e) => {
                tracing::warn!("[startup] failed to read snapshot {:?}: {}", path, e);
            }
        }
    }

    tracing::info!(
        migrated,
        skipped,
        "[startup] re-prettified snapshot baselines"
    );

    // Write marker to prevent re-running on next boot
    if let Err(e) = std::fs::write(&marker, "1") {
        tracing::warn!("[startup] failed to write reprettification marker: {}", e);
    }
}
