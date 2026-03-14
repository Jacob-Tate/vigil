use std::sync::Arc;

use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

use crate::{config::Config, db::DbPool, types::NvdSyncStatus};

use super::{engine::CveEngine, enrichment_alerter::check_enrichment_alerts, nvd_importer};

/// Spawn the NVD scheduled sync task. Returns a token you can cancel to stop it.
pub fn start(
    db: DbPool,
    config: Arc<Config>,
    status: Arc<RwLock<NvdSyncStatus>>,
    cve_engine: Arc<CveEngine>,
) -> CancellationToken {
    let token = CancellationToken::new();
    let token_clone = token.clone();
    let interval_hours = config.nvd_sync_interval_hours;
    let interval = std::time::Duration::from_secs(interval_hours * 3600);

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    run_scheduled_update(&db, &config, &status, &cve_engine).await;
                }
                _ = token_clone.cancelled() => {
                    tracing::info!("[nvd-scheduler] stopped");
                    break;
                }
            }
        }
    });

    tracing::info!(interval_hours, "[nvd-scheduler] started");
    token
}

async fn run_scheduled_update(
    db: &DbPool,
    config: &Arc<Config>,
    status: &Arc<RwLock<NvdSyncStatus>>,
    cve_engine: &Arc<CveEngine>,
) {
    // Check if already running
    if status.read().await.is_importing {
        tracing::info!("[nvd-scheduler] import already in progress, skipping");
        return;
    }

    match nvd_importer::needs_update(db, "modified").await {
        Ok(false) => {
            tracing::info!("[nvd-scheduler] modified feed unchanged, skipping");
            return;
        }
        Ok(true) => {}
        Err(e) => {
            tracing::error!("[nvd-scheduler] failed to check modified feed meta: {}", e);
            return;
        }
    }

    tracing::info!("[nvd-scheduler] modified feed changed — importing");
    {
        let mut w = status.write().await;
        w.is_importing = true;
        w.current_feed = Some("modified".into());
        w.started_at = Some(chrono::Utc::now().to_rfc3339());
        w.error = None;
    }

    match nvd_importer::import_feed(db, "modified", Some(status.clone())).await {
        Ok(count) => {
            tracing::info!(count, "[nvd-scheduler] modified feed import done");
            cve_engine.evaluate_all().await;
            check_enrichment_alerts(db, config).await;
        }
        Err(e) => {
            tracing::error!("[nvd-scheduler] import error: {}", e);
            status.write().await.error = Some(e.to_string());
        }
    }

    {
        let mut w = status.write().await;
        w.is_importing = false;
        w.current_feed = None;
    }
}

/// Run a full NVD import of all feed files (triggered manually via API).
pub async fn run_full_import(
    db: DbPool,
    config: Arc<Config>,
    status: Arc<RwLock<NvdSyncStatus>>,
    cve_engine: Arc<CveEngine>,
) {
    if status.read().await.is_importing {
        tracing::info!("[nvd-scheduler] import already in progress");
        return;
    }

    let feeds = nvd_importer::ALL_FEED_NAMES;
    {
        let mut w = status.write().await;
        w.is_importing = true;
        w.feeds_done = 0;
        w.feeds_total = feeds.len();
        w.started_at = Some(chrono::Utc::now().to_rfc3339());
        w.error = None;
    }

    let mut total = 0usize;
    for feed_name in feeds {
        {
            let mut w = status.write().await;
            w.current_feed = Some(feed_name.to_string());
        }
        match nvd_importer::import_feed(&db, feed_name, Some(status.clone())).await {
            Ok(n) => {
                total += n;
                tracing::info!(feed = feed_name, n, "[nvd-scheduler] feed done");
            }
            Err(e) => {
                tracing::error!(feed = feed_name, "[nvd-scheduler] feed error: {}", e);
                status.write().await.error = Some(format!("{}: {}", feed_name, e));
            }
        }
    }

    tracing::info!(total, "[nvd-scheduler] full import complete");
    cve_engine.evaluate_all().await;
    check_enrichment_alerts(&db, &config).await;

    {
        let mut w = status.write().await;
        w.is_importing = false;
        w.current_feed = None;
    }
}
