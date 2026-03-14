use std::sync::{atomic::{AtomicBool, Ordering}, Arc, Mutex};

use tokio_util::sync::CancellationToken;

use crate::{config::Config, db::DbPool, types::SyncProgress};

use super::{cvelist_importer, engine::CveEngine, enrichment_alerter::check_enrichment_alerts};

pub fn start(
    db: DbPool,
    config: Arc<Config>,
    is_syncing: Arc<AtomicBool>,
    cve_engine: Arc<CveEngine>,
    progress: Arc<Mutex<Option<SyncProgress>>>,
) -> CancellationToken {
    let token = CancellationToken::new();
    let token_clone = token.clone();
    let interval_hours = config.cvelist_sync_interval_hours;
    let interval = std::time::Duration::from_secs(interval_hours * 3600);

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    run(&db, &config, &is_syncing, &cve_engine, &progress).await;
                }
                _ = token_clone.cancelled() => {
                    tracing::info!("[cvelist-scheduler] stopped");
                    break;
                }
            }
        }
    });

    tracing::info!(interval_hours, "[cvelist-scheduler] started");
    token
}

pub async fn run(
    db: &DbPool,
    config: &Arc<Config>,
    is_syncing: &Arc<AtomicBool>,
    cve_engine: &Arc<CveEngine>,
    progress: &Arc<Mutex<Option<SyncProgress>>>,
) {
    if is_syncing.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        tracing::info!("[cvelist-scheduler] already syncing");
        return;
    }
    let data_dir = config.data_dir.clone();
    match cvelist_importer::sync_cvelist(db, &data_dir, progress.clone()).await {
        Ok(r) => {
            tracing::info!(count = r.count, "[cvelist-scheduler] sync complete");
            cve_engine.evaluate_all().await;
            check_enrichment_alerts(db, config).await;
        }
        Err(e) => tracing::error!("[cvelist-scheduler] sync error: {}", e),
    }
    // Clear progress state on completion
    if let Ok(mut p) = progress.lock() { *p = None; }
    is_syncing.store(false, Ordering::SeqCst);
}
