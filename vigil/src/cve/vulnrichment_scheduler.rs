use std::sync::{atomic::{AtomicBool, Ordering}, Arc, Mutex};

use tokio_util::sync::CancellationToken;

use crate::{config::Config, db::DbPool, types::SyncProgress};

use super::{enrichment_alerter::check_enrichment_alerts, vulnrichment_importer};

pub fn start(
    db: DbPool,
    config: Arc<Config>,
    is_syncing: Arc<AtomicBool>,
    progress: Arc<Mutex<Option<SyncProgress>>>,
) -> CancellationToken {
    let token = CancellationToken::new();
    let token_clone = token.clone();
    let interval_hours = config.vulnrichment_sync_interval_hours;
    let interval = std::time::Duration::from_secs(interval_hours * 3600);

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    run(&db, &config, &is_syncing, &progress).await;
                }
                _ = token_clone.cancelled() => {
                    tracing::info!("[vulnrichment-scheduler] stopped");
                    break;
                }
            }
        }
    });

    tracing::info!(interval_hours, "[vulnrichment-scheduler] started");
    token
}

pub async fn run(
    db: &DbPool,
    config: &Arc<Config>,
    is_syncing: &Arc<AtomicBool>,
    progress: &Arc<Mutex<Option<SyncProgress>>>,
) {
    if is_syncing.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        tracing::info!("[vulnrichment-scheduler] already syncing");
        return;
    }
    let data_dir = config.data_dir.clone();
    match vulnrichment_importer::sync_vulnrichment(db, &data_dir, progress.clone()).await {
        Ok(r) => {
            tracing::info!(count = r.count, "[vulnrichment-scheduler] sync complete");
            if r.count > 0 {
                check_enrichment_alerts(db, config).await;
            }
        }
        Err(e) => tracing::error!("[vulnrichment-scheduler] sync error: {}", e),
    }
    // Clear progress state on completion
    if let Ok(mut p) = progress.lock() { *p = None; }
    is_syncing.store(false, Ordering::SeqCst);
}
