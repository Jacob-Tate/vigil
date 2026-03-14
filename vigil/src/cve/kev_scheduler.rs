use std::sync::{atomic::{AtomicBool, Ordering}, Arc};

use tokio_util::sync::CancellationToken;

use crate::{config::Config, db::DbPool};

use super::{enrichment_alerter::check_enrichment_alerts, kev_importer};

pub fn start(
    db: DbPool,
    config: Arc<Config>,
    is_syncing: Arc<AtomicBool>,
) -> CancellationToken {
    let token = CancellationToken::new();
    let token_clone = token.clone();
    let interval_hours = config.kev_sync_interval_hours;
    let interval = std::time::Duration::from_secs(interval_hours * 3600);

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    run(&db, &config, &is_syncing).await;
                }
                _ = token_clone.cancelled() => {
                    tracing::info!("[kev-scheduler] stopped");
                    break;
                }
            }
        }
    });

    tracing::info!(interval_hours, "[kev-scheduler] started");
    token
}

pub async fn run(db: &DbPool, config: &Arc<Config>, is_syncing: &Arc<AtomicBool>) {
    if is_syncing.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        tracing::info!("[kev-scheduler] already syncing");
        return;
    }
    match kev_importer::sync_kev(db).await {
        Ok(r) => {
            tracing::info!(count = r.count, "[kev-scheduler] sync complete");
            check_enrichment_alerts(db, config).await;
        }
        Err(e) => tracing::error!("[kev-scheduler] sync error: {}", e),
    }
    is_syncing.store(false, Ordering::SeqCst);
}
