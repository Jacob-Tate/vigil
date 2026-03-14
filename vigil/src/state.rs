use std::sync::{
    atomic::AtomicBool,
    Arc,
};

use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

use crate::{
    config::Config,
    cve::engine::CveEngine,
    db::DbPool,
    monitor::engine::MonitorEngine,
    ssl::engine::SslEngine,
    types::NvdSyncStatus,
};

/// Shared application state injected into every Axum handler via `State<AppState>`.
#[derive(Clone)]
pub struct AppState {
    pub db: DbPool,
    pub config: Arc<Config>,
    pub monitor_engine: Arc<MonitorEngine>,
    pub ssl_engine: Arc<SslEngine>,
    pub cve_engine: Arc<CveEngine>,
    // NVD sync — detailed progress for the status endpoint
    pub nvd_status: Arc<RwLock<NvdSyncStatus>>,
    // Simpler is-syncing flags for the other three importers
    pub kev_syncing: Arc<AtomicBool>,
    pub vulnrichment_syncing: Arc<AtomicBool>,
    pub cvelist_syncing: Arc<AtomicBool>,
    // Scheduler cancellation tokens (held so main can stop them on shutdown)
    pub scheduler_tokens: Arc<Vec<CancellationToken>>,
}
