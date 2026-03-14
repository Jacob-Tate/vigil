use std::sync::{atomic::AtomicBool, Arc, Mutex};

use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;

mod api;
mod auth;
mod config;
mod crypto;
mod cve;
mod db;
mod error;
mod monitor;
mod notifiers;
mod ssl;
mod startup;
mod state;
mod types;

use config::Config;
use cve::engine::CveEngine;
use db::DbPool;
use monitor::engine::MonitorEngine;
use ssl::engine::SslEngine;
use state::AppState;
use types::NvdSyncStatus;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialise structured logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "vigil=info,tower_http=info".parse().unwrap()),
        )
        .init();

    // Install ring as the default rustls crypto provider (required before any TLS use)
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok(); // ok() in case it was already installed by reqwest

    // Load .env file (ignore if missing — production uses real env vars)
    dotenvy::dotenv().ok();

    // Validate and load configuration
    let config = Config::from_env().map_err(|e| anyhow::anyhow!("{}", e))?;

    // Ensure data directories exist
    db::ensure_data_dirs(&config.data_dir)?;

    // --- Startup maintenance tasks ---
    // Delete diffs older than the configured retention window
    startup::cleanup_old_diffs(&config.data_dir, config.diff_retention_days);
    // One-time migration: re-prettify Node.js baselines to match Rust prettifier output
    startup::reprettify_baselines(&config.data_dir);

    let db_path = format!("{}/monitor.db", config.data_dir);

    tracing::info!("Opening database at {}", db_path);
    let pool: DbPool = db::init(&db_path)?;

    // Seed the initial admin user
    auth::seed::seed_admin_user(pool.clone(), config.clone()).await?;

    let config_arc = Arc::new(config.clone());

    // Build monitor and SSL engines
    let monitor_engine = MonitorEngine::new(pool.clone(), config_arc.clone());
    let ssl_engine = SslEngine::new(pool.clone(), config_arc.clone());
    let cve_engine = CveEngine::new(pool.clone(), config_arc.clone());

    // Shared sync state
    let nvd_status = Arc::new(RwLock::new(NvdSyncStatus {
        is_importing: false,
        current_feed: None,
        feed_progress: 0.0,
        feeds_done: 0,
        feeds_total: 0,
        error: None,
        started_at: None,
        feed_states: Vec::new(),
    }));
    let kev_syncing = Arc::new(AtomicBool::new(false));
    let vulnrichment_syncing = Arc::new(AtomicBool::new(false));
    let cvelist_syncing = Arc::new(AtomicBool::new(false));
    let vulnrichment_progress: Arc<Mutex<Option<types::SyncProgress>>> = Arc::new(Mutex::new(None));
    let cvelist_progress: Arc<Mutex<Option<types::SyncProgress>>> = Arc::new(Mutex::new(None));

    // Start schedulers
    let nvd_token = cve::nvd_scheduler::start(
        pool.clone(),
        config_arc.clone(),
        nvd_status.clone(),
        cve_engine.clone(),
    );
    let kev_token = cve::kev_scheduler::start(
        pool.clone(),
        config_arc.clone(),
        kev_syncing.clone(),
    );
    let vr_token = cve::vulnrichment_scheduler::start(
        pool.clone(),
        config_arc.clone(),
        vulnrichment_syncing.clone(),
        vulnrichment_progress.clone(),
    );
    let cvelist_token = cve::cvelist_scheduler::start(
        pool.clone(),
        config_arc.clone(),
        cvelist_syncing.clone(),
        cve_engine.clone(),
        cvelist_progress.clone(),
    );

    let state = AppState {
        db: pool,
        config: config_arc,
        monitor_engine,
        ssl_engine,
        cve_engine,
        nvd_status,
        kev_syncing,
        vulnrichment_syncing,
        cvelist_syncing,
        vulnrichment_progress,
        cvelist_progress,
        scheduler_tokens: Arc::new(vec![nvd_token, kev_token, vr_token, cvelist_token]),
    };

    // Start the monitoring engines (schedules all active servers/targets)
    state.monitor_engine.start().await;
    state.ssl_engine.start().await;
    state.cve_engine.start().await;

    // CORS — allow the configured frontend origin with credentials
    let cors = CorsLayer::new()
        .allow_origin(
            config
                .client_origin
                .parse::<axum::http::HeaderValue>()
                .expect("CLIENT_ORIGIN is not a valid header value"),
        )
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
            axum::http::Method::DELETE,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
            axum::http::header::ACCEPT,
            axum::http::header::COOKIE,
        ])
        .allow_credentials(true);

    let app = api::router(state.clone()).layer(cors);

    let addr = format!("0.0.0.0:{}", config.port);
    tracing::info!("Vigil server listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    // Graceful shutdown: cancel all engine tasks and schedulers
    state.monitor_engine.stop().await;
    state.ssl_engine.stop().await;
    state.cve_engine.stop().await;
    for token in state.scheduler_tokens.iter() {
        token.cancel();
    }
    tracing::info!("Server shut down cleanly");
    Ok(())
}

/// Waits for Ctrl-C (SIGINT) or SIGTERM on Unix.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM handler");
        let mut sigint = signal(SignalKind::interrupt()).expect("SIGINT handler");
        tokio::select! {
            _ = sigterm.recv() => { tracing::info!("Received SIGTERM"); }
            _ = sigint.recv() => { tracing::info!("Received SIGINT"); }
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to listen for Ctrl-C");
        tracing::info!("Received Ctrl-C");
    }
}
