use axum::{
    middleware,
    routing::{get, post, put},
    Router,
};
use serde_json::json;

use crate::state::AppState;

pub mod audit;
pub mod auth;
pub mod checks;
pub mod cve_findings;
pub mod cve_targets;
pub mod cvelist;
pub mod diffs;
pub mod kev;
pub mod notifications;
pub mod nvd;
pub mod servers;
pub mod ssl_checks;
pub mod ssl_targets;
pub mod users;
pub mod vulnrichment;

/// Builds the full Axum router with all API routes mounted.
pub fn router(state: AppState) -> Router {
    Router::new()
        // Health check (no auth required)
        .route("/api/health", get(health))
        // Auth (no auth required — checked per-handler via extractors)
        .route("/api/auth/login", post(auth::login))
        .route("/api/auth/logout", post(auth::logout))
        .route("/api/auth/me", get(auth::me))
        // HTTP Monitor servers
        .route("/api/servers", get(servers::list).post(servers::create))
        .route(
            "/api/servers/:id",
            get(servers::get_one)
                .put(servers::update)
                .delete(servers::delete),
        )
        .route("/api/servers/:id/check", post(servers::trigger_check))
        // Checks
        .route("/api/checks", get(checks::list))
        .route("/api/checks/:serverId", get(checks::latest))
        // Content diffs
        .route("/api/diffs/:diffId", get(diffs::get_diff))
        // Notifications
        .route(
            "/api/notifications",
            get(notifications::list).post(notifications::create),
        )
        .route(
            "/api/notifications/:id",
            put(notifications::update).delete(notifications::delete),
        )
        .route("/api/notifications/test", post(notifications::test_send))
        // SSL targets
        .route(
            "/api/ssl/targets",
            get(ssl_targets::list).post(ssl_targets::create),
        )
        .route(
            "/api/ssl/targets/:id",
            get(ssl_targets::get_one)
                .put(ssl_targets::update)
                .delete(ssl_targets::delete),
        )
        .route("/api/ssl/targets/:id/check", post(ssl_targets::trigger_check))
        // SSL checks
        .route("/api/ssl/checks", get(ssl_checks::list))
        .route("/api/ssl/checks/:targetId", get(ssl_checks::latest))
        // NVD sync & browse
        .route("/api/nvd/sync", post(nvd::trigger_sync))
        .route("/api/nvd/status", get(nvd::sync_status))
        .route("/api/nvd/browse/search", get(nvd::browse_search))
        .route("/api/nvd/browse/detail/:cveId", get(nvd::browse_detail))
        // CVE targets
        .route(
            "/api/cve/targets",
            get(cve_targets::list).post(cve_targets::create),
        )
        .route(
            "/api/cve/targets/:id",
            get(cve_targets::get_one)
                .put(cve_targets::update)
                .delete(cve_targets::delete),
        )
        .route("/api/cve/targets/:id/check", post(cve_targets::trigger_check))
        // CVE findings
        .route("/api/cve/findings", get(cve_findings::list))
        .route(
            "/api/cve/findings/:id",
            put(cve_findings::update).delete(cve_findings::delete),
        )
        // KEV
        .route("/api/kev", get(kev::list))
        .route("/api/kev/status", get(kev::status))
        .route("/api/kev/sync", post(kev::trigger_sync))
        // Vulnrichment
        .route("/api/vulnrichment", get(vulnrichment::list))
        .route("/api/vulnrichment/status", get(vulnrichment::status))
        .route("/api/vulnrichment/sync", post(vulnrichment::trigger_sync))
        // CVEList
        .route("/api/cvelist", get(cvelist::list))
        .route("/api/cvelist/status", get(cvelist::status))
        //.route("/api/cvelist/sync", post(cvelist::trigger_sync)) // DISABLED: sync broken
        // Users (admin only — enforced per-handler)
        .route("/api/users", get(users::list).post(users::create))
        .route(
            "/api/users/:id",
            put(users::update).delete(users::delete),
        )
        .route("/api/users/:id/change-password", post(users::change_password))
        .with_state(state)
        .layer(middleware::from_fn(audit::audit_log))
}

async fn health() -> axum::Json<serde_json::Value> {
    axum::Json(json!({ "ok": true, "timestamp": chrono::Utc::now().to_rfc3339() }))
}
