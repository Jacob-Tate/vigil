use axum::{extract::State, Json};
use serde_json::{json, Value};

use crate::{
    auth::middleware::{RequireAdmin, RequireAuth},
    error::AppError,
    state::AppState,
    types::CvelistSyncState,
};

// GET /api/cvelist/status
pub async fn status(_auth: RequireAuth, State(state): State<AppState>) -> Result<Json<Value>, AppError> {
    let db = state.db.clone();
    let st: CvelistSyncState = tokio::task::spawn_blocking(move || {
        let conn = db.lock().unwrap();
        let total: i64 = conn.query_row("SELECT COUNT(*) FROM cvelist_cves WHERE state = 'PUBLISHED'", [], |r| r.get(0)).unwrap_or(0);
        let rejected_count: i64 = conn.query_row("SELECT COUNT(*) FROM cvelist_cves WHERE state = 'REJECTED'", [], |r| r.get(0)).unwrap_or(0);
        let last_synced_at: Option<String> = conn.query_row("SELECT MAX(synced_at) FROM cvelist_cves", [], |r| r.get(0)).ok().flatten();
        let repo_version: Option<String> = conn.query_row(
            "SELECT sha256 FROM nvd_feed_state WHERE feed_name = 'cvelist'", [], |r| r.get(0)
        ).ok();
        Ok::<_, rusqlite::Error>(CvelistSyncState {
            total,
            rejected_count,
            last_synced_at,
            is_syncing: false, // overwritten below
            last_repo_version: repo_version.filter(|s| s.len() >= 8).map(|s| s[..8].to_string()),
        })
    })
    .await
    .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
    .map_err(AppError::Db)?;
    use std::sync::atomic::Ordering;
    let is_syncing = state.cvelist_syncing.load(Ordering::Relaxed);
    Ok(Json(json!(CvelistSyncState { is_syncing, ..st })))
}

// GET /api/cvelist  (list CVEs from cvelistV5)
pub async fn list(_auth: RequireAuth, State(state): State<AppState>) -> Result<Json<Value>, AppError> {
    let db = state.db.clone();
    let rows: Vec<Value> = tokio::task::spawn_blocking(move || {
        let conn = db.lock().unwrap();
        let rows = conn.prepare(
            "SELECT cve_id, state, cna_description, cna_title, date_published, date_updated, synced_at \
             FROM cvelist_cves ORDER BY date_published DESC LIMIT 200"
        )?.query_map([], |row| Ok(json!({
            "cve_id": row.get::<_, String>(0)?,
            "state": row.get::<_, String>(1)?,
            "cna_description": row.get::<_, Option<String>>(2)?,
            "cna_title": row.get::<_, Option<String>>(3)?,
            "date_published": row.get::<_, Option<String>>(4)?,
            "date_updated": row.get::<_, Option<String>>(5)?,
            "synced_at": row.get::<_, String>(6)?,
        })))?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok::<_, rusqlite::Error>(rows)
    })
    .await
    .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
    .map_err(AppError::Db)?;
    Ok(Json(json!(rows)))
}

// POST /api/cvelist/sync
pub async fn trigger_sync(_admin: RequireAdmin, State(state): State<AppState>) -> Result<Json<Value>, AppError> {
    use std::sync::atomic::Ordering;
    if state.cvelist_syncing.load(Ordering::Relaxed) {
        return Ok(Json(json!({ "ok": false, "message": "Sync already in progress" })));
    }
    let db = state.db.clone();
    let config = state.config.clone();
    let is_syncing = state.cvelist_syncing.clone();
    let cve_engine = state.cve_engine.clone();
    tokio::spawn(async move {
        crate::cve::cvelist_scheduler::run(&db, &config, &is_syncing, &cve_engine).await;
    });
    Ok(Json(json!({ "ok": true, "queued": true })))
}
