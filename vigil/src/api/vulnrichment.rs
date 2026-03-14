use axum::{extract::State, Json};
use serde_json::{json, Value};

use crate::{
    auth::middleware::{RequireAdmin, RequireAuth},
    error::AppError,
    state::AppState,
    types::{SsvcExploitationStat, VulnrichmentSyncState},
};

// GET /api/vulnrichment/status
pub async fn status(_auth: RequireAuth, State(state): State<AppState>) -> Result<Json<Value>, AppError> {
    let db = state.db.clone();
    let mut st: VulnrichmentSyncState = tokio::task::spawn_blocking(move || {
        let conn = db.lock().unwrap();
        let total: i64 = conn.query_row("SELECT COUNT(*) FROM cisa_ssvc", [], |r| r.get(0)).unwrap_or(0);
        let last_synced_at: Option<String> = conn.query_row("SELECT MAX(synced_at) FROM cisa_ssvc", [], |r| r.get(0)).ok().flatten();
        let exploitation_breakdown: Vec<SsvcExploitationStat> = conn.prepare(
            "SELECT exploitation, COUNT(*) FROM cisa_ssvc WHERE exploitation IS NOT NULL GROUP BY exploitation ORDER BY COUNT(*) DESC"
        )?.query_map([], |row| Ok(SsvcExploitationStat {
            exploitation: row.get(0)?,
            count: row.get(1)?,
        }))?.collect::<rusqlite::Result<_>>()?;
        Ok::<_, rusqlite::Error>(VulnrichmentSyncState {
            total, last_synced_at, is_syncing: false, exploitation_breakdown,
            stage: None, stage_message: None, files_done: None, files_total: None,
        })
    })
    .await
    .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
    .map_err(AppError::Db)?;

    use std::sync::atomic::Ordering;
    st.is_syncing = state.vulnrichment_syncing.load(Ordering::Relaxed);

    // Merge in live progress if a sync is running
    if st.is_syncing {
        if let Ok(p) = state.vulnrichment_progress.lock() {
            if let Some(ref prog) = *p {
                st.stage = Some(prog.stage.clone());
                st.stage_message = Some(prog.message.clone());
                st.files_done = Some(prog.files_done);
                st.files_total = Some(prog.files_total);
            }
        }
    }

    Ok(Json(json!(st)))
}

// GET /api/vulnrichment  (list SSVC data)
pub async fn list(_auth: RequireAuth, State(state): State<AppState>) -> Result<Json<Value>, AppError> {
    let db = state.db.clone();
    let rows: Vec<Value> = tokio::task::spawn_blocking(move || {
        let conn = db.lock().unwrap();
        let rows = conn.prepare(
            "SELECT cve_id, exploitation, automatable, technical_impact, timestamp, synced_at FROM cisa_ssvc ORDER BY synced_at DESC LIMIT 1000"
        )?.query_map([], |row| Ok(json!({
            "cve_id": row.get::<_, String>(0)?,
            "exploitation": row.get::<_, Option<String>>(1)?,
            "automatable": row.get::<_, Option<String>>(2)?,
            "technical_impact": row.get::<_, Option<String>>(3)?,
            "timestamp": row.get::<_, Option<String>>(4)?,
            "synced_at": row.get::<_, String>(5)?,
        })))?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok::<_, rusqlite::Error>(rows)
    })
    .await
    .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
    .map_err(AppError::Db)?;
    Ok(Json(json!(rows)))
}

// POST /api/vulnrichment/sync
pub async fn trigger_sync(_admin: RequireAdmin, State(state): State<AppState>) -> Result<Json<Value>, AppError> {
    use std::sync::atomic::Ordering;
    if state.vulnrichment_syncing.load(Ordering::Relaxed) {
        return Ok(Json(json!({ "ok": false, "message": "Sync already in progress" })));
    }
    let db = state.db.clone();
    let config = state.config.clone();
    let is_syncing = state.vulnrichment_syncing.clone();
    let progress = state.vulnrichment_progress.clone();
    tokio::spawn(async move {
        crate::cve::vulnrichment_scheduler::run(&db, &config, &is_syncing, &progress).await;
    });
    Ok(Json(json!({ "ok": true, "queued": true })))
}
