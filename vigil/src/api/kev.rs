use axum::{
    extract::{Query, State},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    auth::middleware::{RequireAdmin, RequireAuth},
    error::AppError,
    state::AppState,
    types::{CisaKevEntry, KevSyncState, KevYearStat},
};

#[derive(Deserialize)]
pub struct KevQuery {
    q: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

// GET /api/kev
pub async fn list(_auth: RequireAuth, State(state): State<AppState>, Query(q): Query<KevQuery>) -> Result<Json<Value>, AppError> {
    let db = state.db.clone();
    let entries: Vec<CisaKevEntry> = tokio::task::spawn_blocking(move || {
        let conn = db.lock().unwrap();
        let limit = q.limit.unwrap_or(100).min(1000);
        let offset = q.offset.unwrap_or(0);
        let search = q.q.unwrap_or_default();

        let (where_clause, pattern): (String, Option<String>) = if search.is_empty() {
            (String::new(), None)
        } else {
            ("WHERE (cve_id LIKE ? OR vulnerability_name LIKE ? OR product LIKE ?)".into(), Some(format!("%{}%", search)))
        };

        let sql = format!(
            "SELECT cve_id, vendor_project, product, vulnerability_name, date_added, \
             short_description, required_action, due_date, known_ransomware_campaign_use, notes, synced_at \
             FROM cisa_kev {} ORDER BY date_added DESC LIMIT ? OFFSET ?",
            where_clause
        );

        let row_fn = |row: &rusqlite::Row<'_>| Ok(CisaKevEntry {
            cve_id: row.get(0)?,
            vendor_project: row.get(1)?,
            product: row.get(2)?,
            vulnerability_name: row.get(3)?,
            date_added: row.get(4)?,
            short_description: row.get(5)?,
            required_action: row.get(6)?,
            due_date: row.get(7)?,
            known_ransomware_campaign_use: row.get(8)?,
            notes: row.get(9)?,
            synced_at: row.get(10)?,
        });

        let rows = if let Some(ref p) = pattern {
            conn.prepare(&sql)?.query_map(rusqlite::params![p, p, p, limit, offset], row_fn)?.collect::<rusqlite::Result<Vec<_>>>()?
        } else {
            conn.prepare(&sql)?.query_map(rusqlite::params![limit, offset], row_fn)?.collect::<rusqlite::Result<Vec<_>>>()?
        };
        Ok::<_, rusqlite::Error>(rows)
    })
    .await
    .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
    .map_err(AppError::Db)?;

    Ok(Json(json!(entries)))
}

// GET /api/kev/status
pub async fn status(_auth: RequireAuth, State(state): State<AppState>) -> Result<Json<Value>, AppError> {
    let db = state.db.clone();
    let st: KevSyncState = tokio::task::spawn_blocking(move || {
        let conn = db.lock().unwrap();
        let total: i64 = conn.query_row("SELECT COUNT(*) FROM cisa_kev", [], |r| r.get(0)).unwrap_or(0);
        let last_synced_at: Option<String> = conn.query_row("SELECT MAX(synced_at) FROM cisa_kev", [], |r| r.get(0)).ok().flatten();
        let year_stats: Vec<KevYearStat> = conn.prepare(
            "SELECT strftime('%Y', date_added) as year, COUNT(*), \
             SUM(CASE WHEN known_ransomware_campaign_use = 'Known' THEN 1 ELSE 0 END) \
             FROM cisa_kev WHERE date_added IS NOT NULL GROUP BY year ORDER BY year DESC"
        )?.query_map([], |row| Ok(KevYearStat {
            year: row.get(0)?,
            count: row.get(1)?,
            ransomware_count: row.get(2)?,
        }))?.collect::<rusqlite::Result<_>>()?;
        Ok::<_, rusqlite::Error>(KevSyncState { total, last_synced_at, is_syncing: false, year_stats }) // is_syncing overwritten below
    })
    .await
    .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
    .map_err(AppError::Db)?;

    use std::sync::atomic::Ordering;
    let is_syncing = state.kev_syncing.load(Ordering::Relaxed);
    Ok(Json(json!(KevSyncState { is_syncing, ..st })))
}

// POST /api/kev/sync
pub async fn trigger_sync(_admin: RequireAdmin, State(state): State<AppState>) -> Result<Json<Value>, AppError> {
    use std::sync::atomic::Ordering;
    if state.kev_syncing.load(Ordering::Relaxed) {
        return Ok(Json(json!({ "ok": false, "message": "Sync already in progress" })));
    }
    let db = state.db.clone();
    let config = state.config.clone();
    let is_syncing = state.kev_syncing.clone();
    tokio::spawn(async move {
        crate::cve::kev_scheduler::run(&db, &config, &is_syncing).await;
    });
    Ok(Json(json!({ "ok": true, "queued": true })))
}
