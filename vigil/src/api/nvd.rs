use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    auth::middleware::{RequireAdmin, RequireAuth},
    error::AppError,
    state::AppState,
    types::{NvdCpeEntry, NvdCveDetail, NvdCveRef, NvdFeedState, NvdSyncStatus},
};

// GET /api/nvd/sync/status
pub async fn sync_status(_auth: RequireAuth, State(state): State<AppState>) -> Result<Json<Value>, AppError> {
    let live = state.nvd_status.read().await.clone();

    // If importing, return live status; otherwise fetch fresh feed_states from DB
    let feed_states = if live.is_importing {
        live.feed_states.clone()
    } else {
        let db = state.db.clone();
        tokio::task::spawn_blocking(move || {
            let conn = db.lock().unwrap();
            let rows = conn.prepare(
                "SELECT feed_name, last_modified_date, sha256, total_cves, imported_at FROM nvd_feed_state ORDER BY feed_name"
            )?.query_map([], |row| Ok(NvdFeedState {
                feed_name: row.get(0)?,
                last_modified_date: row.get(1)?,
                sha256: row.get(2)?,
                total_cves: row.get(3)?,
                imported_at: row.get(4)?,
            }))?.collect::<rusqlite::Result<Vec<_>>>()?;
            Ok::<_, rusqlite::Error>(rows)
        })
        .await
        .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
        .map_err(AppError::Db)?
    };

    let status = NvdSyncStatus { feed_states, ..live };
    Ok(Json(json!(status)))
}

// POST /api/nvd/sync  (trigger full sync)
pub async fn trigger_sync(_admin: RequireAdmin, State(state): State<AppState>) -> Result<Json<Value>, AppError> {
    if state.nvd_status.read().await.is_importing {
        return Ok(Json(json!({ "ok": false, "message": "Import already in progress" })));
    }
    let db = state.db.clone();
    let config = state.config.clone();
    let nvd_status = state.nvd_status.clone();
    let cve_engine = state.cve_engine.clone();
    tokio::spawn(crate::cve::nvd_scheduler::run_full_import(db, config, nvd_status, cve_engine));
    Ok(Json(json!({ "ok": true, "queued": true })))
}

#[derive(Deserialize)]
pub struct NvdSearchQuery {
    q: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

// GET /api/nvd/browse/search
pub async fn browse_search(
    _auth: RequireAuth,
    State(state): State<AppState>,
    Query(q): Query<NvdSearchQuery>,
) -> Result<Json<Value>, AppError> {
    let db = state.db.clone();
    let (cves, total): (Vec<Value>, i64) = tokio::task::spawn_blocking(move || {
        let conn = db.lock().unwrap();
        let limit = q.limit.unwrap_or(20).min(100);
        let offset = q.offset.unwrap_or(0);
        let search = q.q.unwrap_or_default();

        let (where_clause, pattern): (String, Option<String>) = if search.is_empty() {
            (String::new(), None)
        } else {
            ("WHERE (cve_id LIKE ? OR description LIKE ?)".into(), Some(format!("%{}%", search)))
        };

        let count_sql = format!("SELECT COUNT(*) FROM nvd_cves {}", where_clause);
        let total: i64 = if let Some(ref p) = pattern {
            conn.query_row(&count_sql, rusqlite::params![p, p], |r| r.get(0))?
        } else {
            conn.query_row(&count_sql, [], |r| r.get(0))?
        };

        let data_sql = format!(
            "SELECT cve_id, published_at, last_modified_at, cvss_score, cvss_severity, description, nvd_url \
             FROM nvd_cves {} ORDER BY published_at DESC LIMIT ? OFFSET ?",
            where_clause
        );

        let rows: Vec<Value> = if let Some(ref p) = pattern {
            conn.prepare(&data_sql)?
                .query_map(rusqlite::params![p, p, limit, offset], |row| {
                    Ok(json!({
                        "cve_id": row.get::<_, String>(0)?,
                        "published_at": row.get::<_, Option<String>>(1)?,
                        "last_modified_at": row.get::<_, Option<String>>(2)?,
                        "cvss_score": row.get::<_, Option<f64>>(3)?,
                        "cvss_severity": row.get::<_, Option<String>>(4)?,
                        "description": row.get::<_, Option<String>>(5)?,
                        "nvd_url": row.get::<_, Option<String>>(6)?,
                    }))
                })?
                .collect::<rusqlite::Result<_>>()?
        } else {
            conn.prepare(&data_sql)?
                .query_map(rusqlite::params![limit, offset], |row| {
                    Ok(json!({
                        "cve_id": row.get::<_, String>(0)?,
                        "published_at": row.get::<_, Option<String>>(1)?,
                        "last_modified_at": row.get::<_, Option<String>>(2)?,
                        "cvss_score": row.get::<_, Option<f64>>(3)?,
                        "cvss_severity": row.get::<_, Option<String>>(4)?,
                        "description": row.get::<_, Option<String>>(5)?,
                        "nvd_url": row.get::<_, Option<String>>(6)?,
                    }))
                })?
                .collect::<rusqlite::Result<_>>()?
        };

        Ok::<_, rusqlite::Error>((rows, total))
    })
    .await
    .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
    .map_err(AppError::Db)?;

    Ok(Json(json!({
        "data": cves,
        "pagination": {
            "total": total,
            "limit": q.limit.unwrap_or(20),
            "offset": q.offset.unwrap_or(0),
        }
    })))
}

// GET /api/nvd/browse/detail/:cveId
pub async fn browse_detail(
    _auth: RequireAuth,
    State(state): State<AppState>,
    Path(cve_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    use rusqlite::OptionalExtension;
    let db = state.db.clone();

    let cve_id_clone = cve_id.clone();
    let detail: Option<NvdCveDetail> = tokio::task::spawn_blocking(move || {
        let cve_id = cve_id_clone;
        let conn = db.lock().unwrap();

        let base: Option<(String, Option<String>, Option<String>, Option<f64>, Option<String>, Option<String>, Option<String>, Option<String>)> = conn
            .query_row(
                "SELECT cve_id, published_at, last_modified_at, cvss_score, cvss_severity, description, nvd_url, references_json \
                 FROM nvd_cves WHERE cve_id = ?1",
                rusqlite::params![cve_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?)),
            )
            .optional()?;

        let Some((cid, pub_at, mod_at, cvss, severity, desc, url, refs_json)) = base else {
            return Ok::<_, rusqlite::Error>(None);
        };

        let cpe_entries: Vec<NvdCpeEntry> = conn
            .prepare("SELECT cpe_string, version_start_including, version_start_excluding, version_end_including, version_end_excluding FROM nvd_cve_cpes WHERE cve_id = ?1")?
            .query_map(rusqlite::params![cid], |row| Ok(NvdCpeEntry {
                cpe_string: row.get(0)?,
                version_start_including: row.get(1)?,
                version_start_excluding: row.get(2)?,
                version_end_including: row.get(3)?,
                version_end_excluding: row.get(4)?,
            }))?
            .collect::<rusqlite::Result<_>>()?;

        let references: Vec<NvdCveRef> = refs_json
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();

        let kev = conn
            .query_row(
                "SELECT date_added, vulnerability_name, required_action, due_date, known_ransomware_campaign_use FROM cisa_kev WHERE cve_id = ?1",
                rusqlite::params![cid],
                |row| Ok(crate::types::KevDetail {
                    date_added: row.get(0)?,
                    vulnerability_name: row.get(1)?,
                    required_action: row.get(2)?,
                    due_date: row.get(3)?,
                    known_ransomware_campaign_use: row.get(4)?,
                }),
            )
            .optional()?;

        let ssvc = conn
            .query_row(
                "SELECT exploitation, automatable, technical_impact FROM cisa_ssvc WHERE cve_id = ?1",
                rusqlite::params![cid],
                |row| Ok(crate::types::SsvcDetail {
                    exploitation: row.get(0)?,
                    automatable: row.get(1)?,
                    technical_impact: row.get(2)?,
                }),
            )
            .optional()?;

        let cvelist = conn
            .query_row(
                "SELECT state, cna_description, cna_title, date_published, date_updated FROM cvelist_cves WHERE cve_id = ?1",
                rusqlite::params![cid],
                |row| Ok(crate::types::CvelistDetail {
                    state: row.get(0)?,
                    cna_description: row.get(1)?,
                    cna_title: row.get(2)?,
                    date_published: row.get(3)?,
                    date_updated: row.get(4)?,
                }),
            )
            .optional()?;

        Ok(Some(NvdCveDetail { cve_id: cid, published_at: pub_at, last_modified_at: mod_at, cvss_score: cvss, cvss_severity: severity, description: desc, nvd_url: url, cpe_entries, references, kev, ssvc, cvelist }))
    })
    .await
    .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
    .map_err(AppError::Db)?;

    detail
        .map(|d| Json(json!(d)))
        .ok_or_else(|| AppError::NotFound(format!("{} not found", cve_id)))
}
