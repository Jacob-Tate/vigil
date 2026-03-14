use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{auth::middleware::{RequireAdmin, RequireAuth}, error::AppError, state::AppState, types::CveFinding};

fn row_to_finding(row: &rusqlite::Row<'_>) -> rusqlite::Result<CveFinding> {
    Ok(CveFinding {
        id: row.get(0)?,
        target_id: row.get(1)?,
        cve_id: row.get(2)?,
        published_at: row.get(3)?,
        last_modified_at: row.get(4)?,
        cvss_score: row.get(5)?,
        cvss_severity: row.get(6)?,
        description: row.get(7)?,
        nvd_url: row.get(8)?,
        found_at: row.get(9)?,
        alerted: row.get(10)?,
        is_kev: row.get(11).unwrap_or(0),
        kev_date_added: row.get(12).ok().flatten(),
        ssvc_exploitation: row.get(13).ok().flatten(),
        ssvc_automatable: row.get(14).ok().flatten(),
        ssvc_technical_impact: row.get(15).ok().flatten(),
        enrichment_fingerprint: row.get(16)?,
        exploitation_alert_sent: row.get(17)?,
        rejection_alert_sent: row.get(18)?,
        cvelist_state: row.get(19).ok().flatten(),
        cvelist_cna_description: row.get(20).ok().flatten(),
    })
}

const FINDINGS_SELECT: &str =
    "SELECT f.id, f.target_id, f.cve_id, f.published_at, f.last_modified_at, \
     f.cvss_score, f.cvss_severity, f.description, f.nvd_url, f.found_at, f.alerted, \
     CASE WHEN k.cve_id IS NOT NULL THEN 1 ELSE 0 END as is_kev, k.date_added, \
     s.exploitation, s.automatable, s.technical_impact, \
     f.enrichment_fingerprint, f.exploitation_alert_sent, f.rejection_alert_sent, \
     cv.state, cv.cna_description \
     FROM cve_findings f \
     LEFT JOIN cisa_kev k ON f.cve_id = k.cve_id \
     LEFT JOIN cisa_ssvc s ON f.cve_id = s.cve_id \
     LEFT JOIN cvelist_cves cv ON f.cve_id = cv.cve_id";

#[derive(Deserialize)]
pub struct FindingsQuery {
    target_id: Option<i64>,
    alerted: Option<i64>,
    limit: Option<i64>,
    offset: Option<i64>,
}

// GET /api/cve/findings
pub async fn list(_auth: RequireAuth, State(state): State<AppState>, Query(q): Query<FindingsQuery>) -> Result<Json<Value>, AppError> {
    let db = state.db.clone();
    let findings: Vec<CveFinding> = tokio::task::spawn_blocking(move || {
        let conn = db.lock().unwrap();
        let limit = q.limit.unwrap_or(100).min(1000);
        let offset = q.offset.unwrap_or(0);

        use rusqlite::types::Value;
        let mut conditions = Vec::new();
        let mut params: Vec<Value> = Vec::new();
        if let Some(tid) = q.target_id { conditions.push("f.target_id = ?".to_string()); params.push(Value::Integer(tid)); }
        if let Some(al) = q.alerted { conditions.push("f.alerted = ?".to_string()); params.push(Value::Integer(al)); }

        let where_clause = if conditions.is_empty() { String::new() } else { format!("WHERE {}", conditions.join(" AND ")) };
        let sql = format!("{} {} ORDER BY f.found_at DESC LIMIT ? OFFSET ?", FINDINGS_SELECT, where_clause);
        params.push(Value::Integer(limit));
        params.push(Value::Integer(offset));
        let refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p as &dyn rusqlite::ToSql).collect();
        let rows = conn.prepare(&sql)?.query_map(refs.as_slice(), row_to_finding)?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok::<_, rusqlite::Error>(rows)
    })
    .await
    .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
    .map_err(AppError::Db)?;
    Ok(Json(json!(findings)))
}

// PUT /api/cve/findings/:id
pub async fn update(_admin: RequireAdmin, State(state): State<AppState>, Path(id): Path<i64>, Json(body): Json<Value>) -> Result<Json<Value>, AppError> {
    let alerted = body.get("alerted").and_then(|v| v.as_i64());
    let db = state.db.clone();
    tokio::task::spawn_blocking(move || {
        let conn = db.lock().unwrap();
        if let Some(a) = alerted {
            conn.execute("UPDATE cve_findings SET alerted = ?1 WHERE id = ?2", rusqlite::params![a, id])?;
        }
        Ok::<_, rusqlite::Error>(())
    })
    .await
    .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
    .map_err(AppError::Db)?;
    Ok(Json(json!({ "ok": true })))
}

// DELETE /api/cve/findings/:id
pub async fn delete(_admin: RequireAdmin, State(state): State<AppState>, Path(id): Path<i64>) -> Result<Json<Value>, AppError> {
    let db = state.db.clone();
    let changes = tokio::task::spawn_blocking(move || {
        let conn = db.lock().unwrap();
        conn.execute("DELETE FROM cve_findings WHERE id = ?1", rusqlite::params![id])
    })
    .await
    .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
    .map_err(AppError::Db)?;
    if changes == 0 { return Err(AppError::NotFound(format!("Finding {} not found", id))); }
    Ok(Json(json!({ "ok": true })))
}
