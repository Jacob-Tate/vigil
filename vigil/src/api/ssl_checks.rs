use axum::{
    extract::{Path, Query, State},
    Json,
};
use rusqlite::OptionalExtension;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{auth::middleware::RequireAuth, error::AppError, state::AppState, types::SslCheck};

fn row_to_check(row: &rusqlite::Row<'_>) -> rusqlite::Result<SslCheck> {
    Ok(SslCheck {
        id: row.get(0)?,
        target_id: row.get(1)?,
        checked_at: row.get(2)?,
        error: row.get(3)?,
        tls_version: row.get(4)?,
        subject_cn: row.get(5)?,
        subject_o: row.get(6)?,
        issuer_cn: row.get(7)?,
        issuer_o: row.get(8)?,
        valid_from: row.get(9)?,
        valid_to: row.get(10)?,
        days_remaining: row.get(11)?,
        fingerprint_sha256: row.get(12)?,
        serial_number: row.get(13)?,
        sans: row.get(14)?,
        chain_json: row.get(15)?,
        cert_file: row.get(16)?,
        alert_type: row.get(17)?,
    })
}

#[derive(Deserialize)]
pub struct SslChecksQuery {
    #[serde(rename = "targetId")]
    target_id: Option<i64>,
    limit: Option<i64>,
    page: Option<i64>,
}

// GET /api/ssl/checks
pub async fn list(
    _auth: RequireAuth,
    State(state): State<AppState>,
    Query(q): Query<SslChecksQuery>,
) -> Result<Json<Value>, AppError> {
    let db = state.db.clone();
    let result = tokio::task::spawn_blocking(move || {
        let conn = db.lock().unwrap();
        let limit = q.limit.unwrap_or(50).min(500);
        let page = q.page.unwrap_or(1).max(1);
        let offset = (page - 1) * limit;

        let (where_clause, target_id_param): (String, Option<i64>) =
            if let Some(tid) = q.target_id {
                ("WHERE target_id = ?1".into(), Some(tid))
            } else {
                (String::new(), None)
            };

        // Count total for pagination
        let count_sql = format!("SELECT COUNT(*) FROM ssl_checks {}", where_clause);
        let total: i64 = if let Some(tid) = target_id_param {
            conn.query_row(&count_sql, rusqlite::params![tid], |r| r.get(0))?
        } else {
            conn.query_row(&count_sql, [], |r| r.get(0))?
        };

        let data_sql = format!(
            "SELECT id, target_id, checked_at, error, tls_version, subject_cn, subject_o, \
             issuer_cn, issuer_o, valid_from, valid_to, days_remaining, fingerprint_sha256, \
             serial_number, sans, chain_json, cert_file, alert_type \
             FROM ssl_checks {} ORDER BY checked_at DESC LIMIT ?{} OFFSET ?{}",
            where_clause,
            if target_id_param.is_some() { "2" } else { "1" },
            if target_id_param.is_some() { "3" } else { "2" },
        );

        let rows: Vec<SslCheck> = if let Some(tid) = target_id_param {
            conn.prepare(&data_sql)?
                .query_map(rusqlite::params![tid, limit, offset], row_to_check)?
                .collect::<rusqlite::Result<_>>()?
        } else {
            conn.prepare(&data_sql)?
                .query_map(rusqlite::params![limit, offset], row_to_check)?
                .collect::<rusqlite::Result<_>>()?
        };

        let pages = ((total as f64) / (limit as f64)).ceil() as i64;
        Ok::<_, rusqlite::Error>((rows, total, page, limit, pages))
    })
    .await
    .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
    .map_err(AppError::Db)?;

    let (data, total, page, limit, pages) = result;
    Ok(Json(json!({
        "data": data,
        "pagination": { "page": page, "limit": limit, "total": total, "pages": pages }
    })))
}

// GET /api/ssl/checks/stats/:targetId
pub async fn stats(
    _auth: RequireAuth,
    State(state): State<AppState>,
    Path(target_id): Path<i64>,
) -> Result<Json<Value>, AppError> {
    let db = state.db.clone();
    let row = tokio::task::spawn_blocking(move || {
        let conn = db.lock().unwrap();
        conn.query_row(
            "SELECT
                COUNT(*) as total_checks,
                SUM(CASE WHEN error IS NOT NULL THEN 1 ELSE 0 END) as error_checks,
                AVG(days_remaining) as avg_days_remaining,
                MIN(days_remaining) as min_days_remaining,
                SUM(CASE WHEN alert_type = 'SSL_CHANGED' THEN 1 ELSE 0 END) as cert_changes
             FROM ssl_checks WHERE target_id = ?1",
            rusqlite::params![target_id],
            |row| {
                Ok(json!({
                    "total_checks": row.get::<_, i64>(0)?,
                    "error_checks": row.get::<_, i64>(1)?,
                    "avg_days_remaining": row.get::<_, Option<f64>>(2)?,
                    "min_days_remaining": row.get::<_, Option<f64>>(3)?,
                    "cert_changes": row.get::<_, i64>(4)?,
                }))
            },
        )
    })
    .await
    .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
    .map_err(AppError::Db)?;

    Ok(Json(row))
}

// GET /api/ssl/checks/:targetId
pub async fn latest(
    _auth: RequireAuth,
    State(state): State<AppState>,
    Path(target_id): Path<i64>,
) -> Result<Json<Value>, AppError> {
    let db = state.db.clone();
    let check: Option<SslCheck> = tokio::task::spawn_blocking(move || {
        let conn = db.lock().unwrap();
        conn.query_row(
            "SELECT id, target_id, checked_at, error, tls_version, subject_cn, subject_o, \
             issuer_cn, issuer_o, valid_from, valid_to, days_remaining, fingerprint_sha256, \
             serial_number, sans, chain_json, cert_file, alert_type \
             FROM ssl_checks WHERE target_id = ?1 ORDER BY checked_at DESC LIMIT 1",
            rusqlite::params![target_id],
            row_to_check,
        )
        .optional()
    })
    .await
    .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
    .map_err(AppError::Db)?;

    Ok(Json(json!(check)))
}
