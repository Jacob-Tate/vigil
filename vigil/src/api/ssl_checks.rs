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
    target_id: Option<i64>,
    limit: Option<i64>,
    offset: Option<i64>,
}

// GET /api/ssl/checks
pub async fn list(
    _auth: RequireAuth,
    State(state): State<AppState>,
    Query(q): Query<SslChecksQuery>,
) -> Result<Json<Value>, AppError> {
    let db = state.db.clone();
    let checks: Vec<SslCheck> = tokio::task::spawn_blocking(move || {
        let conn = db.lock().unwrap();
        let limit = q.limit.unwrap_or(50).min(500);
        let offset = q.offset.unwrap_or(0);

        let (where_clause, target_id_param): (String, Option<i64>) =
            if let Some(tid) = q.target_id {
                ("WHERE target_id = ?1".into(), Some(tid))
            } else {
                (String::new(), None)
            };

        let sql = format!(
            "SELECT id, target_id, checked_at, error, tls_version, subject_cn, subject_o, \
             issuer_cn, issuer_o, valid_from, valid_to, days_remaining, fingerprint_sha256, \
             serial_number, sans, chain_json, cert_file, alert_type \
             FROM ssl_checks {} ORDER BY checked_at DESC LIMIT ?{} OFFSET ?{}",
            where_clause,
            if target_id_param.is_some() { "2" } else { "1" },
            if target_id_param.is_some() { "3" } else { "2" },
        );

        let rows: Vec<SslCheck> = if let Some(tid) = target_id_param {
            conn.prepare(&sql)?
                .query_map(rusqlite::params![tid, limit, offset], row_to_check)?
                .collect::<rusqlite::Result<_>>()?
        } else {
            conn.prepare(&sql)?
                .query_map(rusqlite::params![limit, offset], row_to_check)?
                .collect::<rusqlite::Result<_>>()?
        };
        Ok::<_, rusqlite::Error>(rows)
    })
    .await
    .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
    .map_err(AppError::Db)?;

    Ok(Json(json!(checks)))
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
