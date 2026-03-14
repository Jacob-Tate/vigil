use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{auth::middleware::RequireAuth, error::AppError, state::AppState, types::Check};

fn row_to_check(row: &rusqlite::Row<'_>) -> rusqlite::Result<Check> {
    Ok(Check {
        id: row.get(0)?,
        server_id: row.get(1)?,
        checked_at: row.get(2)?,
        status_code: row.get(3)?,
        response_time_ms: row.get(4)?,
        is_up: row.get(5)?,
        content_hash: row.get(6)?,
        content_changed: row.get(7)?,
        diff_id: row.get(8)?,
    })
}

#[derive(Deserialize)]
pub struct ChecksQuery {
    server_id: Option<i64>,
    status: Option<String>, // "up" | "down"
    limit: Option<i64>,
    offset: Option<i64>,
}

// GET /api/checks
pub async fn list(
    _auth: RequireAuth,
    State(state): State<AppState>,
    Query(q): Query<ChecksQuery>,
) -> Result<Json<Value>, AppError> {
    let db = state.db.clone();
    let checks: Vec<Check> = tokio::task::spawn_blocking(move || {
        let conn = db.lock().unwrap();
        let limit = q.limit.unwrap_or(50).min(500);
        let offset = q.offset.unwrap_or(0);

        use rusqlite::types::Value;
        let mut conditions: Vec<String> = Vec::new();
        let mut params: Vec<Value> = Vec::new();

        if let Some(sid) = q.server_id {
            conditions.push("server_id = ?".into());
            params.push(Value::Integer(sid));
        }
        if let Some(ref status) = q.status {
            match status.as_str() {
                "up" => conditions.push("is_up = 1".into()),
                "down" => conditions.push("is_up = 0".into()),
                _ => {}
            }
        }

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

        let sql = format!(
            "SELECT id, server_id, checked_at, status_code, response_time_ms, is_up, \
             content_hash, content_changed, diff_id FROM checks {} \
             ORDER BY checked_at DESC LIMIT ? OFFSET ?",
            where_clause
        );

        params.push(Value::Integer(limit));
        params.push(Value::Integer(offset));

        let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p as &dyn rusqlite::ToSql).collect();
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt
            .query_map(param_refs.as_slice(), row_to_check)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok::<_, rusqlite::Error>(rows)
    })
    .await
    .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
    .map_err(AppError::Db)?;

    Ok(Json(json!(checks)))
}

// GET /api/checks/:serverId  — latest check for server
pub async fn latest(
    _auth: RequireAuth,
    State(state): State<AppState>,
    Path(server_id): Path<i64>,
) -> Result<Json<Value>, AppError> {
    use rusqlite::OptionalExtension;
    let db = state.db.clone();
    let check: Option<Check> = tokio::task::spawn_blocking(move || {
        let conn = db.lock().unwrap();
        conn.query_row(
            "SELECT id, server_id, checked_at, status_code, response_time_ms, is_up, \
             content_hash, content_changed, diff_id FROM checks \
             WHERE server_id = ?1 ORDER BY checked_at DESC LIMIT 1",
            rusqlite::params![server_id],
            row_to_check,
        )
        .optional()
    })
    .await
    .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
    .map_err(AppError::Db)?;

    Ok(Json(json!(check)))
}
