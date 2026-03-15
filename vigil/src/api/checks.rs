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
    #[serde(rename = "serverId")]
    server_id: Option<i64>,
    status: Option<String>, // "up" | "down"
    limit: Option<i64>,
    page: Option<i64>,
}

// GET /api/checks
pub async fn list(
    _auth: RequireAuth,
    State(state): State<AppState>,
    Query(q): Query<ChecksQuery>,
) -> Result<Json<Value>, AppError> {
    let db = state.db.clone();
    let result = tokio::task::spawn_blocking(move || {
        let conn = db.lock().unwrap();
        let limit = q.limit.unwrap_or(50).min(500);
        let page = q.page.unwrap_or(1).max(1);
        let offset = (page - 1) * limit;

        use rusqlite::types::Value;
        let mut conditions: Vec<String> = Vec::new();
        let mut filter_params: Vec<Value> = Vec::new();

        if let Some(sid) = q.server_id {
            conditions.push("server_id = ?".into());
            filter_params.push(Value::Integer(sid));
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

        // Count total for pagination
        let count_sql = format!("SELECT COUNT(*) FROM checks {}", where_clause);
        let count_param_refs: Vec<&dyn rusqlite::ToSql> = filter_params.iter().map(|p| p as &dyn rusqlite::ToSql).collect();
        let total: i64 = conn.query_row(&count_sql, count_param_refs.as_slice(), |r| r.get(0))?;

        let data_sql = format!(
            "SELECT id, server_id, checked_at, status_code, response_time_ms, is_up, \
             content_hash, content_changed, diff_id FROM checks {} \
             ORDER BY checked_at DESC LIMIT ? OFFSET ?",
            where_clause
        );

        let mut params: Vec<Value> = filter_params;
        params.push(Value::Integer(limit));
        params.push(Value::Integer(offset));

        let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p as &dyn rusqlite::ToSql).collect();
        let mut stmt = conn.prepare(&data_sql)?;
        let rows = stmt
            .query_map(param_refs.as_slice(), row_to_check)?
            .collect::<rusqlite::Result<Vec<_>>>()?;

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

// GET /api/checks/stats/:serverId
pub async fn stats(
    _auth: RequireAuth,
    State(state): State<AppState>,
    Path(server_id): Path<i64>,
) -> Result<Json<Value>, AppError> {
    let db = state.db.clone();
    let row = tokio::task::spawn_blocking(move || {
        let conn = db.lock().unwrap();
        conn.query_row(
            "SELECT
                COUNT(*) as total_checks,
                SUM(CASE WHEN is_up = 1 THEN 1 ELSE 0 END) as up_checks,
                AVG(response_time_ms) as avg_response_time_ms,
                MIN(response_time_ms) as min_response_time_ms,
                MAX(response_time_ms) as max_response_time_ms,
                SUM(CASE WHEN content_changed = 1 THEN 1 ELSE 0 END) as content_changes
             FROM checks WHERE server_id = ?1",
            rusqlite::params![server_id],
            |row| {
                let total: i64 = row.get(0)?;
                let up: i64 = row.get(1)?;
                let avg_rt: Option<f64> = row.get(2)?;
                let min_rt: Option<f64> = row.get(3)?;
                let max_rt: Option<f64> = row.get(4)?;
                let changes: i64 = row.get(5)?;
                let uptime_pct = if total > 0 {
                    Some(up as f64 / total as f64 * 100.0)
                } else {
                    None
                };
                Ok(json!({
                    "total_checks": total,
                    "up_checks": up,
                    "avg_response_time_ms": avg_rt,
                    "min_response_time_ms": min_rt,
                    "max_response_time_ms": max_rt,
                    "content_changes": changes,
                    "uptime_pct": uptime_pct,
                }))
            },
        )
    })
    .await
    .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
    .map_err(AppError::Db)?;

    Ok(Json(row))
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
