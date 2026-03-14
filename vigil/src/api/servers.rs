use axum::{
    extract::{Path, State},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    auth::middleware::{RequireAdmin, RequireAuth},
    error::AppError,
    state::AppState,
    types::{Check, Server, ServerWithStatus},
};

fn query_server_with_status(
    conn: &rusqlite::Connection,
    id: i64,
) -> Result<Option<ServerWithStatus>, rusqlite::Error> {
    use rusqlite::OptionalExtension;

    let server: Option<Server> = conn
        .query_row(
            "SELECT id, name, url, interval_seconds, response_time_threshold_ms, active, \
             created_at, baseline_hash, baseline_file, last_alerted_at, last_alert_type, \
             ignore_patterns FROM servers WHERE id = ?1",
            rusqlite::params![id],
            row_to_server,
        )
        .optional()?;

    let Some(server) = server else {
        return Ok(None);
    };

    let last_check: Option<Check> = conn
        .query_row(
            "SELECT id, server_id, checked_at, status_code, response_time_ms, is_up, \
             content_hash, content_changed, diff_id FROM checks \
             WHERE server_id = ?1 ORDER BY checked_at DESC LIMIT 1",
            rusqlite::params![id],
            row_to_check,
        )
        .optional()?;

    Ok(Some(ServerWithStatus { server, last_check }))
}

fn row_to_server(row: &rusqlite::Row<'_>) -> rusqlite::Result<Server> {
    Ok(Server {
        id: row.get(0)?,
        name: row.get(1)?,
        url: row.get(2)?,
        interval_seconds: row.get(3)?,
        response_time_threshold_ms: row.get(4)?,
        active: row.get(5)?,
        created_at: row.get(6)?,
        baseline_hash: row.get(7)?,
        baseline_file: row.get(8)?,
        last_alerted_at: row.get(9)?,
        last_alert_type: row.get(10)?,
        ignore_patterns: row.get(11)?,
    })
}

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

// GET /api/servers
pub async fn list(
    _auth: RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<Value>, AppError> {
    let db = state.db.clone();
    let servers: Vec<ServerWithStatus> = tokio::task::spawn_blocking(move || {
        let conn = db.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, name, url, interval_seconds, response_time_threshold_ms, active, \
             created_at, baseline_hash, baseline_file, last_alerted_at, last_alert_type, \
             ignore_patterns FROM servers ORDER BY created_at DESC",
        )?;
        let ids: Vec<i64> = stmt
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        drop(stmt);

        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(s) = query_server_with_status(&conn, id)? {
                out.push(s);
            }
        }
        Ok::<_, rusqlite::Error>(out)
    })
    .await
    .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
    .map_err(AppError::Db)?;

    Ok(Json(json!(servers)))
}

// GET /api/servers/:id
pub async fn get_one(
    _auth: RequireAuth,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<Value>, AppError> {
    let db = state.db.clone();
    let result = tokio::task::spawn_blocking(move || query_server_with_status(&db.lock().unwrap(), id))
        .await
        .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
        .map_err(AppError::Db)?;

    result
        .map(|s| Json(json!(s)))
        .ok_or_else(|| AppError::NotFound(format!("Server {} not found", id)))
}

#[derive(Deserialize)]
pub struct CreateServer {
    name: String,
    url: String,
    interval_seconds: Option<i64>,
    response_time_threshold_ms: Option<i64>,
    ignore_patterns: Option<Value>,
}

// POST /api/servers
pub async fn create(
    _admin: RequireAdmin,
    State(state): State<AppState>,
    Json(body): Json<CreateServer>,
) -> Result<Json<Value>, AppError> {
    let mut errors = Vec::new();
    if body.name.trim().is_empty() {
        errors.push(json!({"msg": "name is required", "path": "name"}));
    }
    if body.url.trim().is_empty() {
        errors.push(json!({"msg": "url is required", "path": "url"}));
    }
    if !errors.is_empty() {
        return Err(AppError::Validation(errors));
    }

    let ignore_patterns = body.ignore_patterns.map(|v| v.to_string());
    let db = state.db.clone();
    let name = body.name.clone();
    let url = body.url.clone();
    let interval = body.interval_seconds.unwrap_or(300);
    let threshold = body.response_time_threshold_ms.unwrap_or(3000);

    let id: i64 = tokio::task::spawn_blocking(move || {
        let conn = db.lock().unwrap();
        conn.execute(
            "INSERT INTO servers (name, url, interval_seconds, response_time_threshold_ms, ignore_patterns) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![name, url, interval, threshold, ignore_patterns],
        )?;
        Ok::<_, rusqlite::Error>(conn.last_insert_rowid())
    })
    .await
    .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
    .map_err(AppError::Db)?;

    let db2 = state.db.clone();
    let server = tokio::task::spawn_blocking(move || query_server_with_status(&db2.lock().unwrap(), id))
        .await
        .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
        .map_err(AppError::Db)?
        .ok_or_else(|| AppError::Internal("Server not found after insert".into()))?;

    // Schedule monitoring for the new server
    state.monitor_engine.schedule(server.server.clone()).await;

    Ok(Json(json!(server)))
}

#[derive(Deserialize)]
pub struct UpdateServer {
    name: Option<String>,
    url: Option<String>,
    interval_seconds: Option<i64>,
    response_time_threshold_ms: Option<i64>,
    active: Option<i64>,
    ignore_patterns: Option<Value>,
}

// PUT /api/servers/:id
pub async fn update(
    _admin: RequireAdmin,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(body): Json<UpdateServer>,
) -> Result<Json<Value>, AppError> {
    let ignore_patterns = body.ignore_patterns.map(|v| v.to_string());
    let db = state.db.clone();

    let changes = tokio::task::spawn_blocking(move || {
        use rusqlite::types::Value;
        let conn = db.lock().unwrap();
        let mut parts: Vec<String> = Vec::new();
        let mut params: Vec<Value> = Vec::new();

        if let Some(v) = body.name { parts.push("name = ?".into()); params.push(Value::Text(v)); }
        if let Some(v) = body.url { parts.push("url = ?".into()); params.push(Value::Text(v)); }
        if let Some(v) = body.interval_seconds { parts.push("interval_seconds = ?".into()); params.push(Value::Integer(v)); }
        if let Some(v) = body.response_time_threshold_ms { parts.push("response_time_threshold_ms = ?".into()); params.push(Value::Integer(v)); }
        if let Some(v) = body.active { parts.push("active = ?".into()); params.push(Value::Integer(v)); }
        if let Some(v) = ignore_patterns { parts.push("ignore_patterns = ?".into()); params.push(Value::Text(v)); }

        if parts.is_empty() {
            return Ok::<_, rusqlite::Error>(0usize);
        }

        let sql = format!("UPDATE servers SET {} WHERE id = ?", parts.join(", "));
        params.push(Value::Integer(id));

        let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p as &dyn rusqlite::ToSql).collect();
        let changes = conn.execute(&sql, param_refs.as_slice())?;
        Ok(changes)
    })
    .await
    .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
    .map_err(AppError::Db)?;

    if changes == 0 {
        return Err(AppError::NotFound(format!("Server {} not found", id)));
    }

    let db2 = state.db.clone();
    let server = tokio::task::spawn_blocking(move || query_server_with_status(&db2.lock().unwrap(), id))
        .await
        .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
        .map_err(AppError::Db)?
        .ok_or_else(|| AppError::Internal("Server not found after update".into()))?;

    // Reschedule with updated config (handles active toggle too)
    state.monitor_engine.reschedule(server.server.clone()).await;

    Ok(Json(json!(server)))
}

// DELETE /api/servers/:id
pub async fn delete(
    _admin: RequireAdmin,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<Value>, AppError> {
    let db = state.db.clone();
    let changes = tokio::task::spawn_blocking(move || {
        let conn = db.lock().unwrap();
        conn.execute("DELETE FROM servers WHERE id = ?1", rusqlite::params![id])
    })
    .await
    .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
    .map_err(AppError::Db)?;

    if changes == 0 {
        return Err(AppError::NotFound(format!("Server {} not found", id)));
    }
    // Cancel the monitoring task for the deleted server
    state.monitor_engine.unschedule(id).await;
    Ok(Json(json!({ "ok": true })))
}

// POST /api/servers/:id/check  (trigger immediate check)
pub async fn trigger_check(
    _admin: RequireAdmin,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<Value>, AppError> {
    // Load the server and reschedule (which triggers an immediate check on next tick)
    let db = state.db.clone();
    let server_opt = tokio::task::spawn_blocking(move || {
        query_server_with_status(&db.lock().unwrap(), id)
    })
    .await
    .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
    .map_err(AppError::Db)?;

    let Some(s) = server_opt else {
        return Err(AppError::NotFound(format!("Server {} not found", id)));
    };

    state.monitor_engine.reschedule(s.server).await;
    Ok(Json(json!({ "ok": true, "queued": true })))
}
