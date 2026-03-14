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
    types::NotificationChannel,
};

fn row_to_channel(row: &rusqlite::Row<'_>) -> rusqlite::Result<NotificationChannel> {
    Ok(NotificationChannel {
        id: row.get(0)?,
        channel_type: row.get(1)?,
        label: row.get(2)?,
        config_json: row.get(3)?,
        active: row.get(4)?,
    })
}

// GET /api/notifications
pub async fn list(
    _auth: RequireAuth,
    State(state): State<AppState>,
) -> Result<Json<Value>, AppError> {
    let db = state.db.clone();
    let channels: Vec<NotificationChannel> = tokio::task::spawn_blocking(move || {
        let conn = db.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT id, type, label, config_json, active FROM notification_channels ORDER BY id")?;
        let rows = stmt
            .query_map([], row_to_channel)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok::<_, rusqlite::Error>(rows)
    })
    .await
    .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
    .map_err(AppError::Db)?;

    // Strip config_json from the list response (sensitive data)
    let safe: Vec<Value> = channels
        .into_iter()
        .map(|c| {
            json!({
                "id": c.id,
                "type": c.channel_type,
                "label": c.label,
                "active": c.active
            })
        })
        .collect();

    Ok(Json(json!(safe)))
}

#[derive(Deserialize)]
pub struct CreateChannel {
    #[serde(rename = "type")]
    channel_type: String,
    label: Option<String>,
    config: Value, // raw config object (not yet encrypted)
    active: Option<i64>,
}

// POST /api/notifications
pub async fn create(
    _admin: RequireAdmin,
    State(state): State<AppState>,
    Json(body): Json<CreateChannel>,
) -> Result<Json<Value>, AppError> {
    let config_str = body.config.to_string();
    let config_json = if let Some(ref key) = state.config.notifications_encryption_key {
        crate::crypto::encrypt_config(&config_str, key)
            .map_err(|e| AppError::Internal(e.to_string()))?
    } else {
        config_str
    };

    let channel_type = body.channel_type.clone();
    let label = body.label.clone();
    let active = body.active.unwrap_or(1);
    let db = state.db.clone();

    let id: i64 = tokio::task::spawn_blocking(move || {
        let conn = db.lock().unwrap();
        conn.execute(
            "INSERT INTO notification_channels (type, label, config_json, active) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![channel_type, label, config_json, active],
        )?;
        Ok::<_, rusqlite::Error>(conn.last_insert_rowid())
    })
    .await
    .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
    .map_err(AppError::Db)?;

    Ok(Json(json!({ "id": id, "ok": true })))
}

#[derive(Deserialize)]
pub struct UpdateChannel {
    label: Option<String>,
    config: Option<Value>,
    active: Option<i64>,
}

// PUT /api/notifications/:id
pub async fn update(
    _admin: RequireAdmin,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(body): Json<UpdateChannel>,
) -> Result<Json<Value>, AppError> {
    let encryption_key = state.config.notifications_encryption_key.clone();
    let db = state.db.clone();

    let changes = tokio::task::spawn_blocking(move || {
        use rusqlite::types::Value;
        let conn = db.lock().unwrap();
        let mut parts: Vec<String> = Vec::new();
        let mut params: Vec<Value> = Vec::new();

        if let Some(v) = body.label {
            parts.push("label = ?".into());
            params.push(Value::Text(v));
        }
        if let Some(config) = body.config {
            let config_str = config.to_string();
            let stored = if let Some(ref key) = encryption_key {
                crate::crypto::encrypt_config(&config_str, key)
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(
                        std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                    )))?
            } else {
                config_str
            };
            parts.push("config_json = ?".into());
            params.push(Value::Text(stored));
        }
        if let Some(v) = body.active {
            parts.push("active = ?".into());
            params.push(Value::Integer(v));
        }

        if parts.is_empty() {
            return Ok::<_, rusqlite::Error>(0usize);
        }

        let sql = format!("UPDATE notification_channels SET {} WHERE id = ?", parts.join(", "));
        params.push(Value::Integer(id));
        let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p as &dyn rusqlite::ToSql).collect();
        conn.execute(&sql, param_refs.as_slice())
    })
    .await
    .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
    .map_err(AppError::Db)?;

    if changes == 0 {
        return Err(AppError::NotFound(format!("Notification channel {} not found", id)));
    }
    Ok(Json(json!({ "ok": true })))
}

// DELETE /api/notifications/:id
pub async fn delete(
    _admin: RequireAdmin,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<Value>, AppError> {
    let db = state.db.clone();
    let changes = tokio::task::spawn_blocking(move || {
        let conn = db.lock().unwrap();
        conn.execute(
            "DELETE FROM notification_channels WHERE id = ?1",
            rusqlite::params![id],
        )
    })
    .await
    .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
    .map_err(AppError::Db)?;

    if changes == 0 {
        return Err(AppError::NotFound(format!("Notification channel {} not found", id)));
    }
    Ok(Json(json!({ "ok": true })))
}

// POST /api/notifications/test  — send a test alert
pub async fn test_send(
    _admin: RequireAdmin,
    State(_state): State<AppState>,
    Json(_body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    // Notifier integration added in Phase 4
    Ok(Json(json!({ "ok": true })))
}
