use std::collections::HashMap;

use axum::{
    extract::{Path, State},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    auth::middleware::{RequireAdmin, RequireAuth},
    crypto,
    error::AppError,
    notifiers,
    state::AppState,
    types::{AlertPayload, AlertType, NotificationChannel},
};

/// Returns the set of config keys that are passwords for a given notifier type.
fn password_fields(ch_type: &str) -> &'static [&'static str] {
    match ch_type {
        "discord" => &["webhookUrl"],
        "pushover" => &["appToken", "userKey"],
        "teams" => &["webhookUrl"],
        _ => &[],
    }
}

/// Decrypts config_json and returns a redacted map suitable for the frontend
/// (password fields are replaced with "••••••••", other fields passed through).
fn redact_config(
    ch_type: &str,
    config_json: &str,
    encryption_key: Option<&str>,
) -> HashMap<String, Value> {
    let decrypted = if let Some(key) = encryption_key {
        crypto::decrypt_config(config_json, key).unwrap_or_default()
    } else {
        config_json.to_string()
    };

    let raw: HashMap<String, Value> = serde_json::from_str(&decrypted).unwrap_or_default();
    let passwords = password_fields(ch_type);

    raw.into_iter()
        .map(|(k, v)| {
            if passwords.contains(&k.as_str()) {
                let redacted = if v.as_str().map_or(false, |s| !s.is_empty()) {
                    "••••••••".into()
                } else {
                    Value::String(String::new())
                };
                (k, redacted)
            } else {
                (k, v)
            }
        })
        .collect()
}

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

    let enc_key = state.config.notifications_encryption_key.as_deref();
    let safe: Vec<Value> = channels
        .into_iter()
        .map(|c| {
            let config = redact_config(&c.channel_type, &c.config_json, enc_key);
            json!({
                "id": c.id,
                "type": c.channel_type,
                "label": c.label,
                "active": c.active,
                "config": config,
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
    active: Option<bool>,
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
    let active = if body.active.unwrap_or(true) { 1i64 } else { 0i64 };
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
    #[serde(default, deserialize_with = "crate::api::deserialize_nullable_string")]
    label: Option<Option<String>>,
    config: Option<Value>,
    active: Option<bool>,
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
            params.push(v.map(Value::Text).unwrap_or(Value::Null));
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
            params.push(Value::Integer(if v { 1 } else { 0 }));
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

// GET /api/notifications/types
pub async fn list_types(_auth: RequireAuth) -> Json<Value> {
    Json(json!([
        {
            "type": "discord",
            "displayName": "Discord",
            "configSchema": {
                "webhookUrl": {
                    "label": "Webhook URL",
                    "type": "password",
                    "required": true,
                    "placeholder": "https://discord.com/api/webhooks/..."
                }
            }
        },
        {
            "type": "pushover",
            "displayName": "Pushover",
            "configSchema": {
                "appToken": {
                    "label": "App Token",
                    "type": "password",
                    "required": true,
                    "placeholder": "Pushover application token"
                },
                "userKey": {
                    "label": "User Key",
                    "type": "password",
                    "required": true,
                    "placeholder": "Pushover user key"
                }
            }
        },
        {
            "type": "teams",
            "displayName": "Microsoft Teams",
            "configSchema": {
                "webhookUrl": {
                    "label": "Webhook URL",
                    "type": "password",
                    "required": true,
                    "placeholder": "https://outlook.office.com/webhook/..."
                }
            }
        }
    ]))
}

// POST /api/notifications/:id/test
pub async fn test_send(
    _admin: RequireAdmin,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<Value>, AppError> {
    let db = state.db.clone();
    let row: Option<(String, String)> = tokio::task::spawn_blocking(move || {
        let conn = db.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT type, config_json FROM notification_channels WHERE id = ?1",
        )?;
        let mut rows = stmt.query_map(rusqlite::params![id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        Ok::<_, rusqlite::Error>(rows.next().and_then(|r| r.ok()))
    })
    .await
    .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
    .map_err(AppError::Db)?;

    let (ch_type, config_json) = row
        .ok_or_else(|| AppError::NotFound(format!("Notification channel {} not found", id)))?;

    let decrypted = if let Some(ref key) = state.config.notifications_encryption_key {
        crypto::decrypt_config(&config_json, key).map_err(|e| AppError::Internal(e.to_string()))?
    } else {
        config_json
    };

    let cfg: HashMap<String, Value> =
        serde_json::from_str(&decrypted).map_err(|e| AppError::Internal(e.to_string()))?;

    let payload = AlertPayload {
        server_name: "Test Server".into(),
        url: "https://example.com".into(),
        alert_type: AlertType::Down,
        status_code: Some(503),
        response_time_ms: None,
        threshold: None,
        diff_id: None,
        diff_view_url: None,
        detected_at: chrono::Utc::now().to_rfc3339(),
        message: "This is a test alert from Vigil.".into(),
        ssl_days_remaining: None,
        ssl_fingerprint: None,
        ssl_subject: None,
        cve_id: None,
        cvss_score: None,
        cvss_severity: None,
        cve_digest: None,
        previous_exploitation: None,
        changed_fields: None,
    };

    let result = match ch_type.as_str() {
        "discord" => notifiers::discord::send(&cfg, &payload).await,
        "pushover" => notifiers::pushover::send(&cfg, &payload).await,
        "teams" => notifiers::teams::send(&cfg, &payload).await,
        other => return Err(AppError::Internal(format!("Unknown notifier type: {}", other))),
    };

    result.map_err(|e| AppError::Internal(format!("Test alert failed: {}", e)))?;
    Ok(Json(json!({ "ok": true })))
}
