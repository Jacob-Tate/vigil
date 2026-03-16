use axum::{
    extract::{Path, State},
    Json,
};
use rusqlite::OptionalExtension;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    auth::middleware::{RequireAdmin, RequireAuth},
    error::AppError,
    state::AppState,
    types::{SslCheck, SslTarget, SslTargetWithStatus},
};

fn row_to_target(row: &rusqlite::Row<'_>) -> rusqlite::Result<SslTarget> {
    Ok(SslTarget {
        id: row.get(0)?,
        name: row.get(1)?,
        host: row.get(2)?,
        port: row.get(3)?,
        check_interval_seconds: row.get(4)?,
        expiry_threshold_hours: row.get(5)?,
        active: row.get(6)?,
        created_at: row.get(7)?,
        last_checked_at: row.get(8)?,
        last_alert_type: row.get(9)?,
        last_alerted_at: row.get(10)?,
    })
}

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

fn target_with_status(conn: &rusqlite::Connection, id: i64) -> rusqlite::Result<Option<SslTargetWithStatus>> {
    let target: Option<SslTarget> = conn
        .query_row(
            "SELECT id, name, host, port, check_interval_seconds, expiry_threshold_hours, \
             active, created_at, last_checked_at, last_alert_type, last_alerted_at \
             FROM ssl_targets WHERE id = ?1",
            rusqlite::params![id],
            row_to_target,
        )
        .optional()?;

    let Some(target) = target else { return Ok(None); };

    let last_check: Option<SslCheck> = conn
        .query_row(
            "SELECT id, target_id, checked_at, error, tls_version, subject_cn, subject_o, \
             issuer_cn, issuer_o, valid_from, valid_to, days_remaining, fingerprint_sha256, \
             serial_number, sans, chain_json, cert_file, alert_type FROM ssl_checks \
             WHERE target_id = ?1 ORDER BY checked_at DESC LIMIT 1",
            rusqlite::params![id],
            row_to_check,
        )
        .optional()?;

    Ok(Some(SslTargetWithStatus { target, last_check }))
}

// GET /api/ssl/targets
pub async fn list(_auth: RequireAuth, State(state): State<AppState>) -> Result<Json<Value>, AppError> {
    let db = state.db.clone();
    let results: Vec<SslTargetWithStatus> = tokio::task::spawn_blocking(move || {
        let conn = db.lock().unwrap();
        let ids: Vec<i64> = conn
            .prepare("SELECT id FROM ssl_targets ORDER BY created_at DESC")?
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(t) = target_with_status(&conn, id)? { out.push(t); }
        }
        Ok::<_, rusqlite::Error>(out)
    })
    .await
    .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
    .map_err(AppError::Db)?;

    Ok(Json(json!(results)))
}

// GET /api/ssl/targets/:id
pub async fn get_one(_auth: RequireAuth, State(state): State<AppState>, Path(id): Path<i64>) -> Result<Json<Value>, AppError> {
    let db = state.db.clone();
    let result = tokio::task::spawn_blocking(move || target_with_status(&db.lock().unwrap(), id))
        .await
        .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
        .map_err(AppError::Db)?;

    result
        .map(|t| Json(json!(t)))
        .ok_or_else(|| AppError::NotFound(format!("SSL target {} not found", id)))
}

#[derive(Deserialize)]
pub struct CreateTarget {
    name: String,
    host: String,
    port: Option<i64>,
    check_interval_seconds: Option<i64>,
    expiry_threshold_hours: Option<i64>,
}

// POST /api/ssl/targets
pub async fn create(_admin: RequireAdmin, State(state): State<AppState>, Json(body): Json<CreateTarget>) -> Result<Json<Value>, AppError> {
    let mut errors = Vec::new();
    if body.name.trim().is_empty() { errors.push(json!({"msg": "name is required", "path": "name"})); }
    if body.host.trim().is_empty() { errors.push(json!({"msg": "host is required", "path": "host"})); }
    if !errors.is_empty() { return Err(AppError::Validation(errors)); }

    let db = state.db.clone();
    let id: i64 = tokio::task::spawn_blocking(move || {
        let conn = db.lock().unwrap();
        conn.execute(
            "INSERT INTO ssl_targets (name, host, port, check_interval_seconds, expiry_threshold_hours) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![body.name, body.host, body.port.unwrap_or(443), body.check_interval_seconds.unwrap_or(3600), body.expiry_threshold_hours.unwrap_or(168)],
        )?;
        Ok::<_, rusqlite::Error>(conn.last_insert_rowid())
    })
    .await
    .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
    .map_err(AppError::Db)?;

    let db2 = state.db.clone();
    let t = tokio::task::spawn_blocking(move || target_with_status(&db2.lock().unwrap(), id))
        .await
        .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
        .map_err(AppError::Db)?
        .ok_or_else(|| AppError::Internal("Target not found after insert".into()))?;

    state.ssl_engine.schedule(t.target.clone()).await;
    Ok(Json(json!(t)))
}

#[derive(Deserialize)]
pub struct UpdateTarget {
    name: Option<String>,
    host: Option<String>,
    port: Option<i64>,
    check_interval_seconds: Option<i64>,
    expiry_threshold_hours: Option<i64>,
    active: Option<bool>,
}

// PUT /api/ssl/targets/:id
pub async fn update(_admin: RequireAdmin, State(state): State<AppState>, Path(id): Path<i64>, Json(body): Json<UpdateTarget>) -> Result<Json<Value>, AppError> {
    let db = state.db.clone();
    let changes = tokio::task::spawn_blocking(move || {
        use rusqlite::types::Value;
        let conn = db.lock().unwrap();
        let mut parts: Vec<String> = Vec::new();
        let mut params: Vec<Value> = Vec::new();
        if let Some(v) = body.name { parts.push("name = ?".into()); params.push(Value::Text(v)); }
        if let Some(v) = body.host { parts.push("host = ?".into()); params.push(Value::Text(v)); }
        if let Some(v) = body.port { parts.push("port = ?".into()); params.push(Value::Integer(v)); }
        if let Some(v) = body.check_interval_seconds { parts.push("check_interval_seconds = ?".into()); params.push(Value::Integer(v)); }
        if let Some(v) = body.expiry_threshold_hours { parts.push("expiry_threshold_hours = ?".into()); params.push(Value::Integer(v)); }
        if let Some(v) = body.active { parts.push("active = ?".into()); params.push(Value::Integer(if v { 1 } else { 0 })); }
        if parts.is_empty() { return Ok::<_, rusqlite::Error>(0usize); }
        let sql = format!("UPDATE ssl_targets SET {} WHERE id = ?", parts.join(", "));
        params.push(Value::Integer(id));
        let refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p as &dyn rusqlite::ToSql).collect();
        conn.execute(&sql, refs.as_slice())
    })
    .await
    .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
    .map_err(AppError::Db)?;

    if changes == 0 { return Err(AppError::NotFound(format!("SSL target {} not found", id))); }
    let db2 = state.db.clone();
    let t = tokio::task::spawn_blocking(move || target_with_status(&db2.lock().unwrap(), id))
        .await
        .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
        .map_err(AppError::Db)?
        .ok_or_else(|| AppError::Internal("Target not found after update".into()))?;

    state.ssl_engine.reschedule(t.target.clone()).await;
    Ok(Json(json!(t)))
}

// DELETE /api/ssl/targets/:id
pub async fn delete(_admin: RequireAdmin, State(state): State<AppState>, Path(id): Path<i64>) -> Result<Json<Value>, AppError> {
    let db = state.db.clone();
    let changes = tokio::task::spawn_blocking(move || {
        let conn = db.lock().unwrap();
        conn.execute("DELETE FROM ssl_targets WHERE id = ?1", rusqlite::params![id])
    })
    .await
    .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
    .map_err(AppError::Db)?;
    if changes == 0 { return Err(AppError::NotFound(format!("SSL target {} not found", id))); }
    state.ssl_engine.unschedule(id).await;
    Ok(Json(json!({ "ok": true })))
}

// POST /api/ssl/targets/:id/check
pub async fn trigger_check(_admin: RequireAdmin, State(state): State<AppState>, Path(id): Path<i64>) -> Result<Json<Value>, AppError> {
    let db = state.db.clone();
    let target_opt = tokio::task::spawn_blocking(move || target_with_status(&db.lock().unwrap(), id))
        .await
        .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
        .map_err(AppError::Db)?;

    let Some(t) = target_opt else {
        return Err(AppError::NotFound(format!("SSL target {} not found", id)));
    };
    state.ssl_engine.reschedule(t.target).await;
    Ok(Json(json!({ "ok": true, "queued": true })))
}

#[cfg(test)]
mod tests {
    use super::UpdateTarget;

    /// Regression: frontend sends `active` as a JSON boolean; same class of bug
    /// as cve_targets (fixed in 3f87c00) — Option<i64> caused a 422.
    #[test]
    fn update_ssl_target_active_bool_true() {
        let body: UpdateTarget =
            serde_json::from_str(r#"{"active": true}"#).expect("should deserialise boolean true");
        let db_val = body.active.map(|v| if v { 1i64 } else { 0i64 });
        assert_eq!(db_val, Some(1));
    }

    #[test]
    fn update_ssl_target_active_bool_false() {
        let body: UpdateTarget =
            serde_json::from_str(r#"{"active": false}"#).expect("should deserialise boolean false");
        let db_val = body.active.map(|v| if v { 1i64 } else { 0i64 });
        assert_eq!(db_val, Some(0));
    }

    #[test]
    fn update_ssl_target_active_omitted() {
        let body: UpdateTarget =
            serde_json::from_str(r#"{"name": "example.com"}"#).expect("should deserialise without active");
        assert!(body.active.is_none());
    }

    #[test]
    fn update_ssl_target_active_integer_rejected() {
        let result = serde_json::from_str::<UpdateTarget>(r#"{"active": 1}"#);
        assert!(result.is_err(), "integer active should be rejected; frontend sends booleans");
    }
}
