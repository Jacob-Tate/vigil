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
    types::{CveFinding, CveTarget, CveTargetWithStats},
};

fn row_to_target(row: &rusqlite::Row<'_>) -> rusqlite::Result<CveTarget> {
    Ok(CveTarget {
        id: row.get(0)?,
        name: row.get(1)?,
        vendor: row.get(2)?,
        product: row.get(3)?,
        version: row.get(4)?,
        min_alert_cvss_score: row.get(5)?,
        check_interval_seconds: row.get(6)?,
        active: row.get(7)?,
        created_at: row.get(8)?,
        last_checked_at: row.get(9)?,
        last_alerted_at: row.get(10)?,
    })
}

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

fn target_with_stats(conn: &rusqlite::Connection, id: i64) -> rusqlite::Result<Option<CveTargetWithStats>> {
    let target: Option<CveTarget> = conn
        .query_row(
            "SELECT id, name, vendor, product, version, min_alert_cvss_score, \
             check_interval_seconds, active, created_at, last_checked_at, last_alerted_at \
             FROM cve_targets WHERE id = ?1",
            rusqlite::params![id],
            row_to_target,
        )
        .optional()?;

    let Some(target) = target else { return Ok(None); };

    let (findings_count, top_cvss_score, top_cvss_severity, kev_count): (i64, Option<f64>, Option<String>, i64) = conn
        .query_row(
            "SELECT COUNT(*), MAX(f.cvss_score), \
             (SELECT cvss_severity FROM cve_findings WHERE target_id = ?1 \
              AND cvss_score = (SELECT MAX(cvss_score) FROM cve_findings WHERE target_id = ?1) LIMIT 1), \
             SUM(CASE WHEN k.cve_id IS NOT NULL THEN 1 ELSE 0 END) \
             FROM cve_findings f \
             LEFT JOIN cisa_kev k ON f.cve_id = k.cve_id \
             WHERE f.target_id = ?1",
            rusqlite::params![id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3).unwrap_or(0))),
        )
        .unwrap_or((0, None, None, 0));

    let latest_finding: Option<CveFinding> = conn
        .query_row(
            "SELECT f.id, f.target_id, f.cve_id, f.published_at, f.last_modified_at, \
             f.cvss_score, f.cvss_severity, f.description, f.nvd_url, f.found_at, f.alerted, \
             CASE WHEN k.cve_id IS NOT NULL THEN 1 ELSE 0 END as is_kev, k.date_added, \
             s.exploitation, s.automatable, s.technical_impact, \
             f.enrichment_fingerprint, f.exploitation_alert_sent, f.rejection_alert_sent, \
             cv.state, cv.cna_description \
             FROM cve_findings f \
             LEFT JOIN cisa_kev k ON f.cve_id = k.cve_id \
             LEFT JOIN cisa_ssvc s ON f.cve_id = s.cve_id \
             LEFT JOIN cvelist_cves cv ON f.cve_id = cv.cve_id \
             WHERE f.target_id = ?1 ORDER BY f.found_at DESC LIMIT 1",
            rusqlite::params![id],
            row_to_finding,
        )
        .optional()?;

    Ok(Some(CveTargetWithStats {
        target,
        findings_count,
        latest_finding,
        top_cvss_score,
        top_cvss_severity,
        kev_count,
    }))
}

// GET /api/cve/targets
pub async fn list(_auth: RequireAuth, State(state): State<AppState>) -> Result<Json<Value>, AppError> {
    let db = state.db.clone();
    let results: Vec<CveTargetWithStats> = tokio::task::spawn_blocking(move || {
        let conn = db.lock().unwrap();
        let ids: Vec<i64> = conn
            .prepare("SELECT id FROM cve_targets ORDER BY created_at DESC")?
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(t) = target_with_stats(&conn, id)? { out.push(t); }
        }
        Ok::<_, rusqlite::Error>(out)
    })
    .await
    .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
    .map_err(AppError::Db)?;
    Ok(Json(json!(results)))
}

// GET /api/cve/targets/:id
pub async fn get_one(_auth: RequireAuth, State(state): State<AppState>, Path(id): Path<i64>) -> Result<Json<Value>, AppError> {
    let db = state.db.clone();
    let result = tokio::task::spawn_blocking(move || target_with_stats(&db.lock().unwrap(), id))
        .await
        .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
        .map_err(AppError::Db)?;
    result.map(|t| Json(json!(t))).ok_or_else(|| AppError::NotFound(format!("CVE target {} not found", id)))
}

#[derive(Deserialize)]
pub struct CreateCveTarget {
    name: String,
    vendor: Option<String>,
    product: String,
    version: Option<String>,
    min_alert_cvss_score: Option<f64>,
    check_interval_seconds: Option<i64>,
}

// POST /api/cve/targets
pub async fn create(_admin: RequireAdmin, State(state): State<AppState>, Json(body): Json<CreateCveTarget>) -> Result<Json<Value>, AppError> {
    let mut errors = Vec::new();
    if body.name.trim().is_empty() { errors.push(json!({"msg": "name is required", "path": "name"})); }
    if body.product.trim().is_empty() { errors.push(json!({"msg": "product is required", "path": "product"})); }
    if !errors.is_empty() { return Err(AppError::Validation(errors)); }

    let db = state.db.clone();
    let id: i64 = tokio::task::spawn_blocking(move || {
        let conn = db.lock().unwrap();
        conn.execute(
            "INSERT INTO cve_targets (name, vendor, product, version, min_alert_cvss_score, check_interval_seconds) VALUES (?1,?2,?3,?4,?5,?6)",
            rusqlite::params![body.name, body.vendor, body.product, body.version, body.min_alert_cvss_score.unwrap_or(7.0), body.check_interval_seconds.unwrap_or(86400)],
        )?;
        Ok::<_, rusqlite::Error>(conn.last_insert_rowid())
    })
    .await
    .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
    .map_err(AppError::Db)?;

    let db2 = state.db.clone();
    let t = tokio::task::spawn_blocking(move || target_with_stats(&db2.lock().unwrap(), id))
        .await
        .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
        .map_err(AppError::Db)?
        .ok_or_else(|| AppError::Internal("Target not found after insert".into()))?;

    if t.target.active == 1 {
        state.cve_engine.schedule(t.target.clone()).await;
    }
    Ok(Json(json!(t)))
}

#[derive(Deserialize)]
pub struct UpdateCveTarget {
    name: Option<String>,
    vendor: Option<String>,
    product: Option<String>,
    version: Option<String>,
    min_alert_cvss_score: Option<f64>,
    check_interval_seconds: Option<i64>,
    active: Option<bool>,
}

// PUT /api/cve/targets/:id
pub async fn update(_admin: RequireAdmin, State(state): State<AppState>, Path(id): Path<i64>, Json(body): Json<UpdateCveTarget>) -> Result<Json<Value>, AppError> {
    let db = state.db.clone();
    let changes = tokio::task::spawn_blocking(move || {
        use rusqlite::types::Value;
        let conn = db.lock().unwrap();
        let mut parts: Vec<String> = Vec::new();
        let mut params: Vec<Value> = Vec::new();
        if let Some(v) = body.name { parts.push("name = ?".into()); params.push(Value::Text(v)); }
        if let Some(v) = body.vendor { parts.push("vendor = ?".into()); params.push(Value::Text(v)); }
        if let Some(v) = body.product { parts.push("product = ?".into()); params.push(Value::Text(v)); }
        if let Some(v) = body.version { parts.push("version = ?".into()); params.push(Value::Text(v)); }
        if let Some(v) = body.min_alert_cvss_score { parts.push("min_alert_cvss_score = ?".into()); params.push(Value::Real(v)); }
        if let Some(v) = body.check_interval_seconds { parts.push("check_interval_seconds = ?".into()); params.push(Value::Integer(v)); }
        if let Some(v) = body.active { parts.push("active = ?".into()); params.push(Value::Integer(if v { 1 } else { 0 })); }
        if parts.is_empty() { return Ok::<_, rusqlite::Error>(0usize); }
        let sql = format!("UPDATE cve_targets SET {} WHERE id = ?", parts.join(", "));
        params.push(Value::Integer(id));
        let refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p as &dyn rusqlite::ToSql).collect();
        conn.execute(&sql, refs.as_slice())
    })
    .await
    .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
    .map_err(AppError::Db)?;

    if changes == 0 { return Err(AppError::NotFound(format!("CVE target {} not found", id))); }
    let db2 = state.db.clone();
    let t = tokio::task::spawn_blocking(move || target_with_stats(&db2.lock().unwrap(), id))
        .await
        .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
        .map_err(AppError::Db)?
        .ok_or_else(|| AppError::Internal("Target not found after update".into()))?;
    state.cve_engine.reschedule(t.target.clone()).await;
    Ok(Json(json!(t)))
}

#[cfg(test)]
mod tests {
    use super::UpdateCveTarget;

    /// Regression: frontend sends `active` as a JSON boolean; the handler must
    /// deserialise it correctly and convert to the SQLite 0/1 integer.
    /// Caused a 422 Unprocessable Entity when `active` was typed as Option<i64>.
    #[test]
    fn update_cve_target_active_bool_true() {
        let body: UpdateCveTarget =
            serde_json::from_str(r#"{"active": true}"#).expect("should deserialise boolean true");
        let db_val = body.active.map(|v| if v { 1i64 } else { 0i64 });
        assert_eq!(db_val, Some(1));
    }

    #[test]
    fn update_cve_target_active_bool_false() {
        let body: UpdateCveTarget =
            serde_json::from_str(r#"{"active": false}"#).expect("should deserialise boolean false");
        let db_val = body.active.map(|v| if v { 1i64 } else { 0i64 });
        assert_eq!(db_val, Some(0));
    }

    #[test]
    fn update_cve_target_active_omitted() {
        let body: UpdateCveTarget =
            serde_json::from_str(r#"{"name": "Test"}"#).expect("should deserialise without active");
        assert!(body.active.is_none());
    }

    /// Integer 1 must NOT silently pass — the frontend always sends a boolean.
    /// Catching this prevents the old Option<i64> mistake from sneaking back in.
    #[test]
    fn update_cve_target_active_integer_rejected() {
        let result = serde_json::from_str::<UpdateCveTarget>(r#"{"active": 1}"#);
        assert!(result.is_err(), "integer active should be rejected; frontend sends booleans");
    }
}

// DELETE /api/cve/targets/:id
pub async fn delete(_admin: RequireAdmin, State(state): State<AppState>, Path(id): Path<i64>) -> Result<Json<Value>, AppError> {
    let db = state.db.clone();
    let changes = tokio::task::spawn_blocking(move || {
        let conn = db.lock().unwrap();
        conn.execute("DELETE FROM cve_targets WHERE id = ?1", rusqlite::params![id])
    })
    .await
    .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
    .map_err(AppError::Db)?;
    if changes == 0 { return Err(AppError::NotFound(format!("CVE target {} not found", id))); }
    state.cve_engine.unschedule(id).await;
    Ok(Json(json!({ "ok": true })))
}

// POST /api/cve/targets/:id/check
pub async fn trigger_check(_admin: RequireAdmin, State(state): State<AppState>, Path(id): Path<i64>) -> Result<Json<Value>, AppError> {
    let db = state.db.clone();
    let target = tokio::task::spawn_blocking(move || {
        let conn = db.lock().unwrap();
        conn.query_row(
            "SELECT id, name, vendor, product, version, min_alert_cvss_score, \
             check_interval_seconds, active, created_at, last_checked_at, last_alerted_at \
             FROM cve_targets WHERE id = ?1",
            rusqlite::params![id],
            row_to_target,
        )
    })
    .await
    .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
    .map_err(|_| AppError::NotFound(format!("CVE target {} not found", id)))?;

    // Run the check synchronously so the response reflects the current findings.
    crate::cve::engine::evaluate_cve_target(&state.db, &state.config, &target).await;

    // Reset the periodic timer for future scheduled checks.
    state.cve_engine.reschedule(target.clone()).await;

    // Return fresh stats so the frontend doesn't need a separate GET.
    let db2 = state.db.clone();
    let updated = tokio::task::spawn_blocking(move || target_with_stats(&db2.lock().unwrap(), id))
        .await
        .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
        .map_err(AppError::Db)?
        .ok_or_else(|| AppError::NotFound(format!("CVE target {} not found", id)))?;

    Ok(Json(json!({ "ok": true, "target": updated })))
}
