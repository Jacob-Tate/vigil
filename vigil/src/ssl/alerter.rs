use std::sync::Arc;

use rusqlite::OptionalExtension;

use crate::{
    config::Config,
    db::DbPool,
    notifiers,
    types::{AlertPayload, AlertType, SslTarget},
};

use super::checker::SslCheckResult;

fn build_ssl_message(
    target: &SslTarget,
    alert_type: &AlertType,
    result: &SslCheckResult,
) -> String {
    match alert_type {
        AlertType::SslExpired => format!(
            "{} SSL certificate has EXPIRED ({}).",
            target.name,
            result.subject_cn.as_deref().unwrap_or(&target.host)
        ),
        AlertType::SslExpiring => format!(
            "{} SSL certificate expires in {} day(s) — threshold is {} day(s).",
            target.name,
            result.days_remaining.unwrap_or(0),
            target.expiry_threshold_hours / 24
        ),
        AlertType::SslError => format!(
            "{} SSL check failed: {}.",
            target.name,
            result.error.as_deref().unwrap_or("unknown error")
        ),
        AlertType::SslChanged => format!(
            "{} SSL certificate fingerprint changed — new cert deployed or possible MITM.",
            target.name
        ),
        other => format!("{} SSL alert: {}", target.name, other),
    }
}

/// Returns the alert type that was sent (if any).
pub async fn evaluate_ssl_and_alert(
    db: &DbPool,
    config: &Arc<Config>,
    target: &SslTarget,
    result: &SslCheckResult,
) -> Option<AlertType> {
    let cooldown_seconds = config.alert_cooldown_seconds as i64;
    let base_url = &config.base_url;

    let previous = load_previous_check(db, target.id);

    let alert_type = if result.error.is_some() {
        Some(AlertType::SslError)
    } else if result.days_remaining.map(|d| d < 0).unwrap_or(false) {
        Some(AlertType::SslExpired)
    } else if result
        .days_remaining
        .map(|d| d <= target.expiry_threshold_hours / 24)
        .unwrap_or(false)
    {
        Some(AlertType::SslExpiring)
    } else if let Some((prev_fp, prev_had_error)) = &previous {
        let prev_fp_str = prev_fp.as_deref();
        let new_fp = result.fingerprint_sha256.as_deref();
        if prev_fp_str.is_some() && new_fp.is_some() && prev_fp_str != new_fp && !prev_had_error {
            Some(AlertType::SslChanged)
        } else {
            None
        }
    } else {
        None
    };

    let alert_type = alert_type?;

    // Cooldown for repeating SSL_EXPIRING and SSL_ERROR
    if matches!(alert_type, AlertType::SslExpiring | AlertType::SslError) {
        let last_alerted_ms = target
            .last_alerted_at
            .as_deref()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.timestamp_millis())
            .unwrap_or(0);
        let elapsed_seconds = (chrono::Utc::now().timestamp_millis() - last_alerted_ms) / 1000;
        let same_type = target.last_alert_type.as_deref() == Some(&alert_type.to_string());

        if same_type && elapsed_seconds < cooldown_seconds {
            return Some(alert_type);
        }
    }

    let payload = AlertPayload {
        server_name: target.name.clone(),
        url: format!("https://{}:{}", target.host, target.port),
        alert_type: alert_type.clone(),
        status_code: None,
        response_time_ms: None,
        threshold: None,
        diff_id: None,
        diff_view_url: Some(format!("{}/ssl/{}", base_url, target.id)),
        detected_at: chrono::Utc::now().to_rfc3339(),
        message: build_ssl_message(target, &alert_type, result),
        ssl_days_remaining: result.days_remaining,
        ssl_fingerprint: result.fingerprint_sha256.clone(),
        ssl_subject: result.subject_cn.clone(),
        cve_id: None,
        cvss_score: None,
        cvss_severity: None,
        cve_digest: None,
        previous_exploitation: None,
        changed_fields: None,
    };

    notifiers::send_alert(db.clone(), config.clone(), payload).await;

    let now = chrono::Utc::now().to_rfc3339();
    let alert_str = alert_type.to_string();
    let db2 = db.clone();
    let target_id = target.id;
    tokio::task::spawn_blocking(move || {
        let conn = db2.lock().unwrap();
        conn.execute(
            "UPDATE ssl_targets SET last_alerted_at = ?1, last_alert_type = ?2 WHERE id = ?3",
            rusqlite::params![now, alert_str, target_id],
        )
        .ok();
    })
    .await
    .ok();

    Some(alert_type)
}

/// Returns `(fingerprint_sha256, had_error)` for the most recent ssl_check.
fn load_previous_check(db: &DbPool, target_id: i64) -> Option<(Option<String>, bool)> {
    let conn = db.lock().unwrap();
    conn.query_row(
        "SELECT fingerprint_sha256, error FROM ssl_checks \
         WHERE target_id = ?1 ORDER BY checked_at DESC LIMIT 1",
        rusqlite::params![target_id],
        |row| {
            Ok((
                row.get::<_, Option<String>>(0)?,
                row.get::<_, Option<String>>(1)?.is_some(),
            ))
        },
    )
    .optional()
    .ok()
    .flatten()
}
