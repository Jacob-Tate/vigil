use rusqlite::OptionalExtension;

use crate::{
    config::Config,
    db::DbPool,
    notifiers,
    types::{AlertPayload, AlertType, Check, Server},
};
use std::sync::Arc;

fn build_message(
    server: &Server,
    alert_type: &AlertType,
    status_code: Option<i64>,
    response_time_ms: i64,
) -> String {
    match alert_type {
        AlertType::Down => format!(
            "{} is DOWN. Status: {}, Response time: {}ms",
            server.name,
            status_code
                .map(|c| c.to_string())
                .unwrap_or_else(|| "no response".into()),
            response_time_ms
        ),
        AlertType::Degraded => format!(
            "{} is DEGRADED. Response time {}ms exceeds threshold of {}ms",
            server.name, response_time_ms, server.response_time_threshold_ms
        ),
        AlertType::ContentChanged => {
            format!("{} content has changed. A diff has been recorded.", server.name)
        }
        AlertType::Recovered => format!(
            "{} has RECOVERED. Status: {}, Response time: {}ms",
            server.name,
            status_code
                .map(|c| c.to_string())
                .unwrap_or_else(|| "no response".into()),
            response_time_ms
        ),
        other => format!("{} alert: {}", server.name, other),
    }
}

pub struct CheckSummary {
    pub is_up: bool,
    pub status_code: Option<i64>,
    pub response_time_ms: i64,
    pub content_changed: bool,
    pub diff_id: Option<i64>,
}

pub async fn evaluate_and_alert(
    db: &DbPool,
    config: &Arc<Config>,
    server: &Server,
    current: &CheckSummary,
) {
    let cooldown_seconds = config.alert_cooldown_seconds as i64;
    let base_url = &config.base_url;

    // Fetch the previous check
    let previous_check = {
        let conn = db.lock().unwrap();
        conn.query_row(
            "SELECT id, server_id, checked_at, status_code, response_time_ms, is_up, \
             content_hash, content_changed, diff_id FROM checks \
             WHERE server_id = ?1 ORDER BY checked_at DESC LIMIT 1",
            rusqlite::params![server.id],
            |row| {
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
            },
        )
        .optional()
        .ok()
        .flatten()
    };

    let was_up = previous_check
        .as_ref()
        .map(|c| c.is_up == 1)
        .unwrap_or(true);
    let is_up = current.is_up;
    let is_degraded = is_up && current.response_time_ms > server.response_time_threshold_ms;
    let was_degraded = previous_check
        .as_ref()
        .map(|c| {
            c.is_up == 1
                && c.response_time_ms.unwrap_or(0) > server.response_time_threshold_ms
        })
        .unwrap_or(false);

    let mut alerts_to_send: Vec<AlertType> = Vec::new();

    if was_up && !is_up {
        alerts_to_send.push(AlertType::Down);
    }

    if !was_up && !is_up {
        let last_alerted_ms = server
            .last_alerted_at
            .as_deref()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.timestamp_millis())
            .unwrap_or(0);
        let elapsed_seconds = (chrono::Utc::now().timestamp_millis() - last_alerted_ms) / 1000;
        if elapsed_seconds >= cooldown_seconds as i64 {
            alerts_to_send.push(AlertType::Down);
        }
    }

    if !was_up && is_up {
        alerts_to_send.push(AlertType::Recovered);
    }

    if current.content_changed && current.diff_id.is_some() {
        alerts_to_send.push(AlertType::ContentChanged);
    }

    if is_degraded && !was_degraded {
        alerts_to_send.push(AlertType::Degraded);
    }

    if alerts_to_send.is_empty() {
        return;
    }

    for alert_type in alerts_to_send {
        let diff_view_url = if matches!(alert_type, AlertType::ContentChanged) {
            current.diff_id.map(|id| {
                format!("{}/http/servers/{}/diff/{}", base_url, server.id, id)
            })
        } else {
            None
        };

        let payload = AlertPayload {
            server_name: server.name.clone(),
            url: server.url.clone(),
            alert_type: alert_type.clone(),
            status_code: current.status_code,
            response_time_ms: Some(current.response_time_ms),
            threshold: Some(server.response_time_threshold_ms),
            diff_id: current.diff_id,
            diff_view_url,
            detected_at: chrono::Utc::now().to_rfc3339(),
            message: build_message(
                server,
                &alert_type,
                current.status_code,
                current.response_time_ms,
            ),
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

        notifiers::send_alert(db.clone(), config.clone(), payload).await;

        let now = chrono::Utc::now().to_rfc3339();
        let alert_str = alert_type.to_string();
        let db2 = db.clone();
        let server_id = server.id;
        tokio::task::spawn_blocking(move || {
            let conn = db2.lock().unwrap();
            conn.execute(
                "UPDATE servers SET last_alerted_at = ?1, last_alert_type = ?2 WHERE id = ?3",
                rusqlite::params![now, alert_str, server_id],
            )
            .ok();
        })
        .await
        .ok();
    }
}
