use std::collections::HashMap;

use serde_json::{json, Value};

use crate::types::AlertPayload;

pub async fn send(
    config: &HashMap<String, Value>,
    payload: &AlertPayload,
) -> anyhow::Result<()> {
    let webhook_url = config
        .get("webhookUrl")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Discord webhookUrl is required"))?;

    let color: u32 = match payload.alert_type.to_string().as_str() {
        "DOWN" | "SSL_EXPIRED" | "SSL_ERROR" => 0xff4444,
        "DEGRADED" | "SSL_EXPIRING" => 0xff9900,
        "CONTENT_CHANGED" => 0x5865f2,
        "RECOVERED" => 0x2ecc71,
        "SSL_CHANGED" => 0x9b59b6,
        "CVE_NEW" | "CVE_EXPLOIT_ESCALATION" | "CVE_UPDATED" | "CVE_REJECTED" => 0xe74c3c,
        _ => 0x999999,
    };

    let alert_type = payload.alert_type.to_string();
    let mut fields: Vec<Value> = Vec::new();

    let is_cve = matches!(
        alert_type.as_str(),
        "CVE_NEW" | "CVE_EXPLOIT_ESCALATION" | "CVE_UPDATED" | "CVE_REJECTED"
    );

    if is_cve {
        if let Some(digest) = &payload.cve_digest {
            if digest.len() > 1 {
                let take = digest.len().min(23);
                for c in &digest[..take] {
                    let score = c
                        .cvss_score
                        .map(|s| format!("{:.1}", s))
                        .unwrap_or_else(|| "N/A".into());
                    let severity = c.cvss_severity.as_deref().unwrap_or("").to_string();
                    fields.push(json!({
                        "name": c.cve_id,
                        "value": format!("CVSS {} {}", score, severity).trim().to_string(),
                        "inline": true,
                    }));
                }
                if digest.len() > 23 {
                    fields.push(json!({
                        "name": "…and more",
                        "value": format!("+{} additional CVEs", digest.len() - 23),
                        "inline": false,
                    }));
                }
            } else {
                push_cve_fields(&mut fields, payload);
            }
        } else {
            push_cve_fields(&mut fields, payload);
        }
        if let Some(url) = &payload.diff_view_url {
            fields.push(json!({"name": "View Findings", "value": url, "inline": false}));
        }
    } else {
        fields.push(json!({"name": "URL", "value": payload.url, "inline": true}));
        fields.push(json!({"name": "Status", "value": alert_type, "inline": true}));
        if let Some(code) = payload.status_code {
            fields.push(json!({"name": "HTTP Status", "value": code.to_string(), "inline": true}));
        }
        if let Some(ms) = payload.response_time_ms {
            fields.push(json!({"name": "Response Time", "value": format!("{}ms", ms), "inline": true}));
        }
        if let Some(url) = &payload.diff_view_url {
            fields.push(json!({"name": "View Diff", "value": url, "inline": false}));
        }
    }

    let body = json!({
        "embeds": [{
            "title": format!("[{}] {}", payload.alert_type, payload.server_name),
            "description": payload.message,
            "color": color,
            "fields": fields,
            "timestamp": payload.detected_at,
        }]
    });

    reqwest::Client::new()
        .post(webhook_url)
        .json(&body)
        .send()
        .await?
        .error_for_status()?;

    Ok(())
}

fn push_cve_fields(fields: &mut Vec<Value>, payload: &AlertPayload) {
    if let Some(cve_id) = &payload.cve_id {
        fields.push(json!({"name": "CVE ID", "value": cve_id, "inline": true}));
    }
    if let Some(score) = payload.cvss_score {
        let severity = payload.cvss_severity.as_deref().unwrap_or("").to_string();
        fields.push(json!({
            "name": "CVSS Score",
            "value": format!("{:.1} {}", score, severity).trim().to_string(),
            "inline": true,
        }));
    }
    fields.push(json!({"name": "NVD Link", "value": payload.url, "inline": false}));
}
