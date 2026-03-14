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
        .ok_or_else(|| anyhow::anyhow!("Teams webhookUrl is required"))?;

    let theme_color = match payload.alert_type.to_string().as_str() {
        "DOWN" | "SSL_EXPIRED" | "SSL_ERROR" => "FF4444",
        "DEGRADED" | "SSL_EXPIRING" => "FF9900",
        "CONTENT_CHANGED" => "5865F2",
        "RECOVERED" => "2ECC71",
        "SSL_CHANGED" => "9B59B6",
        "CVE_NEW" | "CVE_EXPLOIT_ESCALATION" | "CVE_UPDATED" | "CVE_REJECTED" => "E74C3C",
        _ => "999999",
    };

    let alert_type = payload.alert_type.to_string();
    let is_cve = matches!(
        alert_type.as_str(),
        "CVE_NEW" | "CVE_EXPLOIT_ESCALATION" | "CVE_UPDATED" | "CVE_REJECTED"
    );

    let mut facts: Vec<Value> = vec![json!({"name": "Alert Type", "value": alert_type})];

    if is_cve {
        if let Some(cve_id) = &payload.cve_id {
            facts.push(json!({"name": "CVE ID", "value": cve_id}));
        }
        if let Some(score) = payload.cvss_score {
            let severity = payload.cvss_severity.as_deref().unwrap_or("").to_string();
            facts.push(json!({
                "name": "CVSS Score",
                "value": format!("{:.1} {}", score, severity).trim().to_string(),
            }));
        }
        facts.push(json!({"name": "NVD Link", "value": payload.url}));
    } else {
        facts.push(json!({"name": "URL", "value": payload.url}));
        if let Some(code) = payload.status_code {
            facts.push(json!({"name": "HTTP Status", "value": code.to_string()}));
        }
        if let Some(ms) = payload.response_time_ms {
            facts.push(json!({"name": "Response Time", "value": format!("{}ms", ms)}));
        }
    }

    let mut sections: Vec<Value> = vec![json!({
        "activityTitle": format!("**[{}]** {}", payload.alert_type, payload.server_name),
        "activityText": payload.message,
        "facts": facts,
    })];

    if let Some(url) = &payload.diff_view_url {
        sections.push(json!({
            "potentialAction": [{
                "@type": "OpenUri",
                "name": "View Diff",
                "targets": [{"os": "default", "uri": url}],
            }]
        }));
    }

    let body = json!({
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "themeColor": theme_color,
        "summary": format!("[{}] {}", payload.alert_type, payload.server_name),
        "sections": sections,
    });

    reqwest::Client::new()
        .post(webhook_url)
        .json(&body)
        .send()
        .await?
        .error_for_status()?;

    Ok(())
}
