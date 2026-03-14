use std::collections::HashMap;

use serde_json::Value;

use crate::types::AlertPayload;

const PUSHOVER_API: &str = "https://api.pushover.net/1/messages.json";

pub async fn send(
    config: &HashMap<String, Value>,
    payload: &AlertPayload,
) -> anyhow::Result<()> {
    let app_token = config
        .get("appToken")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Pushover appToken is required"))?;
    let user_key = config
        .get("userKey")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Pushover userKey is required"))?;

    let priority: i32 = match payload.alert_type.to_string().as_str() {
        "DOWN" => 1,
        "RECOVERED" => -1,
        _ => 0,
    };

    let mut message = payload.message.clone();
    if let Some(url) = &payload.diff_view_url {
        message.push_str(&format!("\nDiff: {}", url));
    }

    let mut params: Vec<(&str, String)> = vec![
        ("token", app_token.to_string()),
        ("user", user_key.to_string()),
        ("title", format!("[{}] {}", payload.alert_type, payload.server_name)),
        ("message", message),
        ("priority", priority.to_string()),
    ];

    if priority == 2 {
        params.push(("retry", "60".to_string()));
        params.push(("expire", "3600".to_string()));
    }

    reqwest::Client::new()
        .post(PUSHOVER_API)
        .form(&params)
        .send()
        .await?
        .error_for_status()?;

    Ok(())
}
