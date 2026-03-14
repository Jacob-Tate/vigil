pub mod discord;
pub mod pushover;
pub mod teams;

use std::{collections::HashMap, sync::Arc};

use crate::{config::Config, crypto, db::DbPool, types::AlertPayload};

/// Dispatch an alert to all active notification channels.
pub async fn send_alert(db: DbPool, config: Arc<Config>, payload: AlertPayload) {
    type ChannelRow = (i64, String, Option<String>, String);
    let channels: Vec<ChannelRow> = tokio::task::spawn_blocking(move || {
        let conn = db.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT id, type, label, config_json FROM notification_channels WHERE active = 1",
            )
            .unwrap();
        stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    })
    .await
    .unwrap_or_default();

    if channels.is_empty() {
        tracing::debug!(
            alert_type = %payload.alert_type,
            target = %payload.server_name,
            "No active notification channels"
        );
        return;
    }

    for (id, ch_type, label, config_json) in channels {
        let label_str = label.as_deref().unwrap_or(&ch_type).to_string();

        // Decrypt config if encryption key is set
        let decrypted = if let Some(ref key) = config.notifications_encryption_key {
            match crypto::decrypt_config(&config_json, key) {
                Ok(d) => d,
                Err(e) => {
                    tracing::error!(channel_id = id, "Failed to decrypt channel config: {}", e);
                    continue;
                }
            }
        } else {
            config_json
        };

        // Parse config as generic JSON map
        let cfg: HashMap<String, serde_json::Value> = match serde_json::from_str(&decrypted) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(channel_id = id, "Failed to parse channel config JSON: {}", e);
                continue;
            }
        };

        let result = match ch_type.as_str() {
            "discord" => discord::send(&cfg, &payload).await,
            "pushover" => pushover::send(&cfg, &payload).await,
            "teams" => teams::send(&cfg, &payload).await,
            other => {
                tracing::warn!(channel_id = id, channel_type = other, "Unknown notifier type");
                continue;
            }
        };

        match result {
            Ok(()) => tracing::info!(
                channel_id = id,
                channel_label = label_str,
                alert_type = %payload.alert_type,
                target = %payload.server_name,
                "Alert sent"
            ),
            Err(e) => tracing::error!(
                channel_id = id,
                channel_label = label_str,
                "Alert dispatch failed: {}",
                e
            ),
        }
    }
}
