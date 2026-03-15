use std::env;

#[derive(Clone, Debug)]
pub struct Config {
    pub port: u16,
    pub jwt_secret: String,
    pub notifications_encryption_key: Option<String>,
    pub admin_username: String,
    pub admin_password: String,
    pub session_duration_hours: u64,
    pub client_origin: String,
    pub base_url: String,
    pub alert_cooldown_seconds: u64,
    pub nvd_sync_interval_hours: u64,
    pub kev_sync_interval_hours: u64,
    pub vulnrichment_sync_interval_hours: u64,
    pub cvelist_sync_interval_hours: u64,
    pub diff_retention_days: u64,
    pub data_dir: String,
    pub is_production: bool,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let is_production = env::var("NODE_ENV").unwrap_or_default() == "production";

        let jwt_secret = env::var("JWT_SECRET").unwrap_or_default();
        if jwt_secret.is_empty() {
            let msg = "JWT_SECRET is not set — sessions cannot be signed";
            if is_production {
                return Err(msg.to_string());
            }
            tracing::warn!("[config] WARNING: {}", msg);
        } else if jwt_secret == "change-me-to-a-long-random-string" {
            let msg = "JWT_SECRET is still the example placeholder — replace it";
            if is_production {
                return Err(msg.to_string());
            }
            tracing::warn!("[config] WARNING: {}", msg);
        }

        let admin_password = env::var("ADMIN_PASSWORD").unwrap_or_default();
        if admin_password == "change-me" {
            let msg = "ADMIN_PASSWORD is still the example placeholder — set a strong password";
            if is_production {
                return Err(msg.to_string());
            }
            tracing::warn!("[config] WARNING: {}", msg);
        }

        let notifications_encryption_key = env::var("NOTIFICATIONS_ENCRYPTION_KEY").ok();
        if notifications_encryption_key.is_none() {
            let msg = "NOTIFICATIONS_ENCRYPTION_KEY is not set — \
                       notification credentials will be stored in plaintext";
            if is_production {
                return Err(msg.to_string());
            }
            tracing::warn!("[config] WARNING: {}", msg);
        }

        let client_origin =
            env::var("CLIENT_ORIGIN").unwrap_or_else(|_| "http://localhost:5173".to_string());
        let base_url =
            env::var("BASE_URL").unwrap_or_else(|_| "http://localhost:5173".to_string());

        if is_production {
            if base_url.contains("localhost") {
                return Err(format!(
                    "BASE_URL is \"{}\" — alert links will be unreachable outside this machine",
                    base_url
                ));
            }
            if client_origin.contains("localhost") {
                return Err(format!(
                    "CLIENT_ORIGIN is \"{}\" — CORS will block requests from your actual frontend",
                    client_origin
                ));
            }
        }

        Ok(Config {
            port: env::var("PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(3001),
            jwt_secret,
            notifications_encryption_key,
            admin_username: env::var("ADMIN_USERNAME")
                .unwrap_or_else(|_| "admin".to_string()),
            admin_password,
            session_duration_hours: env::var("SESSION_DURATION_HOURS")
                .ok()
                .and_then(|h| h.parse().ok())
                .unwrap_or(8),
            client_origin,
            base_url,
            alert_cooldown_seconds: env::var("ALERT_COOLDOWN_SECONDS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(3600),
            nvd_sync_interval_hours: env::var("NVD_SYNC_INTERVAL_HOURS")
                .ok()
                .and_then(|h| h.parse().ok())
                .unwrap_or(2),
            kev_sync_interval_hours: env::var("KEV_SYNC_INTERVAL_HOURS")
                .ok()
                .and_then(|h| h.parse().ok())
                .unwrap_or(24),
            vulnrichment_sync_interval_hours: env::var("VULNRICHMENT_SYNC_INTERVAL_HOURS")
                .ok()
                .and_then(|h| h.parse().ok())
                .unwrap_or(24),
            cvelist_sync_interval_hours: env::var("CVELIST_SYNC_INTERVAL_HOURS")
                .ok()
                .and_then(|h| h.parse().ok())
                .unwrap_or(24),
            diff_retention_days: env::var("DIFF_RETENTION_DAYS")
                .ok()
                .and_then(|d| d.parse().ok())
                .unwrap_or(30),
            data_dir: env::var("DATA_DIR").unwrap_or_else(|_| "data".to_string()),
            is_production,
        })
    }
}
