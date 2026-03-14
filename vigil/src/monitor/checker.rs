use std::time::Instant;

use once_cell::sync::Lazy;
use reqwest::Client;

const REQUEST_TIMEOUT_MS: u64 = 15_000;
const USER_AGENT: &str = "Monitor/1.0 (uptime checker)";

/// Result of a single HTTP check.
pub struct CheckResult {
    pub status_code: Option<i64>,
    pub response_time_ms: i64,
    pub is_up: bool,
    pub raw_html: String,
    pub error: Option<String>,
}

static HTTP_CLIENT: Lazy<Client> = Lazy::new(|| {
    Client::builder()
        .timeout(std::time::Duration::from_millis(REQUEST_TIMEOUT_MS))
        .user_agent(USER_AGENT)
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .expect("Failed to build HTTP client")
});

pub async fn check_server(url: &str, response_time_threshold_ms: i64) -> CheckResult {
    let start = Instant::now();

    match HTTP_CLIENT.get(url).send().await {
        Ok(resp) => {
            let status_code = resp.status().as_u16() as i64;
            let raw_html = match resp.text().await {
                Ok(t) => t,
                Err(e) => {
                    let response_time_ms = start.elapsed().as_millis() as i64;
                    return CheckResult {
                        status_code: Some(status_code),
                        response_time_ms,
                        is_up: false,
                        raw_html: String::new(),
                        error: Some(e.to_string()),
                    };
                }
            };
            let response_time_ms = start.elapsed().as_millis() as i64;

            let is_success = status_code >= 200 && status_code < 400;
            let is_within_threshold = response_time_ms <= response_time_threshold_ms;
            let is_up = is_success && is_within_threshold;

            CheckResult {
                status_code: Some(status_code),
                response_time_ms,
                is_up,
                raw_html,
                error: None,
            }
        }
        Err(e) => {
            let response_time_ms = start.elapsed().as_millis() as i64;
            CheckResult {
                status_code: None,
                response_time_ms,
                is_up: false,
                raw_html: String::new(),
                error: Some(e.to_string()),
            }
        }
    }
}
