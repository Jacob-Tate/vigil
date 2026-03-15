use std::time::Instant;

use axum::{extract::Request, middleware::Next, response::Response};
use base64::Engine as _;

/// Axum middleware that emits a structured `INFO` log line for every request.
///
/// Logged fields:
/// - `method`      — HTTP method (GET, POST, …)
/// - `path`        — request path (not including query string)
/// - `status`      — response status code
/// - `elapsed_ms`  — wall-clock time to produce the response
/// - `user`        — username extracted from the JWT cookie, or "-" if unauthenticated
///
/// The JWT signature is NOT verified here; this is purely for logging / audit trail.
/// Full authentication enforcement happens via the `RequireAuth` / `RequireAdmin`
/// extractors on each handler.
pub async fn audit_log(req: Request, next: Next) -> Response {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let user = extract_username(req.headers());

    let start = Instant::now();
    let response = next.run(req).await;
    let elapsed_ms = start.elapsed().as_millis() as u64;
    let status = response.status().as_u16();

    let is_noisy = path.ends_with("/status")
        || path.ends_with("/health")
        || path == "/api/health";

    if is_noisy {
        tracing::debug!(
            method = method,
            path = path,
            status = status,
            elapsed_ms = elapsed_ms,
            user = user,
            "request"
        );
    } else {
        tracing::info!(
            method = method,
            path = path,
            status = status,
            elapsed_ms = elapsed_ms,
            user = user,
            "request"
        );
    }

    response
}

/// Decode the `auth_token` cookie payload (without signature verification) to extract
/// the `username` claim. Returns `"-"` on any failure.
fn extract_username(headers: &axum::http::HeaderMap) -> String {
    (|| -> Option<String> {
        let cookie_header = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;

        // Find the auth_token cookie value
        let token = cookie_header
            .split(';')
            .map(|s| s.trim())
            .find(|s| s.starts_with("token="))?
            .strip_prefix("token=")?;

        // JWT structure: <header>.<payload>.<signature>
        // We only need the payload (index 1)
        let payload_b64 = token.split('.').nth(1)?;

        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload_b64)
            .ok()?;

        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).ok()?;
        payload["username"].as_str().map(|s| s.to_owned())
    })()
    .unwrap_or_else(|| "-".to_owned())
}
