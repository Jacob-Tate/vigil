use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};

use crate::{
    auth::jwt::{sign_jwt, verify_jwt},
    state::AppState,
    types::AuthUser,
};

/// Tower middleware that re-issues the JWT cookie when more than half of the
/// session lifetime has elapsed, giving active users a rolling window.
///
/// Requests with an absent or invalid token are passed through unchanged —
/// `RequireAuth` is still responsible for rejecting unauthenticated access.
pub async fn sliding_session_renewal(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let renewal_cookie = try_renew(&state, request.headers());

    let mut response = next.run(request).await;

    if let Some(cookie) = renewal_cookie {
        if let Ok(value) = cookie.parse() {
            response
                .headers_mut()
                .append(axum::http::header::SET_COOKIE, value);
        }
    }

    response
}

fn try_renew(state: &AppState, headers: &axum::http::HeaderMap) -> Option<String> {
    let token = headers
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| {
            s.split(';')
                .find_map(|part| part.trim().strip_prefix("token=").map(|v| v.to_string()))
        })?;

    let claims = verify_jwt(&token, &state.config).ok()?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();

    let session_secs = state.config.session_duration_hours * 3600;
    let elapsed = now.saturating_sub(claims.iat);

    // Only renew when past the halfway point.
    if elapsed < session_secs / 2 {
        return None;
    }

    let auth_user = AuthUser {
        id: claims.sub,
        username: claims.username,
        role: claims.role,
    };

    let new_token = sign_jwt(&auth_user, &state.config).ok()?;
    let secure_flag = if state.config.is_production { "; Secure" } else { "" };

    Some(format!(
        "token={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{}",
        new_token, session_secs as i64, secure_flag
    ))
}
