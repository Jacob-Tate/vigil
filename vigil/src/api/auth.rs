use axum::{extract::State, http::header::SET_COOKIE, response::IntoResponse, Json};
use serde::Deserialize;
use serde_json::json;

use rusqlite::OptionalExtension;

use crate::{
    auth::{jwt::sign_jwt, middleware::RequireAuth},
    error::AppError,
    state::AppState,
    types::{AuthUser, User},
};

#[derive(Deserialize)]
pub struct LoginRequest {
    username: Option<String>,
    password: Option<String>,
}

// POST /api/auth/login
pub async fn login(
    State(state): State<AppState>,
    Json(body): Json<LoginRequest>,
) -> Result<impl IntoResponse, AppError> {
    // Validate inputs — match express-validator error shape
    let mut errors = Vec::new();
    let username = body.username.as_deref().map(|s| s.trim().to_string());
    let password = body.password.clone();

    if username.as_deref().map(|s| s.is_empty()).unwrap_or(true) {
        errors.push(json!({"msg": "Invalid value", "path": "username"}));
    }
    if password.as_deref().map(|s| s.is_empty()).unwrap_or(true) {
        errors.push(json!({"msg": "Invalid value", "path": "password"}));
    }
    if !errors.is_empty() {
        return Err(AppError::Validation(errors));
    }

    let username = username.unwrap();
    let password = password.unwrap();

    // Fetch user from DB (blocking)
    let db = state.db.clone();
    let username_clone = username.clone();
    let user: Option<User> = tokio::task::spawn_blocking(move || {
        let conn = db.lock().unwrap();
        conn.query_row(
            "SELECT id, username, password_hash, role, created_at FROM users WHERE username = ?1",
            rusqlite::params![username_clone],
            |row| {
                Ok(User {
                    id: row.get(0)?,
                    username: row.get(1)?,
                    password_hash: row.get(2)?,
                    role: row.get(3)?,
                    created_at: row.get(4)?,
                })
            },
        )
        .optional()
    })
    .await
    .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
    .map_err(AppError::Db)?;

    let user = user.ok_or_else(|| AppError::Unauthorized("Invalid credentials".into()))?;

    // Verify password (bcrypt is CPU-intensive — run on blocking thread pool)
    let hash = user.password_hash.clone();
    let password_clone = password.clone();
    let valid = tokio::task::spawn_blocking(move || bcrypt::verify(&password_clone, &hash))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .map_err(|e| AppError::Internal(format!("bcrypt error: {}", e)))?;

    if !valid {
        return Err(AppError::Unauthorized("Invalid credentials".into()));
    }

    let auth_user = AuthUser {
        id: user.id,
        username: user.username.clone(),
        role: user.role.clone(),
    };

    let token = sign_jwt(&auth_user, &state.config)?;

    let session_seconds = state.config.session_duration_hours as i64 * 3600;
    let secure_flag = if state.config.is_production {
        "; Secure"
    } else {
        ""
    };
    let cookie = format!(
        "token={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{}",
        token, session_seconds, secure_flag
    );

    let mut response = Json(json!({ "user": auth_user })).into_response();
    response
        .headers_mut()
        .insert(SET_COOKIE, cookie.parse().unwrap());

    Ok(response)
}

// POST /api/auth/logout
pub async fn logout(State(state): State<AppState>) -> impl IntoResponse {
    let secure_flag = if state.config.is_production {
        "; Secure"
    } else {
        ""
    };
    let cookie = format!(
        "token=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{}",
        secure_flag
    );

    let mut response = Json(json!({ "ok": true })).into_response();
    response
        .headers_mut()
        .insert(SET_COOKIE, cookie.parse().unwrap());

    response
}

// GET /api/auth/me
pub async fn me(RequireAuth(user): RequireAuth) -> impl IntoResponse {
    Json(json!({ "user": user }))
}
