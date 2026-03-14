use async_trait::async_trait;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum_extra::extract::CookieJar;

use crate::{error::AppError, state::AppState, types::AuthUser};

use super::jwt::verify_jwt;

/// Axum extractor that requires a valid JWT cookie.
/// On success, yields the authenticated `AuthUser`.
/// On failure, short-circuits with a 401 response.
pub struct RequireAuth(pub AuthUser);

#[async_trait]
impl FromRequestParts<AppState> for RequireAuth {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_request_parts(parts, state)
            .await
            .map_err(|_| AppError::Unauthorized("No session cookie".into()))?;

        let token = jar
            .get("token")
            .map(|c| c.value().to_string())
            .ok_or_else(|| AppError::Unauthorized("No session cookie".into()))?;

        let claims = verify_jwt(&token, &state.config)?;

        Ok(RequireAuth(AuthUser {
            id: claims.sub,
            username: claims.username,
            role: claims.role,
        }))
    }
}

/// Axum extractor that requires the authenticated user to be an admin.
/// On success, yields the `AuthUser`.
/// On failure, short-circuits with 401 (no cookie) or 403 (wrong role).
pub struct RequireAdmin(pub AuthUser);

#[async_trait]
impl FromRequestParts<AppState> for RequireAdmin {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let RequireAuth(user) = RequireAuth::from_request_parts(parts, state).await?;

        if user.role != "admin" {
            return Err(AppError::Forbidden("Admin only".into()));
        }

        Ok(RequireAdmin(user))
    }
}
