use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    /// Validation errors — returned as {"errors": [...]} to match express-validator shape
    #[error("Validation failed")]
    Validation(Vec<Value>),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Database error: {0}")]
    Db(#[from] rusqlite::Error),

    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::Validation(errors) => (
                StatusCode::BAD_REQUEST,
                Json(json!({ "errors": errors })),
            )
                .into_response(),

            AppError::Unauthorized(msg) => (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": msg })),
            )
                .into_response(),

            AppError::Forbidden(msg) => (
                StatusCode::FORBIDDEN,
                Json(json!({ "error": msg })),
            )
                .into_response(),

            AppError::NotFound(msg) => (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": msg })),
            )
                .into_response(),

            AppError::BadRequest(msg) => (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": msg })),
            )
                .into_response(),

            AppError::Internal(ref msg) => {
                tracing::error!("Internal error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "Internal server error" })),
                )
                    .into_response()
            }

            AppError::Db(ref e) => {
                tracing::error!("Database error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "Internal server error" })),
                )
                    .into_response()
            }

            AppError::Anyhow(ref e) => {
                tracing::error!("Internal error: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "Internal server error" })),
                )
                    .into_response()
            }
        }
    }
}
