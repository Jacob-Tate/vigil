use axum::{
    extract::{Path, State},
    http::header,
    response::IntoResponse,
};

use crate::{auth::middleware::RequireAuth, error::AppError, state::AppState};

// GET /api/diffs/:diffId
pub async fn get_diff(
    _auth: RequireAuth,
    State(state): State<AppState>,
    Path(diff_id): Path<i64>,
) -> Result<impl IntoResponse, AppError> {
    use rusqlite::OptionalExtension;
    let db = state.db.clone();
    let diff_file: Option<String> = tokio::task::spawn_blocking(move || {
        let conn = db.lock().unwrap();
        conn.query_row(
            "SELECT diff_file FROM content_diffs WHERE id = ?1",
            rusqlite::params![diff_id],
            |row| row.get(0),
        )
        .optional()
    })
    .await
    .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
    .map_err(AppError::Db)?;

    let path = diff_file
        .ok_or_else(|| AppError::NotFound(format!("Diff {} not found", diff_id)))?;

    let html = tokio::fs::read_to_string(&path)
        .await
        .map_err(|e| AppError::NotFound(format!("Diff file not readable: {}", e)))?;

    Ok((
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    ))
}
