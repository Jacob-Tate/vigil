use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{auth::middleware::RequireAuth, error::AppError, state::AppState};

#[derive(Serialize)]
struct ContentDiff {
    id: i64,
    server_id: i64,
    detected_at: String,
    old_hash: Option<String>,
    new_hash: Option<String>,
    diff_file: String,
    diff_content: Option<String>,
}

#[derive(Deserialize)]
pub struct DiffsQuery {
    #[serde(rename = "serverId")]
    server_id: Option<i64>,
}

// GET /api/diffs?serverId=X
pub async fn list(
    _auth: RequireAuth,
    State(state): State<AppState>,
    Query(query): Query<DiffsQuery>,
) -> Result<Json<Value>, AppError> {
    let db = state.db.clone();
    let rows: Vec<(i64, i64, String, Option<String>, Option<String>, String)> =
        tokio::task::spawn_blocking(move || {
            let conn = db.lock().unwrap();
            let (sql, params): (String, Vec<Box<dyn rusqlite::ToSql>>) =
                if let Some(sid) = query.server_id {
                    (
                        "SELECT id, server_id, detected_at, old_hash, new_hash, diff_file \
                         FROM content_diffs WHERE server_id = ?1 ORDER BY detected_at DESC"
                            .into(),
                        vec![Box::new(sid)],
                    )
                } else {
                    (
                        "SELECT id, server_id, detected_at, old_hash, new_hash, diff_file \
                         FROM content_diffs ORDER BY detected_at DESC"
                            .into(),
                        vec![],
                    )
                };

            let params_refs: Vec<&dyn rusqlite::ToSql> =
                params.iter().map(|p| p.as_ref()).collect();
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt
                .query_map(params_refs.as_slice(), |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok::<_, rusqlite::Error>(rows)
        })
        .await
        .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
        .map_err(AppError::Db)?;

    let diffs: Vec<ContentDiff> = rows
        .into_iter()
        .map(|(id, server_id, detected_at, old_hash, new_hash, diff_file)| ContentDiff {
            id,
            server_id,
            detected_at,
            old_hash,
            new_hash,
            diff_file,
            diff_content: None,
        })
        .collect();

    Ok(Json(serde_json::json!(diffs)))
}

// GET /api/diffs/:diffId
pub async fn get_diff(
    _auth: RequireAuth,
    State(state): State<AppState>,
    Path(diff_id): Path<i64>,
) -> Result<Json<Value>, AppError> {
    use rusqlite::OptionalExtension;
    let db = state.db.clone();
    let row: Option<(i64, String, Option<String>, Option<String>, String)> =
        tokio::task::spawn_blocking(move || {
            let conn = db.lock().unwrap();
            conn.query_row(
                "SELECT server_id, detected_at, old_hash, new_hash, diff_file \
                 FROM content_diffs WHERE id = ?1",
                rusqlite::params![diff_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .optional()
        })
        .await
        .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
        .map_err(AppError::Db)?;

    let (server_id, detected_at, old_hash, new_hash, diff_file) =
        row.ok_or_else(|| AppError::NotFound(format!("Diff {} not found", diff_id)))?;

    let path = std::path::PathBuf::from(&state.config.data_dir).join(&diff_file);
    let diff_content = tokio::fs::read_to_string(&path)
        .await
        .map_err(|e| AppError::NotFound(format!("Diff file not readable: {}", e)))?;

    let diff = ContentDiff {
        id: diff_id,
        server_id,
        detected_at,
        old_hash,
        new_hash,
        diff_file,
        diff_content: Some(diff_content),
    };

    Ok(Json(serde_json::json!(diff)))
}
