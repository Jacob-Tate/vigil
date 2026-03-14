use axum::{
    extract::{Path, State},
    Json,
};
use rusqlite::OptionalExtension;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    auth::middleware::{RequireAdmin, RequireAuth},
    error::AppError,
    state::AppState,
    types::User,
};

fn row_to_user(row: &rusqlite::Row<'_>) -> rusqlite::Result<User> {
    Ok(User {
        id: row.get(0)?,
        username: row.get(1)?,
        password_hash: row.get(2)?,
        role: row.get(3)?,
        created_at: row.get(4)?,
    })
}

fn safe_user(u: &User) -> Value {
    json!({ "id": u.id, "username": u.username, "role": u.role, "created_at": u.created_at })
}

// GET /api/users
pub async fn list(
    _admin: RequireAdmin,
    State(state): State<AppState>,
) -> Result<Json<Value>, AppError> {
    let db = state.db.clone();
    let users: Vec<User> = tokio::task::spawn_blocking(move || {
        let conn = db.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT id, username, password_hash, role, created_at FROM users ORDER BY id")?;
        let rows = stmt
            .query_map([], row_to_user)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok::<_, rusqlite::Error>(rows)
    })
    .await
    .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
    .map_err(AppError::Db)?;

    let safe: Vec<Value> = users.iter().map(safe_user).collect();
    Ok(Json(json!(safe)))
}

#[derive(Deserialize)]
pub struct CreateUser {
    username: String,
    password: String,
    role: Option<String>,
}

// POST /api/users
pub async fn create(
    _admin: RequireAdmin,
    State(state): State<AppState>,
    Json(body): Json<CreateUser>,
) -> Result<Json<Value>, AppError> {
    let mut errors = Vec::new();
    if body.username.trim().is_empty() {
        errors.push(json!({"msg": "username is required", "path": "username"}));
    }
    if body.password.len() < 8 {
        errors.push(json!({"msg": "password must be at least 8 characters", "path": "password"}));
    }
    if !errors.is_empty() {
        return Err(AppError::Validation(errors));
    }

    let role = body.role.unwrap_or_else(|| "viewer".into());
    let username = body.username.clone();
    let password = body.password.clone();
    let db = state.db.clone();

    let id: i64 = tokio::task::spawn_blocking(move || {
        let hash = bcrypt::hash(&password, 12)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(
                std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
            )))?;
        let conn = db.lock().unwrap();
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?1, ?2, ?3)",
            rusqlite::params![username, hash, role],
        )?;
        Ok::<_, rusqlite::Error>(conn.last_insert_rowid())
    })
    .await
    .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
    .map_err(|e| {
        if e.to_string().contains("UNIQUE") {
            AppError::BadRequest("Username already exists".into())
        } else {
            AppError::Db(e)
        }
    })?;

    let db2 = state.db.clone();
    let user = tokio::task::spawn_blocking(move || {
        let conn = db2.lock().unwrap();
        conn.query_row(
            "SELECT id, username, password_hash, role, created_at FROM users WHERE id = ?1",
            rusqlite::params![id],
            row_to_user,
        )
    })
    .await
    .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
    .map_err(AppError::Db)?;

    Ok(Json(safe_user(&user)))
}

#[derive(Deserialize)]
pub struct UpdateUser {
    role: Option<String>,
    username: Option<String>,
}

// PUT /api/users/:id
pub async fn update(
    _admin: RequireAdmin,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(body): Json<UpdateUser>,
) -> Result<Json<Value>, AppError> {
    let db = state.db.clone();
    let changes = tokio::task::spawn_blocking(move || {
        use rusqlite::types::Value;
        let conn = db.lock().unwrap();
        let mut parts: Vec<String> = Vec::new();
        let mut params: Vec<Value> = Vec::new();

        if let Some(v) = body.username { parts.push("username = ?".into()); params.push(Value::Text(v)); }
        if let Some(v) = body.role { parts.push("role = ?".into()); params.push(Value::Text(v)); }

        if parts.is_empty() { return Ok::<_, rusqlite::Error>(0usize); }

        let sql = format!("UPDATE users SET {} WHERE id = ?", parts.join(", "));
        params.push(Value::Integer(id));
        let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p as &dyn rusqlite::ToSql).collect();
        conn.execute(&sql, param_refs.as_slice())
    })
    .await
    .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
    .map_err(AppError::Db)?;

    if changes == 0 {
        return Err(AppError::NotFound(format!("User {} not found", id)));
    }

    let db2 = state.db.clone();
    let user = tokio::task::spawn_blocking(move || {
        let conn = db2.lock().unwrap();
        conn.query_row(
            "SELECT id, username, password_hash, role, created_at FROM users WHERE id = ?1",
            rusqlite::params![id],
            row_to_user,
        )
    })
    .await
    .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
    .map_err(AppError::Db)?;

    Ok(Json(safe_user(&user)))
}

// DELETE /api/users/:id
pub async fn delete(
    _admin: RequireAdmin,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<Value>, AppError> {
    let db = state.db.clone();
    let changes = tokio::task::spawn_blocking(move || {
        let conn = db.lock().unwrap();
        conn.execute("DELETE FROM users WHERE id = ?1", rusqlite::params![id])
    })
    .await
    .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
    .map_err(AppError::Db)?;

    if changes == 0 {
        return Err(AppError::NotFound(format!("User {} not found", id)));
    }
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct ChangePassword {
    current_password: Option<String>,
    new_password: String,
}

// POST /api/users/:id/change-password  (self or admin)
pub async fn change_password(
    RequireAuth(caller): RequireAuth,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(body): Json<ChangePassword>,
) -> Result<Json<Value>, AppError> {
    // Non-admins can only change their own password
    if caller.role != "admin" && caller.id != id {
        return Err(AppError::Forbidden("Cannot change another user's password".into()));
    }

    if body.new_password.len() < 8 {
        return Err(AppError::Validation(vec![
            json!({"msg": "password must be at least 8 characters", "path": "new_password"}),
        ]));
    }

    let db = state.db.clone();
    let current_password = body.current_password.clone();
    let new_password = body.new_password.clone();
    let is_admin = caller.role == "admin";

    tokio::task::spawn_blocking(move || {
        let conn = db.lock().unwrap();

        // If not admin, verify current password
        if !is_admin {
            let hash: Option<String> = conn
                .query_row(
                    "SELECT password_hash FROM users WHERE id = ?1",
                    rusqlite::params![id],
                    |row| row.get(0),
                )
                .optional()?;

            let hash = hash.ok_or_else(|| rusqlite::Error::QueryReturnedNoRows)?;
            let current = current_password.unwrap_or_default();
            let valid = bcrypt::verify(&current, &hash).unwrap_or(false);
            if !valid {
                return Err(rusqlite::Error::ToSqlConversionFailure(Box::new(
                    std::io::Error::new(std::io::ErrorKind::PermissionDenied, "invalid_current")
                )));
            }
        }

        let new_hash = bcrypt::hash(&new_password, 12)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(
                std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
            )))?;

        conn.execute(
            "UPDATE users SET password_hash = ?1 WHERE id = ?2",
            rusqlite::params![new_hash, id],
        )?;
        Ok::<_, rusqlite::Error>(())
    })
    .await
    .map_err(|e: tokio::task::JoinError| AppError::Internal(e.to_string()))?
    .map_err(|e| {
        if e.to_string().contains("invalid_current") {
            AppError::Unauthorized("Current password is incorrect".into())
        } else if matches!(e, rusqlite::Error::QueryReturnedNoRows) {
            AppError::NotFound(format!("User {} not found", id))
        } else {
            AppError::Db(e)
        }
    })?;

    Ok(Json(json!({ "ok": true })))
}
