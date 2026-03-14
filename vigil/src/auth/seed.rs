use crate::{config::Config, db::DbPool};

/// Creates the initial admin user from ADMIN_USERNAME / ADMIN_PASSWORD env vars.
///
/// Idempotent — skips silently if the username already exists.
/// Mirrors auth/seed.ts.
pub async fn seed_admin_user(pool: DbPool, config: Config) -> anyhow::Result<()> {
    tokio::task::spawn_blocking(move || {
        let username = &config.admin_username;
        let password = &config.admin_password;

        if password.is_empty() {
            tracing::warn!("[seed] ADMIN_PASSWORD is empty — skipping admin seed");
            return Ok(());
        }

        let conn = pool.lock().unwrap();

        // Check if user already exists
        let exists: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM users WHERE username = ?1",
                rusqlite::params![username],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or(0)
            > 0;

        if exists {
            tracing::debug!("[seed] Admin user '{}' already exists — skipping", username);
            return Ok(());
        }

        let hash = bcrypt::hash(password, 12)
            .map_err(|e| anyhow::anyhow!("bcrypt error: {}", e))?;

        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?1, ?2, 'admin')",
            rusqlite::params![username, hash],
        )?;

        tracing::info!("[seed] Admin user '{}' created", username);
        Ok(())
    })
    .await?
}
