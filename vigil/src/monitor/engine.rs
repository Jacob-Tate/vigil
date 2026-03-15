use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use tokio::time::{interval, Duration, MissedTickBehavior};
use tokio_util::sync::CancellationToken;

use crate::{
    config::Config,
    db::DbPool,
    types::Server,
};

use super::{
    alerter::{evaluate_and_alert, CheckSummary},
    checker::check_server,
    differ::{compute_diff, has_meaningful_changes},
    hasher::{hash_content, normalize_html, parse_ignore_patterns},
    screenshotter,
};

#[derive(Clone)]
pub struct MonitorEngine {
    tokens: Arc<Mutex<HashMap<i64, CancellationToken>>>,
    db: DbPool,
    config: Arc<Config>,
}

impl MonitorEngine {
    pub fn new(db: DbPool, config: Arc<Config>) -> Arc<Self> {
        Arc::new(Self {
            tokens: Arc::new(Mutex::new(HashMap::new())),
            db,
            config,
        })
    }

    /// Schedule all active servers on startup.
    pub async fn start(self: &Arc<Self>) {
        let servers = load_active_servers(&self.db);
        let count = servers.len();
        for server in servers {
            self.schedule(server).await;
        }
        tracing::info!("[monitor] Started monitoring {} server(s)", count);
    }

    /// Schedule a server (or reschedule if already running).
    pub async fn schedule(self: &Arc<Self>, server: Server) {
        if server.active == 0 {
            return;
        }
        self.unschedule(server.id).await;

        let token = CancellationToken::new();
        self.tokens.lock().unwrap().insert(server.id, token.clone());

        let db = self.db.clone();
        let config = self.config.clone();
        let server_id = server.id;
        let interval_secs = server.interval_seconds as u64;
        tracing::info!("[monitor] Scheduled '{}' every {}s", server.name, interval_secs);

        tokio::spawn(async move {
            run_server_task(server_id, interval_secs, db, config, token).await;
        });
    }

    /// Cancel a server's monitoring task.
    pub async fn unschedule(&self, server_id: i64) {
        if let Some(token) = self.tokens.lock().unwrap().remove(&server_id) {
            token.cancel();
        }
    }

    /// Stop and restart a server's monitoring task with fresh config.
    pub async fn reschedule(self: &Arc<Self>, server: Server) {
        self.unschedule(server.id).await;
        if server.active != 0 {
            self.schedule(server).await;
        }
    }

    /// Cancel all running tasks.
    pub async fn stop(&self) {
        let tokens: Vec<CancellationToken> = self
            .tokens
            .lock()
            .unwrap()
            .drain()
            .map(|(_, t)| t)
            .collect();
        for t in tokens {
            t.cancel();
        }
        tracing::info!("[monitor] Engine stopped");
    }
}

fn load_active_servers(db: &DbPool) -> Vec<Server> {
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT id, name, url, interval_seconds, response_time_threshold_ms, active, \
             created_at, baseline_hash, baseline_file, last_alerted_at, last_alert_type, \
             ignore_patterns FROM servers WHERE active = 1",
        )
        .unwrap();
    stmt.query_map([], row_to_server)
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
}

fn load_server(db: &DbPool, id: i64) -> Option<Server> {
    let conn = db.lock().unwrap();
    conn.query_row(
        "SELECT id, name, url, interval_seconds, response_time_threshold_ms, active, \
         created_at, baseline_hash, baseline_file, last_alerted_at, last_alert_type, \
         ignore_patterns FROM servers WHERE id = ?1",
        rusqlite::params![id],
        row_to_server,
    )
    .ok()
}

fn row_to_server(row: &rusqlite::Row<'_>) -> rusqlite::Result<Server> {
    Ok(Server {
        id: row.get(0)?,
        name: row.get(1)?,
        url: row.get(2)?,
        interval_seconds: row.get(3)?,
        response_time_threshold_ms: row.get(4)?,
        active: row.get(5)?,
        created_at: row.get(6)?,
        baseline_hash: row.get(7)?,
        baseline_file: row.get(8)?,
        last_alerted_at: row.get(9)?,
        last_alert_type: row.get(10)?,
        ignore_patterns: row.get(11)?,
    })
}

async fn run_server_task(
    server_id: i64,
    interval_secs: u64,
    db: DbPool,
    config: Arc<Config>,
    token: CancellationToken,
) {
    let mut ticker = interval(Duration::from_secs(interval_secs));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let Some(server) = load_server(&db, server_id) else {
                    tracing::warn!("[monitor] Server {} no longer exists — stopping task", server_id);
                    break;
                };
                if server.active == 0 {
                    tracing::info!("[monitor] Server '{}' deactivated — stopping task", server.name);
                    break;
                }
                run_check_for_server(server, &db, &config).await;
            }
            _ = token.cancelled() => {
                tracing::debug!("[monitor] Task for server {} cancelled", server_id);
                break;
            }
        }
    }
}

async fn run_check_for_server(server: Server, db: &DbPool, config: &Arc<Config>) {
    let extra_patterns = parse_ignore_patterns(server.ignore_patterns.as_deref());

    let result = check_server(&server.url, server.response_time_threshold_ms).await;

    let content_hash = if result.raw_html.is_empty() {
        None
    } else {
        Some(hash_content(&result.raw_html, &extra_patterns))
    };

    let mut content_changed = false;
    let mut diff_id: Option<i64> = None;

    if let Some(ref hash) = content_hash {
        let Some(fresh) = load_server(db, server.id) else {
            return;
        };

        let snapshots_dir = PathBuf::from(&config.data_dir).join("snapshots");
        let snapshot_path = snapshots_dir.join(format!("{}.html", server.id));

        if fresh.baseline_hash.is_none() {
            // First check — set baseline
            if let Err(e) = tokio::fs::write(&snapshot_path, &result.raw_html).await {
                tracing::error!("[monitor] Failed to write baseline for '{}': {}", server.name, e);
            } else {
                let snap_rel = format!("snapshots/{}.html", server.id);
                let h = hash.clone();
                let db2 = db.clone();
                let sid = server.id;
                tokio::task::spawn_blocking(move || {
                    let conn = db2.lock().unwrap();
                    conn.execute(
                        "UPDATE servers SET baseline_hash = ?1, baseline_file = ?2 WHERE id = ?3",
                        rusqlite::params![h, snap_rel, sid],
                    ).ok();
                }).await.ok();
                tracing::info!("[monitor] Baseline set for '{}'", server.name);
                let data_dir = config.data_dir.clone();
                let url = server.url.clone();
                let sid = server.id;
                tokio::spawn(async move {
                    screenshotter::capture_screenshot(&data_dir, sid, &url).await;
                });
            }
        } else if fresh.baseline_hash.as_deref() != Some(hash.as_str()) {
            let old_html = tokio::fs::read_to_string(&snapshot_path)
                .await
                .unwrap_or_default();

            let normalized_old = normalize_html(&old_html, &extra_patterns);
            let normalized_new = normalize_html(&result.raw_html, &extra_patterns);
            let diff_content = compute_diff(&normalized_old, &normalized_new, &server.name);

            if !has_meaningful_changes(&diff_content) {
                // Only dynamic tokens changed — update baseline silently
                if let Err(e) = tokio::fs::write(&snapshot_path, &result.raw_html).await {
                    tracing::error!("[monitor] Failed to update snapshot for '{}': {}", server.name, e);
                } else {
                    let h = hash.clone();
                    let snap_rel = format!("snapshots/{}.html", server.id);
                    let db2 = db.clone();
                    let sid = server.id;
                    tokio::task::spawn_blocking(move || {
                        let conn = db2.lock().unwrap();
                        conn.execute(
                            "UPDATE servers SET baseline_hash = ?1, baseline_file = ?2 WHERE id = ?3",
                            rusqlite::params![h, snap_rel, sid],
                        ).ok();
                    }).await.ok();
                    tracing::info!(
                        "[monitor] Hash changed for '{}' but diff is trivial — updating baseline silently",
                        server.name
                    );
                }
            } else {
                // Meaningful change — save diff file and record in DB
                let timestamp = chrono::Utc::now()
                    .format("%Y-%m-%dT%H-%M-%S%.3fZ")
                    .to_string();
                let diffs_dir = PathBuf::from(&config.data_dir).join("diffs");
                let tmp_filename = format!("tmp-{}-{}.html", server.id, timestamp);
                let tmp_path = diffs_dir.join(&tmp_filename);

                if let Err(e) = tokio::fs::write(&tmp_path, &diff_content).await {
                    tracing::error!("[monitor] Failed to write diff for '{}': {}", server.name, e);
                } else {
                    let tmp_rel = format!("diffs/{}", tmp_filename);
                    let old_hash = fresh.baseline_hash.clone().unwrap_or_default();
                    let new_hash = hash.clone();
                    let sid = server.id;
                    let db2 = db.clone();

                    let inserted_id: Option<i64> = tokio::task::spawn_blocking(move || {
                        let conn = db2.lock().unwrap();
                        conn.execute(
                            "INSERT INTO content_diffs (server_id, old_hash, new_hash, diff_file) \
                             VALUES (?1, ?2, ?3, ?4)",
                            rusqlite::params![sid, old_hash, new_hash, tmp_rel],
                        ).ok()?;
                        Some(conn.last_insert_rowid())
                    }).await.ok().flatten();

                    if let Some(did) = inserted_id {
                        let final_filename = format!("{}-{}.html", did, timestamp);
                        let final_path = diffs_dir.join(&final_filename);
                        tokio::fs::rename(&tmp_path, &final_path).await.ok();

                        let final_rel = format!("diffs/{}", final_filename);
                        let db2 = db.clone();
                        tokio::task::spawn_blocking(move || {
                            let conn = db2.lock().unwrap();
                            conn.execute(
                                "UPDATE content_diffs SET diff_file = ?1 WHERE id = ?2",
                                rusqlite::params![final_rel, did],
                            ).ok();
                        }).await.ok();

                        diff_id = Some(did);
                    }

                    tokio::fs::write(&snapshot_path, &result.raw_html).await.ok();
                    let h = hash.clone();
                    let snap_rel = format!("snapshots/{}.html", server.id);
                    let db2 = db.clone();
                    let sid = server.id;
                    tokio::task::spawn_blocking(move || {
                        let conn = db2.lock().unwrap();
                        conn.execute(
                            "UPDATE servers SET baseline_hash = ?1, baseline_file = ?2 WHERE id = ?3",
                            rusqlite::params![h, snap_rel, sid],
                        ).ok();
                    }).await.ok();

                    content_changed = true;
                    tracing::info!(
                        "[monitor] Content changed for '{}', diff saved (id: {:?})",
                        server.name, diff_id
                    );
                    let data_dir = config.data_dir.clone();
                    let url = server.url.clone();
                    let sid = server.id;
                    tokio::spawn(async move {
                        screenshotter::capture_screenshot(&data_dir, sid, &url).await;
                    });
                }
            }
        }
    }

    // Record the check in the DB
    let is_up_val: i64 = if result.is_up { 1 } else { 0 };
    let changed_val: i64 = if content_changed { 1 } else { 0 };
    let db2 = db.clone();
    let sid = server.id;
    let sc = result.status_code;
    let rt = result.response_time_ms;
    let ch = content_hash.clone();
    let did = diff_id;
    tokio::task::spawn_blocking(move || {
        let conn = db2.lock().unwrap();
        conn.execute(
            "INSERT INTO checks \
             (server_id, status_code, response_time_ms, is_up, content_hash, content_changed, diff_id) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![sid, sc, rt, is_up_val, ch, changed_val, did],
        ).ok();
    }).await.ok();

    // Load the freshest server row for alerting
    if let Some(fresh_server) = load_server(db, server.id) {
        let summary = CheckSummary {
            is_up: result.is_up,
            status_code: result.status_code,
            response_time_ms: result.response_time_ms,
            content_changed,
            diff_id,
        };
        evaluate_and_alert(db, config, &fresh_server, &summary).await;
    }
}
