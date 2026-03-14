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
    types::SslTarget,
};

use super::{alerter::evaluate_ssl_and_alert, checker::check_ssl_certificate};

#[derive(Clone)]
pub struct SslEngine {
    tokens: Arc<Mutex<HashMap<i64, CancellationToken>>>,
    db: DbPool,
    config: Arc<Config>,
}

impl SslEngine {
    pub fn new(db: DbPool, config: Arc<Config>) -> Arc<Self> {
        Arc::new(Self {
            tokens: Arc::new(Mutex::new(HashMap::new())),
            db,
            config,
        })
    }

    pub async fn start(self: &Arc<Self>) {
        let targets = load_active_targets(&self.db);
        let count = targets.len();
        for target in targets {
            self.schedule(target).await;
        }
        tracing::info!("[ssl-engine] Started monitoring {} SSL target(s)", count);
    }

    pub async fn schedule(self: &Arc<Self>, target: SslTarget) {
        if target.active == 0 {
            return;
        }
        self.unschedule(target.id).await;

        let token = CancellationToken::new();
        self.tokens.lock().unwrap().insert(target.id, token.clone());

        let db = self.db.clone();
        let config = self.config.clone();
        let target_id = target.id;
        let interval_secs = target.check_interval_seconds as u64;
        tracing::info!(
            "[ssl-engine] Scheduled '{}' ({}:{}) every {}s",
            target.name, target.host, target.port, interval_secs
        );

        tokio::spawn(async move {
            run_target_task(target_id, interval_secs, db, config, token).await;
        });
    }

    pub async fn unschedule(&self, target_id: i64) {
        if let Some(token) = self.tokens.lock().unwrap().remove(&target_id) {
            token.cancel();
        }
    }

    pub async fn reschedule(self: &Arc<Self>, target: SslTarget) {
        self.unschedule(target.id).await;
        if target.active != 0 {
            self.schedule(target).await;
        }
    }

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
        tracing::info!("[ssl-engine] Engine stopped");
    }
}

fn load_active_targets(db: &DbPool) -> Vec<SslTarget> {
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT id, name, host, port, check_interval_seconds, expiry_threshold_hours, \
             active, created_at, last_checked_at, last_alert_type, last_alerted_at \
             FROM ssl_targets WHERE active = 1",
        )
        .unwrap();
    stmt.query_map([], row_to_target)
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
}

fn load_target(db: &DbPool, id: i64) -> Option<SslTarget> {
    let conn = db.lock().unwrap();
    conn.query_row(
        "SELECT id, name, host, port, check_interval_seconds, expiry_threshold_hours, \
         active, created_at, last_checked_at, last_alert_type, last_alerted_at \
         FROM ssl_targets WHERE id = ?1",
        rusqlite::params![id],
        row_to_target,
    )
    .ok()
}

fn row_to_target(row: &rusqlite::Row<'_>) -> rusqlite::Result<SslTarget> {
    Ok(SslTarget {
        id: row.get(0)?,
        name: row.get(1)?,
        host: row.get(2)?,
        port: row.get(3)?,
        check_interval_seconds: row.get(4)?,
        expiry_threshold_hours: row.get(5)?,
        active: row.get(6)?,
        created_at: row.get(7)?,
        last_checked_at: row.get(8)?,
        last_alert_type: row.get(9)?,
        last_alerted_at: row.get(10)?,
    })
}

async fn run_target_task(
    target_id: i64,
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
                let Some(target) = load_target(&db, target_id) else {
                    tracing::warn!("[ssl-engine] SSL target {} no longer exists — stopping task", target_id);
                    break;
                };
                if target.active == 0 {
                    tracing::info!("[ssl-engine] Target '{}' deactivated — stopping task", target.name);
                    break;
                }
                run_check_for_target(target, &db, &config).await;
            }
            _ = token.cancelled() => {
                tracing::debug!("[ssl-engine] Task for SSL target {} cancelled", target_id);
                break;
            }
        }
    }
}

async fn run_check_for_target(target: SslTarget, db: &DbPool, config: &Arc<Config>) {
    let result = check_ssl_certificate(&target.host, target.port as u16).await;

    let ssl_snapshots_dir = PathBuf::from(&config.data_dir)
        .join("ssl")
        .join("snapshots");
    let snapshot_path = ssl_snapshots_dir.join(format!("{}.pem", target.id));

    if !result.pem_chain.is_empty() {
        tokio::fs::write(&snapshot_path, &result.pem_chain).await.ok();

        // Save historical copy if fingerprint changed
        let prev_fp = load_previous_fingerprint(db, target.id);
        if let (Some(prev), Some(new)) = (
            prev_fp.as_deref(),
            result.fingerprint_sha256.as_deref(),
        ) {
            if prev != new {
                let timestamp = chrono::Utc::now()
                    .format("%Y-%m-%dT%H-%M-%S%.3fZ")
                    .to_string();
                let history_dir =
                    PathBuf::from(&config.data_dir).join("ssl").join("history");
                let history_path =
                    history_dir.join(format!("{}-{}.pem", target.id, timestamp));
                tokio::fs::write(&history_path, &result.pem_chain).await.ok();
                tracing::info!(
                    "[ssl-engine] Cert changed for '{}' — historical PEM saved",
                    target.name
                );
            }
        }
    }

    // Evaluate alerts BEFORE inserting (so previous is still the latest row)
    let Some(fresh_target) = load_target(db, target.id) else {
        return;
    };
    let alert_type = evaluate_ssl_and_alert(db, config, &fresh_target, &result).await;

    let cert_file: Option<String> = if snapshot_path.exists() {
        Some(format!("ssl/snapshots/{}.pem", target.id))
    } else {
        None
    };

    let sans_json = serde_json::to_string(&result.sans).unwrap_or_else(|_| "[]".into());
    let chain_json = serde_json::to_string(&result.chain).unwrap_or_else(|_| "[]".into());
    let alert_str = alert_type.as_ref().map(|a| a.to_string());
    let now = chrono::Utc::now().to_rfc3339();

    let db2 = db.clone();
    let tid = target.id;
    let err = result.error.clone();
    let tls_ver = result.tls_version.clone();
    let scn = result.subject_cn.clone();
    let so = result.subject_o.clone();
    let icn = result.issuer_cn.clone();
    let io_val = result.issuer_o.clone();
    let vf = result.valid_from.clone();
    let vt = result.valid_to.clone();
    let dr = result.days_remaining;
    let fp = result.fingerprint_sha256.clone();
    let sn = result.serial_number.clone();

    tokio::task::spawn_blocking(move || {
        let conn = db2.lock().unwrap();
        conn.execute(
            "INSERT INTO ssl_checks \
             (target_id, error, tls_version, subject_cn, subject_o, issuer_cn, issuer_o, \
              valid_from, valid_to, days_remaining, fingerprint_sha256, serial_number, \
              sans, chain_json, cert_file, alert_type) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            rusqlite::params![
                tid, err, tls_ver, scn, so, icn, io_val, vf, vt, dr, fp, sn,
                sans_json, chain_json, cert_file, alert_str
            ],
        )
        .ok();
        conn.execute(
            "UPDATE ssl_targets SET last_checked_at = ?1 WHERE id = ?2",
            rusqlite::params![now, tid],
        )
        .ok();
    })
    .await
    .ok();

    let status_msg = result
        .error
        .as_deref()
        .map(|e| format!("error: {}", e))
        .unwrap_or_else(|| {
            format!("{} days remaining", result.days_remaining.unwrap_or(0))
        });

    tracing::info!(
        "[ssl-engine] Checked '{}' ({}:{}) — {}",
        target.name, target.host, target.port, status_msg
    );
}

fn load_previous_fingerprint(db: &DbPool, target_id: i64) -> Option<String> {
    use rusqlite::OptionalExtension;
    let conn = db.lock().unwrap();
    conn.query_row(
        "SELECT fingerprint_sha256 FROM ssl_checks \
         WHERE target_id = ?1 ORDER BY checked_at DESC LIMIT 1",
        rusqlite::params![target_id],
        |row| row.get::<_, Option<String>>(0),
    )
    .optional()
    .ok()
    .flatten()
    .flatten()
}
