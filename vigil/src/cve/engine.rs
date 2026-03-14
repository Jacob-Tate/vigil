use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use tokio_util::sync::CancellationToken;

use crate::{
    config::Config,
    db::DbPool,
    notifiers,
    types::{AlertPayload, AlertType, CveTarget, CveDigestItem},
};

pub struct CveEngine {
    tokens: Arc<Mutex<HashMap<i64, CancellationToken>>>,
    db: DbPool,
    config: Arc<Config>,
}

impl CveEngine {
    pub fn new(db: DbPool, config: Arc<Config>) -> Arc<Self> {
        Arc::new(Self {
            tokens: Arc::new(Mutex::new(HashMap::new())),
            db,
            config,
        })
    }

    /// Schedule all active CVE targets on startup.
    pub async fn start(self: &Arc<Self>) {
        let db = self.db.clone();
        let targets: Vec<CveTarget> = tokio::task::spawn_blocking(move || {
            let conn = db.lock().unwrap();
            conn.prepare(
                "SELECT id, name, vendor, product, version, min_alert_cvss_score,
                 check_interval_seconds, active, created_at, last_checked_at, last_alerted_at
                 FROM cve_targets WHERE active = 1",
            )
            .and_then(|mut stmt| {
                stmt.query_map([], |row| {
                    Ok(CveTarget {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        vendor: row.get(2)?,
                        product: row.get(3)?,
                        version: row.get(4)?,
                        min_alert_cvss_score: row.get(5)?,
                        check_interval_seconds: row.get(6)?,
                        active: row.get(7)?,
                        created_at: row.get(8)?,
                        last_checked_at: row.get(9)?,
                        last_alerted_at: row.get(10)?,
                    })
                })
                .and_then(|rows| rows.collect::<rusqlite::Result<Vec<_>>>())
            })
            .unwrap_or_default()
        })
        .await
        .unwrap_or_default();

        let count = targets.len();
        for t in targets {
            self.schedule(t).await;
        }
        tracing::info!("[cve-engine] Started monitoring {} CVE target(s)", count);
    }

    pub async fn schedule(self: &Arc<Self>, target: CveTarget) {
        self.unschedule(target.id).await;

        let token = CancellationToken::new();
        {
            self.tokens.lock().unwrap().insert(target.id, token.clone());
        }

        let engine = Arc::clone(self);
        let interval_secs = target.check_interval_seconds.max(60) as u64;

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        // Re-fetch target in case it changed
                        let db = engine.db.clone();
                        let id = target.id;
                        let fresh = tokio::task::spawn_blocking(move || {
                            let conn = db.lock().unwrap();
                            conn.query_row(
                                "SELECT id, name, vendor, product, version, min_alert_cvss_score,
                                 check_interval_seconds, active, created_at, last_checked_at, last_alerted_at
                                 FROM cve_targets WHERE id = ?1",
                                rusqlite::params![id],
                                |row| Ok(CveTarget {
                                    id: row.get(0)?,
                                    name: row.get(1)?,
                                    vendor: row.get(2)?,
                                    product: row.get(3)?,
                                    version: row.get(4)?,
                                    min_alert_cvss_score: row.get(5)?,
                                    check_interval_seconds: row.get(6)?,
                                    active: row.get(7)?,
                                    created_at: row.get(8)?,
                                    last_checked_at: row.get(9)?,
                                    last_alerted_at: row.get(10)?,
                                }),
                            )
                        })
                        .await
                        .ok()
                        .and_then(|r| r.ok());

                        if let Some(t) = fresh {
                            if t.active == 1 {
                                evaluate_cve_target(&engine.db, &engine.config, &t).await;
                            }
                        }
                    }
                    _ = token.cancelled() => break,
                }
            }
        });

        tracing::info!(
            target_id = target.id,
            name = %target.name,
            interval_secs,
            "[cve-engine] Scheduled target"
        );
    }

    pub async fn unschedule(&self, target_id: i64) {
        if let Some(token) = self.tokens.lock().unwrap().remove(&target_id) {
            token.cancel();
        }
    }

    pub async fn reschedule(self: &Arc<Self>, target: CveTarget) {
        self.unschedule(target.id).await;
        if target.active == 1 {
            self.schedule(target).await;
        }
    }

    /// Run one evaluation pass for all active targets (called after NVD/cvelist sync).
    pub async fn evaluate_all(self: &Arc<Self>) {
        let db = self.db.clone();
        let targets: Vec<CveTarget> = tokio::task::spawn_blocking(move || {
            let conn = db.lock().unwrap();
            conn.prepare(
                "SELECT id, name, vendor, product, version, min_alert_cvss_score,
                 check_interval_seconds, active, created_at, last_checked_at, last_alerted_at
                 FROM cve_targets WHERE active = 1",
            )
            .and_then(|mut stmt| {
                stmt.query_map([], |row| {
                    Ok(CveTarget {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        vendor: row.get(2)?,
                        product: row.get(3)?,
                        version: row.get(4)?,
                        min_alert_cvss_score: row.get(5)?,
                        check_interval_seconds: row.get(6)?,
                        active: row.get(7)?,
                        created_at: row.get(8)?,
                        last_checked_at: row.get(9)?,
                        last_alerted_at: row.get(10)?,
                    })
                })
                .and_then(|rows| rows.collect::<rusqlite::Result<Vec<_>>>())
            })
            .unwrap_or_default()
        })
        .await
        .unwrap_or_default();

        for t in targets {
            evaluate_cve_target(&self.db, &self.config, &t).await;
        }
    }

    pub async fn stop(&self) {
        let tokens: Vec<CancellationToken> =
            self.tokens.lock().unwrap().drain().map(|(_, t)| t).collect();
        for t in tokens {
            t.cancel();
        }
        tracing::info!("[cve-engine] Stopped");
    }
}

// ---------------------------------------------------------------------------
// Core evaluation logic
// ---------------------------------------------------------------------------

struct MatchedCve {
    cve_id: String,
    published_at: Option<String>,
    last_modified_at: Option<String>,
    cvss_score: Option<f64>,
    cvss_severity: Option<String>,
    description: Option<String>,
    nvd_url: Option<String>,
}

pub async fn evaluate_cve_target(db: &DbPool, config: &Arc<Config>, target: &CveTarget) {
    let db_clone = db.clone();
    let target_clone = target.clone();

    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<Option<AlertPayload>> {
        let conn = db_clone.lock().unwrap();

        let is_first_check = target_clone.last_checked_at.is_none();
        let vendor = target_clone.vendor.as_deref().unwrap_or(&target_clone.product);
        let pattern = format!("cpe:2.3:%:{}:{}:%", vendor, target_clone.product);

        // Query CPE matches
        #[allow(clippy::type_complexity)]
        let rows: Vec<(String, Option<String>, Option<String>, Option<f64>, Option<String>, Option<String>, Option<String>, String, Option<String>, Option<String>, Option<String>, Option<String>)> = conn
            .prepare(
                "SELECT c.cve_id, c.published_at, c.last_modified_at,
                 c.cvss_score, c.cvss_severity, c.description, c.nvd_url,
                 cp.cpe_string, cp.version_start_including, cp.version_start_excluding,
                 cp.version_end_including, cp.version_end_excluding
                 FROM nvd_cves c
                 JOIN nvd_cve_cpes cp ON c.cve_id = cp.cve_id
                 WHERE cp.cpe_string LIKE ?1",
            )?
            .query_map(rusqlite::params![pattern], |row| {
                Ok((
                    row.get(0)?,  row.get(1)?,  row.get(2)?,
                    row.get(3)?,  row.get(4)?,  row.get(5)?,  row.get(6)?,
                    row.get(7)?,  row.get(8)?,  row.get(9)?,
                    row.get(10)?, row.get(11)?,
                ))
            })?
            .collect::<rusqlite::Result<_>>()?;

        // Version filter + deduplicate by CVE ID
        let mut cve_map: HashMap<String, MatchedCve> = HashMap::new();
        for (cve_id, pub_at, mod_at, cvss, severity, desc, url, cpe_str, vsi, vse, vei, vee) in rows {
            if cve_map.contains_key(&cve_id) { continue; }
            if let Some(ref v) = target_clone.version {
                if !cpe_covers_version(&cpe_str, vsi.as_deref(), vse.as_deref(), vei.as_deref(), vee.as_deref(), v) {
                    continue;
                }
            }
            cve_map.insert(cve_id.clone(), MatchedCve {
                cve_id, published_at: pub_at, last_modified_at: mod_at,
                cvss_score: cvss, cvss_severity: severity, description: desc, nvd_url: url,
            });
        }
        let matches: Vec<MatchedCve> = cve_map.into_values().collect();

        // Prune stale findings
        let matched_ids: std::collections::HashSet<&str> =
            matches.iter().map(|m| m.cve_id.as_str()).collect();
        let existing_ids: Vec<String> = conn
            .prepare("SELECT cve_id FROM cve_findings WHERE target_id = ?1")?
            .query_map(rusqlite::params![target_clone.id], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        for cve_id in &existing_ids {
            if !matched_ids.contains(cve_id.as_str()) {
                conn.execute(
                    "DELETE FROM cve_findings WHERE target_id = ?1 AND cve_id = ?2",
                    rusqlite::params![target_clone.id, cve_id],
                )?;
            }
        }

        let mut new_findings: Vec<&MatchedCve> = Vec::new();

        for cve in &matches {
            use rusqlite::OptionalExtension;
            let existing: Option<(i64, Option<f64>)> = conn
                .query_row(
                    "SELECT id, cvss_score FROM cve_findings WHERE target_id = ?1 AND cve_id = ?2",
                    rusqlite::params![target_clone.id, cve.cve_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;

            if let Some((_id, existing_score)) = existing {
                // Backfill CVSS if missing
                if existing_score.is_none() && cve.cvss_score.is_some() {
                    conn.execute(
                        "UPDATE cve_findings
                         SET cvss_score = ?1, cvss_severity = ?2,
                             description = COALESCE(description, ?3),
                             nvd_url = COALESCE(nvd_url, ?4),
                             published_at = COALESCE(published_at, ?5),
                             last_modified_at = COALESCE(last_modified_at, ?6)
                         WHERE target_id = ?7 AND cve_id = ?8",
                        rusqlite::params![
                            cve.cvss_score, cve.cvss_severity, cve.description,
                            cve.nvd_url, cve.published_at, cve.last_modified_at,
                            target_clone.id, cve.cve_id,
                        ],
                    )?;
                    if !is_first_check { new_findings.push(cve); }
                }
                continue;
            }

            // Insert new finding
            conn.execute(
                "INSERT INTO cve_findings
                 (target_id, cve_id, published_at, last_modified_at, cvss_score,
                  cvss_severity, description, nvd_url, alerted)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                rusqlite::params![
                    target_clone.id,
                    cve.cve_id,
                    cve.published_at,
                    cve.last_modified_at,
                    cve.cvss_score,
                    cve.cvss_severity,
                    cve.description,
                    cve.nvd_url,
                    if is_first_check { 1i64 } else { 0i64 },
                ],
            )?;

            if !is_first_check {
                new_findings.push(cve);
            }
        }

        // Filter to alertable findings
        let to_alert: Vec<&MatchedCve> = new_findings
            .iter()
            .copied()
            .filter(|c| {
                c.cvss_score
                    .map(|s| s >= target_clone.min_alert_cvss_score)
                    .unwrap_or(false)
            })
            .collect();

        let now = chrono::Utc::now().to_rfc3339();
        let status = if is_first_check {
            format!("seeded {} existing CVEs", matches.len())
        } else {
            format!("found {} new ({} alerted)", new_findings.len(), to_alert.len())
        };
        tracing::info!(
            target = %target_clone.name,
            product = %target_clone.product,
            status,
            "[cve-engine] Evaluation complete"
        );

        if to_alert.is_empty() {
            conn.execute(
                "UPDATE cve_targets SET last_checked_at = ?1 WHERE id = ?2",
                rusqlite::params![now, target_clone.id],
            )?;
            return Ok(None);
        }

        // Sort by CVSS descending
        let mut sorted: Vec<&MatchedCve> = to_alert.clone();
        sorted.sort_by(|a, b| {
            b.cvss_score
                .partial_cmp(&a.cvss_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let top = sorted[0];

        let message = if sorted.len() == 1 {
            let score = top.cvss_score.map(|s| format!("{:.1}", s)).unwrap_or_else(|| "N/A".into());
            let severity = top.cvss_severity.as_deref().unwrap_or("UNKNOWN");
            let desc_suffix = top.description.as_ref().map(|d| {
                let snippet = &d[..d.len().min(200)];
                format!(" — {}{}",  snippet, if d.len() > 200 { "…" } else { "" })
            }).unwrap_or_default();
            format!(
                "New CVE for {}: {} (CVSS {} {}){}",
                target_clone.name, top.cve_id, score, severity, desc_suffix
            )
        } else {
            let score = top.cvss_score.map(|s| format!("{:.1}", s)).unwrap_or_else(|| "N/A".into());
            let severity = top.cvss_severity.as_deref().unwrap_or("UNKNOWN");
            format!(
                "{} new CVEs found for {} (top: {}, CVSS {} {})",
                sorted.len(), target_clone.name, top.cve_id, score, severity
            )
        };

        let cve_digest = if sorted.len() > 1 {
            Some(sorted.iter().map(|c| CveDigestItem {
                cve_id: c.cve_id.clone(),
                cvss_score: c.cvss_score,
                cvss_severity: c.cvss_severity.clone(),
            }).collect())
        } else {
            None
        };

        let payload = AlertPayload {
            server_name: target_clone.name.clone(),
            url: top.nvd_url.clone().unwrap_or_else(|| {
                format!("https://nvd.nist.gov/vuln/detail/{}", top.cve_id)
            }),
            alert_type: AlertType::CveNew,
            status_code: None,
            response_time_ms: None,
            threshold: None,
            diff_id: None,
            diff_view_url: Some(format!("{}/cve/{}", "PLACEHOLDER_BASE_URL", target_clone.id)),
            detected_at: now.clone(),
            message,
            ssl_days_remaining: None,
            ssl_fingerprint: None,
            ssl_subject: None,
            cve_id: Some(top.cve_id.clone()),
            cvss_score: top.cvss_score,
            cvss_severity: top.cvss_severity.clone(),
            cve_digest,
            previous_exploitation: None,
            changed_fields: None,
        };

        // Mark as alerted
        let fp = build_enrichment_fingerprint(top.cvss_score, top.cvss_severity.as_deref());
        for cve in &to_alert {
            conn.execute(
                "UPDATE cve_findings SET alerted = 1, enrichment_fingerprint = ?1
                 WHERE target_id = ?2 AND cve_id = ?3",
                rusqlite::params![fp, target_clone.id, cve.cve_id],
            )?;
        }

        conn.execute(
            "UPDATE cve_targets SET last_checked_at = ?1, last_alerted_at = ?1 WHERE id = ?2",
            rusqlite::params![now, target_clone.id],
        )?;

        Ok(Some(payload))
    })
    .await;

    match result {
        Ok(Ok(Some(mut payload))) => {
            // Replace placeholder with real base_url
            if let Some(ref mut url) = payload.diff_view_url {
                *url = url.replace("PLACEHOLDER_BASE_URL", &config.base_url);
            }
            notifiers::send_alert(db.clone(), config.clone(), payload).await;
        }
        Ok(Ok(None)) => {}
        Ok(Err(e)) => tracing::error!("[cve-engine] Evaluation error: {}", e),
        Err(e) => tracing::error!("[cve-engine] Spawn blocking error: {}", e),
    }
}

fn build_enrichment_fingerprint(cvss_score: Option<f64>, cvss_severity: Option<&str>) -> String {
    format!(
        "{}|{}|0|||",
        cvss_score.map(|s| s.to_string()).unwrap_or_default(),
        cvss_severity.unwrap_or("")
    )
}

fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let ap: Vec<u32> = a.split('.').map(|s| s.parse().unwrap_or(0)).collect();
    let bp: Vec<u32> = b.split('.').map(|s| s.parse().unwrap_or(0)).collect();
    let len = ap.len().max(bp.len());
    for i in 0..len {
        let av = ap.get(i).copied().unwrap_or(0);
        let bv = bp.get(i).copied().unwrap_or(0);
        let ord = av.cmp(&bv);
        if ord != std::cmp::Ordering::Equal {
            return ord;
        }
    }
    std::cmp::Ordering::Equal
}

fn cpe_covers_version(
    cpe_string: &str,
    vsi: Option<&str>,
    vse: Option<&str>,
    vei: Option<&str>,
    vee: Option<&str>,
    target_version: &str,
) -> bool {
    let cpe_version = cpe_string.split(':').nth(5).unwrap_or("*");
    if cpe_version != "*" && cpe_version != "-" {
        return cpe_version == target_version;
    }
    if let Some(v) = vsi {
        if compare_versions(target_version, v) == std::cmp::Ordering::Less {
            return false;
        }
    }
    if let Some(v) = vse {
        if compare_versions(target_version, v) != std::cmp::Ordering::Greater {
            return false;
        }
    }
    if let Some(v) = vei {
        if compare_versions(target_version, v) == std::cmp::Ordering::Greater {
            return false;
        }
    }
    if let Some(v) = vee {
        if compare_versions(target_version, v) != std::cmp::Ordering::Less {
            return false;
        }
    }
    true
}
