use std::collections::HashMap;
use std::sync::Arc;

use crate::{config::Config, db::DbPool, notifiers, types::{AlertPayload, AlertType, CveDigestItem}};

pub async fn check_enrichment_alerts(db: &DbPool, config: &Arc<Config>) {
    if let Err(e) = check_exploitation_escalations(db, config).await {
        tracing::error!("[enrichment-alerter] exploitation escalation check failed: {}", e);
    }
    if let Err(e) = check_enrichment_updates(db, config).await {
        tracing::error!("[enrichment-alerter] enrichment update check failed: {}", e);
    }
    if let Err(e) = check_rejections(db, config).await {
        tracing::error!("[enrichment-alerter] rejection check failed: {}", e);
    }
}

// ---------------------------------------------------------------------------
// Shared finding row type
// ---------------------------------------------------------------------------

struct FindingRow {
    id: i64,
    target_id: i64,
    cve_id: String,
    cvss_score: Option<f64>,
    cvss_severity: Option<String>,
    nvd_url: Option<String>,
    enrichment_fingerprint: Option<String>,
    exploitation_alert_sent: Option<String>,
    target_name: String,
    _min_alert_cvss_score: f64,
    is_kev: i64,
    ssvc_exploitation: Option<String>,
    ssvc_automatable: Option<String>,
    ssvc_technical_impact: Option<String>,
}

// ---------------------------------------------------------------------------
// Check A: exploitation escalated to 'active'
// ---------------------------------------------------------------------------

async fn check_exploitation_escalations(db: &DbPool, config: &Arc<Config>) -> anyhow::Result<()> {
    let db_clone = db.clone();
    let rows: Vec<FindingRow> = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<FindingRow>> {
        let conn = db_clone.lock().unwrap();
        let rows = conn.prepare(
            "SELECT f.id, f.target_id, f.cve_id, f.cvss_score, f.cvss_severity,
             f.nvd_url, f.enrichment_fingerprint, f.exploitation_alert_sent,
             t.name, t.min_alert_cvss_score,
             CASE WHEN k.cve_id IS NOT NULL THEN 1 ELSE 0 END,
             s.exploitation, s.automatable, s.technical_impact
             FROM cve_findings f
             JOIN cve_targets t ON f.target_id = t.id AND t.active = 1
             JOIN cisa_ssvc s ON f.cve_id = s.cve_id
             LEFT JOIN cisa_kev k ON f.cve_id = k.cve_id
             WHERE s.exploitation = 'active'
               AND (f.exploitation_alert_sent IS NULL OR f.exploitation_alert_sent != 'active')",
        )?.query_map([], |row| Ok(FindingRow {
            id: row.get(0)?, target_id: row.get(1)?, cve_id: row.get(2)?,
            cvss_score: row.get(3)?, cvss_severity: row.get(4)?, nvd_url: row.get(5)?,
            enrichment_fingerprint: row.get(6)?, exploitation_alert_sent: row.get(7)?,
            target_name: row.get(8)?, _min_alert_cvss_score: row.get(9)?,
            is_kev: row.get(10).unwrap_or(0), ssvc_exploitation: row.get(11)?,
            ssvc_automatable: row.get(12)?, ssvc_technical_impact: row.get(13)?,
        }))?.collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }).await??;

    if rows.is_empty() { return Ok(()); }

    let mut by_target: HashMap<i64, Vec<usize>> = HashMap::new();
    for (i, f) in rows.iter().enumerate() {
        by_target.entry(f.target_id).or_default().push(i);
    }

    for (_, indices) in by_target {
        let group: Vec<&FindingRow> = indices.iter().map(|&i| &rows[i]).collect();
        let mut sorted = group.clone();
        sorted.sort_by(|a, b| b.cvss_score.partial_cmp(&a.cvss_score).unwrap_or(std::cmp::Ordering::Equal));
        let top = sorted[0];

        let message = if sorted.len() == 1 {
            let score_str = top.cvss_score.map(|s| format!(" (CVSS {:.1} {})", s, top.cvss_severity.as_deref().unwrap_or(""))).unwrap_or_default();
            let auto_str = if top.ssvc_automatable.as_deref() == Some("yes") { " | Automatable: yes" } else { "" };
            let impact_str = if top.ssvc_technical_impact.as_deref() == Some("total") { " | Total impact" } else { "" };
            format!("Exploitation escalated to ACTIVE for {}: {}{}{}{}", top.target_name, top.cve_id, score_str, auto_str, impact_str)
        } else {
            let score_str = top.cvss_score.map(|s| format!(", CVSS {:.1}", s)).unwrap_or_default();
            format!("{} CVEs now actively exploited for {} (top: {}{})", sorted.len(), top.target_name, top.cve_id, score_str)
        };

        let cve_digest = if sorted.len() > 1 {
            Some(sorted.iter().map(|f| CveDigestItem {
                cve_id: f.cve_id.clone(), cvss_score: f.cvss_score, cvss_severity: f.cvss_severity.clone(),
            }).collect())
        } else { None };

        let payload = AlertPayload {
            server_name: top.target_name.clone(),
            url: top.nvd_url.clone().unwrap_or_else(|| format!("https://nvd.nist.gov/vuln/detail/{}", top.cve_id)),
            alert_type: AlertType::CveExploitEscalation,
            status_code: None, response_time_ms: None, threshold: None, diff_id: None,
            diff_view_url: Some(format!("{}/cve/{}", config.base_url, top.target_id)),
            detected_at: chrono::Utc::now().to_rfc3339(), message,
            ssl_days_remaining: None, ssl_fingerprint: None, ssl_subject: None,
            cve_id: Some(top.cve_id.clone()), cvss_score: top.cvss_score,
            cvss_severity: top.cvss_severity.clone(), cve_digest,
            previous_exploitation: top.exploitation_alert_sent.clone().or(Some("none".into())),
            changed_fields: None,
        };

        notifiers::send_alert(db.clone(), config.clone(), payload).await;

        let ids: Vec<i64> = sorted.iter().map(|f| f.id).collect();
        let db_clone = db.clone();
        tokio::task::spawn_blocking(move || {
            let conn = db_clone.lock().unwrap();
            for id in ids {
                let _ = conn.execute(
                    "UPDATE cve_findings SET exploitation_alert_sent = 'active' WHERE id = ?1",
                    rusqlite::params![id],
                );
            }
        }).await.ok();
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Check B: enrichment data changed since last alert
// ---------------------------------------------------------------------------

async fn check_enrichment_updates(db: &DbPool, config: &Arc<Config>) -> anyhow::Result<()> {
    let db_clone = db.clone();
    let rows: Vec<FindingRow> = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<FindingRow>> {
        let conn = db_clone.lock().unwrap();
        let rows = conn.prepare(
            "SELECT f.id, f.target_id, f.cve_id, f.cvss_score, f.cvss_severity,
             f.nvd_url, f.enrichment_fingerprint, f.exploitation_alert_sent,
             t.name, t.min_alert_cvss_score,
             CASE WHEN k.cve_id IS NOT NULL THEN 1 ELSE 0 END,
             s.exploitation, s.automatable, s.technical_impact
             FROM cve_findings f
             JOIN cve_targets t ON f.target_id = t.id AND t.active = 1
             LEFT JOIN cisa_kev k ON f.cve_id = k.cve_id
             LEFT JOIN cisa_ssvc s ON f.cve_id = s.cve_id
             WHERE f.alerted = 1 AND f.cvss_score IS NOT NULL
               AND f.cvss_score >= t.min_alert_cvss_score",
        )?.query_map([], |row| Ok(FindingRow {
            id: row.get(0)?, target_id: row.get(1)?, cve_id: row.get(2)?,
            cvss_score: row.get(3)?, cvss_severity: row.get(4)?, nvd_url: row.get(5)?,
            enrichment_fingerprint: row.get(6)?, exploitation_alert_sent: row.get(7)?,
            target_name: row.get(8)?, _min_alert_cvss_score: row.get(9)?,
            is_kev: row.get(10).unwrap_or(0), ssvc_exploitation: row.get(11)?,
            ssvc_automatable: row.get(12)?, ssvc_technical_impact: row.get(13)?,
        }))?.collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }).await??;

    // Compute which findings changed
    struct Changed { idx: usize, new_fp: String, changed_fields: Vec<String> }
    let mut changed_list: Vec<Changed> = Vec::new();
    for (i, f) in rows.iter().enumerate() {
        let new_fp = build_fingerprint(f);
        let Some(ref old_fp) = f.enrichment_fingerprint else { continue };
        if old_fp == &new_fp { continue; }
        let cf = detect_changed_fields(old_fp, &new_fp);
        if !cf.is_empty() { changed_list.push(Changed { idx: i, new_fp, changed_fields: cf }); }
    }
    if changed_list.is_empty() { return Ok(()); }

    let mut by_target: HashMap<i64, Vec<usize>> = HashMap::new();
    for (ci, c) in changed_list.iter().enumerate() {
        by_target.entry(rows[c.idx].target_id).or_default().push(ci);
    }

    for (_, ch_indices) in by_target {
        let mut sorted: Vec<&Changed> = ch_indices.iter().map(|&i| &changed_list[i]).collect();
        sorted.sort_by(|a, b| {
            rows[b.idx].cvss_score.partial_cmp(&rows[a.idx].cvss_score).unwrap_or(std::cmp::Ordering::Equal)
        });
        let top_c = sorted[0];
        let top = &rows[top_c.idx];

        let all_changed: Vec<String> = {
            let mut seen = std::collections::HashSet::new();
            sorted.iter().flat_map(|c| c.changed_fields.iter().cloned()).filter(|f| seen.insert(f.clone())).collect()
        };

        let message = if sorted.len() == 1 {
            format!("CVE updated for {}: {} — {}", top.target_name, top.cve_id, describe_fields(&top_c.changed_fields))
        } else {
            format!("{} CVEs updated for {}: {}", sorted.len(), top.target_name, describe_fields(&all_changed))
        };

        let cve_digest = if sorted.len() > 1 {
            Some(sorted.iter().map(|c| { let f = &rows[c.idx]; CveDigestItem { cve_id: f.cve_id.clone(), cvss_score: f.cvss_score, cvss_severity: f.cvss_severity.clone() } }).collect())
        } else { None };

        let payload = AlertPayload {
            server_name: top.target_name.clone(),
            url: top.nvd_url.clone().unwrap_or_else(|| format!("https://nvd.nist.gov/vuln/detail/{}", top.cve_id)),
            alert_type: AlertType::CveUpdated,
            status_code: None, response_time_ms: None, threshold: None, diff_id: None,
            diff_view_url: Some(format!("{}/cve/{}", config.base_url, top.target_id)),
            detected_at: chrono::Utc::now().to_rfc3339(), message,
            ssl_days_remaining: None, ssl_fingerprint: None, ssl_subject: None,
            cve_id: Some(top.cve_id.clone()), cvss_score: top.cvss_score,
            cvss_severity: top.cvss_severity.clone(), cve_digest,
            previous_exploitation: None, changed_fields: Some(all_changed),
        };

        notifiers::send_alert(db.clone(), config.clone(), payload).await;

        let updates: Vec<(i64, String)> = sorted.iter().map(|c| (rows[c.idx].id, c.new_fp.clone())).collect();
        let db_clone = db.clone();
        tokio::task::spawn_blocking(move || {
            let conn = db_clone.lock().unwrap();
            for (id, fp) in updates {
                let _ = conn.execute(
                    "UPDATE cve_findings SET enrichment_fingerprint = ?1 WHERE id = ?2",
                    rusqlite::params![fp, id],
                );
            }
        }).await.ok();
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Check C: CVE rejected by MITRE
// ---------------------------------------------------------------------------

async fn check_rejections(db: &DbPool, config: &Arc<Config>) -> anyhow::Result<()> {
    struct RejRow { id: i64, target_id: i64, cve_id: String, cvss_score: Option<f64>, cvss_severity: Option<String>, nvd_url: Option<String>, target_name: String }

    let db_clone = db.clone();
    let rows: Vec<RejRow> = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<RejRow>> {
        let conn = db_clone.lock().unwrap();
        let rows = conn.prepare(
            "SELECT f.id, f.target_id, f.cve_id, f.cvss_score, f.cvss_severity,
             f.nvd_url, t.name
             FROM cve_findings f
             JOIN cve_targets t ON f.target_id = t.id AND t.active = 1
             JOIN cvelist_cves cl ON f.cve_id = cl.cve_id
             WHERE cl.state = 'REJECTED' AND f.alerted = 1
               AND (f.rejection_alert_sent IS NULL OR f.rejection_alert_sent != 1)",
        )?.query_map([], |row| Ok(RejRow {
            id: row.get(0)?, target_id: row.get(1)?, cve_id: row.get(2)?,
            cvss_score: row.get(3)?, cvss_severity: row.get(4)?,
            nvd_url: row.get(5)?, target_name: row.get(6)?,
        }))?.collect::<rusqlite::Result<Vec<RejRow>>>()?;
        Ok(rows)
    }).await??;

    if rows.is_empty() { return Ok(()); }

    let mut by_target: HashMap<i64, Vec<usize>> = HashMap::new();
    for (i, f) in rows.iter().enumerate() { by_target.entry(f.target_id).or_default().push(i); }

    for (_, indices) in by_target {
        let mut group: Vec<&RejRow> = indices.iter().map(|&i| &rows[i]).collect();
        group.sort_by(|a, b| b.cvss_score.partial_cmp(&a.cvss_score).unwrap_or(std::cmp::Ordering::Equal));
        let top = group[0];

        let message = if group.len() == 1 {
            format!("CVE rejected by MITRE for {}: {} has been officially REJECTED and is no longer valid", top.target_name, top.cve_id)
        } else {
            format!("{} CVEs rejected by MITRE for {}: {}", group.len(), top.target_name, group.iter().map(|f| f.cve_id.as_str()).collect::<Vec<_>>().join(", "))
        };

        let cve_digest = if group.len() > 1 {
            Some(group.iter().map(|f| CveDigestItem { cve_id: f.cve_id.clone(), cvss_score: f.cvss_score, cvss_severity: f.cvss_severity.clone() }).collect())
        } else { None };

        let payload = AlertPayload {
            server_name: top.target_name.clone(),
            url: top.nvd_url.clone().unwrap_or_else(|| format!("https://www.cve.org/CVERecord?id={}", top.cve_id)),
            alert_type: AlertType::CveRejected,
            status_code: None, response_time_ms: None, threshold: None, diff_id: None,
            diff_view_url: Some(format!("{}/cve/{}", config.base_url, top.target_id)),
            detected_at: chrono::Utc::now().to_rfc3339(), message,
            ssl_days_remaining: None, ssl_fingerprint: None, ssl_subject: None,
            cve_id: Some(top.cve_id.clone()), cvss_score: top.cvss_score,
            cvss_severity: top.cvss_severity.clone(), cve_digest,
            previous_exploitation: None, changed_fields: None,
        };

        notifiers::send_alert(db.clone(), config.clone(), payload).await;

        let ids: Vec<i64> = group.iter().map(|f| f.id).collect();
        let db_clone = db.clone();
        tokio::task::spawn_blocking(move || {
            let conn = db_clone.lock().unwrap();
            for id in ids {
                let _ = conn.execute("UPDATE cve_findings SET rejection_alert_sent = 1 WHERE id = ?1", rusqlite::params![id]);
            }
        }).await.ok();
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Fingerprint helpers
// ---------------------------------------------------------------------------

fn build_fingerprint(f: &FindingRow) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}",
        f.cvss_score.map(|s| s.to_string()).unwrap_or_default(),
        f.cvss_severity.as_deref().unwrap_or(""),
        f.is_kev,
        f.ssvc_exploitation.as_deref().unwrap_or(""),
        f.ssvc_automatable.as_deref().unwrap_or(""),
        f.ssvc_technical_impact.as_deref().unwrap_or(""),
    )
}

fn detect_changed_fields(old_fp: &str, new_fp: &str) -> Vec<String> {
    let o: Vec<&str> = old_fp.splitn(6, '|').collect();
    let n: Vec<&str> = new_fp.splitn(6, '|').collect();
    fn get<'a>(v: &'a [&'a str], i: usize) -> &'a str { v.get(i).copied().unwrap_or("") }
    let mut changed = Vec::new();
    if get(&o, 0) != get(&n, 0) || get(&o, 1) != get(&n, 1) { changed.push("cvss_score".into()); }
    if get(&o, 2) != get(&n, 2) { changed.push("is_kev".into()); }
    if get(&o, 3) != get(&n, 3) { changed.push("ssvc_exploitation".into()); }
    if get(&o, 4) != get(&n, 4) { changed.push("ssvc_automatable".into()); }
    if get(&o, 5) != get(&n, 5) { changed.push("ssvc_technical_impact".into()); }
    changed
}

fn describe_fields(fields: &[String]) -> String {
    fields.iter().map(|f| match f.as_str() {
        "cvss_score" => "CVSS score updated",
        "is_kev" => "added to CISA KEV",
        "ssvc_exploitation" => "exploitation status changed",
        "ssvc_automatable" => "automatable status changed",
        "ssvc_technical_impact" => "technical impact changed",
        other => other,
    }).collect::<Vec<_>>().join(", ")
}
