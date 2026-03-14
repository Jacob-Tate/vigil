use std::io::Read as _;
use std::sync::Arc;

use flate2::read::GzDecoder;
use rusqlite::OptionalExtension;
use serde::Deserialize;
use tokio::sync::RwLock;

use crate::{db::DbPool, types::NvdSyncStatus};

const FEED_BASE: &str = "https://nvd.nist.gov/feeds/json/cve/2.0";
const BATCH_SIZE: usize = 2_000;

pub const ALL_FEED_NAMES: &[&str] = &[
    "modified", "recent",
    "2002", "2003", "2004", "2005", "2006", "2007", "2008", "2009",
    "2010", "2011", "2012", "2013", "2014", "2015", "2016", "2017",
    "2018", "2019", "2020", "2021", "2022", "2023", "2024", "2025", "2026",
];

// ---------------------------------------------------------------------------
// Serde structures for NVD JSON 2.0 feed format
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct NvdFeed {
    vulnerabilities: Vec<NvdVulnWrapper>,
}

#[derive(Deserialize)]
struct NvdVulnWrapper {
    cve: NvdCveEntry,
}

#[derive(Deserialize)]
struct NvdCveEntry {
    id: String,
    published: Option<String>,
    #[serde(rename = "lastModified")]
    last_modified: Option<String>,
    descriptions: Option<Vec<NvdDescription>>,
    metrics: Option<NvdMetrics>,
    configurations: Option<Vec<NvdConfiguration>>,
    references: Option<Vec<NvdReference>>,
}

#[derive(Deserialize)]
struct NvdDescription {
    lang: String,
    value: String,
}

#[derive(Deserialize)]
struct NvdMetrics {
    #[serde(rename = "cvssMetricV31")]
    cvss_v31: Option<Vec<NvdCvssMetric>>,
    #[serde(rename = "cvssMetricV30")]
    cvss_v30: Option<Vec<NvdCvssMetric>>,
    #[serde(rename = "cvssMetricV2")]
    cvss_v2: Option<Vec<NvdCvssMetric>>,
}

#[derive(Deserialize)]
struct NvdCvssMetric {
    #[serde(rename = "type")]
    metric_type: Option<String>,
    #[serde(rename = "cvssData")]
    cvss_data: Option<NvdCvssData>,
}

#[derive(Deserialize)]
struct NvdCvssData {
    #[serde(rename = "baseScore")]
    base_score: Option<f64>,
    #[serde(rename = "baseSeverity")]
    base_severity: Option<String>,
}

#[derive(Deserialize)]
struct NvdConfiguration {
    nodes: Option<Vec<NvdNode>>,
}

#[derive(Deserialize)]
struct NvdNode {
    #[serde(rename = "cpeMatch")]
    cpe_match: Option<Vec<NvdCpeMatch>>,
    nodes: Option<Vec<NvdNode>>,
}

#[derive(Deserialize)]
struct NvdCpeMatch {
    vulnerable: Option<bool>,
    criteria: Option<String>,
    #[serde(rename = "versionStartIncluding")]
    version_start_including: Option<String>,
    #[serde(rename = "versionStartExcluding")]
    version_start_excluding: Option<String>,
    #[serde(rename = "versionEndIncluding")]
    version_end_including: Option<String>,
    #[serde(rename = "versionEndExcluding")]
    version_end_excluding: Option<String>,
}

#[derive(Deserialize)]
struct NvdReference {
    url: String,
    source: Option<String>,
    tags: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// Internal row types
// ---------------------------------------------------------------------------

struct CveRow {
    cve_id: String,
    published_at: String,
    last_modified_at: String,
    cvss_score: Option<f64>,
    cvss_severity: Option<String>,
    description: Option<String>,
    nvd_url: String,
    references_json: Option<String>,
    cpes: Vec<CpeRow>,
}

struct CpeRow {
    criteria: String,
    vsi: Option<String>,
    vse: Option<String>,
    vei: Option<String>,
    vee: Option<String>,
}

pub struct FeedMeta {
    pub last_modified_date: String,
    pub sha256: String,
}

// ---------------------------------------------------------------------------
// Meta fetch
// ---------------------------------------------------------------------------

pub async fn check_meta(feed_name: &str) -> anyhow::Result<FeedMeta> {
    let url = format!("{}/nvdcve-2.0-{}.meta", FEED_BASE, feed_name);
    let text = reqwest::Client::new()
        .get(&url)
        .header("User-Agent", "monitor-app/1.0")
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;

    parse_meta(&text)
}

fn parse_meta(text: &str) -> anyhow::Result<FeedMeta> {
    let mut last_modified_date = String::new();
    let mut sha256 = String::new();
    for line in text.trim().lines() {
        if let Some(pos) = line.find(':') {
            let key = line[..pos].trim();
            let val = line[pos + 1..].trim();
            match key {
                "lastModifiedDate" => last_modified_date = val.to_string(),
                "sha256" => sha256 = val.to_string(),
                _ => {}
            }
        }
    }
    Ok(FeedMeta { last_modified_date, sha256 })
}

/// Returns true if the feed's remote SHA-256 differs from what we last imported.
pub async fn needs_update(db: &DbPool, feed_name: &str) -> anyhow::Result<bool> {
    let meta = check_meta(feed_name).await?;
    let feed_name = feed_name.to_string();
    let db = db.clone();
    let stored_sha: Option<String> = tokio::task::spawn_blocking(move || {
        let conn = db.lock().unwrap();
        conn.query_row(
            "SELECT sha256 FROM nvd_feed_state WHERE feed_name = ?1",
            rusqlite::params![feed_name],
            |row| row.get(0),
        )
        .optional()
    })
    .await??;
    Ok(stored_sha
        .map(|s| s.to_uppercase() != meta.sha256.to_uppercase())
        .unwrap_or(true))
}

// ---------------------------------------------------------------------------
// Feed import
// ---------------------------------------------------------------------------

/// Download, decompress, parse, and batch-upsert a single NVD feed file.
/// Returns the number of CVE records inserted/replaced.
pub async fn import_feed(
    db: &DbPool,
    feed_name: &str,
    status: Option<Arc<RwLock<NvdSyncStatus>>>,
) -> anyhow::Result<usize> {
    let meta = check_meta(feed_name).await?;
    let url = format!("{}/nvdcve-2.0-{}.json.gz", FEED_BASE, feed_name);

    tracing::info!(feed = feed_name, "Downloading NVD feed");

    let gz_bytes = reqwest::Client::new()
        .get(&url)
        .header("User-Agent", "monitor-app/1.0")
        .timeout(std::time::Duration::from_secs(600))
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    let feed_name_owned = feed_name.to_string();
    let db_clone = db.clone();
    let meta_lmd = meta.last_modified_date.clone();
    let meta_sha = meta.sha256.clone();

    let count = tokio::task::spawn_blocking(move || -> anyhow::Result<usize> {
        // Decompress
        let mut decoder = GzDecoder::new(gz_bytes.as_ref());
        let mut json_bytes = Vec::with_capacity(gz_bytes.len() * 5);
        decoder.read_to_end(&mut json_bytes)?;

        // Parse
        let feed: NvdFeed = serde_json::from_slice(&json_bytes)?;
        let vulns = feed.vulnerabilities;
        let total = vulns.len();

        tracing::info!(feed = feed_name_owned, total, "Parsed NVD feed — starting upsert");

        // Extract rows
        let rows: Vec<CveRow> = vulns.into_iter().map(|v| extract_row(v.cve)).collect();

        // Batch upsert
        let conn = db_clone.lock().unwrap();
        let mut processed = 0usize;

        for chunk in rows.chunks(BATCH_SIZE) {
            conn.execute_batch("BEGIN IMMEDIATE")?;
            let result: rusqlite::Result<()> = (|| {
                let mut stmt_cve = conn.prepare_cached(
                    "INSERT OR REPLACE INTO nvd_cves
                     (cve_id, published_at, last_modified_at, cvss_score, cvss_severity,
                      description, nvd_url, references_json)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                )?;
                let mut stmt_cpe = conn.prepare_cached(
                    "INSERT OR IGNORE INTO nvd_cve_cpes
                     (cve_id, cpe_string, version_start_including, version_start_excluding,
                      version_end_including, version_end_excluding)
                     VALUES (?1,?2,?3,?4,?5,?6)",
                )?;
                for row in chunk {
                    stmt_cve.execute(rusqlite::params![
                        row.cve_id,
                        row.published_at,
                        row.last_modified_at,
                        row.cvss_score,
                        row.cvss_severity,
                        row.description,
                        row.nvd_url,
                        row.references_json,
                    ])?;
                    for cpe in &row.cpes {
                        stmt_cpe.execute(rusqlite::params![
                            row.cve_id,
                            cpe.criteria,
                            cpe.vsi,
                            cpe.vse,
                            cpe.vei,
                            cpe.vee,
                        ])?;
                    }
                }
                Ok(())
            })();
            match result {
                Ok(()) => conn.execute_batch("COMMIT")?,
                Err(e) => {
                    conn.execute_batch("ROLLBACK")?;
                    return Err(e.into());
                }
            }
            processed += chunk.len();
        }

        // Update feed state
        conn.execute(
            "INSERT OR REPLACE INTO nvd_feed_state
             (feed_name, last_modified_date, sha256, total_cves, imported_at)
             VALUES (?1,?2,?3,?4,?5)",
            rusqlite::params![
                feed_name_owned,
                meta_lmd,
                meta_sha,
                total as i64,
                chrono::Utc::now().to_rfc3339(),
            ],
        )?;

        Ok(processed)
    })
    .await??;

    // Update in-progress status
    if let Some(s) = status {
        let mut w = s.write().await;
        w.feeds_done += 1;
        w.current_feed = Some(feed_name.to_string());
    }

    tracing::info!(feed = feed_name, count, "NVD feed import complete");
    Ok(count)
}

// ---------------------------------------------------------------------------
// CVE data extraction
// ---------------------------------------------------------------------------

fn extract_row(cve: NvdCveEntry) -> CveRow {
    let description = cve
        .descriptions
        .as_deref()
        .and_then(|ds| ds.iter().find(|d| d.lang == "en"))
        .map(|d| d.value.clone());

    let (cvss_score, cvss_severity) = extract_cvss(cve.metrics.as_ref());

    let mut cpes: Vec<CpeRow> = Vec::new();
    if let Some(configs) = cve.configurations {
        for config in configs {
            if let Some(nodes) = config.nodes {
                extract_cpes(&nodes, &mut cpes);
            }
        }
    }
    // Deduplicate CPEs by full key
    let mut seen = std::collections::HashSet::new();
    cpes.retain(|c| {
        let key = format!(
            "{}|{}|{}|{}|{}",
            c.criteria,
            c.vsi.as_deref().unwrap_or(""),
            c.vse.as_deref().unwrap_or(""),
            c.vei.as_deref().unwrap_or(""),
            c.vee.as_deref().unwrap_or(""),
        );
        seen.insert(key)
    });

    let refs_json = cve.references.as_ref().filter(|r| !r.is_empty()).map(|refs| {
        let serializable: Vec<serde_json::Value> = refs
            .iter()
            .map(|r| {
                serde_json::json!({
                    "url": r.url,
                    "source": r.source,
                    "tags": r.tags,
                })
            })
            .collect();
        serde_json::to_string(&serializable).unwrap_or_default()
    });

    CveRow {
        nvd_url: format!("https://nvd.nist.gov/vuln/detail/{}", cve.id),
        cve_id: cve.id,
        published_at: cve.published.unwrap_or_default(),
        last_modified_at: cve.last_modified.unwrap_or_default(),
        cvss_score,
        cvss_severity,
        description,
        references_json: refs_json,
        cpes,
    }
}

fn extract_cvss(metrics: Option<&NvdMetrics>) -> (Option<f64>, Option<String>) {
    let Some(m) = metrics else { return (None, None) };
    for metric_set in [m.cvss_v31.as_deref(), m.cvss_v30.as_deref(), m.cvss_v2.as_deref()]
        .into_iter()
        .flatten()
    {
        if metric_set.is_empty() {
            continue;
        }
        let primary = metric_set
            .iter()
            .find(|m| m.metric_type.as_deref() == Some("Primary"))
            .or_else(|| metric_set.first());
        if let Some(p) = primary {
            if let Some(data) = &p.cvss_data {
                return (data.base_score, data.base_severity.clone());
            }
        }
    }
    (None, None)
}

fn extract_cpes(nodes: &[NvdNode], out: &mut Vec<CpeRow>) {
    for node in nodes {
        if let Some(matches) = &node.cpe_match {
            for m in matches {
                if m.vulnerable == Some(true) {
                    if let Some(criteria) = &m.criteria {
                        out.push(CpeRow {
                            criteria: criteria.clone(),
                            vsi: m.version_start_including.clone(),
                            vse: m.version_start_excluding.clone(),
                            vei: m.version_end_including.clone(),
                            vee: m.version_end_excluding.clone(),
                        });
                    }
                }
            }
        }
        if let Some(children) = &node.nodes {
            extract_cpes(children, out);
        }
    }
}


