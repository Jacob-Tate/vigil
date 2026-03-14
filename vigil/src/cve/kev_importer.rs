use serde::Deserialize;

use crate::db::DbPool;

const KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

#[derive(Deserialize)]
struct KevFeed {
    #[serde(rename = "catalogVersion")]
    catalog_version: Option<String>,
    #[serde(rename = "dateReleased")]
    date_released: Option<String>,
    vulnerabilities: Vec<KevVuln>,
}

#[derive(Deserialize)]
struct KevVuln {
    #[serde(rename = "cveID")]
    cve_id: String,
    #[serde(rename = "vendorProject")]
    vendor_project: Option<String>,
    product: Option<String>,
    #[serde(rename = "vulnerabilityName")]
    vulnerability_name: Option<String>,
    #[serde(rename = "dateAdded")]
    date_added: Option<String>,
    #[serde(rename = "shortDescription")]
    short_description: Option<String>,
    #[serde(rename = "requiredAction")]
    required_action: Option<String>,
    #[serde(rename = "dueDate")]
    due_date: Option<String>,
    #[serde(rename = "knownRansomwareCampaignUse")]
    known_ransomware_campaign_use: Option<String>,
    notes: Option<String>,
}

pub struct KevSyncResult {
    pub count: usize,
    pub catalog_version: String,
    pub date_released: String,
}

pub async fn sync_kev(db: &DbPool) -> anyhow::Result<KevSyncResult> {
    tracing::info!("Downloading CISA KEV feed");

    let feed: KevFeed = reqwest::Client::new()
        .get(KEV_URL)
        .header("User-Agent", "monitor-app/1.0")
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let vulns = feed.vulnerabilities;
    let catalog_version = feed.catalog_version.unwrap_or_default();
    let date_released = feed.date_released.unwrap_or_default();
    let count = vulns.len();
    let synced_at = chrono::Utc::now().to_rfc3339();

    let db = db.clone();
    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let conn = db.lock().unwrap();
        conn.execute_batch("BEGIN IMMEDIATE")?;
        let result: rusqlite::Result<()> = (|| {
            let mut stmt = conn.prepare_cached(
                "INSERT OR REPLACE INTO cisa_kev
                 (cve_id, vendor_project, product, vulnerability_name, date_added,
                  short_description, required_action, due_date,
                  known_ransomware_campaign_use, notes, synced_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            )?;
            for v in &vulns {
                stmt.execute(rusqlite::params![
                    v.cve_id,
                    v.vendor_project,
                    v.product,
                    v.vulnerability_name,
                    v.date_added,
                    v.short_description,
                    v.required_action,
                    v.due_date,
                    v.known_ransomware_campaign_use,
                    v.notes,
                    synced_at,
                ])?;
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
        Ok(())
    })
    .await??;

    tracing::info!(count, "CISA KEV sync complete");
    Ok(KevSyncResult { count, catalog_version, date_released })
}
