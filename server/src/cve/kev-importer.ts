import axios from "axios";
import { db, dbAll, dbGet } from "../db/database";
import { KevSyncState, KevYearStat } from "../types";
import { checkEnrichmentAlerts } from "./enrichment-alerter";

const KEV_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

interface KevVulnerability {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse: string;
  notes: string;
}

interface KevFeed {
  catalogVersion: string;
  dateReleased: string;
  count: number;
  vulnerabilities: KevVulnerability[];
}

interface KevSyncResult {
  count: number;
  catalogVersion: string;
  dateReleased: string;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
let _upsert: any = null;

function ensureStmt(): void {
  if (_upsert) return;
  _upsert = db.prepare(
    `INSERT OR REPLACE INTO cisa_kev
       (cve_id, vendor_project, product, vulnerability_name, date_added,
        short_description, required_action, due_date, known_ransomware_campaign_use,
        notes, synced_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  );
}

export async function syncKev(): Promise<KevSyncResult> {
  const response = await axios.get<KevFeed>(KEV_URL, {
    responseType: "json",
    headers: { "User-Agent": "monitor-app/1.0" },
    timeout: 30000,
  });

  const feed = response.data;
  const vulns = feed.vulnerabilities ?? [];
  const syncedAt = new Date().toISOString();

  ensureStmt();
  db.exec("BEGIN IMMEDIATE");
  try {
    for (const v of vulns) {
      _upsert.run(
        v.cveID,
        v.vendorProject ?? null,
        v.product ?? null,
        v.vulnerabilityName ?? null,
        v.dateAdded ?? null,
        v.shortDescription ?? null,
        v.requiredAction ?? null,
        v.dueDate ?? null,
        v.knownRansomwareCampaignUse ?? null,
        v.notes ?? null,
        syncedAt
      );
    }
    db.exec("COMMIT");
  } catch (err) {
    db.exec("ROLLBACK");
    throw err;
  }

  await checkEnrichmentAlerts();

  return {
    count: vulns.length,
    catalogVersion: feed.catalogVersion ?? "",
    dateReleased: feed.dateReleased ?? "",
  };
}

export function getKevSyncState(): KevSyncState {
  const row = dbGet<{ total: number; last_synced_at: string | null }>(
    "SELECT COUNT(*) AS total, MAX(synced_at) AS last_synced_at FROM cisa_kev"
  );
  const year_stats = dbAll<KevYearStat>(
    `SELECT strftime('%Y', date_added) AS year,
            COUNT(*) AS count,
            SUM(CASE WHEN known_ransomware_campaign_use = 'Known' THEN 1 ELSE 0 END) AS ransomware_count
     FROM cisa_kev
     WHERE date_added IS NOT NULL
     GROUP BY year
     ORDER BY year DESC`
  );
  return {
    total: row?.total ?? 0,
    last_synced_at: row?.last_synced_at ?? null,
    is_syncing: false, // caller sets this in-memory
    year_stats,
  };
}
