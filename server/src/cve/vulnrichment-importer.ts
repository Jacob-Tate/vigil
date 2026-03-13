import { join } from "path";
import { promises as fs } from "fs";
import simpleGit from "simple-git";
import { db, dbGet, dbAll, DATA_DIR } from "../db/database";
import { VulnrichmentSyncState, SsvcExploitationStat } from "../types";
import { checkEnrichmentAlerts } from "./enrichment-alerter";

const REPO_URL = "https://github.com/cisagov/vulnrichment.git";
const CISA_ORG_ID = "134c704f-9b21-4f2e-91b3-4a467353bcc0";

export function getRepoDir(): string {
  return join(DATA_DIR, "vulnrichment");
}

interface SsvcSyncResult {
  count: number;
  repoVersion: string;
}

interface SsvcOptions {
  Exploitation?: string;
  Automatable?: string;
  "Technical Impact"?: string;
  [key: string]: string | undefined;
}

interface AdpMetricOther {
  type?: string;
  content?: {
    options?: Array<Record<string, string>>;
    timestamp?: string;
  };
}

interface AdpMetric {
  other?: AdpMetricOther;
}

interface AdpEntry {
  providerMetadata?: { orgId?: string };
  metrics?: AdpMetric[];
}

interface CveRecord {
  containers?: {
    adp?: AdpEntry[];
  };
}

function extractSsvc(record: CveRecord): { exploitation: string | null; automatable: string | null; technical_impact: string | null; timestamp: string | null } | null {
  const adpList = record.containers?.adp ?? [];
  for (const adp of adpList) {
    if (adp.providerMetadata?.orgId !== CISA_ORG_ID) continue;
    for (const metric of adp.metrics ?? []) {
      if (metric.other?.type !== "ssvc") continue;
      const options = metric.other.content?.options ?? [];
      const opts: SsvcOptions = {};
      for (const opt of options) {
        Object.assign(opts, opt);
      }
      const exploitation = opts["Exploitation"]?.toLowerCase() ?? null;
      const automatable = opts["Automatable"]?.toLowerCase() ?? null;
      const technical_impact = opts["Technical Impact"]?.toLowerCase() ?? null;
      if (!exploitation && !automatable && !technical_impact) continue;
      return {
        exploitation,
        automatable,
        technical_impact,
        timestamp: metric.other.content?.timestamp ?? null,
      };
    }
  }
  return null;
}

async function walkJsonFiles(dir: string): Promise<string[]> {
  const results: string[] = [];
  let entries: import("fs").Dirent[];
  try {
    entries = await fs.readdir(dir, { withFileTypes: true });
  } catch {
    return results;
  }
  for (const entry of entries) {
    const fullPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      const nested = await walkJsonFiles(fullPath);
      results.push(...nested);
    } else if (entry.isFile() && entry.name.endsWith(".json") && entry.name.startsWith("CVE-")) {
      results.push(fullPath);
    }
  }
  return results;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
let _upsert: any = null;

function ensureStmt(): void {
  if (_upsert) return;
  _upsert = db.prepare(
    `INSERT OR REPLACE INTO cisa_ssvc
       (cve_id, exploitation, automatable, technical_impact, timestamp, synced_at)
     VALUES (?, ?, ?, ?, ?, ?)`
  );
}

export async function syncVulnrichment(): Promise<SsvcSyncResult> {
  const repoDir = getRepoDir();
  const git = simpleGit();

  // Clone or pull
  try {
    await fs.access(join(repoDir, ".git"));
    // Repo exists — pull
    console.log("[vulnrichment] pulling latest changes...");
    await simpleGit(repoDir).pull();
  } catch {
    // Repo doesn't exist — clone
    console.log("[vulnrichment] cloning repository (first time, may take a moment)...");
    await git.clone(REPO_URL, repoDir, ["--depth", "1"]);
  }

  // Get current HEAD commit hash
  let repoVersion = "";
  try {
    const log = await simpleGit(repoDir).log({ maxCount: 1 });
    repoVersion = log.latest?.hash ?? "";
  } catch {
    // non-critical
  }

  // Walk all CVE JSON files
  const jsonFiles = await walkJsonFiles(repoDir);
  const syncedAt = new Date().toISOString();

  ensureStmt();

  let count = 0;
  const BATCH_SIZE = 500;
  let batch: Array<[string, string | null, string | null, string | null, string | null, string]> = [];

  const flush = () => {
    if (batch.length === 0) return;
    db.exec("BEGIN IMMEDIATE");
    try {
      for (const row of batch) {
        _upsert.run(...row);
      }
      db.exec("COMMIT");
    } catch (err) {
      db.exec("ROLLBACK");
      throw err;
    }
    count += batch.length;
    batch = [];
  };

  for (const filePath of jsonFiles) {
    let record: CveRecord;
    try {
      const raw = await fs.readFile(filePath, "utf-8");
      record = JSON.parse(raw) as CveRecord;
    } catch {
      continue;
    }

    const ssvc = extractSsvc(record);
    if (!ssvc) continue;

    // Extract CVE ID from filename
    const cveId = filePath.replace(/\\/g, "/").split("/").pop()?.replace(".json", "") ?? "";
    if (!cveId.startsWith("CVE-")) continue;

    batch.push([cveId, ssvc.exploitation, ssvc.automatable, ssvc.technical_impact, ssvc.timestamp, syncedAt]);

    if (batch.length >= BATCH_SIZE) {
      flush();
    }
  }
  flush();

  console.log(`[vulnrichment] upserted ${count} SSVC entries`);

  // Run enrichment alert checks
  await checkEnrichmentAlerts();

  return { count, repoVersion };
}

export function getVulnrichmentSyncState(): VulnrichmentSyncState {
  const row = dbGet<{ total: number; last_synced_at: string | null }>(
    "SELECT COUNT(*) AS total, MAX(synced_at) AS last_synced_at FROM cisa_ssvc"
  );
  const exploitation_breakdown = dbAll<SsvcExploitationStat>(
    `SELECT exploitation, COUNT(*) AS count
     FROM cisa_ssvc
     WHERE exploitation IS NOT NULL
     GROUP BY exploitation
     ORDER BY CASE exploitation WHEN 'active' THEN 0 WHEN 'poc' THEN 1 ELSE 2 END`
  );
  return {
    total: row?.total ?? 0,
    last_synced_at: row?.last_synced_at ?? null,
    is_syncing: false,
    exploitation_breakdown,
  };
}
