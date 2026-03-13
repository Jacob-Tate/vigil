import { join, sep } from "path";
import { promises as fs } from "fs";
import simpleGit from "simple-git";
import { db, dbGet, dbAll, DATA_DIR } from "../db/database";
import { CvelistSyncState } from "../types";
import { checkEnrichmentAlerts } from "./enrichment-alerter";
import { evaluateCveTargetsFromCvelist } from "./cvelist-engine";

const REPO_URL = "https://github.com/CVEProject/cvelistV5.git";

export function getRepoDir(): string {
  return join(DATA_DIR, "cvelistV5");
}

interface CvelistSyncResult {
  count: number;
  repoVersion: string;
}

interface VersionRange {
  version?: string;
  lessThan?: string;
  lessThanOrEqual?: string;
  versionType?: string;
  status?: string;
}

interface AffectedEntry {
  vendor?: string;
  product?: string;
  versions?: VersionRange[];
  defaultStatus?: string;
}

interface CvelistRecord {
  cveMetadata?: {
    cveId?: string;
    state?: string;
    datePublished?: string;
    dateUpdated?: string;
  };
  containers?: {
    cna?: {
      title?: string;
      descriptions?: Array<{ lang: string; value: string }>;
      affected?: AffectedEntry[];
    };
  };
}

interface CvelistRow {
  cveId: string;
  state: string;
  cnaDescription: string | null;
  cnaTitle: string | null;
  datePublished: string | null;
  dateUpdated: string | null;
  affected: AffectedEntry[];
}

function extractCvelist(record: CvelistRecord): CvelistRow | null {
  const meta = record.cveMetadata;
  if (!meta?.cveId || !meta.state) return null;
  if (!meta.cveId.startsWith("CVE-")) return null;

  const cna = record.containers?.cna;
  const descriptions = cna?.descriptions ?? [];
  const enDesc = descriptions.find(
    (d) => d.lang === "en" || d.lang.startsWith("en")
  )?.value ?? null;

  return {
    cveId: meta.cveId,
    state: meta.state,
    cnaDescription: enDesc,
    cnaTitle: cna?.title ?? null,
    datePublished: meta.datePublished ?? null,
    dateUpdated: meta.dateUpdated ?? null,
    affected: cna?.affected ?? [],
  };
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

async function getChangedFiles(repoDir: string, fromHash: string): Promise<string[] | null> {
  try {
    const result = await simpleGit(repoDir).raw([
      "diff", "--name-only", fromHash, "HEAD",
    ]);
    return result
      .trim()
      .split("\n")
      .filter((f) => f.endsWith(".json") && f.includes("CVE-"))
      .map((f) => join(repoDir, f.replace(/\//g, sep)));
  } catch {
    return null;
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
let _upsertCve: any = null;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let _upsertAffected: any = null;

function ensureStmts(): void {
  if (!_upsertCve) {
    _upsertCve = db.prepare(
      `INSERT OR REPLACE INTO cvelist_cves
         (cve_id, state, cna_description, cna_title, date_published, date_updated, synced_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    );
  }
  if (!_upsertAffected) {
    _upsertAffected = db.prepare(
      `INSERT INTO cvelist_affected (cve_id, vendor, product, versions_json, default_status)
       VALUES (?, ?, ?, ?, ?)`
    );
  }
}

export async function syncCvelist(): Promise<CvelistSyncResult> {
  const repoDir = getRepoDir();
  const git = simpleGit();

  // Clone (blobless: full history for diff, no blob content upfront) or pull
  try {
    await fs.access(join(repoDir, ".git"));
    console.log("[cvelist] pulling latest changes...");
    await simpleGit(repoDir).pull();
  } catch {
    console.log("[cvelist] cloning repository (blobless, may take a moment)...");
    await git.clone(REPO_URL, repoDir, ["--filter=blob:none", "--no-tags"]);
  }

  // Get new HEAD hash
  let repoVersion = "";
  try {
    const log = await simpleGit(repoDir).log({ maxCount: 1 });
    repoVersion = log.latest?.hash ?? "";
  } catch {
    // non-critical
  }

  // Get last processed hash from nvd_feed_state
  const stateRow = dbGet<{ sha256: string | null }>(
    "SELECT sha256 FROM nvd_feed_state WHERE feed_name = 'cvelist'"
  );
  const lastHash = stateRow?.sha256 ?? null;

  // Determine which files to process
  if (lastHash && repoVersion && lastHash === repoVersion) {
    console.log("[cvelist] already up to date, nothing to process");
    await checkEnrichmentAlerts();
    await evaluateCveTargetsFromCvelist();
    return { count: 0, repoVersion };
  }

  let filesToProcess: string[] | null = null;
  if (lastHash && repoVersion) {
    console.log(`[cvelist] computing diff from ${lastHash.slice(0, 8)} to ${repoVersion.slice(0, 8)}...`);
    filesToProcess = await getChangedFiles(repoDir, lastHash);
    if (filesToProcess !== null) {
      console.log(`[cvelist] incremental: ${filesToProcess.length} changed files`);
    } else {
      console.log("[cvelist] git diff failed, falling back to full walk");
    }
  }

  const jsonFiles = filesToProcess ?? await walkJsonFiles(join(repoDir, "cves"));
  if (!filesToProcess) {
    console.log(`[cvelist] full walk: ${jsonFiles.length} files`);
  }

  const syncedAt = new Date().toISOString();
  ensureStmts();

  let count = 0;
  const BATCH_SIZE = 500;
  let batch: CvelistRow[] = [];

  const flush = () => {
    if (batch.length === 0) return;
    db.exec("BEGIN IMMEDIATE");
    try {
      for (const row of batch) {
        _upsertCve.run(
          row.cveId, row.state, row.cnaDescription, row.cnaTitle,
          row.datePublished, row.dateUpdated, syncedAt
        );
        // Delete old affected entries and re-insert
        db.prepare("DELETE FROM cvelist_affected WHERE cve_id = ?").run(row.cveId);
        for (const aff of row.affected) {
          if (!aff.product) continue;
          _upsertAffected.run(
            row.cveId,
            aff.vendor?.toLowerCase() ?? null,
            aff.product.toLowerCase(),
            aff.versions ? JSON.stringify(aff.versions) : null,
            aff.defaultStatus ?? null
          );
        }
      }
      db.exec("COMMIT");
    } catch (err) {
      db.exec("ROLLBACK");
      throw err;
    }
    count += batch.length;
    batch = [];
  };

  const LOG_INTERVAL = 10_000;
  let filesRead = 0;

  for (const filePath of jsonFiles) {
    let record: CvelistRecord;
    try {
      const raw = await fs.readFile(filePath, "utf-8");
      record = JSON.parse(raw) as CvelistRecord;
    } catch {
      continue;
    }

    const row = extractCvelist(record);
    if (!row) continue;

    batch.push(row);
    if (batch.length >= BATCH_SIZE) flush();

    filesRead++;
    if (filesRead % LOG_INTERVAL === 0) {
      console.log(`[cvelist] processed ${filesRead.toLocaleString()} / ${jsonFiles.length.toLocaleString()} files (${count.toLocaleString()} upserted so far)...`);
    }
  }
  flush();

  console.log(`[cvelist] upserted ${count} CVE records`);

  // Update sync state
  db.prepare(
    `INSERT OR REPLACE INTO nvd_feed_state (feed_name, sha256, total_cves, imported_at)
     VALUES ('cvelist', ?, ?, ?)`
  ).run(repoVersion, count, syncedAt);

  // Run enrichment checks and target evaluation
  await checkEnrichmentAlerts();
  await evaluateCveTargetsFromCvelist();

  return { count, repoVersion };
}

export function getCvelistSyncState(): CvelistSyncState {
  const row = dbGet<{ total: number; rejected_count: number; last_synced_at: string | null }>(
    `SELECT COUNT(*) AS total,
            SUM(CASE WHEN state = 'REJECTED' THEN 1 ELSE 0 END) AS rejected_count,
            MAX(synced_at) AS last_synced_at
     FROM cvelist_cves`
  );
  const stateRow = dbGet<{ sha256: string | null; imported_at: string | null }>(
    "SELECT sha256, imported_at FROM nvd_feed_state WHERE feed_name = 'cvelist'"
  );
  return {
    total: row?.total ?? 0,
    rejected_count: row?.rejected_count ?? 0,
    last_synced_at: stateRow?.imported_at ?? null,
    is_syncing: false,
    last_repo_version: stateRow?.sha256 ? stateRow.sha256.slice(0, 8) : null,
  };
}

export type { AffectedEntry, VersionRange };
export { dbAll };
