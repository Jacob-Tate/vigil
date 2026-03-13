import axios from "axios";
import { createGunzip } from "zlib";
import makeParser from "stream-json";
import Pick from "stream-json/filters/Pick";
import StreamArray from "stream-json/streamers/StreamArray";
import Chain from "stream-chain";
import { db, dbGet, dbRun } from "../db/database";
import { NvdFeedState } from "../types";

const FEED_BASE = "https://nvd.nist.gov/feeds/json/cve/2.0";
const BATCH_SIZE = 100;

export const ALL_FEED_NAMES = [
  "modified",
  "recent",
  "2002",
  "2003",
  "2004",
  "2005",
  "2006",
  "2007",
  "2008",
  "2009",
  "2010",
  "2011",
  "2012",
  "2013",
  "2014",
  "2015",
  "2016",
  "2017",
  "2018",
  "2019",
  "2020",
  "2021",
  "2022",
  "2023",
  "2024",
  "2025",
  "2026",
];

interface FeedMeta {
  lastModifiedDate: string;
  sha256: string;
}

interface CpeEntry {
  criteria: string;
  versionStartIncluding: string | null;
  versionStartExcluding: string | null;
  versionEndIncluding: string | null;
  versionEndExcluding: string | null;
}

interface CveRef {
  url: string;
  source?: string;
  tags?: string[];
}

interface CveData {
  cveId: string;
  publishedAt: string;
  lastModifiedAt: string;
  cvssScore: number | null;
  cvssSeverity: string | null;
  description: string | null;
  nvdUrl: string;
  cpes: CpeEntry[];
  references: CveRef[];
}

function parseMeta(text: string): FeedMeta {
  const lines: Record<string, string> = {};
  for (const line of text.trim().split("\n")) {
    const colonIdx = line.indexOf(":");
    if (colonIdx > 0) {
      lines[line.slice(0, colonIdx).trim()] = line.slice(colonIdx + 1).trim();
    }
  }
  return {
    lastModifiedDate: lines["lastModifiedDate"] ?? "",
    sha256: lines["sha256"] ?? "",
  };
}

// Recursively extract vulnerable CPE entries (with version ranges) from configuration nodes
function extractCpes(nodes: unknown[]): CpeEntry[] {
  const cpes: CpeEntry[] = [];
  for (const node of nodes) {
    if (typeof node !== "object" || node === null) continue;
    const n = node as Record<string, unknown>;
    if (Array.isArray(n["cpeMatch"])) {
      for (const m of n["cpeMatch"] as Record<string, unknown>[]) {
        if (m["vulnerable"] === true && typeof m["criteria"] === "string") {
          cpes.push({
            criteria: m["criteria"] as string,
            versionStartIncluding: (m["versionStartIncluding"] as string | undefined) ?? null,
            versionStartExcluding: (m["versionStartExcluding"] as string | undefined) ?? null,
            versionEndIncluding: (m["versionEndIncluding"] as string | undefined) ?? null,
            versionEndExcluding: (m["versionEndExcluding"] as string | undefined) ?? null,
          });
        }
      }
    }
    if (Array.isArray(n["nodes"])) {
      cpes.push(...extractCpes(n["nodes"] as unknown[]));
    }
  }
  return cpes;
}

function extractCveData(vuln: unknown): CveData {
  const cve = (vuln as Record<string, unknown>)["cve"] as Record<
    string,
    unknown
  >;
  const id = cve["id"] as string;
  const published = (cve["published"] as string) ?? "";
  const lastModified = (cve["lastModified"] as string) ?? "";

  // English description
  const descriptions =
    (cve["descriptions"] as { lang: string; value: string }[]) ?? [];
  const desc = descriptions.find((d) => d.lang === "en")?.value ?? null;

  // CVSS: prefer v3.1 Primary → v3.1 any → v3.0 → v2
  let cvssScore: number | null = null;
  let cvssSeverity: string | null = null;
  const metrics = (cve["metrics"] ?? {}) as Record<string, unknown>;
  const metricSets = [
    (metrics["cvssMetricV31"] as Record<string, unknown>[] | undefined) ?? [],
    (metrics["cvssMetricV30"] as Record<string, unknown>[] | undefined) ?? [],
    (metrics["cvssMetricV2"] as Record<string, unknown>[] | undefined) ?? [],
  ];
  for (const metricSet of metricSets) {
    if (metricSet.length === 0) continue;
    const primary =
      metricSet.find((m) => m["type"] === "Primary") ?? metricSet[0];
    const cvssData = primary?.["cvssData"] as
      | Record<string, unknown>
      | undefined;
    if (cvssData) {
      cvssScore = (cvssData["baseScore"] as number | undefined) ?? null;
      cvssSeverity =
        (cvssData["baseSeverity"] as string | undefined) ?? null;
      break;
    }
  }

  // CPE strings from configurations
  const configurations =
    (cve["configurations"] as Record<string, unknown>[] | undefined) ?? [];
  const rawCpes: CpeEntry[] = [];
  for (const config of configurations) {
    const nodes = (config["nodes"] as unknown[] | undefined) ?? [];
    rawCpes.push(...extractCpes(nodes));
  }

  // Deduplicate by criteria + version range combination
  // (same criteria CPE string can appear multiple times with different version ranges)
  const seenKeys = new Set<string>();
  const uniqueCpes = rawCpes.filter((entry) => {
    const key = `${entry.criteria}|${entry.versionStartIncluding ?? ""}|${entry.versionStartExcluding ?? ""}|${entry.versionEndIncluding ?? ""}|${entry.versionEndExcluding ?? ""}`;
    if (seenKeys.has(key)) return false;
    seenKeys.add(key);
    return true;
  });

  // References
  const rawRefs =
    (cve["references"] as Record<string, unknown>[] | undefined) ?? [];
  const references: CveRef[] = rawRefs
    .filter((r) => typeof r["url"] === "string")
    .map((r) => ({
      url: r["url"] as string,
      source: (r["source"] as string | undefined) ?? undefined,
      tags: Array.isArray(r["tags"])
        ? (r["tags"] as unknown[]).filter((t): t is string => typeof t === "string")
        : undefined,
    }));

  return {
    cveId: id,
    publishedAt: published,
    lastModifiedAt: lastModified,
    cvssScore,
    cvssSeverity,
    description: desc,
    nvdUrl: `https://nvd.nist.gov/vuln/detail/${id}`,
    cpes: uniqueCpes,
    references,
  };
}

// Prepared statements — initialised lazily after db is ready
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let _insertCve: any = null;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let _insertCpe: any = null;

function ensureStmts(): void {
  if (_insertCve) return;
  _insertCve = db.prepare(
    `INSERT OR REPLACE INTO nvd_cves
       (cve_id, published_at, last_modified_at, cvss_score, cvss_severity, description, nvd_url, references_json)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  );
  _insertCpe = db.prepare(
    `INSERT OR IGNORE INTO nvd_cve_cpes
       (cve_id, cpe_string, version_start_including, version_start_excluding,
        version_end_including, version_end_excluding)
     VALUES (?, ?, ?, ?, ?, ?)`
  );
}

function upsertBatch(batch: CveData[]): void {
  ensureStmts();
  db.exec("BEGIN IMMEDIATE");
  try {
    for (const cve of batch) {
      // INSERT OR REPLACE cascades-deletes old CPE rows for this CVE
      _insertCve.run(
        cve.cveId,
        cve.publishedAt,
        cve.lastModifiedAt,
        cve.cvssScore,
        cve.cvssSeverity,
        cve.description,
        cve.nvdUrl,
        cve.references.length > 0 ? JSON.stringify(cve.references) : null
      );
      for (const cpe of cve.cpes) {
        _insertCpe.run(
          cve.cveId,
          cpe.criteria,
          cpe.versionStartIncluding,
          cpe.versionStartExcluding,
          cpe.versionEndIncluding,
          cpe.versionEndExcluding
        );
      }
    }
    db.exec("COMMIT");
  } catch (err) {
    db.exec("ROLLBACK");
    throw err;
  }
}

export async function checkMeta(feedName: string): Promise<FeedMeta> {
  const url = `${FEED_BASE}/nvdcve-2.0-${feedName}.meta`;
  const response = await axios.get<string>(url, {
    responseType: "text",
    headers: { "User-Agent": "monitor-app/1.0" },
    timeout: 15000,
  });
  return parseMeta(response.data);
}

export async function needsUpdate(feedName: string): Promise<boolean> {
  const meta = await checkMeta(feedName);
  const state = dbGet<NvdFeedState>(
    "SELECT * FROM nvd_feed_state WHERE feed_name = ?",
    feedName
  );
  if (!state) return true;
  return state.sha256?.toUpperCase() !== meta.sha256.toUpperCase();
}

export async function importFeed(
  feedName: string,
  onProgress?: (processed: number) => void
): Promise<number> {
  const meta = await checkMeta(feedName);
  const url = `${FEED_BASE}/nvdcve-2.0-${feedName}.json.gz`;

  const response = await axios.get(url, {
    responseType: "stream",
    headers: { "User-Agent": "monitor-app/1.0" },
    timeout: 600000, // 10 min for large year feeds
  });

  const pipeline = new Chain([
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    response.data as any,
    createGunzip(),
    makeParser.parser(),
    Pick.pick({ filter: "vulnerabilities" }),
    StreamArray.streamArray(),
  ]);

  let batch: CveData[] = [];
  let processed = 0;

  await new Promise<void>((resolve, reject) => {
    pipeline.on(
      "data",
      ({ value }: { key: number; value: unknown }) => {
        batch.push(extractCveData(value));
        if (batch.length >= BATCH_SIZE) {
          upsertBatch(batch);
          processed += batch.length;
          batch = [];
          onProgress?.(processed);
        }
      }
    );

    pipeline.on("end", () => {
      if (batch.length > 0) {
        upsertBatch(batch);
        processed += batch.length;
        batch = [];
        onProgress?.(processed);
      }
      resolve();
    });

    pipeline.on("error", (err: Error) => {
      reject(err);
    });
  });

  dbRun(
    `INSERT OR REPLACE INTO nvd_feed_state
       (feed_name, last_modified_date, sha256, total_cves, imported_at)
     VALUES (?, ?, ?, ?, ?)`,
    feedName,
    meta.lastModifiedDate,
    meta.sha256,
    processed,
    new Date().toISOString()
  );

  return processed;
}
