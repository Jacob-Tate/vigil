import * as semver from "semver";
import { dbAll, dbGet, dbRun } from "../db/database";
import { CveTarget } from "../types";
import { AffectedEntry, VersionRange } from "./cvelist-importer";

interface CvelistAffectedRow {
  cve_id: string;
  vendor: string | null;
  product: string;
  versions_json: string | null;
  default_status: string | null;
}

interface CvelistCveRow {
  cve_id: string;
  state: string;
  cna_description: string | null;
  date_published: string | null;
  date_updated: string | null;
}

function parseVersionRanges(versionsJson: string | null): VersionRange[] {
  if (!versionsJson) return [];
  try {
    return JSON.parse(versionsJson) as VersionRange[];
  } catch {
    return [];
  }
}

/**
 * Check if a target version falls within an affected entry's version ranges.
 * Returns true if the version is affected, false if unaffected/unknown.
 * If target has no version, always returns true.
 */
function isVersionAffected(targetVersion: string | null, affected: AffectedEntry): boolean {
  if (!targetVersion) return true; // no version constraint → match all

  const coerced = semver.coerce(targetVersion);
  if (!coerced) return false; // can't parse target version → skip

  const ranges = affected.versions ?? [];
  const affectedRanges = ranges.filter(
    (r) => r.status === "affected" && (r.versionType === "semver" || !r.versionType)
  );

  for (const range of affectedRanges) {
    const start = range.version ? semver.coerce(range.version) : null;

    // Check lower bound
    if (start && semver.lt(coerced, start)) continue;

    // Check upper bound (lessThan = exclusive)
    if (range.lessThan) {
      // Handle glob-style like "4.0.*" → treat as "< 4.1.0"
      const cleanedLt = range.lessThan.replace(/\.\*$/, ".0");
      const ltCoerced = semver.coerce(cleanedLt);
      if (ltCoerced && !semver.lt(coerced, ltCoerced)) continue;
    }

    // Check upper bound (lessThanOrEqual = inclusive)
    if (range.lessThanOrEqual) {
      const lteCoerced = semver.coerce(range.lessThanOrEqual);
      if (lteCoerced && semver.gt(coerced, lteCoerced)) continue;
    }

    return true; // falls within this affected range
  }

  // No range matched — check defaultStatus
  if (affected.defaultStatus === "affected") return true;

  return false;
}

export async function evaluateCveTargetsFromCvelist(): Promise<void> {
  const targets = dbAll<CveTarget>("SELECT * FROM cve_targets WHERE active = 1");

  for (const target of targets) {
    await evaluateCveTargetFromCvelist(target);
  }
}

async function evaluateCveTargetFromCvelist(target: CveTarget): Promise<void> {
  const productLower = target.product.toLowerCase();

  // Find all cvelist affected entries for this product
  let affectedRows: CvelistAffectedRow[];
  if (target.vendor) {
    const vendorLower = target.vendor.toLowerCase();
    // Match on product exactly, vendor loosely (LIKE with wildcards on both sides)
    affectedRows = dbAll<CvelistAffectedRow>(
      `SELECT cve_id, vendor, product, versions_json, default_status
       FROM cvelist_affected
       WHERE product = ?
         AND (vendor IS NULL OR vendor LIKE ?)`,
      productLower,
      `%${vendorLower}%`
    );
  } else {
    affectedRows = dbAll<CvelistAffectedRow>(
      `SELECT cve_id, vendor, product, versions_json, default_status
       FROM cvelist_affected
       WHERE product = ?`,
      productLower
    );
  }

  if (affectedRows.length === 0) return;

  // Filter to only PUBLISHED CVEs
  const candidateCveIds = new Set<string>();
  for (const row of affectedRows) {
    const cveInfo = dbGet<{ state: string }>(
      "SELECT state FROM cvelist_cves WHERE cve_id = ?",
      row.cve_id
    );
    if (cveInfo?.state !== "PUBLISHED") continue;

    // Check version
    const affectedEntry: AffectedEntry = {
      vendor: row.vendor ?? undefined,
      product: row.product,
      versions: parseVersionRanges(row.versions_json),
      defaultStatus: row.default_status ?? undefined,
    };

    if (isVersionAffected(target.version, affectedEntry)) {
      candidateCveIds.add(row.cve_id);
    }
  }

  if (candidateCveIds.size === 0) return;

  // Find CVEs not yet in findings for this target
  const existingFindings = new Set(
    dbAll<{ cve_id: string }>(
      "SELECT cve_id FROM cve_findings WHERE target_id = ?",
      target.id
    ).map((r) => r.cve_id)
  );

  let newCount = 0;
  for (const cveId of candidateCveIds) {
    if (existingFindings.has(cveId)) continue;

    // Get CVE metadata from cvelist_cves
    const cveRow = dbGet<CvelistCveRow>(
      "SELECT cve_id, state, cna_description, date_published, date_updated FROM cvelist_cves WHERE cve_id = ?",
      cveId
    );
    if (!cveRow) continue;

    // Check if NVD has data for this CVE
    const nvdRow = dbGet<{ cvss_score: number | null; cvss_severity: string | null; description: string | null; nvd_url: string | null; published_at: string | null; last_modified_at: string | null }>(
      "SELECT cvss_score, cvss_severity, description, nvd_url, published_at, last_modified_at FROM nvd_cves WHERE cve_id = ?",
      cveId
    );

    // NVD data takes priority; fall back to cvelist data
    dbRun(
      `INSERT OR IGNORE INTO cve_findings
         (target_id, cve_id, published_at, last_modified_at, cvss_score,
          cvss_severity, description, nvd_url, alerted)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)`,
      target.id,
      cveId,
      nvdRow?.published_at ?? cveRow.date_published,
      nvdRow?.last_modified_at ?? cveRow.date_updated,
      nvdRow?.cvss_score ?? null,
      nvdRow?.cvss_severity ?? null,
      nvdRow?.description ?? cveRow.cna_description,
      nvdRow?.nvd_url ?? null
    );
    newCount++;
  }

  if (newCount > 0) {
    console.log(
      `[cvelist-engine] Found ${newCount} new CVE(s) from cvelistV5 for target: ${target.name} (${target.product}:${target.version ?? "*"})`
    );
  }
}
