import { dbAll, dbRun } from "../db/database";
import { AlertPayload } from "../types";
import { sendAlert } from "../notifiers";
import dotenv from "dotenv";

dotenv.config();

const BASE_URL = process.env.BASE_URL ?? "http://localhost:5173";

interface FindingWithEnrichment {
  id: number;
  target_id: number;
  cve_id: string;
  cvss_score: number | null;
  cvss_severity: string | null;
  description: string | null;
  nvd_url: string | null;
  alerted: number;
  enrichment_fingerprint: string | null;
  exploitation_alert_sent: string | null;
  // joined
  target_name: string;
  min_alert_cvss_score: number;
  is_kev: number;
  ssvc_exploitation: string | null;
  ssvc_automatable: string | null;
  ssvc_technical_impact: string | null;
}

export function buildEnrichmentFingerprint(f: {
  cvss_score: number | null;
  cvss_severity: string | null;
  is_kev: number;
  ssvc_exploitation: string | null;
  ssvc_automatable: string | null;
  ssvc_technical_impact: string | null;
}): string {
  return [
    f.cvss_score ?? "",
    f.cvss_severity ?? "",
    f.is_kev,
    f.ssvc_exploitation ?? "",
    f.ssvc_automatable ?? "",
    f.ssvc_technical_impact ?? "",
  ].join("|");
}

function parseFingerprint(fp: string): {
  cvss_score: string;
  cvss_severity: string;
  is_kev: string;
  ssvc_exploitation: string;
  ssvc_automatable: string;
  ssvc_technical_impact: string;
} {
  const [cvss_score = "", cvss_severity = "", is_kev = "", ssvc_exploitation = "", ssvc_automatable = "", ssvc_technical_impact = ""] = fp.split("|");
  return { cvss_score, cvss_severity, is_kev, ssvc_exploitation, ssvc_automatable, ssvc_technical_impact };
}

function detectChangedFields(oldFp: string, newFp: string): string[] {
  const o = parseFingerprint(oldFp);
  const n = parseFingerprint(newFp);
  const changed: string[] = [];
  if (o.cvss_score !== n.cvss_score || o.cvss_severity !== n.cvss_severity) changed.push("cvss_score");
  if (o.is_kev !== n.is_kev) changed.push("is_kev");
  if (o.ssvc_exploitation !== n.ssvc_exploitation) changed.push("ssvc_exploitation");
  if (o.ssvc_automatable !== n.ssvc_automatable) changed.push("ssvc_automatable");
  if (o.ssvc_technical_impact !== n.ssvc_technical_impact) changed.push("ssvc_technical_impact");
  return changed;
}

function describeChangedFields(fields: string[]): string {
  const labels: Record<string, string> = {
    cvss_score: "CVSS score updated",
    is_kev: "added to CISA KEV",
    ssvc_exploitation: "exploitation status changed",
    ssvc_automatable: "automatable status changed",
    ssvc_technical_impact: "technical impact changed",
  };
  return fields.map((f) => labels[f] ?? f).join(", ");
}

// Check A: exploitation escalated to 'active' for any finding (no CVSS threshold)
async function checkExploitationEscalations(): Promise<void> {
  const findings = dbAll<FindingWithEnrichment>(
    `SELECT f.id, f.target_id, f.cve_id, f.cvss_score, f.cvss_severity,
            f.description, f.nvd_url, f.alerted, f.enrichment_fingerprint,
            f.exploitation_alert_sent,
            t.name AS target_name, t.min_alert_cvss_score,
            CASE WHEN k.cve_id IS NOT NULL THEN 1 ELSE 0 END AS is_kev,
            s.exploitation AS ssvc_exploitation,
            s.automatable AS ssvc_automatable,
            s.technical_impact AS ssvc_technical_impact
     FROM cve_findings f
     JOIN cve_targets t ON f.target_id = t.id AND t.active = 1
     JOIN cisa_ssvc s ON f.cve_id = s.cve_id
     LEFT JOIN cisa_kev k ON f.cve_id = k.cve_id
     WHERE s.exploitation = 'active'
       AND (f.exploitation_alert_sent IS NULL OR f.exploitation_alert_sent != 'active')`
  );

  if (findings.length === 0) return;

  // Group by target
  const byTarget = new Map<number, FindingWithEnrichment[]>();
  for (const f of findings) {
    const arr = byTarget.get(f.target_id) ?? [];
    arr.push(f);
    byTarget.set(f.target_id, arr);
  }

  for (const [, group] of byTarget) {
    const sorted = [...group].sort((a, b) => (b.cvss_score ?? 0) - (a.cvss_score ?? 0));
    const top = sorted[0]!;
    const targetName = top.target_name;

    const message =
      sorted.length === 1
        ? `Exploitation escalated to ACTIVE for ${targetName}: ${top.cve_id}${top.cvss_score !== null ? ` (CVSS ${top.cvss_score.toFixed(1)} ${top.cvss_severity ?? ""})` : ""}${top.ssvc_automatable === "yes" ? " | Automatable: yes" : ""}${top.ssvc_technical_impact === "total" ? " | Total impact" : ""}`
        : `${sorted.length} CVEs now actively exploited for ${targetName} (top: ${top.cve_id}${top.cvss_score !== null ? `, CVSS ${top.cvss_score.toFixed(1)}` : ""})`;

    const payload: AlertPayload = {
      serverName: targetName,
      url: top.nvd_url ?? `https://nvd.nist.gov/vuln/detail/${top.cve_id}`,
      alertType: "CVE_EXPLOIT_ESCALATION",
      statusCode: null,
      responseTimeMs: null,
      threshold: null,
      diffId: null,
      diffViewUrl: `${BASE_URL}/cve/${top.target_id}`,
      detectedAt: new Date().toISOString(),
      message,
      cveId: top.cve_id,
      cvssScore: top.cvss_score,
      cvssSeverity: top.cvss_severity,
      previousExploitation: top.exploitation_alert_sent ?? "none",
      cveDigest: sorted.length > 1
        ? sorted.map((c) => ({ cveId: c.cve_id, cvssScore: c.cvss_score, cvssSeverity: c.cvss_severity }))
        : undefined,
    };

    await sendAlert(payload);

    for (const f of group) {
      dbRun(
        "UPDATE cve_findings SET exploitation_alert_sent = 'active' WHERE id = ?",
        f.id
      );
    }
  }
}

// Check B: above-threshold findings whose enrichment data changed since last alert
async function checkEnrichmentUpdates(): Promise<void> {
  const findings = dbAll<FindingWithEnrichment>(
    `SELECT f.id, f.target_id, f.cve_id, f.cvss_score, f.cvss_severity,
            f.description, f.nvd_url, f.alerted, f.enrichment_fingerprint,
            f.exploitation_alert_sent,
            t.name AS target_name, t.min_alert_cvss_score,
            CASE WHEN k.cve_id IS NOT NULL THEN 1 ELSE 0 END AS is_kev,
            s.exploitation AS ssvc_exploitation,
            s.automatable AS ssvc_automatable,
            s.technical_impact AS ssvc_technical_impact
     FROM cve_findings f
     JOIN cve_targets t ON f.target_id = t.id AND t.active = 1
     LEFT JOIN cisa_kev k ON f.cve_id = k.cve_id
     LEFT JOIN cisa_ssvc s ON f.cve_id = s.cve_id
     WHERE f.alerted = 1
       AND f.cvss_score IS NOT NULL
       AND f.cvss_score >= t.min_alert_cvss_score`
  );

  const toAlert: Array<{ finding: FindingWithEnrichment; newFp: string; changedFields: string[] }> = [];

  for (const f of findings) {
    const newFp = buildEnrichmentFingerprint({
      cvss_score: f.cvss_score,
      cvss_severity: f.cvss_severity,
      is_kev: f.is_kev,
      ssvc_exploitation: f.ssvc_exploitation,
      ssvc_automatable: f.ssvc_automatable,
      ssvc_technical_impact: f.ssvc_technical_impact,
    });

    // Skip if fingerprint unchanged or no previous fingerprint (not yet set means no baseline to compare)
    if (!f.enrichment_fingerprint || f.enrichment_fingerprint === newFp) continue;

    const changedFields = detectChangedFields(f.enrichment_fingerprint, newFp);
    if (changedFields.length > 0) {
      toAlert.push({ finding: f, newFp, changedFields });
    }
  }

  if (toAlert.length === 0) return;

  // Group by target
  const byTarget = new Map<number, typeof toAlert>();
  for (const item of toAlert) {
    const arr = byTarget.get(item.finding.target_id) ?? [];
    arr.push(item);
    byTarget.set(item.finding.target_id, arr);
  }

  for (const [, group] of byTarget) {
    const sorted = [...group].sort((a, b) => (b.finding.cvss_score ?? 0) - (a.finding.cvss_score ?? 0));
    const topItem = sorted[0]!;
    const top = topItem.finding;
    const targetName = top.target_name;

    const allChangedFields = [...new Set(group.flatMap((g) => g.changedFields))];

    const message =
      sorted.length === 1
        ? `CVE updated for ${targetName}: ${top.cve_id} — ${describeChangedFields(topItem.changedFields)}`
        : `${sorted.length} CVEs updated for ${targetName}: ${describeChangedFields(allChangedFields)}`;

    const payload: AlertPayload = {
      serverName: targetName,
      url: top.nvd_url ?? `https://nvd.nist.gov/vuln/detail/${top.cve_id}`,
      alertType: "CVE_UPDATED",
      statusCode: null,
      responseTimeMs: null,
      threshold: null,
      diffId: null,
      diffViewUrl: `${BASE_URL}/cve/${top.target_id}`,
      detectedAt: new Date().toISOString(),
      message,
      cveId: top.cve_id,
      cvssScore: top.cvss_score,
      cvssSeverity: top.cvss_severity,
      changedFields: allChangedFields,
      cveDigest: sorted.length > 1
        ? sorted.map((i) => ({ cveId: i.finding.cve_id, cvssScore: i.finding.cvss_score, cvssSeverity: i.finding.cvss_severity }))
        : undefined,
    };

    await sendAlert(payload);

    for (const { finding, newFp } of group) {
      dbRun(
        "UPDATE cve_findings SET enrichment_fingerprint = ? WHERE id = ?",
        newFp,
        finding.id
      );
    }
  }
}

export async function checkEnrichmentAlerts(): Promise<void> {
  try {
    await checkExploitationEscalations();
  } catch (err) {
    console.error("[enrichment-alerter] exploitation escalation check failed:", err);
  }
  try {
    await checkEnrichmentUpdates();
  } catch (err) {
    console.error("[enrichment-alerter] enrichment update check failed:", err);
  }
}
