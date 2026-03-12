import { writeFileSync, existsSync } from "fs";
import { join } from "path";
import { dbGet, dbAll, dbRun, SSL_SNAPSHOTS_DIR, SSL_HISTORY_DIR } from "../db/database";
import { SslTarget, SslCheck } from "../types";
import { checkSslCertificate } from "./ssl-checker";
import { evaluateSslAndAlert } from "./ssl-alerter";

const intervals = new Map<number, ReturnType<typeof setInterval>>();
const checking = new Map<number, boolean>();

export async function runCheckForTarget(target: SslTarget): Promise<void> {
  if (checking.get(target.id)) {
    console.log(`[ssl-engine] Skipping check for ${target.name} — previous check still running`);
    return;
  }
  checking.set(target.id, true);

  try {
    const result = await checkSslCertificate(target.host, target.port);

    // Save latest PEM snapshot (always overwrite)
    const snapshotPath = join(SSL_SNAPSHOTS_DIR, `${target.id}.pem`);
    if (result.pemChain) {
      writeFileSync(snapshotPath, result.pemChain, "utf-8");
    }

    // If fingerprint changed from last check, save a historical copy
    if (result.fingerprintSha256 && result.pemChain) {
      const previous = dbGet<SslCheck>(
        "SELECT * FROM ssl_checks WHERE target_id = ? ORDER BY checked_at DESC LIMIT 1",
        target.id
      );
      if (
        previous !== undefined &&
        previous.fingerprint_sha256 !== null &&
        previous.fingerprint_sha256 !== result.fingerprintSha256 &&
        previous.error === null
      ) {
        const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
        const historyPath = join(SSL_HISTORY_DIR, `${target.id}-${timestamp}.pem`);
        writeFileSync(historyPath, result.pemChain, "utf-8");
        console.log(`[ssl-engine] Cert changed for ${target.name} — historical PEM saved`);
      }
    }

    // Evaluate alerts before inserting (so previous is still the latest row)
    const fresh = dbGet<SslTarget>("SELECT * FROM ssl_targets WHERE id = ?", target.id);
    if (!fresh) return;

    const alertType = await evaluateSslAndAlert(fresh, result);

    const certFile = existsSync(snapshotPath)
      ? `ssl/snapshots/${target.id}.pem`
      : null;

    dbRun(
      `INSERT INTO ssl_checks
         (target_id, error, tls_version, subject_cn, subject_o, issuer_cn, issuer_o,
          valid_from, valid_to, days_remaining, fingerprint_sha256, serial_number,
          sans, chain_json, cert_file, alert_type)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      target.id,
      result.error,
      result.tlsVersion,
      result.subjectCn,
      result.subjectO,
      result.issuerCn,
      result.issuerO,
      result.validFrom,
      result.validTo,
      result.daysRemaining,
      result.fingerprintSha256,
      result.serialNumber,
      JSON.stringify(result.sans),
      JSON.stringify(result.chain),
      certFile,
      alertType
    );

    dbRun(
      "UPDATE ssl_targets SET last_checked_at = ? WHERE id = ?",
      new Date().toISOString(),
      target.id
    );

    const status = result.error
      ? `error: ${result.error}`
      : `${result.daysRemaining ?? "?"} days remaining`;
    console.log(`[ssl-engine] Checked ${target.name} (${target.host}:${target.port}) — ${status}`);
  } catch (err) {
    console.error(`[ssl-engine] Error checking ${target.name}:`, err);
  } finally {
    checking.set(target.id, false);
  }
}

export function scheduleTarget(target: SslTarget): void {
  if (!target.active) return;
  unscheduleTarget(target.id);

  void runCheckForTarget(target);
  const handle = setInterval(() => {
    const fresh = dbGet<SslTarget>("SELECT * FROM ssl_targets WHERE id = ?", target.id);
    if (fresh && fresh.active) {
      void runCheckForTarget(fresh);
    }
  }, target.check_interval_seconds * 1000);

  intervals.set(target.id, handle);
  console.log(`[ssl-engine] Scheduled ${target.name} every ${target.check_interval_seconds}s`);
}

export function unscheduleTarget(targetId: number): void {
  const handle = intervals.get(targetId);
  if (handle) {
    clearInterval(handle);
    intervals.delete(targetId);
    checking.delete(targetId);
  }
}

export function rescheduleTarget(target: SslTarget): void {
  unscheduleTarget(target.id);
  if (target.active) {
    scheduleTarget(target);
  }
}

export function startSslEngine(): void {
  const targets = dbAll<SslTarget>("SELECT * FROM ssl_targets WHERE active = 1");
  for (const target of targets) {
    scheduleTarget(target);
  }
  console.log(`[ssl-engine] Started monitoring ${targets.length} SSL target(s)`);
}

export function stopSslEngine(): void {
  for (const [id] of intervals) {
    unscheduleTarget(id);
  }
  console.log("[ssl-engine] Stopped");
}
