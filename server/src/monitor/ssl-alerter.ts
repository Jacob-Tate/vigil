import { dbGet, dbRun } from "../db/database";
import { SslTarget, SslCheck, SslCheckResult, SslAlertType, AlertPayload } from "../types";
import { sendAlert } from "../notifiers";
import dotenv from "dotenv";

dotenv.config();

const ALERT_COOLDOWN_SECONDS = parseInt(
  process.env.ALERT_COOLDOWN_SECONDS ?? "3600",
  10
);
const BASE_URL = process.env.BASE_URL ?? "http://localhost:5173";

function buildSslMessage(
  target: SslTarget,
  alertType: SslAlertType,
  result: SslCheckResult
): string {
  switch (alertType) {
    case "SSL_EXPIRED":
      return `${target.name} SSL certificate has EXPIRED (${result.subjectCn ?? target.host}).`;
    case "SSL_EXPIRING":
      return `${target.name} SSL certificate expires in ${result.daysRemaining ?? "?"} day(s) — threshold is ${Math.floor(target.expiry_threshold_hours / 24)} day(s).`;
    case "SSL_ERROR":
      return `${target.name} SSL check failed: ${result.error ?? "unknown error"}.`;
    case "SSL_CHANGED":
      return `${target.name} SSL certificate fingerprint changed — new cert deployed or possible MITM.`;
  }
}

export async function evaluateSslAndAlert(
  target: SslTarget,
  result: SslCheckResult
): Promise<SslAlertType | null> {
  const previous = dbGet<SslCheck>(
    "SELECT * FROM ssl_checks WHERE target_id = ? ORDER BY checked_at DESC LIMIT 1",
    target.id
  );

  let alertType: SslAlertType | null = null;

  if (result.error !== null) {
    alertType = "SSL_ERROR";
  } else if (result.daysRemaining !== null && result.daysRemaining < 0) {
    alertType = "SSL_EXPIRED";
  } else if (
    result.daysRemaining !== null &&
    result.daysRemaining <= target.expiry_threshold_hours / 24
  ) {
    alertType = "SSL_EXPIRING";
  } else if (
    previous !== undefined &&
    previous.fingerprint_sha256 !== null &&
    result.fingerprintSha256 !== null &&
    previous.fingerprint_sha256 !== result.fingerprintSha256 &&
    previous.error === null
  ) {
    alertType = "SSL_CHANGED";
  }

  if (alertType === null) return null;

  // Cooldown check for repeating SSL_EXPIRING and SSL_ERROR alerts
  const isCooldownAlert = alertType === "SSL_EXPIRING" || alertType === "SSL_ERROR";
  if (isCooldownAlert) {
    const lastAlertedAt = target.last_alerted_at
      ? new Date(target.last_alerted_at).getTime()
      : 0;
    const secondsSince = (Date.now() - lastAlertedAt) / 1000;
    const isSameType = target.last_alert_type === alertType;

    if (isSameType && secondsSince < ALERT_COOLDOWN_SECONDS) {
      return alertType; // suppressed — still return so engine can record it
    }
  }

  const payload: AlertPayload = {
    serverName: target.name,
    url: `https://${target.host}:${target.port}`,
    alertType,
    statusCode: null,
    responseTimeMs: null,
    threshold: null,
    diffId: null,
    diffViewUrl: `${BASE_URL}/ssl/${target.id}`,
    detectedAt: new Date().toISOString(),
    message: buildSslMessage(target, alertType, result),
    sslDaysRemaining: result.daysRemaining,
    sslFingerprint: result.fingerprintSha256,
    sslSubject: result.subjectCn,
  };

  await sendAlert(payload);

  dbRun(
    "UPDATE ssl_targets SET last_alerted_at = ?, last_alert_type = ? WHERE id = ?",
    new Date().toISOString(),
    alertType,
    target.id
  );

  return alertType;
}
