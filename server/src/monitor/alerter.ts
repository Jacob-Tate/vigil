import { dbGet, dbRun } from "../db/database";
import { Server, Check, AlertType, AlertPayload } from "../types";
import { sendAlert } from "../notifiers";
import dotenv from "dotenv";

dotenv.config();

const ALERT_COOLDOWN_SECONDS = parseInt(
  process.env.ALERT_COOLDOWN_SECONDS ?? "3600",
  10
);
const BASE_URL = process.env.BASE_URL ?? "http://localhost:5173";

function buildMessage(
  server: Server,
  alertType: AlertType,
  check: { statusCode: number | null; responseTimeMs: number }
): string {
  switch (alertType) {
    case "DOWN":
      return `${server.name} is DOWN. Status: ${check.statusCode ?? "no response"}, Response time: ${check.responseTimeMs}ms`;
    case "DEGRADED":
      return `${server.name} is DEGRADED. Response time ${check.responseTimeMs}ms exceeds threshold of ${server.response_time_threshold_ms}ms`;
    case "CONTENT_CHANGED":
      return `${server.name} content has changed. A diff has been recorded.`;
    case "RECOVERED":
      return `${server.name} has RECOVERED. Status: ${check.statusCode}, Response time: ${check.responseTimeMs}ms`;
  }
}

export async function evaluateAndAlert(
  server: Server,
  currentCheck: {
    isUp: boolean;
    statusCode: number | null;
    responseTimeMs: number;
    contentChanged: boolean;
    diffId: number | null;
  }
): Promise<void> {
  const previousCheck = dbGet<Check>(
    "SELECT * FROM checks WHERE server_id = ? ORDER BY checked_at DESC LIMIT 1",
    server.id
  );

  const wasUp = previousCheck ? previousCheck.is_up === 1 : true;
  const isUp = currentCheck.isUp;
  const isDegraded =
    isUp && currentCheck.responseTimeMs > server.response_time_threshold_ms;

  const alertsToSend: AlertType[] = [];

  if (wasUp && !isUp) {
    alertsToSend.push("DOWN");
  }

  if (!wasUp && !isUp) {
    const lastAlertedAt = server.last_alerted_at
      ? new Date(server.last_alerted_at).getTime()
      : 0;
    const secondsSinceAlert = (Date.now() - lastAlertedAt) / 1000;
    if (secondsSinceAlert >= ALERT_COOLDOWN_SECONDS) {
      alertsToSend.push("DOWN");
    }
  }

  if (!wasUp && isUp) {
    alertsToSend.push("RECOVERED");
  }

  if (currentCheck.contentChanged && currentCheck.diffId !== null) {
    alertsToSend.push("CONTENT_CHANGED");
  }

  const wasDegraded = previousCheck
    ? previousCheck.is_up === 1 &&
      (previousCheck.response_time_ms ?? 0) > server.response_time_threshold_ms
    : false;
  if (isDegraded && !wasDegraded) {
    alertsToSend.push("DEGRADED");
  }

  if (alertsToSend.length === 0) return;

  for (const alertType of alertsToSend) {
    const diffViewUrl =
      alertType === "CONTENT_CHANGED" && currentCheck.diffId !== null
        ? `${BASE_URL}/servers/${server.id}/diff/${currentCheck.diffId}`
        : null;

    const payload: AlertPayload = {
      serverName: server.name,
      url: server.url,
      alertType,
      statusCode: currentCheck.statusCode,
      responseTimeMs: currentCheck.responseTimeMs,
      threshold: server.response_time_threshold_ms,
      diffId: currentCheck.diffId,
      diffViewUrl,
      detectedAt: new Date().toISOString(),
      message: buildMessage(server, alertType, currentCheck),
    };

    await sendAlert(payload);

    dbRun(
      "UPDATE servers SET last_alerted_at = ?, last_alert_type = ? WHERE id = ?",
      new Date().toISOString(),
      alertType,
      server.id
    );
  }
}
