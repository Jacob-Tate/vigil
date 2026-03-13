import axios from "axios";
import { AlertPayload } from "../types";
import { INotifier } from "./types";

const COLORS: Record<string, number> = {
  DOWN: 0xff4444,
  DEGRADED: 0xff9900,
  CONTENT_CHANGED: 0x5865f2,
  RECOVERED: 0x2ecc71,
  SSL_EXPIRING: 0xff9900,
  SSL_EXPIRED: 0xff4444,
  SSL_ERROR: 0xff4444,
  SSL_CHANGED: 0x9b59b6,
  CVE_NEW: 0xe74c3c,
};

const discord: INotifier = {
  type: "discord",
  displayName: "Discord",
  configSchema: {
    webhookUrl: {
      label: "Webhook URL",
      type: "text",
      required: true,
      placeholder: "https://discord.com/api/webhooks/...",
    },
  },
  async send(config: Record<string, unknown>, payload: AlertPayload): Promise<void> {
    const webhookUrl = config.webhookUrl as string;
    if (!webhookUrl) throw new Error("Discord webhookUrl is required");

    const fields: { name: string; value: string; inline: boolean }[] = [];

    if (payload.alertType === "CVE_NEW") {
      if (payload.cveDigest && payload.cveDigest.length > 1) {
        // Digest: list top CVEs (Discord allows up to 25 fields)
        const display = payload.cveDigest.slice(0, 23);
        for (const c of display) {
          fields.push({
            name: c.cveId,
            value: `CVSS ${c.cvssScore?.toFixed(1) ?? "N/A"} ${c.cvssSeverity ?? ""}`.trim(),
            inline: true,
          });
        }
        if (payload.cveDigest.length > 23) {
          fields.push({ name: "…and more", value: `+${payload.cveDigest.length - 23} additional CVEs`, inline: false });
        }
      } else {
        if (payload.cveId) {
          fields.push({ name: "CVE ID", value: payload.cveId, inline: true });
        }
        if (payload.cvssScore !== null && payload.cvssScore !== undefined) {
          fields.push({
            name: "CVSS Score",
            value: `${payload.cvssScore.toFixed(1)} ${payload.cvssSeverity ?? ""}`.trim(),
            inline: true,
          });
        }
        fields.push({ name: "NVD Link", value: payload.url, inline: false });
      }
      if (payload.diffViewUrl) {
        fields.push({ name: "View Findings", value: payload.diffViewUrl, inline: false });
      }
    } else {
      fields.push({ name: "URL", value: payload.url, inline: true });
      fields.push({ name: "Status", value: payload.alertType, inline: true });
      if (payload.statusCode !== null) {
        fields.push({ name: "HTTP Status", value: String(payload.statusCode), inline: true });
      }
      if (payload.responseTimeMs !== null) {
        fields.push({ name: "Response Time", value: `${payload.responseTimeMs}ms`, inline: true });
      }
      if (payload.diffViewUrl) {
        fields.push({ name: "View Diff", value: payload.diffViewUrl, inline: false });
      }
    }

    await axios.post(webhookUrl, {
      embeds: [
        {
          title: `[${payload.alertType}] ${payload.serverName}`,
          description: payload.message,
          color: COLORS[payload.alertType] ?? 0x999999,
          fields,
          timestamp: payload.detectedAt,
        },
      ],
    });
  },
};

export { discord };
