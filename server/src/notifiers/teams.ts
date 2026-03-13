import axios from "axios";
import { AlertPayload } from "../types";
import { INotifier } from "./types";

const THEME_COLORS: Record<string, string> = {
  DOWN: "FF4444",
  DEGRADED: "FF9900",
  CONTENT_CHANGED: "5865F2",
  RECOVERED: "2ECC71",
  SSL_EXPIRING: "FF9900",
  SSL_EXPIRED: "FF4444",
  SSL_ERROR: "FF4444",
  SSL_CHANGED: "9B59B6",
  CVE_NEW: "E74C3C",
};

const teams: INotifier = {
  type: "teams",
  displayName: "Microsoft Teams",
  configSchema: {
    webhookUrl: {
      label: "Webhook URL",
      type: "text",
      required: true,
      placeholder: "https://outlook.office.com/webhook/...",
    },
  },
  async send(config: Record<string, unknown>, payload: AlertPayload): Promise<void> {
    const webhookUrl = config.webhookUrl as string;
    if (!webhookUrl) throw new Error("Teams webhookUrl is required");

    const facts: { name: string; value: string }[] = [
      { name: "Alert Type", value: payload.alertType },
    ];

    if (payload.alertType === "CVE_NEW") {
      if (payload.cveId) facts.push({ name: "CVE ID", value: payload.cveId });
      if (payload.cvssScore !== null && payload.cvssScore !== undefined) {
        facts.push({
          name: "CVSS Score",
          value: `${payload.cvssScore.toFixed(1)} ${payload.cvssSeverity ?? ""}`.trim(),
        });
      }
      facts.push({ name: "NVD Link", value: payload.url });
    } else {
      facts.push({ name: "URL", value: payload.url });
      if (payload.statusCode !== null) {
        facts.push({ name: "HTTP Status", value: String(payload.statusCode) });
      }
      if (payload.responseTimeMs !== null) {
        facts.push({ name: "Response Time", value: `${payload.responseTimeMs}ms` });
      }
    }

    const sections: unknown[] = [
      {
        activityTitle: `**[${payload.alertType}]** ${payload.serverName}`,
        activityText: payload.message,
        facts,
      },
    ];

    if (payload.diffViewUrl) {
      sections.push({
        potentialAction: [
          {
            "@type": "OpenUri",
            name: "View Diff",
            targets: [{ os: "default", uri: payload.diffViewUrl }],
          },
        ],
      });
    }

    // Legacy MessageCard format (broad compatibility)
    await axios.post(webhookUrl, {
      "@type": "MessageCard",
      "@context": "https://schema.org/extensions",
      themeColor: THEME_COLORS[payload.alertType] ?? "999999",
      summary: `[${payload.alertType}] ${payload.serverName}`,
      sections,
    });
  },
};

export { teams };
