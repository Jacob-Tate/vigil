import axios from "axios";
import { AlertPayload } from "../types";
import { INotifier } from "./types";

const THEME_COLORS: Record<string, string> = {
  DOWN: "FF4444",
  DEGRADED: "FF9900",
  CONTENT_CHANGED: "5865F2",
  RECOVERED: "2ECC71",
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

    const facts = [
      { name: "URL", value: payload.url },
      { name: "Alert Type", value: payload.alertType },
    ];

    if (payload.statusCode !== null) {
      facts.push({ name: "HTTP Status", value: String(payload.statusCode) });
    }
    if (payload.responseTimeMs !== null) {
      facts.push({ name: "Response Time", value: `${payload.responseTimeMs}ms` });
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
