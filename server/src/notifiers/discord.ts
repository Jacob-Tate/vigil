import axios from "axios";
import { AlertPayload } from "../types";
import { INotifier } from "./types";

const COLORS: Record<string, number> = {
  DOWN: 0xff4444,
  DEGRADED: 0xff9900,
  CONTENT_CHANGED: 0x5865f2,
  RECOVERED: 0x2ecc71,
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

    const fields = [
      { name: "URL", value: payload.url, inline: true },
      { name: "Status", value: payload.alertType, inline: true },
    ];

    if (payload.statusCode !== null) {
      fields.push({ name: "HTTP Status", value: String(payload.statusCode), inline: true });
    }
    if (payload.responseTimeMs !== null) {
      fields.push({ name: "Response Time", value: `${payload.responseTimeMs}ms`, inline: true });
    }
    if (payload.diffViewUrl) {
      fields.push({ name: "View Diff", value: payload.diffViewUrl, inline: false });
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
