import axios from "axios";
import { AlertPayload } from "../types";
import { INotifier } from "./types";

const PUSHOVER_API = "https://api.pushover.net/1/messages.json";

const PRIORITIES: Record<string, number> = {
  DOWN: 1,
  DEGRADED: 0,
  CONTENT_CHANGED: 0,
  RECOVERED: -1,
  CVE_NEW: 0,
};

const pushover: INotifier = {
  type: "pushover",
  displayName: "Pushover",
  configSchema: {
    appToken: {
      label: "App Token",
      type: "password",
      required: true,
      placeholder: "Your Pushover application token",
    },
    userKey: {
      label: "User Key",
      type: "password",
      required: true,
      placeholder: "Your Pushover user key",
    },
  },
  async send(config: Record<string, unknown>, payload: AlertPayload): Promise<void> {
    const appToken = config.appToken as string;
    const userKey = config.userKey as string;
    if (!appToken || !userKey) throw new Error("Pushover appToken and userKey are required");

    const priority = PRIORITIES[payload.alertType] ?? 0;
    let message = payload.message;
    if (payload.diffViewUrl) {
      message += `\nDiff: ${payload.diffViewUrl}`;
    }

    const params = new URLSearchParams({
      token: appToken,
      user: userKey,
      title: `[${payload.alertType}] ${payload.serverName}`,
      message,
      priority: String(priority),
      ...(priority === 2 ? { retry: "60", expire: "3600" } : {}),
    });

    await axios.post(PUSHOVER_API, params.toString(), {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });
  },
};

export { pushover };
