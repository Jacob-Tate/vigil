import { dbAll } from "../db/database";
import { AlertPayload, NotificationChannel } from "../types";
import { INotifier } from "./types";
import { discord } from "./discord";
import { pushover } from "./pushover";
import { teams } from "./teams";

export const NOTIFIER_MAP: Record<string, INotifier> = {
  discord,
  pushover,
  teams,
};

export async function sendAlert(
  payload: AlertPayload,
  channels?: NotificationChannel[]
): Promise<void> {
  const activeChannels =
    channels ??
    dbAll<NotificationChannel>("SELECT * FROM notification_channels WHERE active = 1");

  const results = await Promise.allSettled(
    activeChannels.map(async (ch) => {
      const notifier = NOTIFIER_MAP[ch.type];
      if (!notifier) {
        console.warn(`[notifiers] Unknown notifier type: ${ch.type}`);
        return;
      }
      const config = JSON.parse(ch.config_json) as Record<string, unknown>;
      await notifier.send(config, payload);
    })
  );

  for (const result of results) {
    if (result.status === "rejected") {
      console.error("[notifiers] Alert delivery failed:", result.reason);
    }
  }
}
