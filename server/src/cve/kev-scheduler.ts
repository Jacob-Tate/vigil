import { syncKev } from "./kev-importer";

const hours = Math.max(1, parseFloat(process.env["KEV_SYNC_INTERVAL_HOURS"] ?? "24"));
const CHECK_INTERVAL_MS = hours * 60 * 60 * 1000;

let intervalHandle: ReturnType<typeof setInterval> | null = null;

async function runScheduledSync(): Promise<void> {
  try {
    console.log("[kev-scheduler] syncing CISA KEV catalog");
    const result = await syncKev();
    console.log(
      `[kev-scheduler] synced ${result.count} KEV entries (catalog v${result.catalogVersion})`
    );
  } catch (err) {
    console.error("[kev-scheduler] error during scheduled sync:", err);
  }
}

export function startKevScheduler(): void {
  if (intervalHandle) return;
  intervalHandle = setInterval(() => {
    void runScheduledSync();
  }, CHECK_INTERVAL_MS);
  console.log(
    `[kev-scheduler] started — syncing every ${hours} hour(s)`
  );
}

export function stopKevScheduler(): void {
  if (intervalHandle) {
    clearInterval(intervalHandle);
    intervalHandle = null;
  }
  console.log("[kev-scheduler] stopped");
}
