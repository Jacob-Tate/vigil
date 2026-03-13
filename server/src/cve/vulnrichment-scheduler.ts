import { syncVulnrichment } from "./vulnrichment-importer";

const hours = Math.max(1, parseFloat(process.env["VULNRICHMENT_SYNC_INTERVAL_HOURS"] ?? "24"));
const CHECK_INTERVAL_MS = hours * 60 * 60 * 1000;

let intervalHandle: ReturnType<typeof setInterval> | null = null;

async function runScheduledSync(): Promise<void> {
  try {
    console.log("[vulnrichment-scheduler] syncing CISA vulnrichment SSVC data");
    const result = await syncVulnrichment();
    console.log(
      `[vulnrichment-scheduler] synced ${result.count} SSVC entries (HEAD: ${result.repoVersion.slice(0, 8)})`
    );
  } catch (err) {
    console.error("[vulnrichment-scheduler] error during scheduled sync:", err);
  }
}

export function startVulnrichmentScheduler(): void {
  if (intervalHandle) return;
  intervalHandle = setInterval(() => {
    void runScheduledSync();
  }, CHECK_INTERVAL_MS);
  console.log(
    `[vulnrichment-scheduler] started — syncing every ${hours} hour(s)`
  );
}

export function stopVulnrichmentScheduler(): void {
  if (intervalHandle) {
    clearInterval(intervalHandle);
    intervalHandle = null;
  }
  console.log("[vulnrichment-scheduler] stopped");
}
