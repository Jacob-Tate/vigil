import { syncCvelist } from "./cvelist-importer";

const hours = Math.max(1, parseFloat(process.env["CVELIST_SYNC_INTERVAL_HOURS"] ?? "24"));
const CHECK_INTERVAL_MS = hours * 60 * 60 * 1000;

let intervalHandle: ReturnType<typeof setInterval> | null = null;

async function runScheduledSync(): Promise<void> {
  try {
    console.log("[cvelist-scheduler] syncing cvelistV5 data");
    const result = await syncCvelist();
    console.log(
      `[cvelist-scheduler] synced ${result.count} CVE records (HEAD: ${result.repoVersion.slice(0, 8)})`
    );
  } catch (err) {
    console.error("[cvelist-scheduler] error during scheduled sync:", err);
  }
}

export function startCvelistScheduler(): void {
  if (intervalHandle) return;
  intervalHandle = setInterval(() => {
    void runScheduledSync();
  }, CHECK_INTERVAL_MS);
  console.log(
    `[cvelist-scheduler] started — syncing every ${hours} hour(s)`
  );
}

export function stopCvelistScheduler(): void {
  if (intervalHandle) {
    clearInterval(intervalHandle);
    intervalHandle = null;
  }
  console.log("[cvelist-scheduler] stopped");
}
