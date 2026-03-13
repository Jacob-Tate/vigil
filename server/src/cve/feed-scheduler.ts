import { checkMeta, importFeed, needsUpdate } from "./feed-importer";
import { evaluateAllCveTargets } from "./cve-engine";

const hours = Math.max(1, parseFloat(process.env["NVD_SYNC_INTERVAL_HOURS"] ?? "2"));
const CHECK_INTERVAL_MS = hours * 60 * 60 * 1000;

let intervalHandle: ReturnType<typeof setInterval> | null = null;

async function runScheduledUpdate(): Promise<void> {
  try {
    const changed = await needsUpdate("modified");
    if (!changed) {
      console.log("[feed-scheduler] modified feed unchanged, skipping");
      return;
    }
    console.log("[feed-scheduler] modified feed changed — importing");
    const meta = await checkMeta("modified");
    console.log(`[feed-scheduler] lastModified: ${meta.lastModifiedDate}`);
    const count = await importFeed("modified");
    console.log(`[feed-scheduler] imported ${count} CVEs from modified feed`);
    await evaluateAllCveTargets();
  } catch (err) {
    console.error("[feed-scheduler] error during scheduled update:", err);
  }
}

export function startFeedScheduler(): void {
  if (intervalHandle) return;
  intervalHandle = setInterval(() => {
    void runScheduledUpdate();
  }, CHECK_INTERVAL_MS);
  console.log(
    `[feed-scheduler] started — checking modified feed every ${hours} hour(s)`
  );
}

export function stopFeedScheduler(): void {
  if (intervalHandle) {
    clearInterval(intervalHandle);
    intervalHandle = null;
  }
  console.log("[feed-scheduler] stopped");
}
