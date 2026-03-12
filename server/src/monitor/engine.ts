import { writeFileSync, readFileSync, renameSync, existsSync } from "fs";
import { join } from "path";
import { dbGet, dbAll, dbRun, SNAPSHOTS_DIR, DIFFS_DIR } from "../db/database";
import { Server } from "../types";
import { checkServer } from "./checker";
import { hashContent } from "./hasher";
import { computeDiff } from "./differ";
import { evaluateAndAlert } from "./alerter";
import { captureScreenshot } from "./screenshotter";

const intervals = new Map<number, ReturnType<typeof setInterval>>();
const checking = new Map<number, boolean>();

export async function runCheckForServer(server: Server): Promise<void> {
  if (checking.get(server.id)) {
    console.log(`[engine] Skipping check for ${server.name} — previous check still running`);
    return;
  }
  checking.set(server.id, true);

  try {
    const result = await checkServer(server.url, server.response_time_threshold_ms);
    const contentHash = result.rawHtml ? hashContent(result.rawHtml) : null;

    let contentChanged = false;
    let diffId: number | null = null;

    if (result.rawHtml && contentHash) {
      const fresh = dbGet<Server>("SELECT * FROM servers WHERE id = ?", server.id);
      if (!fresh) return;

      if (!fresh.baseline_hash) {
        const snapshotPath = join(SNAPSHOTS_DIR, `${server.id}.html`);
        writeFileSync(snapshotPath, result.rawHtml, "utf-8");
        dbRun(
          "UPDATE servers SET baseline_hash = ?, baseline_file = ? WHERE id = ?",
          contentHash,
          `snapshots/${server.id}.html`,
          server.id
        );
        console.log(`[engine] Baseline set for ${server.name}`);
        captureScreenshot(server.id, server.url).catch((err: unknown) => {
          console.warn(`[engine] Screenshot failed for ${server.name}:`, err);
        });
      } else if (fresh.baseline_hash !== contentHash) {
        const oldPath = join(SNAPSHOTS_DIR, `${server.id}.html`);
        const oldHtml = existsSync(oldPath) ? readFileSync(oldPath, "utf-8") : "";

        const diffContent = computeDiff(oldHtml, result.rawHtml, server.name);
        const timestamp = new Date().toISOString().replace(/[:.]/g, "-");

        const tmpPath = join(DIFFS_DIR, `tmp-${server.id}-${timestamp}.html`);
        writeFileSync(tmpPath, diffContent, "utf-8");

        const diffInfo = dbRun(
          "INSERT INTO content_diffs (server_id, old_hash, new_hash, diff_file) VALUES (?, ?, ?, ?)",
          server.id,
          fresh.baseline_hash,
          contentHash,
          `diffs/tmp-${server.id}-${timestamp}.html`
        );

        diffId = Number(diffInfo.lastInsertRowid);
        const finalFilename = `${diffId}-${timestamp}.html`;
        const finalPath = join(DIFFS_DIR, finalFilename);
        renameSync(tmpPath, finalPath);

        dbRun(
          "UPDATE content_diffs SET diff_file = ? WHERE id = ?",
          `diffs/${finalFilename}`,
          diffId
        );

        writeFileSync(oldPath, result.rawHtml, "utf-8");
        dbRun(
          "UPDATE servers SET baseline_hash = ?, baseline_file = ? WHERE id = ?",
          contentHash,
          `snapshots/${server.id}.html`,
          server.id
        );

        contentChanged = true;
        console.log(`[engine] Content changed for ${server.name}, diff saved as ${finalFilename}`);
        captureScreenshot(server.id, server.url).catch((err: unknown) => {
          console.warn(`[engine] Screenshot failed for ${server.name}:`, err);
        });
      }
    }

    dbRun(
      `INSERT INTO checks (server_id, status_code, response_time_ms, is_up, content_hash, content_changed, diff_id)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      server.id,
      result.statusCode,
      result.responseTimeMs,
      result.isUp ? 1 : 0,
      contentHash,
      contentChanged ? 1 : 0,
      diffId
    );

    const freshServer = dbGet<Server>("SELECT * FROM servers WHERE id = ?", server.id);
    if (!freshServer) return;
    await evaluateAndAlert(freshServer, {
      isUp: result.isUp,
      statusCode: result.statusCode,
      responseTimeMs: result.responseTimeMs,
      contentChanged,
      diffId,
    });
  } catch (err) {
    console.error(`[engine] Error checking ${server.name}:`, err);
  } finally {
    checking.set(server.id, false);
  }
}

export function scheduleServer(server: Server): void {
  if (!server.active) return;
  unscheduleServer(server.id);

  void runCheckForServer(server);
  const handle = setInterval(() => {
    const fresh = dbGet<Server>("SELECT * FROM servers WHERE id = ?", server.id);
    if (fresh && fresh.active) {
      void runCheckForServer(fresh);
    }
  }, server.interval_seconds * 1000);

  intervals.set(server.id, handle);
  console.log(`[engine] Scheduled ${server.name} every ${server.interval_seconds}s`);
}

export function unscheduleServer(serverId: number): void {
  const handle = intervals.get(serverId);
  if (handle) {
    clearInterval(handle);
    intervals.delete(serverId);
    checking.delete(serverId);
  }
}

export function rescheduleServer(server: Server): void {
  unscheduleServer(server.id);
  if (server.active) {
    scheduleServer(server);
  }
}

export function startEngine(): void {
  const servers = dbAll<Server>("SELECT * FROM servers WHERE active = 1");
  for (const server of servers) {
    scheduleServer(server);
  }
  console.log(`[engine] Started monitoring ${servers.length} server(s)`);
}

export function stopEngine(): void {
  for (const [id] of intervals) {
    unscheduleServer(id);
  }
  console.log("[engine] Stopped");
}
