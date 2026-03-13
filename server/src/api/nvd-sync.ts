import { Router, Request, Response } from "express";
import { param, validationResult } from "express-validator";
import { dbAll } from "../db/database";
import { NvdFeedState, NvdSyncStatus } from "../types";
import {
  ALL_FEED_NAMES,
  importFeed,
  needsUpdate,
} from "../cve/feed-importer";
import { evaluateAllCveTargets } from "../cve/cve-engine";
import { requireAdmin } from "../middleware/auth";
import { triggerLimiter } from "../middleware/rateLimits";

const router = Router();

// In-memory import state — polled by frontend
const importState: NvdSyncStatus = {
  isImporting: false,
  currentFeed: null,
  feedProgress: 0,
  feedsDone: 0,
  feedsTotal: 0,
  error: null,
  startedAt: null,
  feedStates: [],
};

// GET /api/nvd/status
router.get("/status", (_req: Request, res: Response) => {
  const feedStates = dbAll<NvdFeedState>(
    "SELECT * FROM nvd_feed_state ORDER BY feed_name"
  );
  res.json({ ...importState, feedStates });
});

// Run a full import of all feeds in the background
async function runFullSync(): Promise<void> {
  if (importState.isImporting) return;

  importState.isImporting = true;
  importState.error = null;
  importState.startedAt = new Date().toISOString();
  importState.feedsDone = 0;
  importState.feedsTotal = ALL_FEED_NAMES.length;
  importState.feedProgress = 0;
  importState.currentFeed = null;

  try {
    for (const feedName of ALL_FEED_NAMES) {
      importState.currentFeed = feedName;
      importState.feedProgress = 0;
      console.log(`[nvd-sync] Importing feed: ${feedName}`);

      await importFeed(feedName, (processed) => {
        importState.feedProgress = processed;
      });

      importState.feedsDone++;
      console.log(
        `[nvd-sync] Feed ${feedName} done (${importState.feedsDone}/${importState.feedsTotal})`
      );
    }

    console.log("[nvd-sync] Full sync complete — evaluating CVE targets");
    await evaluateAllCveTargets();
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    importState.error = msg;
    console.error("[nvd-sync] Sync failed:", err);
  } finally {
    importState.isImporting = false;
    importState.currentFeed = null;
    importState.feedProgress = 0;
  }
}

// Run import of a single feed
async function runFeedSync(feedName: string): Promise<void> {
  if (importState.isImporting) return;

  importState.isImporting = true;
  importState.error = null;
  importState.startedAt = new Date().toISOString();
  importState.feedsDone = 0;
  importState.feedsTotal = 1;
  importState.feedProgress = 0;
  importState.currentFeed = feedName;

  try {
    await importFeed(feedName, (processed) => {
      importState.feedProgress = processed;
    });
    importState.feedsDone = 1;
    await evaluateAllCveTargets();
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    importState.error = msg;
    console.error(`[nvd-sync] Feed ${feedName} failed:`, err);
  } finally {
    importState.isImporting = false;
    importState.currentFeed = null;
    importState.feedProgress = 0;
  }
}

// POST /api/nvd/sync  — trigger full import
router.post("/sync", requireAdmin, triggerLimiter, (_req: Request, res: Response) => {
  if (importState.isImporting) {
    res.status(409).json({ error: "Import already in progress" });
    return;
  }
  void runFullSync();
  res.json({ ok: true, message: "Full NVD sync started in background" });
});

// POST /api/nvd/sync/check  — sync only feeds that have changed
router.post("/sync/check", requireAdmin, triggerLimiter, (_req: Request, res: Response) => {
  if (importState.isImporting) {
    res.status(409).json({ error: "Import already in progress" });
    return;
  }

  void (async () => {
    importState.isImporting = true;
    importState.error = null;
    importState.startedAt = new Date().toISOString();
    importState.feedsDone = 0;
    importState.feedsTotal = 0;
    importState.feedProgress = 0;

    try {
      // Determine which feeds need updating
      const toUpdate: string[] = [];
      for (const feedName of ALL_FEED_NAMES) {
        const changed = await needsUpdate(feedName);
        if (changed) toUpdate.push(feedName);
      }

      importState.feedsTotal = toUpdate.length;
      if (toUpdate.length === 0) {
        console.log("[nvd-sync] All feeds are up to date");
        return;
      }

      for (const feedName of toUpdate) {
        importState.currentFeed = feedName;
        importState.feedProgress = 0;
        await importFeed(feedName, (processed) => {
          importState.feedProgress = processed;
        });
        importState.feedsDone++;
      }

      await evaluateAllCveTargets();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      importState.error = msg;
    } finally {
      importState.isImporting = false;
      importState.currentFeed = null;
      importState.feedProgress = 0;
    }
  })();

  res.json({ ok: true, message: "Selective sync started in background" });
});

// POST /api/nvd/sync/:feedName  — import a specific feed
router.post(
  "/sync/:feedName",
  requireAdmin,
  triggerLimiter,
  param("feedName").isString().trim().notEmpty(),
  (req: Request, res: Response) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    const feedName = req.params["feedName"] as string;

    if (!ALL_FEED_NAMES.includes(feedName)) {
      res.status(400).json({ error: `Unknown feed name: ${feedName}` });
      return;
    }

    if (importState.isImporting) {
      res.status(409).json({ error: "Import already in progress" });
      return;
    }

    void runFeedSync(feedName);
    res.json({ ok: true, message: `Sync of ${feedName} feed started` });
  }
);

export { router as nvdSyncRouter };
