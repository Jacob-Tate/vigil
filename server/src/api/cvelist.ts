import { Router, Request, Response } from "express";
import { getCvelistSyncState, syncCvelist } from "../cve/cvelist-importer";
import { CvelistSyncState } from "../types";
import { requireAdmin } from "../middleware/auth";
import { triggerLimiter } from "../middleware/rateLimits";

const router = Router();

// In-memory sync flag — polled by frontend
let isSyncing = false;

// GET /api/cvelist/status
router.get("/status", (_req: Request, res: Response) => {
  const state: CvelistSyncState = { ...getCvelistSyncState(), is_syncing: isSyncing };
  res.json(state);
});

// POST /api/cvelist/sync
router.post("/sync", requireAdmin, triggerLimiter, (_req: Request, res: Response) => {
  if (isSyncing) {
    res.status(409).json({ error: "cvelistV5 sync already in progress" });
    return;
  }

  isSyncing = true;
  void (async () => {
    try {
      const result = await syncCvelist();
      console.log(`[cvelist-api] synced ${result.count} CVE records (HEAD: ${result.repoVersion.slice(0, 8)})`);
    } catch (err) {
      console.error("[cvelist-api] sync failed:", err);
    } finally {
      isSyncing = false;
    }
  })();

  res.json({ ok: true, message: "cvelistV5 sync started in background" });
});

export { router as cvelistRouter };
