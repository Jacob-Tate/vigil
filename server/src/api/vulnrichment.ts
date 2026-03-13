import { Router, Request, Response } from "express";
import { getVulnrichmentSyncState, syncVulnrichment } from "../cve/vulnrichment-importer";
import { VulnrichmentSyncState } from "../types";
import { requireAdmin } from "../middleware/auth";
import { triggerLimiter } from "../middleware/rateLimits";

const router = Router();

// In-memory sync flag — polled by frontend
let isSyncing = false;

// GET /api/vulnrichment/status
router.get("/status", (_req: Request, res: Response) => {
  const state: VulnrichmentSyncState = { ...getVulnrichmentSyncState(), is_syncing: isSyncing };
  res.json(state);
});

// POST /api/vulnrichment/sync
router.post("/sync", requireAdmin, triggerLimiter, (_req: Request, res: Response) => {
  if (isSyncing) {
    res.status(409).json({ error: "Vulnrichment sync already in progress" });
    return;
  }

  isSyncing = true;
  void (async () => {
    try {
      const result = await syncVulnrichment();
      console.log(`[vulnrichment-api] synced ${result.count} SSVC entries (HEAD: ${result.repoVersion.slice(0, 8)})`);
    } catch (err) {
      console.error("[vulnrichment-api] sync failed:", err);
    } finally {
      isSyncing = false;
    }
  })();

  res.json({ ok: true, message: "Vulnrichment sync started in background" });
});

export { router as vulnrichmentRouter };
