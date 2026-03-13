import { Router, Request, Response } from "express";
import { getKevSyncState, syncKev } from "../cve/kev-importer";
import { KevSyncState } from "../types";
import { requireAdmin } from "../middleware/auth";
import { triggerLimiter } from "../middleware/rateLimits";

const router = Router();

// In-memory sync flag — polled by frontend
let isSyncing = false;

// GET /api/kev/status
router.get("/status", (_req: Request, res: Response) => {
  const state: KevSyncState = { ...getKevSyncState(), is_syncing: isSyncing };
  res.json(state);
});

// POST /api/kev/sync
router.post("/sync", requireAdmin, triggerLimiter, (_req: Request, res: Response) => {
  if (isSyncing) {
    res.status(409).json({ error: "KEV sync already in progress" });
    return;
  }

  isSyncing = true;
  void (async () => {
    try {
      const result = await syncKev();
      console.log(`[kev-api] synced ${result.count} KEV entries (v${result.catalogVersion})`);
    } catch (err) {
      console.error("[kev-api] sync failed:", err);
    } finally {
      isSyncing = false;
    }
  })();

  res.json({ ok: true, message: "KEV sync started in background" });
});

export { router as kevRouter };
