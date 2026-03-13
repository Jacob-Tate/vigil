import { Router, Request, Response } from "express";
import { body, param, validationResult } from "express-validator";
import { readFileSync, existsSync } from "fs";
import { dbGet, dbAll, dbRun } from "../db/database";
import { Server, ServerWithStatus, Check } from "../types";
import { scheduleServer, unscheduleServer, rescheduleServer, runCheckForServer } from "../monitor/engine";
import { captureScreenshot, isScreenshotStale, screenshotPath } from "../monitor/screenshotter";
import { requireAdmin } from "../middleware/auth";
import { triggerLimiter } from "../middleware/rateLimits";

const router = Router();

function getLastCheck(serverId: number): Check | null {
  return dbGet<Check>(
    "SELECT * FROM checks WHERE server_id = ? ORDER BY checked_at DESC LIMIT 1",
    serverId
  ) ?? null;
}

// GET /api/servers
router.get("/", (_req: Request, res: Response) => {
  const servers = dbAll<Server>("SELECT * FROM servers ORDER BY created_at ASC");
  const result: ServerWithStatus[] = servers.map((s) => ({
    ...s,
    last_check: getLastCheck(s.id),
  }));
  res.json(result);
});

// GET /api/servers/:id
router.get(
  "/:id",
  param("id").isInt(),
  (req: Request, res: Response) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }
    const server = dbGet<Server>("SELECT * FROM servers WHERE id = ?", req.params["id"] as string);
    if (!server) {
      res.status(404).json({ error: "Server not found" });
      return;
    }
    res.json({ ...server, last_check: getLastCheck(server.id) });
  }
);

// POST /api/servers
router.post(
  "/",
  requireAdmin,
  body("name").isString().trim().notEmpty(),
  body("url").isURL({ require_tld: false }),
  body("interval_seconds").optional().isInt({ min: 30 }),
  body("response_time_threshold_ms").optional().isInt({ min: 100 }),
  body("ignore_patterns").optional().isArray(),
  body("ignore_patterns.*").optional().isString(),
  (req: Request, res: Response) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    const { name, url, interval_seconds = 300, response_time_threshold_ms = 3000, ignore_patterns } = req.body as {
      name: string;
      url: string;
      interval_seconds?: number;
      response_time_threshold_ms?: number;
      ignore_patterns?: string[];
    };

    const ignorePatternsJson = ignore_patterns != null ? JSON.stringify(ignore_patterns.filter(Boolean)) : null;

    try {
      const info = dbRun(
        "INSERT INTO servers (name, url, interval_seconds, response_time_threshold_ms, ignore_patterns) VALUES (?, ?, ?, ?, ?)",
        name, url, interval_seconds, response_time_threshold_ms, ignorePatternsJson
      );
      const server = dbGet<Server>("SELECT * FROM servers WHERE id = ?", info.lastInsertRowid);
      if (!server) { res.status(500).json({ error: "Failed to retrieve created server" }); return; }
      scheduleServer(server);
      res.status(201).json(server);
    } catch (err) {
      const error = err as NodeJS.ErrnoException;
      if (error.message?.includes("UNIQUE constraint")) {
        res.status(409).json({ error: "URL already exists" });
      } else {
        res.status(500).json({ error: "Failed to create server" });
      }
    }
  }
);

// PUT /api/servers/:id
router.put(
  "/:id",
  requireAdmin,
  param("id").isInt(),
  body("name").optional().isString().trim().notEmpty(),
  body("url").optional().isURL({ require_tld: false }),
  body("interval_seconds").optional().isInt({ min: 30 }),
  body("response_time_threshold_ms").optional().isInt({ min: 100 }),
  body("active").optional().isBoolean(),
  body("ignore_patterns").optional().isArray(),
  body("ignore_patterns.*").optional().isString(),
  (req: Request, res: Response) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    const server = dbGet<Server>("SELECT * FROM servers WHERE id = ?", req.params["id"] as string);
    if (!server) {
      res.status(404).json({ error: "Server not found" });
      return;
    }

    const bodyData = req.body as Partial<{
      name: string;
      url: string;
      interval_seconds: number;
      response_time_threshold_ms: number;
      active: boolean;
      ignore_patterns: string[];
    }>;

    const ignorePatternsJson = bodyData.ignore_patterns != null
      ? JSON.stringify(bodyData.ignore_patterns.filter(Boolean))
      : server.ignore_patterns;

    const updated: Server = {
      ...server,
      name: bodyData.name ?? server.name,
      url: bodyData.url ?? server.url,
      interval_seconds: bodyData.interval_seconds ?? server.interval_seconds,
      response_time_threshold_ms: bodyData.response_time_threshold_ms ?? server.response_time_threshold_ms,
      active: bodyData.active !== undefined ? (bodyData.active ? 1 : 0) : server.active,
      ignore_patterns: ignorePatternsJson,
    };

    dbRun(
      `UPDATE servers SET name = ?, url = ?, interval_seconds = ?,
       response_time_threshold_ms = ?, active = ?, ignore_patterns = ? WHERE id = ?`,
      updated.name, updated.url, updated.interval_seconds,
      updated.response_time_threshold_ms, updated.active, updated.ignore_patterns, server.id
    );

    rescheduleServer(updated);
    res.json({ ...updated, last_check: getLastCheck(server.id) });
  }
);

// DELETE /api/servers/:id
router.delete(
  "/:id",
  requireAdmin,
  param("id").isInt(),
  (req: Request, res: Response) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    const server = dbGet<Server>("SELECT * FROM servers WHERE id = ?", req.params["id"] as string);
    if (!server) {
      res.status(404).json({ error: "Server not found" });
      return;
    }

    unscheduleServer(server.id);
    dbRun("DELETE FROM servers WHERE id = ?", server.id);
    res.status(204).send();
  }
);

// POST /api/servers/:id/check
router.post(
  "/:id/check",
  requireAdmin,
  triggerLimiter,
  param("id").isInt(),
  async (req: Request, res: Response) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    const server = dbGet<Server>("SELECT * FROM servers WHERE id = ?", req.params["id"] as string);
    if (!server) {
      res.status(404).json({ error: "Server not found" });
      return;
    }

    try {
      await runCheckForServer(server);
      const lastCheck = getLastCheck(server.id);
      res.json({ ok: true, check: lastCheck });
    } catch {
      res.status(500).json({ error: "Check failed" });
    }
  }
);

// GET /api/servers/:id/screenshot
router.get(
  "/:id/screenshot",
  param("id").isInt(),
  async (req: Request, res: Response) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    const server = dbGet<Server>("SELECT * FROM servers WHERE id = ?", req.params["id"] as string);
    if (!server) {
      res.status(404).json({ error: "Server not found" });
      return;
    }

    const force = req.query["force"] === "1";

    try {
      if (force || isScreenshotStale(server.id)) {
        await captureScreenshot(server.id, server.url);
      }

      const imgPath = screenshotPath(server.id);
      if (!existsSync(imgPath)) {
        res.status(404).json({ error: "Screenshot not available" });
        return;
      }

      const buffer = readFileSync(imgPath);
      res.set("Content-Type", "image/png");
      res.set("Cache-Control", "no-cache");
      res.send(buffer);
    } catch (err) {
      console.error("[screenshot] Failed:", err);
      res.status(500).json({ error: "Failed to capture screenshot" });
    }
  }
);

// POST /api/servers/:id/reset-baseline
router.post(
  "/:id/reset-baseline",
  requireAdmin,
  param("id").isInt(),
  (req: Request, res: Response) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    const server = dbGet<Server>("SELECT * FROM servers WHERE id = ?", req.params["id"] as string);
    if (!server) {
      res.status(404).json({ error: "Server not found" });
      return;
    }

    dbRun("UPDATE servers SET baseline_hash = NULL, baseline_file = NULL WHERE id = ?", server.id);
    res.json({ ok: true, message: "Baseline cleared — next check will set a new baseline" });
  }
);

export { router as serversRouter };
