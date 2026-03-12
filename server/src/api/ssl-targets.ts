import { Router, Request, Response } from "express";
import { body, param, validationResult } from "express-validator";
import { readFileSync, existsSync } from "fs";
import { join } from "path";
import { dbGet, dbAll, dbRun, SSL_SNAPSHOTS_DIR } from "../db/database";
import { SslTarget, SslCheck, SslTargetWithStatus } from "../types";
import {
  scheduleTarget,
  unscheduleTarget,
  rescheduleTarget,
  runCheckForTarget,
} from "../monitor/ssl-engine";

const router = Router();

function getLastCheck(targetId: number): SslCheck | null {
  const row = dbGet<SslCheck>(
    "SELECT * FROM ssl_checks WHERE target_id = ? ORDER BY checked_at DESC LIMIT 1",
    targetId
  );
  if (!row) return null;
  return {
    ...row,
    sans: row.sans ?? null,
    chain_json: row.chain_json ?? null,
  };
}

// GET /api/ssl/targets
router.get("/", (_req: Request, res: Response) => {
  const targets = dbAll<SslTarget>("SELECT * FROM ssl_targets ORDER BY created_at ASC");
  const result: SslTargetWithStatus[] = targets.map((t) => ({
    ...t,
    last_check: getLastCheck(t.id),
  }));
  res.json(result);
});

// GET /api/ssl/targets/:id
router.get(
  "/:id",
  param("id").isInt(),
  (req: Request, res: Response) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) { res.status(400).json({ errors: errors.array() }); return; }

    const target = dbGet<SslTarget>(
      "SELECT * FROM ssl_targets WHERE id = ?",
      req.params["id"] as string
    );
    if (!target) { res.status(404).json({ error: "SSL target not found" }); return; }

    res.json({ ...target, last_check: getLastCheck(target.id) });
  }
);

// POST /api/ssl/targets
router.post(
  "/",
  body("name").isString().trim().notEmpty(),
  body("host").isString().trim().notEmpty(),
  body("port").optional().isInt({ min: 1, max: 65535 }),
  body("check_interval_seconds").optional().isInt({ min: 60 }),
  body("expiry_threshold_hours").optional().isInt({ min: 1 }),
  body("active").optional().isBoolean(),
  (req: Request, res: Response) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) { res.status(400).json({ errors: errors.array() }); return; }

    const {
      name,
      host,
      port = 443,
      check_interval_seconds = 3600,
      expiry_threshold_hours = 168,
      active = true,
    } = req.body as {
      name: string;
      host: string;
      port?: number;
      check_interval_seconds?: number;
      expiry_threshold_hours?: number;
      active?: boolean;
    };

    // Strip protocol prefix if user pasted a full URL
    const cleanHost = host.replace(/^https?:\/\//i, "").split("/")[0] ?? host;

    try {
      const info = dbRun(
        `INSERT INTO ssl_targets (name, host, port, check_interval_seconds, expiry_threshold_hours, active)
         VALUES (?, ?, ?, ?, ?, ?)`,
        name,
        cleanHost,
        port,
        check_interval_seconds,
        expiry_threshold_hours,
        active ? 1 : 0
      );

      const created = dbGet<SslTarget>(
        "SELECT * FROM ssl_targets WHERE id = ?",
        info.lastInsertRowid
      );
      if (!created) { res.status(500).json({ error: "Failed to retrieve created target" }); return; }

      scheduleTarget(created);
      res.status(201).json(created);
    } catch (err) {
      console.error("[ssl-targets] Create error:", err);
      res.status(500).json({ error: "Failed to create SSL target" });
    }
  }
);

// PUT /api/ssl/targets/:id
router.put(
  "/:id",
  param("id").isInt(),
  body("name").optional().isString().trim().notEmpty(),
  body("host").optional().isString().trim().notEmpty(),
  body("port").optional().isInt({ min: 1, max: 65535 }),
  body("check_interval_seconds").optional().isInt({ min: 60 }),
  body("expiry_threshold_hours").optional().isInt({ min: 1 }),
  body("active").optional().isBoolean(),
  (req: Request, res: Response) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) { res.status(400).json({ errors: errors.array() }); return; }

    const target = dbGet<SslTarget>(
      "SELECT * FROM ssl_targets WHERE id = ?",
      req.params["id"] as string
    );
    if (!target) { res.status(404).json({ error: "SSL target not found" }); return; }

    const bodyData = req.body as Partial<{
      name: string;
      host: string;
      port: number;
      check_interval_seconds: number;
      expiry_threshold_hours: number;
      active: boolean;
    }>;

    let cleanHost = bodyData.host ?? target.host;
    cleanHost = cleanHost.replace(/^https?:\/\//i, "").split("/")[0] ?? cleanHost;

    const updated: SslTarget = {
      ...target,
      name: bodyData.name ?? target.name,
      host: cleanHost,
      port: bodyData.port ?? target.port,
      check_interval_seconds: bodyData.check_interval_seconds ?? target.check_interval_seconds,
      expiry_threshold_hours: bodyData.expiry_threshold_hours ?? target.expiry_threshold_hours,
      active: bodyData.active !== undefined ? (bodyData.active ? 1 : 0) : target.active,
    };

    dbRun(
      `UPDATE ssl_targets SET name = ?, host = ?, port = ?, check_interval_seconds = ?,
       expiry_threshold_hours = ?, active = ? WHERE id = ?`,
      updated.name,
      updated.host,
      updated.port,
      updated.check_interval_seconds,
      updated.expiry_threshold_hours,
      updated.active,
      target.id
    );

    rescheduleTarget(updated);
    res.json({ ...updated, last_check: getLastCheck(target.id) });
  }
);

// DELETE /api/ssl/targets/:id
router.delete(
  "/:id",
  param("id").isInt(),
  (req: Request, res: Response) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) { res.status(400).json({ errors: errors.array() }); return; }

    const target = dbGet<SslTarget>(
      "SELECT * FROM ssl_targets WHERE id = ?",
      req.params["id"] as string
    );
    if (!target) { res.status(404).json({ error: "SSL target not found" }); return; }

    unscheduleTarget(target.id);
    dbRun("DELETE FROM ssl_targets WHERE id = ?", target.id);
    res.status(204).send();
  }
);

// POST /api/ssl/targets/:id/check  — manual trigger
router.post(
  "/:id/check",
  param("id").isInt(),
  async (req: Request, res: Response) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) { res.status(400).json({ errors: errors.array() }); return; }

    const target = dbGet<SslTarget>(
      "SELECT * FROM ssl_targets WHERE id = ?",
      req.params["id"] as string
    );
    if (!target) { res.status(404).json({ error: "SSL target not found" }); return; }

    try {
      await runCheckForTarget(target);
      res.json({ ok: true, check: getLastCheck(target.id) });
    } catch {
      res.status(500).json({ error: "Check failed" });
    }
  }
);

// GET /api/ssl/targets/:id/cert  — download latest PEM
router.get(
  "/:id/cert",
  param("id").isInt(),
  (req: Request, res: Response) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) { res.status(400).json({ errors: errors.array() }); return; }

    const target = dbGet<SslTarget>(
      "SELECT * FROM ssl_targets WHERE id = ?",
      req.params["id"] as string
    );
    if (!target) { res.status(404).json({ error: "SSL target not found" }); return; }

    const pemPath = join(SSL_SNAPSHOTS_DIR, `${target.id}.pem`);
    if (!existsSync(pemPath)) {
      res.status(404).json({ error: "No certificate on file — run a check first" });
      return;
    }

    const pem = readFileSync(pemPath, "utf-8");
    res.set("Content-Type", "application/x-pem-file");
    res.set("Content-Disposition", `attachment; filename="${target.host}.pem"`);
    res.send(pem);
  }
);

export { router as sslTargetsRouter };
