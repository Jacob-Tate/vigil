import { Router, Request, Response } from "express";
import { query, param, validationResult } from "express-validator";
import { dbGet, dbAll } from "../db/database";
import { SslCheck } from "../types";

const router = Router();

// GET /api/ssl/checks?targetId=&page=&limit=
router.get(
  "/",
  query("targetId").isInt(),
  query("page").optional().isInt({ min: 1 }),
  query("limit").optional().isInt({ min: 1, max: 200 }),
  (req: Request, res: Response) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) { res.status(400).json({ errors: errors.array() }); return; }

    const targetId = parseInt(req.query["targetId"] as string, 10);
    const page = parseInt((req.query["page"] as string | undefined) ?? "1", 10);
    const limit = parseInt((req.query["limit"] as string | undefined) ?? "50", 10);
    const offset = (page - 1) * limit;

    const rows = dbAll<SslCheck>(
      "SELECT * FROM ssl_checks WHERE target_id = ? ORDER BY checked_at DESC LIMIT ? OFFSET ?",
      targetId,
      limit,
      offset
    );

    const totalRow = dbGet<{ total: number }>(
      "SELECT COUNT(*) AS total FROM ssl_checks WHERE target_id = ?",
      targetId
    );
    const total = totalRow?.total ?? 0;

    res.json({
      data: rows,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
      },
    });
  }
);

// GET /api/ssl/checks/stats/:targetId
router.get(
  "/stats/:targetId",
  param("targetId").isInt(),
  (req: Request, res: Response) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) { res.status(400).json({ errors: errors.array() }); return; }

    const targetId = parseInt(req.params["targetId"] as string, 10);

    const stats = dbGet<{
      total_checks: number;
      error_checks: number;
      avg_days_remaining: number | null;
      min_days_remaining: number | null;
      cert_changes: number;
    }>(
      `SELECT
         COUNT(*) AS total_checks,
         SUM(CASE WHEN error IS NOT NULL THEN 1 ELSE 0 END) AS error_checks,
         AVG(CASE WHEN error IS NULL THEN days_remaining END) AS avg_days_remaining,
         MIN(CASE WHEN error IS NULL THEN days_remaining END) AS min_days_remaining,
         SUM(CASE WHEN alert_type = 'SSL_CHANGED' THEN 1 ELSE 0 END) AS cert_changes
       FROM ssl_checks WHERE target_id = ?`,
      targetId
    );

    res.json(stats ?? {
      total_checks: 0,
      error_checks: 0,
      avg_days_remaining: null,
      min_days_remaining: null,
      cert_changes: 0,
    });
  }
);

// GET /api/ssl/checks/:id
router.get(
  "/:id",
  param("id").isInt(),
  (req: Request, res: Response) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) { res.status(400).json({ errors: errors.array() }); return; }

    const row = dbGet<SslCheck>(
      "SELECT * FROM ssl_checks WHERE id = ?",
      req.params["id"] as string
    );
    if (!row) { res.status(404).json({ error: "SSL check not found" }); return; }

    res.json(row);
  }
);

export { router as sslChecksRouter };
