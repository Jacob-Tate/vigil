import { Router, Request, Response } from "express";
import { query, param, validationResult } from "express-validator";
import { dbGet, dbAll } from "../db/database";
import { Check } from "../types";

const router = Router();

// GET /api/checks?serverId=&page=&limit=
router.get(
  "/",
  query("serverId").isInt(),
  query("page").optional().isInt({ min: 1 }),
  query("limit").optional().isInt({ min: 1, max: 200 }),
  (req: Request, res: Response) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    const serverId = parseInt(req.query.serverId as string, 10);
    const page = parseInt((req.query.page as string) ?? "1", 10);
    const limit = parseInt((req.query.limit as string) ?? "50", 10);
    const offset = (page - 1) * limit;

    const countRow = dbGet<{ count: number }>(
      "SELECT COUNT(*) as count FROM checks WHERE server_id = ?",
      serverId
    );
    const total = countRow?.count ?? 0;

    const checks = dbAll<Check>(
      "SELECT * FROM checks WHERE server_id = ? ORDER BY checked_at DESC LIMIT ? OFFSET ?",
      serverId,
      limit,
      offset
    );

    res.json({
      data: checks,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) },
    });
  }
);

// GET /api/checks/stats/:serverId
router.get(
  "/stats/:serverId",
  param("serverId").isInt(),
  (req: Request, res: Response) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    const serverId = parseInt(req.params["serverId"] as string, 10);

    const stats = dbGet<{
      total_checks: number;
      up_checks: number;
      avg_response_time_ms: number | null;
      min_response_time_ms: number | null;
      max_response_time_ms: number | null;
      content_changes: number;
    }>(
      `SELECT
        COUNT(*) as total_checks,
        SUM(CASE WHEN is_up = 1 THEN 1 ELSE 0 END) as up_checks,
        ROUND(AVG(response_time_ms), 0) as avg_response_time_ms,
        MIN(response_time_ms) as min_response_time_ms,
        MAX(response_time_ms) as max_response_time_ms,
        SUM(CASE WHEN content_changed = 1 THEN 1 ELSE 0 END) as content_changes
       FROM checks WHERE server_id = ?`,
      serverId
    );

    const uptime_pct =
      stats && stats.total_checks > 0
        ? Math.round((stats.up_checks / stats.total_checks) * 10000) / 100
        : null;

    res.json({ ...(stats ?? {}), uptime_pct });
  }
);

export { router as checksRouter };
