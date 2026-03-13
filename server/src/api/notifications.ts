import { Router, Request, Response } from "express";
import { body, param, validationResult } from "express-validator";
import { dbGet, dbAll, dbRun } from "../db/database";
import { NotificationChannel } from "../types";
import { sendAlert, NOTIFIER_MAP } from "../notifiers";
import { requireAdmin } from "../middleware/auth";

const router = Router();

// GET /api/notifications
router.get("/", (_req: Request, res: Response) => {
  const channels = dbAll<NotificationChannel>("SELECT * FROM notification_channels ORDER BY id ASC");
  const safe = channels.map((ch) => {
    const config = JSON.parse(ch.config_json) as Record<string, unknown>;
    const notifier = NOTIFIER_MAP[ch.type];
    const redacted: Record<string, unknown> = {};
    if (notifier) {
      for (const [key, schema] of Object.entries(notifier.configSchema)) {
        if (schema.type === "password") {
          redacted[key] = config[key] ? "••••••••" : "";
        } else {
          redacted[key] = config[key] ?? "";
        }
      }
    }
    return { ...ch, config: redacted, config_json: undefined };
  });
  res.json(safe);
});

// GET /api/notifications/types
router.get("/types", (_req: Request, res: Response) => {
  const types = Object.values(NOTIFIER_MAP).map((n) => ({
    type: n.type,
    displayName: n.displayName,
    configSchema: n.configSchema,
  }));
  res.json(types);
});

// POST /api/notifications
router.post(
  "/",
  requireAdmin,
  body("type").isString().notEmpty(),
  body("label").optional().isString(),
  body("config").isObject(),
  body("active").optional().isBoolean(),
  (req: Request, res: Response) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    const { type, label, config, active = true } = req.body as {
      type: string;
      label?: string;
      config: Record<string, unknown>;
      active?: boolean;
    };

    if (!NOTIFIER_MAP[type]) {
      res.status(400).json({ error: `Unknown notifier type: ${type}` });
      return;
    }

    const info = dbRun(
      "INSERT INTO notification_channels (type, label, config_json, active) VALUES (?, ?, ?, ?)",
      type, label ?? null, JSON.stringify(config), active ? 1 : 0
    );

    const channel = dbGet<NotificationChannel>(
      "SELECT * FROM notification_channels WHERE id = ?",
      info.lastInsertRowid
    );
    res.status(201).json(channel);
  }
);

// PUT /api/notifications/:id
router.put(
  "/:id",
  requireAdmin,
  param("id").isInt(),
  body("label").optional().isString(),
  body("config").optional().isObject(),
  body("active").optional().isBoolean(),
  (req: Request, res: Response) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    const channel = dbGet<NotificationChannel>(
      "SELECT * FROM notification_channels WHERE id = ?",
      req.params["id"] as string
    );
    if (!channel) {
      res.status(404).json({ error: "Channel not found" });
      return;
    }

    const bodyData = req.body as Partial<{
      label: string;
      config: Record<string, unknown>;
      active: boolean;
    }>;

    const existingConfig = JSON.parse(channel.config_json) as Record<string, unknown>;
    const mergedConfig = bodyData.config
      ? { ...existingConfig, ...bodyData.config }
      : existingConfig;

    dbRun(
      "UPDATE notification_channels SET label = ?, config_json = ?, active = ? WHERE id = ?",
      bodyData.label ?? channel.label,
      JSON.stringify(mergedConfig),
      bodyData.active !== undefined ? (bodyData.active ? 1 : 0) : channel.active,
      channel.id
    );

    const updated = dbGet<NotificationChannel>(
      "SELECT * FROM notification_channels WHERE id = ?",
      channel.id
    );
    res.json(updated);
  }
);

// DELETE /api/notifications/:id
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

    const channel = dbGet<NotificationChannel>(
      "SELECT * FROM notification_channels WHERE id = ?",
      req.params["id"] as string
    );
    if (!channel) {
      res.status(404).json({ error: "Channel not found" });
      return;
    }

    dbRun("DELETE FROM notification_channels WHERE id = ?", channel.id);
    res.status(204).send();
  }
);

// POST /api/notifications/:id/test
router.post(
  "/:id/test",
  requireAdmin,
  param("id").isInt(),
  async (req: Request, res: Response) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    const channel = dbGet<NotificationChannel>(
      "SELECT * FROM notification_channels WHERE id = ?",
      req.params["id"] as string
    );
    if (!channel) {
      res.status(404).json({ error: "Channel not found" });
      return;
    }

    try {
      await sendAlert(
        {
          serverName: "Test Server",
          url: "https://example.com",
          alertType: "DOWN",
          statusCode: 503,
          responseTimeMs: 0,
          threshold: 3000,
          diffId: null,
          diffViewUrl: null,
          detectedAt: new Date().toISOString(),
          message: "This is a test alert from Monitor.",
        },
        [channel]
      );
      res.json({ ok: true });
    } catch {
      res.status(500).json({ error: "Test alert failed" });
    }
  }
);

export { router as notificationsRouter };
