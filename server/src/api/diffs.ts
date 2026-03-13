import { Router, Request, Response } from "express";
import { query, param, validationResult } from "express-validator";
import { readFileSync, existsSync } from "fs";
import { join, resolve } from "path";
import { dbGet, dbAll, DATA_DIR, DIFFS_DIR } from "../db/database";
import { ContentDiff } from "../types";

const router = Router();

// GET /api/diffs?serverId=
router.get(
  "/",
  query("serverId").isInt(),
  (req: Request, res: Response) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    const serverId = parseInt(req.query.serverId as string, 10);
    const diffs = dbAll<ContentDiff>(
      "SELECT id, server_id, detected_at, old_hash, new_hash, diff_file FROM content_diffs WHERE server_id = ? ORDER BY detected_at DESC",
      serverId
    );

    res.json(diffs);
  }
);

// GET /api/diffs/:id
router.get(
  "/:id",
  param("id").isInt(),
  (req: Request, res: Response) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    const diff = dbGet<ContentDiff>(
      "SELECT * FROM content_diffs WHERE id = ?",
      req.params["id"] as string
    );

    if (!diff) {
      res.status(404).json({ error: "Diff not found" });
      return;
    }

    const filePath = resolve(join(DATA_DIR, diff.diff_file));
    if (!filePath.startsWith(DIFFS_DIR + "/") && !filePath.startsWith(DIFFS_DIR + "\\")) {
      res.status(400).json({ error: "Invalid diff file path" });
      return;
    }
    if (!existsSync(filePath)) {
      res.status(404).json({ error: "Diff file not found on disk" });
      return;
    }

    const diffContent = readFileSync(filePath, "utf-8");
    res.json({ ...diff, diff_content: diffContent });
  }
);

export { router as diffsRouter };
