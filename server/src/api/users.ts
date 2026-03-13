import { Router, Request, Response } from "express";
import { body, validationResult } from "express-validator";
import bcrypt from "bcryptjs";
import { dbAll, dbGet, dbRun } from "../db/database";
import { requireAdmin } from "../middleware/auth";
import { User, AuthUser } from "../types";

const router = Router();

// All routes in this file require admin — enforced at app level too, but belt-and-suspenders
router.use(requireAdmin);

function toPublic(user: User): Omit<User, "password_hash"> {
  return { id: user.id, username: user.username, role: user.role, created_at: user.created_at };
}

function countAdmins(): number {
  const row = dbGet<{ n: number }>("SELECT COUNT(*) as n FROM users WHERE role = 'admin'");
  return row?.n ?? 0;
}

// GET /api/users
router.get("/", (_req: Request, res: Response): void => {
  const users = dbAll<User>("SELECT * FROM users ORDER BY created_at ASC");
  res.json(users.map(toPublic));
});

// POST /api/users
router.post(
  "/",
  body("username").isString().trim().notEmpty().withMessage("Username is required"),
  body("password").isString().isLength({ min: 8 }).withMessage("Password must be at least 8 characters"),
  body("role").isIn(["admin", "viewer"]).withMessage("Role must be admin or viewer"),
  async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    const { username, password, role } = req.body as { username: string; password: string; role: string };

    const existing = dbGet<User>("SELECT * FROM users WHERE username = ?", username);
    if (existing) {
      res.status(409).json({ error: "Username already exists" });
      return;
    }

    const hash = await bcrypt.hash(password, 12);
    const result = dbRun(
      "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
      username,
      hash,
      role
    );

    const created = dbGet<User>("SELECT * FROM users WHERE id = ?", result.lastInsertRowid);
    if (!created) { res.status(500).json({ error: "Failed to create user" }); return; }
    res.status(201).json(toPublic(created));
  }
);

// PUT /api/users/:id
router.put(
  "/:id",
  body("username").optional().isString().trim().notEmpty().withMessage("Username cannot be empty"),
  body("password").optional().isString().isLength({ min: 8 }).withMessage("Password must be at least 8 characters"),
  body("role").optional().isIn(["admin", "viewer"]).withMessage("Role must be admin or viewer"),
  async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    const id = parseInt(req.params["id"] as string, 10);
    const target = dbGet<User>("SELECT * FROM users WHERE id = ?", id);
    if (!target) { res.status(404).json({ error: "User not found" }); return; }

    const { username, password, role } = req.body as {
      username?: string;
      password?: string;
      role?: string;
    };

    // Prevent demoting the last admin
    if (role === "viewer" && target.role === "admin" && countAdmins() <= 1) {
      res.status(400).json({ error: "Cannot demote the last admin" });
      return;
    }

    if (username && username !== target.username) {
      const clash = dbGet<User>("SELECT id FROM users WHERE username = ? AND id != ?", username, id);
      if (clash) { res.status(409).json({ error: "Username already exists" }); return; }
    }

    if (username) dbRun("UPDATE users SET username = ? WHERE id = ?", username, id);
    if (role) dbRun("UPDATE users SET role = ? WHERE id = ?", role, id);
    if (password) {
      const hash = await bcrypt.hash(password, 12);
      dbRun("UPDATE users SET password_hash = ? WHERE id = ?", hash, id);
    }

    const updated = dbGet<User>("SELECT * FROM users WHERE id = ?", id);
    if (!updated) { res.status(500).json({ error: "Failed to fetch updated user" }); return; }
    res.json(toPublic(updated));
  }
);

// DELETE /api/users/:id
router.delete("/:id", (req: Request, res: Response): void => {
  const id = parseInt(req.params["id"] as string, 10);
  const target = dbGet<User>("SELECT * FROM users WHERE id = ?", id);
  if (!target) { res.status(404).json({ error: "User not found" }); return; }

  const currentUser = req.user as AuthUser;
  if (currentUser.id === id) {
    res.status(400).json({ error: "Cannot delete your own account" });
    return;
  }

  if (target.role === "admin" && countAdmins() <= 1) {
    res.status(400).json({ error: "Cannot delete the last admin" });
    return;
  }

  dbRun("DELETE FROM users WHERE id = ?", id);
  res.status(204).end();
});

export { router as usersRouter };
