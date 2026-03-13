import { Router, Request, Response } from "express";
import { body, validationResult } from "express-validator";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { dbGet } from "../db/database";
import { requireAuth } from "../middleware/auth";
import { User, AuthUser, JwtPayload } from "../types";

const router = Router();

function getJwtSecret(): string {
  const s = process.env.JWT_SECRET;
  if (!s) throw new Error("JWT_SECRET is not set");
  return s;
}

function getSessionMaxAgeMs(): number {
  const hours = parseInt(process.env.SESSION_DURATION_HOURS ?? "24", 10);
  return hours * 60 * 60 * 1000;
}

// POST /api/auth/login
router.post(
  "/login",
  body("username").isString().trim().notEmpty(),
  body("password").isString().notEmpty(),
  async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    const { username, password } = req.body as { username: string; password: string };

    const user = dbGet<User>("SELECT * FROM users WHERE username = ?", username);
    if (!user) {
      res.status(401).json({ error: "Invalid credentials" });
      return;
    }

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      res.status(401).json({ error: "Invalid credentials" });
      return;
    }

    const maxAgeMs = getSessionMaxAgeMs();
    const expiresInSeconds = Math.floor(maxAgeMs / 1000);

    const payloadData: Omit<JwtPayload, "iat" | "exp"> = {
      sub: user.id,
      username: user.username,
      role: user.role,
    };

    const token = jwt.sign(payloadData, getJwtSecret(), { expiresIn: expiresInSeconds });

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: maxAgeMs,
    });

    const authUser: AuthUser = { id: user.id, username: user.username, role: user.role };
    res.json({ user: authUser });
  }
);

// POST /api/auth/logout
router.post("/logout", (_req: Request, res: Response): void => {
  res.clearCookie("token", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
  });
  res.json({ ok: true });
});

// GET /api/auth/me
router.get("/me", requireAuth, (req: Request, res: Response): void => {
  res.json({ user: req.user });
});

export { router as authRouter };
