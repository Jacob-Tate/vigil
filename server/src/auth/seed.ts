import bcrypt from "bcryptjs";
import { dbGet, dbRun } from "../db/database";
import { User } from "../types";

export async function seedAdminUser(): Promise<void> {
  const username = process.env.ADMIN_USERNAME;
  const password = process.env.ADMIN_PASSWORD;

  if (!username || !password) {
    console.log("[auth] ADMIN_USERNAME / ADMIN_PASSWORD not set — skipping admin seed");
    return;
  }

  const existing = dbGet<User>("SELECT * FROM users WHERE username = ?", username);
  if (existing) {
    return;
  }

  const hash = await bcrypt.hash(password, 12);
  dbRun(
    "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')",
    username,
    hash
  );
  console.log(`[auth] Admin user "${username}" created`);
}
