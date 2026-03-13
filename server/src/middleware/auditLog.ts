import { Request, Response, NextFunction } from "express";

/**
 * Logs one line per completed API request:
 *   [audit] METHOD /path user=<username|anonymous> status=<code> <ms>ms
 *
 * Attach this after authentication middleware so req.user is populated
 * for protected routes. For unauthenticated routes (login, health) the
 * user field will be "anonymous".
 */
export function auditLog(req: Request, res: Response, next: NextFunction): void {
  // Capture path now — req.path is mutated by sub-routers before the "finish" event fires
  const path = req.path;

  // Skip high-frequency polling endpoints that add no audit value
  if (path.endsWith("/status") || path === "/health") {
    next();
    return;
  }

  const start = Date.now();
  res.on("finish", () => {
    const user = req.user?.username ?? "anonymous";
    const ms = Date.now() - start;
    console.log(`[audit] ${req.method} ${path} user=${user} status=${res.statusCode} ${ms}ms`);
  });
  next();
}
