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
  const start = Date.now();
  res.on("finish", () => {
    const user = req.user?.username ?? "anonymous";
    const ms = Date.now() - start;
    console.log(`[audit] ${req.method} ${req.path} user=${user} status=${res.statusCode} ${ms}ms`);
  });
  next();
}
