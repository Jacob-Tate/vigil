import rateLimit from "express-rate-limit";

/**
 * Broad floor applied to all /api routes.
 * Stops simple DoS loops from saturating the server.
 */
export const generalLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  limit: 300,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "Too many requests, please slow down." },
});

/**
 * Strict limiter on auth routes to block brute-force login attacks.
 */
export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  limit: 20,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "Too many login attempts, please try again later." },
});

/**
 * Limiter for expensive trigger endpoints:
 * manual check-now, NVD sync, notification test, SSL/CVE manual checks.
 * These fire real HTTP requests, screenshots, or external API calls.
 */
export const triggerLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "Too many trigger requests, please wait before retrying." },
});
