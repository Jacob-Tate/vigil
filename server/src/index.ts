import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";
import { join } from "path";
import { existsSync, unlinkSync } from "fs";
import { dbAll, dbRun, DATA_DIR } from "./db/database";
import { authRouter } from "./api/auth";
import { serversRouter } from "./api/servers";
import { notificationsRouter } from "./api/notifications";
import { checksRouter } from "./api/checks";
import { diffsRouter } from "./api/diffs";
import { sslTargetsRouter } from "./api/ssl-targets";
import { sslChecksRouter } from "./api/ssl-checks";
import { nvdSyncRouter } from "./api/nvd-sync";
import { cveTargetsRouter } from "./api/cve-targets";
import { cveFindingsRouter } from "./api/cve-findings";
import { nvdBrowseRouter } from "./api/nvd-browse";
import { startEngine, stopEngine } from "./monitor/engine";
import { startSslEngine, stopSslEngine } from "./monitor/ssl-engine";
import { startCveEngine, stopCveEngine } from "./cve/cve-engine";
import { startFeedScheduler, stopFeedScheduler } from "./cve/feed-scheduler";
import { requireAuth, requireAdmin } from "./middleware/auth";
import { usersRouter } from "./api/users";
import { seedAdminUser } from "./auth/seed";
import { ContentDiff } from "./types";

dotenv.config();

const PORT = parseInt(process.env.PORT ?? "3001", 10);
const DIFF_RETENTION_DAYS = parseInt(process.env.DIFF_RETENTION_DAYS ?? "30", 10);

const app = express();

const ALLOWED_ORIGIN = process.env.CLIENT_ORIGIN ?? "http://localhost:5173";
app.use(cors({ origin: ALLOWED_ORIGIN, credentials: true }));
app.use(express.json());
app.use(cookieParser());

// Auth routes (no authentication required)
app.use("/api/auth", authRouter);

// Protected API routes (all require a valid session)
app.use("/api/servers", requireAuth, serversRouter);
app.use("/api/notifications", requireAuth, notificationsRouter);
app.use("/api/checks", requireAuth, checksRouter);
app.use("/api/diffs", requireAuth, diffsRouter);
app.use("/api/ssl/targets", requireAuth, sslTargetsRouter);
app.use("/api/ssl/checks", requireAuth, sslChecksRouter);
// nvd/browse must be registered before nvd so its routes take precedence
app.use("/api/nvd/browse", requireAuth, nvdBrowseRouter);
app.use("/api/nvd", requireAuth, nvdSyncRouter);
app.use("/api/cve/targets", requireAuth, cveTargetsRouter);
app.use("/api/cve/findings", requireAuth, cveFindingsRouter);
app.use("/api/users", requireAdmin, usersRouter);

// Health check
app.get("/api/health", (_req, res) => {
  res.json({ ok: true, timestamp: new Date().toISOString() });
});

// Serve built React app in production
const CLIENT_DIST = join(__dirname, "../../client/dist");
if (existsSync(CLIENT_DIST)) {
  app.use(express.static(CLIENT_DIST));
  app.get("*", (_req, res) => {
    res.sendFile(join(CLIENT_DIST, "index.html"));
  });
}

function cleanupOldDiffs(): void {
  const cutoff = new Date();
  cutoff.setDate(cutoff.getDate() - DIFF_RETENTION_DAYS);
  const cutoffStr = cutoff.toISOString();

  const oldDiffs = dbAll<ContentDiff>("SELECT * FROM content_diffs WHERE detected_at < ?", cutoffStr);

  for (const diff of oldDiffs) {
    const filePath = join(DATA_DIR, diff.diff_file);
    if (existsSync(filePath)) {
      try {
        unlinkSync(filePath);
      } catch {
        console.warn(`[cleanup] Could not delete diff file: ${filePath}`);
      }
    }
    dbRun("DELETE FROM content_diffs WHERE id = ?", diff.id);
  }

  if (oldDiffs.length > 0) {
    console.log(`[cleanup] Removed ${oldDiffs.length} diff(s) older than ${DIFF_RETENTION_DAYS} days`);
  }
}

const server = app.listen(PORT, () => {
  console.log(`[server] Listening on http://localhost:${PORT}`);

  // Seed admin user from env vars (no-op if already exists)
  void seedAdminUser();

  // Clean up old diffs on startup
  cleanupOldDiffs();

  // Start the monitor engines
  startEngine();
  void startSslEngine();
  startCveEngine();
  startFeedScheduler();
});

// Graceful shutdown
process.on("SIGINT", () => {
  console.log("\n[server] Shutting down...");
  stopEngine();
  stopSslEngine();
  stopCveEngine();
  stopFeedScheduler();
  server.close(() => process.exit(0));
});

process.on("SIGTERM", () => {
  stopEngine();
  stopSslEngine();
  stopCveEngine();
  stopFeedScheduler();
  server.close(() => process.exit(0));
});
