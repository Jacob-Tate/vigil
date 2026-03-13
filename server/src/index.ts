import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { join } from "path";
import { existsSync, unlinkSync } from "fs";
import { dbAll, dbRun, DATA_DIR } from "./db/database";
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
import { ContentDiff } from "./types";

dotenv.config();

const PORT = parseInt(process.env.PORT ?? "3001", 10);
const DIFF_RETENTION_DAYS = parseInt(process.env.DIFF_RETENTION_DAYS ?? "30", 10);

const app = express();

app.use(cors());
app.use(express.json());

// API routes
app.use("/api/servers", serversRouter);
app.use("/api/notifications", notificationsRouter);
app.use("/api/checks", checksRouter);
app.use("/api/diffs", diffsRouter);
app.use("/api/ssl/targets", sslTargetsRouter);
app.use("/api/ssl/checks", sslChecksRouter);
app.use("/api/nvd", nvdSyncRouter);
app.use("/api/nvd/browse", nvdBrowseRouter);
app.use("/api/cve/targets", cveTargetsRouter);
app.use("/api/cve/findings", cveFindingsRouter);

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
