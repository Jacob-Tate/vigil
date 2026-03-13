import { DatabaseSync } from "node:sqlite";
import { readFileSync, mkdirSync } from "fs";
import { join } from "path";
import dotenv from "dotenv";

dotenv.config();

const DATA_DIR = process.env.DATA_DIR
  ? join(process.cwd(), process.env.DATA_DIR)
  : join(process.cwd(), "data");

const SNAPSHOTS_DIR = join(DATA_DIR, "snapshots");
const DIFFS_DIR = join(DATA_DIR, "diffs");
const SCREENSHOTS_DIR = join(DATA_DIR, "screenshots");
const SSL_SNAPSHOTS_DIR = join(DATA_DIR, "ssl", "snapshots");
const SSL_HISTORY_DIR = join(DATA_DIR, "ssl", "history");
const DB_PATH = join(DATA_DIR, "monitor.db");

// Ensure all data directories exist
mkdirSync(DATA_DIR, { recursive: true });
mkdirSync(SNAPSHOTS_DIR, { recursive: true });
mkdirSync(DIFFS_DIR, { recursive: true });
mkdirSync(SCREENSHOTS_DIR, { recursive: true });
mkdirSync(SSL_SNAPSHOTS_DIR, { recursive: true });
mkdirSync(SSL_HISTORY_DIR, { recursive: true });

const schemaPath = join(__dirname, "schema.sql");
const schema = readFileSync(schemaPath, "utf-8");

const db = new DatabaseSync(DB_PATH);

// Enable foreign key enforcement and WAL mode
db.exec("PRAGMA foreign_keys = ON");
db.exec("PRAGMA journal_mode = WAL");

// Initialize schema
db.exec(schema);

// Migrations: add columns that may not exist in older databases
try { db.exec("ALTER TABLE servers ADD COLUMN ignore_patterns TEXT"); } catch { /* column already exists */ }
try { db.exec("ALTER TABLE nvd_cve_cpes ADD COLUMN version_start_including TEXT"); } catch { /* exists */ }
try { db.exec("ALTER TABLE nvd_cve_cpes ADD COLUMN version_start_excluding TEXT"); } catch { /* exists */ }
try { db.exec("ALTER TABLE nvd_cve_cpes ADD COLUMN version_end_including TEXT"); } catch { /* exists */ }
try { db.exec("ALTER TABLE nvd_cve_cpes ADD COLUMN version_end_excluding TEXT"); } catch { /* exists */ }
try { db.exec("ALTER TABLE nvd_cves ADD COLUMN references_json TEXT"); } catch { /* exists */ }
// Rename min_cvss_score → min_alert_cvss_score: add new column, copy data, leave old for compat
try { db.exec("ALTER TABLE cve_targets ADD COLUMN min_alert_cvss_score REAL NOT NULL DEFAULT 7.0"); } catch { /* exists */ }
try { db.exec("UPDATE cve_targets SET min_alert_cvss_score = min_cvss_score WHERE min_cvss_score IS NOT NULL"); } catch { /* old column may not exist */ }

// Type-safe query helpers that work around node:sqlite's untyped return values
export function dbGet<T>(sql: string, ...params: unknown[]): T | undefined {
  const stmt = db.prepare(sql);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return (stmt.get as (...args: any[]) => unknown)(...params) as T | undefined;
}

export function dbAll<T>(sql: string, ...params: unknown[]): T[] {
  const stmt = db.prepare(sql);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return (stmt.all as (...args: any[]) => unknown[])(...params) as T[];
}

export function dbRun(sql: string, ...params: unknown[]): { lastInsertRowid: number | bigint; changes: number | bigint } {
  const stmt = db.prepare(sql);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return (stmt.run as (...args: any[]) => { lastInsertRowid: number | bigint; changes: number | bigint })(...params);
}

export { db, DATA_DIR, SNAPSHOTS_DIR, DIFFS_DIR, SCREENSHOTS_DIR, SSL_SNAPSHOTS_DIR, SSL_HISTORY_DIR };
