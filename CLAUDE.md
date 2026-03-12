# Claude Code Instructions — Monitor

## Project Overview

Full-stack TypeScript server monitoring app. Express backend + React/Tailwind frontend. See README.md for full feature list.

## Structure

```
server/src/         Express API + monitor engine (TypeScript, CommonJS)
client/src/         React + Vite + Tailwind (TypeScript, ESM)
server/data/        GITIGNORED — SQLite DB, HTML snapshots, diff files
```

## TypeScript Rules

- **Strict mode everywhere** — no `any` casts; use `unknown` with type guards
- **Named exports only** — no default exports (except React components, which may use default)
- **No implicit returns** in async functions that should always return a value
- All interfaces live in `server/src/types.ts` (backend) or `client/src/types.ts` (frontend)
- Shared notifier interfaces live in `server/src/notifiers/types.ts`

## Before Finishing Any Task

Always run:
```bash
npm run typecheck   # must pass with 0 errors
npm run lint        # must pass with 0 errors
```

## Database Schema Changes

1. Edit `server/src/db/schema.sql`
2. If changing existing tables: add a migration comment and handle it in `database.ts` (use `ALTER TABLE` or drop+recreate for dev)
3. **Never** delete `server/data/` manually — let the app recreate it

## Key Files

| File | Purpose |
|------|---------|
| `server/src/types.ts` | All shared backend types (Server, CheckResult, AlertPayload, etc.) |
| `server/src/db/database.ts` | SQLite singleton; also ensures `data/snapshots/` and `data/diffs/` exist |
| `server/src/monitor/engine.ts` | Scheduler — call `scheduleServer`/`unscheduleServer`/`rescheduleServer` from API routes |
| `server/src/notifiers/types.ts` | `INotifier` interface — implement this to add a new channel |
| `server/src/notifiers/index.ts` | `NOTIFIER_MAP` registry + `sendAlert()` dispatch |
| `client/src/api/client.ts` | All frontend API calls go through this typed fetch wrapper |

## Monitor Engine Flow

```
engine → checker → hasher → (diff if hash changed) → alerter → notifiers
```

Content is **always stored on disk** (`data/snapshots/` and `data/diffs/`), never in the DB. The DB stores only hashes, file paths, and metadata.

## Notification Channels

Each notifier module exports an `INotifier` object. To add a new channel:
1. Create `server/src/notifiers/<name>.ts`
2. Add it to `NOTIFIER_MAP` in `server/src/notifiers/index.ts`

## Dev Ports

- Express API: `http://localhost:3001`
- Vite dev server: `http://localhost:5173` (proxies `/api` → `:3001`)
