# Claude Code Instructions — Monitor

## Project Overview

Full-stack TypeScript server monitoring platform ("Vigil"). Express backend + React/Tailwind frontend. See README.md for full feature list.

## Structure

```
server/src/         Express API + monitor engines (TypeScript, CommonJS)
client/src/         React + Vite + Tailwind (TypeScript, ESM)
server/data/        GITIGNORED — SQLite DB, HTML snapshots, diff files, NVD mirror
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
| `server/src/types.ts` | All shared backend types (Server, CheckResult, AlertPayload, auth types, etc.) |
| `server/src/db/database.ts` | SQLite singleton; also ensures `data/snapshots/` and `data/diffs/` exist |
| `server/src/middleware/auth.ts` | `requireAuth` and `requireAdmin` Express middleware; augments `req.user` |
| `server/src/auth/seed.ts` | First-boot admin user seeding from env vars (idempotent) |
| `server/src/api/auth.ts` | Login / logout / me routes (no auth required) |
| `server/src/api/users.ts` | User CRUD (admin-only) |
| `server/src/monitor/engine.ts` | HTTP check scheduler — call `scheduleServer`/`unscheduleServer`/`rescheduleServer` from API routes |
| `server/src/notifiers/types.ts` | `INotifier` interface — implement this to add a new notification channel |
| `server/src/notifiers/index.ts` | `NOTIFIER_MAP` registry + `sendAlert()` dispatch |
| `client/src/api/client.ts` | All frontend API calls — typed fetch wrapper with `credentials: "include"` and 401 redirect |
| `client/src/contexts/AuthContext.tsx` | React context providing `user`, `isAdmin`, `loading`, `login`, `logout` |
| `client/src/hooks/useAuth.ts` | `useAuth()` hook — import from here, not from AuthContext directly |
| `client/src/components/ProtectedRoute.tsx` | Route guard — redirects to `/login` if unauthenticated; `requireAdmin` prop for admin-only routes |

## Authentication

All API routes require a valid session. The only exceptions are `/api/auth/login`, `/api/auth/logout`, and `/api/health`.

- `requireAuth` — validates the httpOnly JWT cookie, attaches `req.user`; registered at the router level in `index.ts`
- `requireAdmin` — calls `requireAuth` then checks `role === "admin"`; applied inline on every mutating route (POST/PUT/DELETE/trigger) inside each router file

When adding a new router:
1. Register it in `index.ts` with `requireAuth` (or `requireAdmin` if fully admin-only)
2. Add `requireAdmin` as the first argument on any write routes inside the router file

When adding write actions to the frontend:
- Gate buttons/forms with `const { isAdmin } = useAuth()` and `{isAdmin && ...}`
- Pass handlers as `undefined` to card components for non-admins (they conditionally render based on prop presence)

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
