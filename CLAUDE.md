# Claude Code Instructions — Monitor

## Project Overview

Full-stack server monitoring platform ("Vigil"). Rust/Axum backend + React/Tailwind frontend. See README.md for full feature list.

## Structure

```
vigil/src/          Rust/Axum API + monitor engines
client/src/         React + Vite + Tailwind (TypeScript, ESM)
data/               GITIGNORED — SQLite DB, HTML snapshots, diff files, NVD mirror
```

## TypeScript Rules (frontend)

- **Strict mode everywhere** — no `any` casts; use `unknown` with type guards
- **Named exports only** — no default exports (except React components, which may use default)
- **No implicit returns** in async functions that should always return a value
- All interfaces live in `client/src/types.ts`

## Rust Rules (backend)

- All shared types live in `vigil/src/types.rs`
- Auth middleware in `vigil/src/auth/middleware.rs` — `require_auth` and `require_admin` extractors
- Add new routes in `vigil/src/api/mod.rs` and implement handlers in `vigil/src/api/<domain>.rs`

## Before Finishing Any Task

Always run:
```bash
cargo check --manifest-path vigil/Cargo.toml   # must pass with 0 errors
npm run typecheck --prefix client               # must pass with 0 errors
npm run lint --prefix client                    # must pass with 0 errors
```

## Database Schema Changes

1. Edit `vigil/src/db/schema.sql`
2. Handle migrations in `vigil/src/db/mod.rs`
3. **Never** delete `data/` manually — let the app recreate it

## Key Files

| File | Purpose |
|------|---------|
| `vigil/src/types.rs` | All shared backend types (Server, CheckResult, AlertPayload, auth types, etc.) |
| `vigil/src/db/mod.rs` | SQLite connection pool; also ensures `data/snapshots/` and `data/diffs/` exist |
| `vigil/src/auth/middleware.rs` | `require_auth` and `require_admin` Axum extractors |
| `vigil/src/auth/seed.rs` | First-boot admin user seeding from env vars (idempotent) |
| `vigil/src/api/auth.rs` | Login / logout / me routes (no auth required) |
| `vigil/src/api/users.rs` | User CRUD (admin-only) |
| `vigil/src/api/mod.rs` | All route registrations |
| `vigil/src/monitor/engine.rs` | HTTP check scheduler |
| `vigil/src/notifiers/mod.rs` | Notifier trait + `send_alert()` dispatch |
| `client/src/api/client.ts` | All frontend API calls — typed fetch wrapper with `credentials: "include"` and 401 redirect |
| `client/src/contexts/AuthContext.tsx` | React context providing `user`, `isAdmin`, `loading`, `login`, `logout` |
| `client/src/hooks/useAuth.ts` | `useAuth()` hook — import from here, not from AuthContext directly |
| `client/src/components/ProtectedRoute.tsx` | Route guard — redirects to `/login` if unauthenticated; `requireAdmin` prop for admin-only routes |

## Authentication

All API routes require a valid session. The only exceptions are `/api/auth/login`, `/api/auth/logout`, and `/api/health`.

- `require_auth` — validates the httpOnly JWT cookie, attaches user to request state
- `require_admin` — checks `role == "admin"`; applied on all mutating routes

When adding a new router:
1. Register it in `vigil/src/api/mod.rs`
2. Apply `require_admin` on any write routes inside the handler file

When adding write actions to the frontend:
- Gate buttons/forms with `const { isAdmin } = useAuth()` and `{isAdmin && ...}`
- Pass handlers as `undefined` to card components for non-admins (they conditionally render based on prop presence)

## Monitor Engine Flow

```
engine → checker → hasher → (diff if hash changed) → alerter → notifiers
```

Content is **always stored on disk** (`data/snapshots/` and `data/diffs/`), never in the DB. The DB stores only hashes, file paths, and metadata.

## Notification Channels

Each notifier implements the notifier trait. To add a new channel:
1. Create `vigil/src/notifiers/<name>.rs`
2. Register it in `vigil/src/notifiers/mod.rs`

## Dev Ports

- Rust API: `http://localhost:3001`
- Vite dev server: `http://localhost:5173` (proxies `/api` → `:3001`)
