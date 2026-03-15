# Vigil

A self-hosted monitoring platform. Tracks HTTP uptime, SSL certificate health, and CVE vulnerabilities — alerting via Discord, Pushover, or Microsoft Teams.

## Features

- **HTTP monitoring** — alerts on non-2xx/3xx responses, slow response times, and content changes
- **Content change detection** — SHA-256 page hashing; stores and displays diffs when content changes
- **SSL certificate monitoring** — tracks expiry, fingerprint changes, and TLS errors
- **CVE monitoring** — matches your technology stack against the local NVD mirror and alerts on new findings
- **NVD mirror** — downloads and indexes the full NVD dataset locally for fast, offline CVE lookups
- **Multi-channel alerts** — Discord webhook, Pushover, Microsoft Teams webhook (pluggable)
- **Authentication** — JWT-based sessions (httpOnly cookies), admin and viewer roles
- **User management** — admins can create, edit, and delete user accounts from the UI
- **Per-target check intervals** — each monitored target has its own polling schedule
- **Manual triggers** — run an immediate check from the UI
- **Diff viewer** — visual inline diff of old vs new page content

## Prerequisites

- Rust (stable toolchain)
- Node.js 22+ / npm 9+ (frontend only)

## Quick Start

```bash
git clone <repo>
cd monitor
cp vigil/.env.example vigil/.env
# Edit vigil/.env — set JWT_SECRET, ADMIN_USERNAME, ADMIN_PASSWORD at minimum
npm run dev
```

- Frontend: http://localhost:5173
- API: http://localhost:3001

On first start the server seeds an admin account from `ADMIN_USERNAME` / `ADMIN_PASSWORD` if no users exist yet.

## Environment Variables

Create `vigil/.env` from `vigil/.env.example`:

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3001` | Server port |
| `JWT_SECRET` | — | **Required in production** — secret used to sign JWT session tokens |
| `NOTIFICATIONS_ENCRYPTION_KEY` | — | **Strongly recommended** — AES-256-GCM key for encrypting notification credentials at rest. Generate with: `openssl rand -hex 32` |
| `ADMIN_USERNAME` | — | First-boot admin username (seeded once if no users exist) |
| `ADMIN_PASSWORD` | — | First-boot admin password |
| `SESSION_DURATION_HOURS` | `24` | Cookie/token lifetime in hours |
| `CLIENT_ORIGIN` | `http://localhost:5173` | Allowed CORS origin (set to your frontend URL in production) |
| `BASE_URL` | `http://localhost:5173` | Base URL used in alert notification deep links |
| `ALERT_COOLDOWN_SECONDS` | `3600` | Seconds between repeat alerts for the same target |
| `NVD_SYNC_INTERVAL_HOURS` | `2` | How often the NVD feed is refreshed |
| `DIFF_RETENTION_DAYS` | `30` | Days to keep content diff files on disk |
| `DATA_DIR` | `data` | Path for SQLite DB, snapshots, and diffs |
| `BROWSER_EXECUTABLE_PATH` | — | Optional path to Chrome/Chromium for screenshot-based checks |

## Scripts

| Command | Description |
|---------|-------------|
| `npm run dev` | Start Rust server (port 3001) and client (port 5173) in watch mode |
| `npm run build` | Build Rust server and client for production |
| `npm start` | Run production build (`vigil/target/release/vigil`) |
| `npm run typecheck` | Run `tsc --noEmit` for the client |
| `npm run lint` | Run ESLint for the client |
| `npm install --prefix client` | Install frontend dependencies |

## Architecture

```
monitor/
├── vigil/           Rust + Axum API + background monitor engines
│   └── src/
│       ├── api/         REST endpoints (auth, servers, ssl, cve, users, …)
│       ├── auth/        JWT middleware + admin user seeding
│       ├── config.rs    Environment config
│       ├── cve/         CVE check engine + NVD/KEV/cvelist schedulers
│       ├── db/          SQLite schema + connection pool
│       ├── monitor/     HTTP check scheduler, checker, hasher, differ, alerter
│       ├── notifiers/   Discord, Pushover, Teams (pluggable trait)
│       ├── ssl/         SSL check engine + alerter
│       └── types.rs     Shared types
└── client/          React + Vite + Tailwind
    └── src/
        ├── api/         Typed fetch wrapper (credentials: include on all requests)
        ├── components/  Reusable UI components + ProtectedRoute
        ├── contexts/    AuthContext (user session state)
        ├── hooks/       Data-fetching hooks + useAuth
        └── pages/       Dashboard, SSL, CVE, Users, Login, …
```

## Authentication

All API routes require a valid session cookie except `/api/auth/*` and `/api/health`.

- **Admin** — full read and write access; can manage users, targets, and notifications
- **Viewer** — read-only access; write buttons are hidden in the UI and blocked at the API level

Passwords are hashed with bcrypt. Sessions are httpOnly cookies signed with `JWT_SECRET`.

## Adding a New Notifier

1. Create `vigil/src/notifiers/<name>.rs` implementing the notifier trait
2. Register it in `vigil/src/notifiers/mod.rs`

The UI dynamically renders config fields from the notifier's config schema — no frontend changes needed.

## Data Storage

- `data/monitor.db` — SQLite database (metadata only)
- `data/snapshots/{serverId}.html` — current baseline HTML per server
- `data/diffs/{diffId}-{timestamp}.html` — immutable diff file per change event
- `data/nvd/` — local NVD mirror (JSON feeds)
- Diffs older than `DIFF_RETENTION_DAYS` are automatically cleaned up on startup
