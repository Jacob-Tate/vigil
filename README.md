# Monitor

A self-hosted server monitoring application. Checks URLs for uptime, response time, and content changes — alerting you via Discord, Pushover, or Microsoft Teams when something goes wrong.

## Features

- **Uptime monitoring** — alerts on non-2xx/3xx responses
- **Response time tracking** — configurable threshold per server; alerts on slow responses
- **Content change detection** — SHA-256 page hashing; stores and displays diffs when content changes
- **Per-server check intervals** — each server has its own polling interval
- **Multi-channel alerts** — Discord webhook, Pushover, Microsoft Teams webhook
- **Diff viewer** — visual inline diff of old vs new page content, stored on disk
- **Manual triggers** — run an immediate check from the UI
- **Baseline reset** — re-snapshot a page as the new baseline

## Prerequisites

- Node.js 18+
- npm 9+

## Quick Start

```bash
git clone <repo>
cd monitor
npm run install:all
cp .env.example server/.env
npm run dev
```

- Frontend: http://localhost:5173
- API: http://localhost:3001

## Environment Variables

Create `server/.env` (see `.env.example`):

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3001` | Express server port |
| `BASE_URL` | `http://localhost:5173` | Base URL for deep links in alerts |
| `DATA_DIR` | `./data` | Path to store SQLite DB, snapshots, and diffs |
| `ALERT_COOLDOWN_SECONDS` | `3600` | Seconds between repeat down alerts (per server) |
| `DIFF_RETENTION_DAYS` | `30` | Days to keep content diff files on disk |

## Scripts

| Command | Description |
|---------|-------------|
| `npm run dev` | Start both server (port 3001) and client (port 5173) in watch mode |
| `npm run build` | Build client and server for production |
| `npm start` | Run production build (`node server/dist/index.js`) |
| `npm run typecheck` | Run `tsc --noEmit` for both workspaces |
| `npm run lint` | Run ESLint for both workspaces |
| `npm run install:all` | Install all workspace dependencies |

## Architecture

```
monitor/
├── server/          Node.js + Express API + background monitor engine
│   └── src/
│       ├── api/         REST endpoints
│       ├── db/          SQLite schema + connection
│       ├── monitor/     Check scheduler, HTTP checker, hasher, differ, alerter
│       └── notifiers/   Discord, Pushover, Teams (pluggable INotifier interface)
└── client/          React + Vite + Tailwind
    └── src/
        ├── api/         Typed fetch wrapper
        ├── components/  Reusable UI components
        ├── hooks/       Data-fetching hooks
        └── pages/       Dashboard, ServerDetail, DiffViewer, NotificationConfig
```

### Adding a New Notifier

1. Create `server/src/notifiers/<name>.ts` implementing the `INotifier` interface
2. Register it in `server/src/notifiers/index.ts` in the `NOTIFIER_MAP`

No other changes needed — the UI dynamically renders config fields from `configSchema`.

## Data Storage

- `server/data/monitor.db` — SQLite database (metadata only)
- `server/data/snapshots/{serverId}.html` — current baseline HTML per server
- `server/data/diffs/{diffId}-{timestamp}.html` — immutable diff file per change event
- Diffs older than `DIFF_RETENTION_DAYS` are automatically cleaned up on startup
