-- content_diffs must be defined before checks due to FK reference
CREATE TABLE IF NOT EXISTS content_diffs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id     INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    detected_at   TEXT NOT NULL DEFAULT (datetime('now')),
    old_hash      TEXT,
    new_hash      TEXT,
    diff_file     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_diffs_server_id ON content_diffs(server_id);
CREATE INDEX IF NOT EXISTS idx_diffs_detected_at ON content_diffs(detected_at DESC);

CREATE TABLE IF NOT EXISTS servers (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    name                        TEXT NOT NULL,
    url                         TEXT NOT NULL UNIQUE,
    interval_seconds            INTEGER NOT NULL DEFAULT 300,
    response_time_threshold_ms  INTEGER NOT NULL DEFAULT 3000,
    active                      INTEGER NOT NULL DEFAULT 1,
    created_at                  TEXT NOT NULL DEFAULT (datetime('now')),
    baseline_hash               TEXT,
    baseline_file               TEXT,
    last_alerted_at             TEXT,
    last_alert_type             TEXT
);

CREATE TABLE IF NOT EXISTS checks (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id         INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    checked_at        TEXT NOT NULL DEFAULT (datetime('now')),
    status_code       INTEGER,
    response_time_ms  INTEGER,
    is_up             INTEGER NOT NULL DEFAULT 0,
    content_hash      TEXT,
    content_changed   INTEGER NOT NULL DEFAULT 0,
    diff_id           INTEGER REFERENCES content_diffs(id)
);

CREATE INDEX IF NOT EXISTS idx_checks_server_id  ON checks(server_id);
CREATE INDEX IF NOT EXISTS idx_checks_checked_at ON checks(checked_at DESC);

CREATE TABLE IF NOT EXISTS notification_channels (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    type        TEXT NOT NULL,
    label       TEXT,
    config_json TEXT NOT NULL,
    active      INTEGER NOT NULL DEFAULT 1
);
