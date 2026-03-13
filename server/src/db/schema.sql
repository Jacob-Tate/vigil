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
    last_alert_type             TEXT,
    ignore_patterns             TEXT
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

-- SSL Monitor: one row per monitored domain/host
CREATE TABLE IF NOT EXISTS ssl_targets (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    name                     TEXT NOT NULL,
    host                     TEXT NOT NULL,
    port                     INTEGER NOT NULL DEFAULT 443,
    check_interval_seconds   INTEGER NOT NULL DEFAULT 3600,
    expiry_threshold_hours   INTEGER NOT NULL DEFAULT 168,
    active                   INTEGER NOT NULL DEFAULT 1,
    created_at               TEXT NOT NULL DEFAULT (datetime('now')),
    last_checked_at          TEXT,
    last_alert_type          TEXT,
    last_alerted_at          TEXT
);

-- SSL Monitor: one row per check run
CREATE TABLE IF NOT EXISTS ssl_checks (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id           INTEGER NOT NULL REFERENCES ssl_targets(id) ON DELETE CASCADE,
    checked_at          TEXT NOT NULL DEFAULT (datetime('now')),
    error               TEXT,
    tls_version         TEXT,
    subject_cn          TEXT,
    subject_o           TEXT,
    issuer_cn           TEXT,
    issuer_o            TEXT,
    valid_from          TEXT,
    valid_to            TEXT,
    days_remaining      INTEGER,
    fingerprint_sha256  TEXT,
    serial_number       TEXT,
    sans                TEXT,       -- JSON array of strings
    chain_json          TEXT,       -- JSON array of CertChainEntry objects
    cert_file           TEXT,       -- path to PEM snapshot file
    alert_type          TEXT        -- null | SSL_EXPIRING | SSL_EXPIRED | SSL_ERROR | SSL_CHANGED
);

CREATE INDEX IF NOT EXISTS idx_ssl_checks_target ON ssl_checks(target_id);
CREATE INDEX IF NOT EXISTS idx_ssl_checks_at     ON ssl_checks(checked_at DESC);

-- CVE Monitor: local NVD mirror
CREATE TABLE IF NOT EXISTS nvd_cves (
    cve_id           TEXT PRIMARY KEY,
    published_at     TEXT,
    last_modified_at TEXT,
    cvss_score       REAL,
    cvss_severity    TEXT,   -- CRITICAL | HIGH | MEDIUM | LOW | NONE
    description      TEXT,
    nvd_url          TEXT,
    references_json  TEXT    -- JSON array of {url, source, tags[]}
);

-- CPE applicability: one row per CPE string per CVE
CREATE TABLE IF NOT EXISTS nvd_cve_cpes (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id                  TEXT NOT NULL REFERENCES nvd_cves(cve_id) ON DELETE CASCADE,
    cpe_string              TEXT NOT NULL,
    version_start_including TEXT,
    version_start_excluding TEXT,
    version_end_including   TEXT,
    version_end_excluding   TEXT
);
CREATE INDEX IF NOT EXISTS idx_nvd_cpe_cve_id    ON nvd_cve_cpes(cve_id);
CREATE INDEX IF NOT EXISTS idx_nvd_cpe_string    ON nvd_cve_cpes(cpe_string);

-- Feed import state: one row per named feed
CREATE TABLE IF NOT EXISTS nvd_feed_state (
    feed_name          TEXT PRIMARY KEY,  -- "modified", "recent", "2024", etc.
    last_modified_date TEXT,              -- from META file
    sha256             TEXT,              -- from META file
    total_cves         INTEGER,
    imported_at        TEXT
);

-- CVE monitoring targets (standalone, like SSL targets)
CREATE TABLE IF NOT EXISTS cve_targets (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    name                   TEXT NOT NULL,
    vendor                 TEXT,      -- CPE vendor segment; defaults to product if omitted
    product                TEXT NOT NULL,
    version                TEXT,      -- CPE version; NULL means match any version
    min_alert_cvss_score   REAL NOT NULL DEFAULT 7.0,
    check_interval_seconds INTEGER NOT NULL DEFAULT 86400,
    active                 INTEGER NOT NULL DEFAULT 1,
    created_at             TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_checked_at        TEXT,
    last_alerted_at        TEXT
);

-- CVEs found/matched for each target
CREATE TABLE IF NOT EXISTS cve_findings (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id        INTEGER NOT NULL REFERENCES cve_targets(id) ON DELETE CASCADE,
    cve_id           TEXT NOT NULL,
    published_at     TEXT,
    last_modified_at TEXT,
    cvss_score       REAL,
    cvss_severity    TEXT,
    description      TEXT,
    nvd_url          TEXT,
    found_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    alerted          INTEGER NOT NULL DEFAULT 0,
    UNIQUE(target_id, cve_id)
);
CREATE INDEX IF NOT EXISTS idx_cve_findings_target_id ON cve_findings(target_id);
CREATE INDEX IF NOT EXISTS idx_cve_findings_found_at  ON cve_findings(found_at DESC);
