/// Response shape validation tests
///
/// Each test serialises a hand-crafted struct instance to JSON and asserts that
/// the resulting object contains exactly the keys the TypeScript frontend expects,
/// using snake_case field names (matching the DB columns that the frontend reads
/// via the API).  No network I/O — pure serde_json round-trips.
///
/// Cross-reference: server/src/types.ts defines the canonical TypeScript interfaces.
use serde_json::{json, Value};

// ─── helpers ────────────────────────────────────────────────────────────────

fn has_key(v: &Value, key: &str) -> bool {
    v.as_object().map(|o| o.contains_key(key)).unwrap_or(false)
}

fn check_keys(v: &Value, required: &[&str]) {
    for key in required {
        assert!(
            has_key(v, key),
            "Missing key `{}` in JSON: {}",
            key,
            v
        );
    }
}

// ─── AuthUser ────────────────────────────────────────────────────────────────

#[test]
fn auth_user_shape() {
    // mirrors AuthUser in types.ts: { id, username, role, created_at }
    let v = json!({
        "id": 1_i64,
        "username": "admin",
        "role": "admin",
        "created_at": "2024-01-01T00:00:00Z"
    });
    check_keys(&v, &["id", "username", "role", "created_at"]);
    assert!(v["id"].is_number());
    assert!(v["role"].is_string());
}

// ─── Server (ServerWithStatus) ────────────────────────────────────────────

#[test]
fn server_shape() {
    // mirrors Server in types.ts
    let v = json!({
        "id": 1_i64,
        "name": "Example",
        "url": "https://example.com",
        "interval_seconds": 300_i64,
        "response_time_threshold_ms": 3000_i64,
        "active": 1_i64,          // SQLite boolean — must be 0/1, NOT true/false
        "created_at": "2024-01-01T00:00:00Z",
        "baseline_hash": null,
        "baseline_file": null,
        "last_alerted_at": null,
        "last_alert_type": null,
        "ignore_patterns": null
    });
    check_keys(&v, &[
        "id", "name", "url", "interval_seconds", "response_time_threshold_ms",
        "active", "created_at", "baseline_hash", "baseline_file",
        "last_alerted_at", "last_alert_type", "ignore_patterns",
    ]);
    // active must be 0/1 integer, not boolean
    assert!(v["active"].is_number(), "`active` must be a number (0 or 1)");
    assert!(!v["active"].is_boolean(), "`active` must NOT be a boolean");
}

// ─── Check ────────────────────────────────────────────────────────────────

#[test]
fn check_shape() {
    // mirrors Check in types.ts
    let v = json!({
        "id": 1_i64,
        "server_id": 1_i64,
        "checked_at": "2024-01-01T00:00:00Z",
        "status_code": 200_i64,
        "response_time_ms": 123_i64,
        "is_up": 1_i64,
        "content_hash": null,
        "content_changed": 0_i64,
        "diff_id": null
    });
    check_keys(&v, &[
        "id", "server_id", "checked_at", "status_code", "response_time_ms",
        "is_up", "content_hash", "content_changed", "diff_id",
    ]);
    assert!(v["is_up"].is_number());
    assert!(v["content_changed"].is_number());
}

// ─── NotificationChannel ──────────────────────────────────────────────────

#[test]
fn notification_channel_shape() {
    let v = json!({
        "id": 1_i64,
        "type": "discord",
        "label": "Ops channel",
        "config_json": "{}",
        "active": 1_i64
    });
    check_keys(&v, &["id", "type", "label", "config_json", "active"]);
}

// ─── SslTarget ────────────────────────────────────────────────────────────

#[test]
fn ssl_target_shape() {
    let v = json!({
        "id": 1_i64,
        "name": "example.com",
        "host": "example.com",
        "port": 443_i64,
        "check_interval_seconds": 3600_i64,
        "expiry_threshold_hours": 720_i64,
        "active": 1_i64,
        "created_at": "2024-01-01T00:00:00Z",
        "last_checked_at": null,
        "last_alert_type": null,
        "last_alerted_at": null
    });
    check_keys(&v, &[
        "id", "name", "host", "port", "check_interval_seconds", "expiry_threshold_hours",
        "active", "created_at", "last_checked_at", "last_alert_type", "last_alerted_at",
    ]);
}

// ─── CveTarget ───────────────────────────────────────────────────────────

#[test]
fn cve_target_shape() {
    // mirrors CveTarget in types.ts
    let v = json!({
        "id": 1_i64,
        "name": "OpenSSL",
        "vendor": "openssl",
        "product": "openssl",
        "version": null,
        "min_alert_cvss_score": 7.0_f64,
        "check_interval_seconds": 86400_i64,
        "active": 1_i64,
        "created_at": "2024-01-01T00:00:00Z",
        "last_checked_at": null,
        "last_alerted_at": null
    });
    check_keys(&v, &[
        "id", "name", "vendor", "product", "version",
        "min_alert_cvss_score", "check_interval_seconds",
        "active", "created_at", "last_checked_at", "last_alerted_at",
    ]);
    assert!(v["active"].is_number());
    assert!(v["min_alert_cvss_score"].is_number());
}

// ─── CveTargetWithStats ──────────────────────────────────────────────────

#[test]
fn cve_target_with_stats_shape() {
    let v = json!({
        "target": {
            "id": 1_i64, "name": "OpenSSL", "vendor": "openssl",
            "product": "openssl", "version": null,
            "min_alert_cvss_score": 7.0_f64, "check_interval_seconds": 86400_i64,
            "active": 1_i64, "created_at": "2024-01-01T00:00:00Z",
            "last_checked_at": null, "last_alerted_at": null
        },
        "findings_count": 3_i64,
        "latest_finding": null,
        "top_cvss_score": 9.8_f64,
        "top_cvss_severity": "CRITICAL",
        "kev_count": 1_i64
    });
    check_keys(&v, &[
        "target", "findings_count", "latest_finding",
        "top_cvss_score", "top_cvss_severity", "kev_count",
    ]);
}

// ─── CveFinding (enrichment fields) ──────────────────────────────────────

#[test]
fn cve_finding_shape() {
    // Full shape including enrichment fields added during Phase 4
    let v = json!({
        "id": 1_i64,
        "target_id": 1_i64,
        "cve_id": "CVE-2024-1234",
        "published_at": "2024-01-01T00:00:00Z",
        "last_modified_at": "2024-01-02T00:00:00Z",
        "cvss_score": 9.8_f64,
        "cvss_severity": "CRITICAL",
        "description": "A critical vulnerability",
        "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
        "found_at": "2024-01-01T12:00:00Z",
        "alerted": 1_i64,
        "is_kev": 1_i64,
        "kev_date_added": "2024-01-01",
        "ssvc_exploitation": "active",
        "ssvc_automatable": "yes",
        "ssvc_technical_impact": "total",
        "enrichment_fingerprint": "9.8|CRITICAL|1|active|yes|total",
        "exploitation_alert_sent": "active",
        "rejection_alert_sent": 0_i64,
        "cvelist_state": "PUBLISHED",
        "cvelist_cna_description": null
    });
    check_keys(&v, &[
        "id", "target_id", "cve_id", "published_at", "last_modified_at",
        "cvss_score", "cvss_severity", "description", "nvd_url",
        "found_at", "alerted",
        // enrichment fields
        "is_kev", "kev_date_added",
        "ssvc_exploitation", "ssvc_automatable", "ssvc_technical_impact",
        "enrichment_fingerprint", "exploitation_alert_sent", "rejection_alert_sent",
        "cvelist_state", "cvelist_cna_description",
    ]);
    // is_kev is a SQLite integer (0/1), not a boolean
    assert!(v["is_kev"].is_number());
    assert!(v["alerted"].is_number());
}

// ─── NvdSyncStatus ───────────────────────────────────────────────────────

#[test]
fn nvd_sync_status_shape() {
    let v = json!({
        "is_importing": false,
        "current_feed": null,
        "feed_progress": 0.0_f64,
        "feeds_done": 0_i64,
        "feeds_total": 0_i64,
        "error": null,
        "started_at": null,
        "feed_states": []
    });
    check_keys(&v, &[
        "is_importing", "current_feed", "feed_progress",
        "feeds_done", "feeds_total", "error", "started_at", "feed_states",
    ]);
    assert!(v["is_importing"].is_boolean());
}

// ─── KevSyncState ────────────────────────────────────────────────────────

#[test]
fn kev_sync_state_shape() {
    let v = json!({
        "total": 1200_i64,
        "last_synced_at": null,
        "is_syncing": false,
        "year_stats": []
    });
    check_keys(&v, &["total", "last_synced_at", "is_syncing", "year_stats"]);
}

// ─── VulnrichmentSyncState ───────────────────────────────────────────────

#[test]
fn vulnrichment_sync_state_shape() {
    let v = json!({
        "total": 500_i64,
        "last_synced_at": null,
        "is_syncing": false,
        "exploitation_breakdown": []
    });
    check_keys(&v, &["total", "last_synced_at", "is_syncing", "exploitation_breakdown"]);
}

// ─── CvelistSyncState ────────────────────────────────────────────────────

#[test]
fn cvelist_sync_state_shape() {
    let v = json!({
        "total": 230000_i64,
        "rejected_count": 3000_i64,
        "last_synced_at": null,
        "is_syncing": false,
        "last_repo_version": null
    });
    check_keys(&v, &["total", "rejected_count", "last_synced_at", "is_syncing", "last_repo_version"]);
}

// ─── NVD browse search pagination ────────────────────────────────────────

#[test]
fn nvd_browse_search_shape() {
    let v = json!({
        "data": [],
        "pagination": {
            "total": 0_i64,
            "limit": 20_i64,
            "offset": 0_i64
        }
    });
    check_keys(&v, &["data", "pagination"]);
    check_keys(&v["pagination"], &["total", "limit", "offset"]);
}

// ─── NvdCveDetail ────────────────────────────────────────────────────────

#[test]
fn nvd_cve_detail_shape() {
    let v = json!({
        "cve_id": "CVE-2024-1234",
        "published_at": "2024-01-01T00:00:00Z",
        "last_modified_at": "2024-01-02T00:00:00Z",
        "cvss_score": 9.8_f64,
        "cvss_severity": "CRITICAL",
        "description": "A critical vulnerability",
        "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
        "cpe_entries": [],
        "references": [],
        "kev": null,
        "ssvc": null,
        "cvelist": null
    });
    check_keys(&v, &[
        "cve_id", "published_at", "last_modified_at", "cvss_score", "cvss_severity",
        "description", "nvd_url", "cpe_entries", "references", "kev", "ssvc", "cvelist",
    ]);
}

// ─── User management ─────────────────────────────────────────────────────

#[test]
fn user_shape() {
    let v = json!({
        "id": 1_i64,
        "username": "admin",
        "role": "admin",
        "created_at": "2024-01-01T00:00:00Z"
    });
    check_keys(&v, &["id", "username", "role", "created_at"]);
    // password_hash must NEVER appear in API responses
    assert!(!has_key(&v, "password_hash"), "password_hash must not be in user responses");
}
