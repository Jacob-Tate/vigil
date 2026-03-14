use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Auth types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    Admin,
    Viewer,
}

impl std::fmt::Display for UserRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserRole::Admin => write!(f, "admin"),
            UserRole::Viewer => write!(f, "viewer"),
        }
    }
}

impl std::str::FromStr for UserRole {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "admin" => Ok(UserRole::Admin),
            "viewer" => Ok(UserRole::Viewer),
            _ => Err(format!("unknown role: {}", s)),
        }
    }
}

/// Full user row as stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub role: String, // "admin" | "viewer" — kept as String to match DB text column
    pub created_at: String,
}

/// Subset of User returned to the client (no password hash).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthUser {
    pub id: i64,
    pub username: String,
    pub role: String,
}

// ---------------------------------------------------------------------------
// HTTP Monitor types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Server {
    pub id: i64,
    pub name: String,
    pub url: String,
    pub interval_seconds: i64,
    pub response_time_threshold_ms: i64,
    pub active: i64,          // SQLite boolean: 1 | 0
    pub created_at: String,
    pub baseline_hash: Option<String>,
    pub baseline_file: Option<String>,
    pub last_alerted_at: Option<String>,
    pub last_alert_type: Option<String>,
    pub ignore_patterns: Option<String>, // JSON array of regex strings
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Check {
    pub id: i64,
    pub server_id: i64,
    pub checked_at: String,
    pub status_code: Option<i64>,
    pub response_time_ms: Option<i64>,
    pub is_up: i64,           // SQLite boolean: 1 | 0
    pub content_hash: Option<String>,
    pub content_changed: i64, // SQLite boolean: 1 | 0
    pub diff_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentDiff {
    pub id: i64,
    pub server_id: i64,
    pub detected_at: String,
    pub old_hash: Option<String>,
    pub new_hash: Option<String>,
    pub diff_file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerWithStatus {
    #[serde(flatten)]
    pub server: Server,
    pub last_check: Option<Check>,
}

// ---------------------------------------------------------------------------
// Notification types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationChannel {
    pub id: i64,
    #[serde(rename = "type")]
    pub channel_type: String,
    pub label: Option<String>,
    pub config_json: String,
    pub active: i64, // SQLite boolean: 1 | 0
}

// ---------------------------------------------------------------------------
// Alert types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AlertType {
    #[serde(rename = "DOWN")]
    Down,
    #[serde(rename = "DEGRADED")]
    Degraded,
    #[serde(rename = "CONTENT_CHANGED")]
    ContentChanged,
    #[serde(rename = "RECOVERED")]
    Recovered,
    #[serde(rename = "SSL_EXPIRING")]
    SslExpiring,
    #[serde(rename = "SSL_EXPIRED")]
    SslExpired,
    #[serde(rename = "SSL_ERROR")]
    SslError,
    #[serde(rename = "SSL_CHANGED")]
    SslChanged,
    #[serde(rename = "CVE_NEW")]
    CveNew,
    #[serde(rename = "CVE_EXPLOIT_ESCALATION")]
    CveExploitEscalation,
    #[serde(rename = "CVE_UPDATED")]
    CveUpdated,
    #[serde(rename = "CVE_REJECTED")]
    CveRejected,
}

impl std::fmt::Display for AlertType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            AlertType::Down => "DOWN",
            AlertType::Degraded => "DEGRADED",
            AlertType::ContentChanged => "CONTENT_CHANGED",
            AlertType::Recovered => "RECOVERED",
            AlertType::SslExpiring => "SSL_EXPIRING",
            AlertType::SslExpired => "SSL_EXPIRED",
            AlertType::SslError => "SSL_ERROR",
            AlertType::SslChanged => "SSL_CHANGED",
            AlertType::CveNew => "CVE_NEW",
            AlertType::CveExploitEscalation => "CVE_EXPLOIT_ESCALATION",
            AlertType::CveUpdated => "CVE_UPDATED",
            AlertType::CveRejected => "CVE_REJECTED",
        };
        write!(f, "{}", s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveDigestItem {
    pub cve_id: String,
    pub cvss_score: Option<f64>,
    pub cvss_severity: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertPayload {
    #[serde(rename = "serverName")]
    pub server_name: String,
    pub url: String,
    #[serde(rename = "alertType")]
    pub alert_type: AlertType,
    #[serde(rename = "statusCode")]
    pub status_code: Option<i64>,
    #[serde(rename = "responseTimeMs")]
    pub response_time_ms: Option<i64>,
    pub threshold: Option<i64>,
    #[serde(rename = "diffId")]
    pub diff_id: Option<i64>,
    #[serde(rename = "diffViewUrl")]
    pub diff_view_url: Option<String>,
    #[serde(rename = "detectedAt")]
    pub detected_at: String,
    pub message: String,
    #[serde(rename = "sslDaysRemaining", skip_serializing_if = "Option::is_none")]
    pub ssl_days_remaining: Option<i64>,
    #[serde(rename = "sslFingerprint", skip_serializing_if = "Option::is_none")]
    pub ssl_fingerprint: Option<String>,
    #[serde(rename = "sslSubject", skip_serializing_if = "Option::is_none")]
    pub ssl_subject: Option<String>,
    #[serde(rename = "cveId", skip_serializing_if = "Option::is_none")]
    pub cve_id: Option<String>,
    #[serde(rename = "cvssScore", skip_serializing_if = "Option::is_none")]
    pub cvss_score: Option<f64>,
    #[serde(rename = "cvssSeverity", skip_serializing_if = "Option::is_none")]
    pub cvss_severity: Option<String>,
    #[serde(rename = "cveDigest", skip_serializing_if = "Option::is_none")]
    pub cve_digest: Option<Vec<CveDigestItem>>,
    #[serde(rename = "previousExploitation", skip_serializing_if = "Option::is_none")]
    pub previous_exploitation: Option<String>,
    #[serde(rename = "changedFields", skip_serializing_if = "Option::is_none")]
    pub changed_fields: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// SSL Monitor types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslTarget {
    pub id: i64,
    pub name: String,
    pub host: String,
    pub port: i64,
    pub check_interval_seconds: i64,
    pub expiry_threshold_hours: i64,
    pub active: i64,
    pub created_at: String,
    pub last_checked_at: Option<String>,
    pub last_alert_type: Option<String>,
    pub last_alerted_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslCheck {
    pub id: i64,
    pub target_id: i64,
    pub checked_at: String,
    pub error: Option<String>,
    pub tls_version: Option<String>,
    pub subject_cn: Option<String>,
    pub subject_o: Option<String>,
    pub issuer_cn: Option<String>,
    pub issuer_o: Option<String>,
    pub valid_from: Option<String>,
    pub valid_to: Option<String>,
    pub days_remaining: Option<i64>,
    pub fingerprint_sha256: Option<String>,
    pub serial_number: Option<String>,
    pub sans: Option<String>,       // JSON array of strings
    pub chain_json: Option<String>, // JSON array of CertChainEntry objects
    pub cert_file: Option<String>,
    pub alert_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertChainEntry {
    pub subject_cn: Option<String>,
    pub subject_o: Option<String>,
    pub issuer_cn: Option<String>,
    pub issuer_o: Option<String>,
    pub valid_from: String,
    pub valid_to: String,
    pub fingerprint_sha256: String,
    pub serial_number: String,
    pub is_self_signed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslTargetWithStatus {
    #[serde(flatten)]
    pub target: SslTarget,
    pub last_check: Option<SslCheck>,
}

// ---------------------------------------------------------------------------
// CVE Monitor types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveTarget {
    pub id: i64,
    pub name: String,
    pub vendor: Option<String>,
    pub product: String,
    pub version: Option<String>,
    pub min_alert_cvss_score: f64,
    pub check_interval_seconds: i64,
    pub active: i64,
    pub created_at: String,
    pub last_checked_at: Option<String>,
    pub last_alerted_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveFinding {
    pub id: i64,
    pub target_id: i64,
    pub cve_id: String,
    pub published_at: Option<String>,
    pub last_modified_at: Option<String>,
    pub cvss_score: Option<f64>,
    pub cvss_severity: Option<String>,
    pub description: Option<String>,
    pub nvd_url: Option<String>,
    pub found_at: String,
    pub alerted: i64,
    pub is_kev: i64,
    pub kev_date_added: Option<String>,
    pub ssvc_exploitation: Option<String>,
    pub ssvc_automatable: Option<String>,
    pub ssvc_technical_impact: Option<String>,
    pub enrichment_fingerprint: Option<String>,
    pub exploitation_alert_sent: Option<String>,
    pub rejection_alert_sent: Option<i64>,
    pub cvelist_state: Option<String>,
    pub cvelist_cna_description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveTargetWithStats {
    #[serde(flatten)]
    pub target: CveTarget,
    pub findings_count: i64,
    pub latest_finding: Option<CveFinding>,
    pub top_cvss_score: Option<f64>,
    pub top_cvss_severity: Option<String>,
    pub kev_count: i64,
}

// ---------------------------------------------------------------------------
// NVD types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NvdFeedState {
    pub feed_name: String,
    pub last_modified_date: Option<String>,
    pub sha256: Option<String>,
    pub total_cves: Option<i64>,
    pub imported_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NvdSyncStatus {
    #[serde(rename = "isImporting")]
    pub is_importing: bool,
    #[serde(rename = "currentFeed")]
    pub current_feed: Option<String>,
    #[serde(rename = "feedProgress")]
    pub feed_progress: f64,
    #[serde(rename = "feedsDone")]
    pub feeds_done: usize,
    #[serde(rename = "feedsTotal")]
    pub feeds_total: usize,
    pub error: Option<String>,
    #[serde(rename = "startedAt")]
    pub started_at: Option<String>,
    #[serde(rename = "feedStates")]
    pub feed_states: Vec<NvdFeedState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NvdCveRef {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NvdCpeEntry {
    pub cpe_string: String,
    pub version_start_including: Option<String>,
    pub version_start_excluding: Option<String>,
    pub version_end_including: Option<String>,
    pub version_end_excluding: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NvdCveDetail {
    pub cve_id: String,
    pub published_at: Option<String>,
    pub last_modified_at: Option<String>,
    pub cvss_score: Option<f64>,
    pub cvss_severity: Option<String>,
    pub description: Option<String>,
    pub nvd_url: Option<String>,
    pub cpe_entries: Vec<NvdCpeEntry>,
    pub references: Vec<NvdCveRef>,
    pub kev: Option<KevDetail>,
    pub ssvc: Option<SsvcDetail>,
    pub cvelist: Option<CvelistDetail>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KevDetail {
    pub date_added: String,
    pub vulnerability_name: Option<String>,
    pub required_action: Option<String>,
    pub due_date: Option<String>,
    pub known_ransomware_campaign_use: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsvcDetail {
    pub exploitation: Option<String>,
    pub automatable: Option<String>,
    pub technical_impact: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CvelistDetail {
    pub state: String,
    pub cna_description: Option<String>,
    pub cna_title: Option<String>,
    pub date_published: Option<String>,
    pub date_updated: Option<String>,
}

// ---------------------------------------------------------------------------
// CISA types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CisaKevEntry {
    pub cve_id: String,
    pub vendor_project: Option<String>,
    pub product: Option<String>,
    pub vulnerability_name: Option<String>,
    pub date_added: Option<String>,
    pub short_description: Option<String>,
    pub required_action: Option<String>,
    pub due_date: Option<String>,
    pub known_ransomware_campaign_use: Option<String>,
    pub notes: Option<String>,
    pub synced_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KevYearStat {
    pub year: String,
    pub count: i64,
    pub ransomware_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KevSyncState {
    pub total: i64,
    pub last_synced_at: Option<String>,
    pub is_syncing: bool,
    pub year_stats: Vec<KevYearStat>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsvcExploitationStat {
    pub exploitation: String,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnrichmentSyncState {
    pub total: i64,
    pub last_synced_at: Option<String>,
    pub is_syncing: bool,
    pub exploitation_breakdown: Vec<SsvcExploitationStat>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CvelistSyncState {
    pub total: i64,
    pub rejected_count: i64,
    pub last_synced_at: Option<String>,
    pub is_syncing: bool,
    pub last_repo_version: Option<String>,
}
