export interface Server {
  id: number;
  name: string;
  url: string;
  interval_seconds: number;
  response_time_threshold_ms: number;
  active: number;
  created_at: string;
  baseline_hash: string | null;
  baseline_file: string | null;
  last_alerted_at: string | null;
  last_alert_type: string | null;
  ignore_patterns: string | null; // JSON array of regex strings
  last_check: Check | null;
}

export interface Check {
  id: number;
  server_id: number;
  checked_at: string;
  status_code: number | null;
  response_time_ms: number | null;
  is_up: number;
  content_hash: string | null;
  content_changed: number;
  diff_id: number | null;
}

export interface ContentDiff {
  id: number;
  server_id: number;
  detected_at: string;
  old_hash: string | null;
  new_hash: string | null;
  diff_file: string;
  diff_content?: string;
}

export interface CheckStats {
  total_checks: number;
  up_checks: number;
  avg_response_time_ms: number | null;
  min_response_time_ms: number | null;
  max_response_time_ms: number | null;
  content_changes: number;
  uptime_pct: number | null;
}

export interface PaginatedChecks {
  data: Check[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    pages: number;
  };
}

export type AlertType =
  | "DOWN"
  | "DEGRADED"
  | "CONTENT_CHANGED"
  | "RECOVERED"
  | "SSL_EXPIRING"
  | "SSL_EXPIRED"
  | "SSL_ERROR"
  | "SSL_CHANGED";

export type SslAlertType = "SSL_EXPIRING" | "SSL_EXPIRED" | "SSL_ERROR" | "SSL_CHANGED";

export type NotifierType = "discord" | "pushover" | "teams";

export interface ConfigField {
  label: string;
  type: "text" | "password" | "number";
  required: boolean;
  placeholder?: string;
}

export interface NotifierTypeDef {
  type: NotifierType;
  displayName: string;
  configSchema: Record<string, ConfigField>;
}

export interface NotificationChannel {
  id: number;
  type: NotifierType;
  label: string | null;
  config: Record<string, unknown>;
  active: number;
}

export interface ServerFormData {
  name: string;
  url: string;
  interval_seconds: number;
  response_time_threshold_ms: number;
  active: boolean;
  ignore_patterns: string[];
}

// SSL Monitor types

export interface CertChainEntry {
  subject_cn: string | null;
  subject_o: string | null;
  issuer_cn: string | null;
  issuer_o: string | null;
  valid_from: string;
  valid_to: string;
  fingerprint_sha256: string;
  serial_number: string;
  is_self_signed: boolean;
}

export interface SslTarget {
  id: number;
  name: string;
  host: string;
  port: number;
  check_interval_seconds: number;
  expiry_threshold_hours: number;
  active: number;
  created_at: string;
  last_checked_at: string | null;
  last_alert_type: string | null;
  last_alerted_at: string | null;
  last_check: SslCheck | null;
}

export interface SslCheck {
  id: number;
  target_id: number;
  checked_at: string;
  error: string | null;
  tls_version: string | null;
  subject_cn: string | null;
  subject_o: string | null;
  issuer_cn: string | null;
  issuer_o: string | null;
  valid_from: string | null;
  valid_to: string | null;
  days_remaining: number | null;
  fingerprint_sha256: string | null;
  serial_number: string | null;
  sans: string | null;       // JSON array string
  chain_json: string | null; // JSON array string
  cert_file: string | null;
  alert_type: SslAlertType | null;
}

export interface SslCheckStats {
  total_checks: number;
  error_checks: number;
  avg_days_remaining: number | null;
  min_days_remaining: number | null;
  cert_changes: number;
}

export interface PaginatedSslChecks {
  data: SslCheck[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    pages: number;
  };
}

export interface SslTargetFormData {
  name: string;
  host: string;
  port: number;
  check_interval_seconds: number;
  expiry_threshold_hours: number;
  active: boolean;
}

// CVE Monitor types

export interface CveTarget {
  id: number;
  name: string;
  vendor: string | null;
  product: string;
  version: string | null;
  min_alert_cvss_score: number;
  check_interval_seconds: number;
  active: number;
  created_at: string;
  last_checked_at: string | null;
  last_alerted_at: string | null;
}

export interface CveFinding {
  id: number;
  target_id: number;
  cve_id: string;
  published_at: string | null;
  last_modified_at: string | null;
  cvss_score: number | null;
  cvss_severity: string | null;
  description: string | null;
  nvd_url: string | null;
  found_at: string;
  alerted: number;
  is_kev: number; // 1 | 0
  kev_date_added: string | null;
  ssvc_exploitation: string | null;
  ssvc_automatable: string | null;
  ssvc_technical_impact: string | null;
  cvelist_state: string | null;
  cvelist_cna_description: string | null;
}

export interface CveTargetWithStats extends CveTarget {
  findings_count: number;
  latest_finding: CveFinding | null;
  top_cvss_score: number | null;
  top_cvss_severity: string | null;
  kev_count: number;
}

export interface CveTargetFormData {
  name: string;
  vendor: string | null;
  product: string;
  version: string | null;
  min_alert_cvss_score: number;
  check_interval_seconds: number;
  active: boolean;
}

export interface NvdFeedState {
  feed_name: string;
  last_modified_date: string | null;
  sha256: string | null;
  total_cves: number | null;
  imported_at: string | null;
}

export interface NvdSyncStatus {
  isImporting: boolean;
  currentFeed: string | null;
  feedProgress: number;
  feedsDone: number;
  feedsTotal: number;
  error: string | null;
  startedAt: string | null;
  feedStates: NvdFeedState[];
}

export interface NvdCveRef {
  url: string;
  source?: string;
  tags?: string[];
}

export interface NvdCpeEntry {
  cpe_string: string;
  version_start_including: string | null;
  version_start_excluding: string | null;
  version_end_including: string | null;
  version_end_excluding: string | null;
}

export interface NvdCveDetail {
  cve_id: string;
  published_at: string | null;
  last_modified_at: string | null;
  cvss_score: number | null;
  cvss_severity: string | null;
  description: string | null;
  nvd_url: string | null;
  cpe_entries: NvdCpeEntry[];
  references?: NvdCveRef[];
  kev?: {
    date_added: string;
    vulnerability_name: string | null;
    required_action: string | null;
    due_date: string | null;
    known_ransomware_campaign_use: string | null;
  } | null;
  ssvc?: {
    exploitation: string | null;
    automatable: string | null;
    technical_impact: string | null;
  } | null;
  cvelist?: {
    state: string;
    cna_description: string | null;
    cna_title: string | null;
    date_published: string | null;
    date_updated: string | null;
  } | null;
}

export interface KevYearStat {
  year: string;
  count: number;
  ransomware_count: number;
}

export interface KevSyncState {
  total: number;
  last_synced_at: string | null;
  is_syncing: boolean;
  year_stats: KevYearStat[];
}

export interface SsvcExploitationStat {
  exploitation: string;
  count: number;
}

export interface VulnrichmentSyncState {
  total: number;
  last_synced_at: string | null;
  is_syncing: boolean;
  exploitation_breakdown: SsvcExploitationStat[];
}

export interface CvelistSyncState {
  total: number;
  rejected_count: number;
  last_synced_at: string | null;
  is_syncing: boolean;
  last_repo_version: string | null;
}

export interface PaginatedCveFindings {
  data: CveFinding[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    pages: number;
  };
}

export interface NvdCveBrowseRow extends Omit<NvdCveDetail, "cpe_entries" | "references" | "kev" | "ssvc" | "cvelist"> {
  is_kev: number; // 1 | 0
  ssvc_exploitation: string | null;
  cvelist_state: string | null;
}

export interface PaginatedNvdCves {
  data: NvdCveBrowseRow[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    pages: number;
  };
}


// Auth types

export type UserRole = "admin" | "viewer";

export interface AuthUser {
  id: number;
  username: string;
  role: UserRole;
}

export interface UserListItem {
  id: number;
  username: string;
  role: UserRole;
  created_at: string;
}

export interface UserFormData {
  username: string;
  password: string;
  role: UserRole;
}

export interface UserUpdateData {
  username?: string;
  password?: string;
  role?: UserRole;
}
