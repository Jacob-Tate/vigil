export interface Server {
  id: number;
  name: string;
  url: string;
  interval_seconds: number;
  response_time_threshold_ms: number;
  active: number; // SQLite boolean: 1 | 0
  created_at: string;
  baseline_hash: string | null;
  baseline_file: string | null;
  last_alerted_at: string | null;
  last_alert_type: string | null;
  ignore_patterns: string | null; // JSON array of regex strings
}

export interface Check {
  id: number;
  server_id: number;
  checked_at: string;
  status_code: number | null;
  response_time_ms: number | null;
  is_up: number; // SQLite boolean: 1 | 0
  content_hash: string | null;
  content_changed: number; // SQLite boolean: 1 | 0
  diff_id: number | null;
}

export interface ContentDiff {
  id: number;
  server_id: number;
  detected_at: string;
  old_hash: string | null;
  new_hash: string | null;
  diff_file: string;
}

export interface NotificationChannel {
  id: number;
  type: string;
  label: string | null;
  config_json: string;
  active: number; // SQLite boolean: 1 | 0
}

export interface CheckResult {
  statusCode: number | null;
  responseTimeMs: number;
  isUp: boolean;
  rawHtml: string;
  error?: string;
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

export interface AlertPayload {
  serverName: string;
  url: string;
  alertType: AlertType;
  statusCode: number | null;
  responseTimeMs: number | null;
  threshold: number | null;
  diffId: number | null;
  diffViewUrl: string | null;
  detectedAt: string;
  message: string;
  sslDaysRemaining?: number | null;
  sslFingerprint?: string | null;
  sslSubject?: string | null;
}

// SSL Monitor types

export interface SslTarget {
  id: number;
  name: string;
  host: string;
  port: number;
  check_interval_seconds: number;
  expiry_threshold_hours: number;
  active: number; // SQLite boolean: 1 | 0
  created_at: string;
  last_checked_at: string | null;
  last_alert_type: string | null;
  last_alerted_at: string | null;
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
  sans: string | null;       // JSON array of strings
  chain_json: string | null; // JSON array of CertChainEntry objects
  cert_file: string | null;
  alert_type: SslAlertType | null;
}

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

export interface SslCheckResult {
  error: string | null;
  tlsVersion: string | null;
  subjectCn: string | null;
  subjectO: string | null;
  issuerCn: string | null;
  issuerO: string | null;
  validFrom: string | null;
  validTo: string | null;
  daysRemaining: number | null;
  fingerprintSha256: string | null;
  serialNumber: string | null;
  sans: string[];
  chain: CertChainEntry[];
  pemChain: string;
}

export interface SslTargetWithStatus extends SslTarget {
  last_check: SslCheck | null;
}

export interface ServerWithStatus extends Server {
  last_check: Check | null;
}
