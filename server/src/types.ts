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

export type AlertType = "DOWN" | "DEGRADED" | "CONTENT_CHANGED" | "RECOVERED";

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
}

export interface ServerWithStatus extends Server {
  last_check: Check | null;
}
