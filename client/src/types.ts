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

export type AlertType = "DOWN" | "DEGRADED" | "CONTENT_CHANGED" | "RECOVERED";

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
