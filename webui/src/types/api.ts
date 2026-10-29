/** API envelope + domain types for the castctl /api/v1 management API. */

// Error thrown by the fetch wrapper. `apiCode` is the typed `type` string
// from the server envelope `{error: {type, message}}`, when present.
export type ApiError = Error & {
  status?: number;
  code?: string;
  apiCode?: string;
  details?: unknown;
  data?: unknown;
};

export interface ApiEnvelope<T> {
  data: T;
}

export interface ApiErrorEnvelope {
  error: { type: string; message: string };
}

export interface StatusInfo {
  version: string;
  go_version: string;
  singbox_version: string;
  listen_addr: string;
  remote_exposure: boolean;
  config_path: string;
  config_source: string;
  default_profile: string;
  profile_count: number;
  outbound_count: number;
  endpoint_count: number;
  bundle_sha256: string;
}

export interface ProfileSummary {
  name: string;
  default: boolean;
  source: string;
  has_cookies: boolean;
  outbound_tag: string | null;
  fingerprint: string;
  dir: string;
}

export interface ProfileDetail extends ProfileSummary {
  // Full redacted entry as returned by `profile show` (secrets redacted
  // server-side). Kept open: the server owns the exact key set.
  entry: Record<string, unknown>;
  paths: Record<string, string>;
  warnings: string[];
}

export interface ProfileTestPhase {
  phase: string;
  status: string;
  duration_ms: number;
  detail?: string;
}

export interface ProfileTestResult {
  profile: string;
  phases: ProfileTestPhase[];
  egress_ip?: string;
  first_failing_phase?: string;
  overall: string;
}

export interface LoginStatus {
  logged_in: boolean;
  vm_id_prefix: string | null;
  expiry: string | null;
  cookies_present: boolean;
  cookies_format: string | null;
  last_checked_at: string | null;
  error?: { type: string; message: string };
}

export interface LoginImportResult {
  saved: boolean;
  verified: boolean;
  vm_id_prefix?: string;
  error?: { type: string; message: string };
}

export interface OutboundSummary {
  tag: string;
  type: string;
  summary: string;
  used_by: string[];
}

export interface EndpointSummary {
  tag: string;
  type: string;
  summary: string;
  used_by: string[];
}

export interface LogEntry {
  ts: string;
  level: string;
  kind: string;
  message: string;
}

export interface LogsPage {
  entries: LogEntry[];
  next_cursor: string | null;
  more: boolean;
}

export interface TelegramSettings {
  configured: boolean;
  masked: string;
  owner_id?: number;
  allowed_user_ids?: number[];
  auto_approve: boolean;
  auto_allow_once: boolean;
  watch: boolean;
}

export interface ConfigContent {
  content: string;
  sha256: string;
  source: string;
}
