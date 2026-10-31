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
  /** Live logs disabled server-side (log gate off / file output not
   * configured): entries is empty and the page shows the disabled
   * notice instead of the table. */
  disabled?: boolean;
  reason?: string;
}

export interface TelegramSettings {
  configured: boolean;
  masked: string;
  /** Profile the bot operates (Go telegram block `profile` key).
   * Absent when no block exists. */
  profile?: string;
  allowed_user_ids?: number[];
  auto_approve: boolean;
  auto_allow_once: boolean;
}

/** One keeper entry with its state-file status (GET /keeper). The
 * status object mirrors keeper.ReadStatus: name-only cookie records,
 * never values. */
export interface KeeperEntryStatus {
  tag: string;
  profile: string;
  browser: string;
  interval_seconds: number;
  notify: string;
  /** keeper.Status verbatim: omitempty fields are absent (not
   * null) when unset; the object itself is always present — a
   * never-ticked entry has an empty last_tick_outcome. */
  status: {
    tag: string;
    profile: string;
    logged_out: boolean;
    keeper_stopped: boolean;
    keeper_stopped_reason?: string;
    last_checked_at?: string;
    last_tick_outcome: string;
    earliest_expiry?: string;
    next_check_at?: string;
    state_corrupt?: boolean;
  };
}

/** Screencast availability for one profile (GET /screencast/status). */
export interface ScreencastStatus {
  available: boolean;
  reason: string;
  profile: string;
}

/** Minted screencast session (POST /screencast/{profile}/start). The
 * ws_url carries the single-use session token in its query string;
 * the management Bearer token is NEVER put in a URL. */
export interface ScreencastStartResult {
  session_id: string;
  ws_url: string;
}

export interface ConfigContent {
  content: string;
  sha256: string;
  source: string;
}
