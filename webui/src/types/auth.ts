/** Auth state for the castctl web UI (per-run Bearer token, sessionStorage). */

// Credentials entered on the Login page: the management token only.
// Same-origin only — there is no apiBase input.
export interface LoginCredentials {
  managementKey: string;
}

// Auth state. The token lives in sessionStorage (never localStorage, never
// persisted to disk) and dies with the tab/process.
export interface AuthState {
  isAuthenticated: boolean;
  managementKey: string;
  serverVersion: string | null;
  serverBuildDate: string | null;
}

export type ConnectionStatus = 'connected' | 'disconnected' | 'connecting' | 'error';
