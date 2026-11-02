/** Frontend idle expiry (webui.session_idle_timeout).
 *
 * The server stays stateless Bearer: the frontend discards the token
 * after `idleTimeoutSeconds` without user activity and forces a
 * re-login. A stolen Bearer stays valid until token rotation — the
 * server cannot revoke it; this expiry only bounds an unattended
 * browser tab. Pure helpers (testable without a DOM) plus the
 * sessionStorage activity stamp.
 */

import { SESSION_KEY_LAST_ACTIVITY } from './constants';

/** Last-activity timestamp (ms since epoch) from sessionStorage. */
export function lastActivityAt(): number | null {
  try {
    const raw = sessionStorage.getItem(SESSION_KEY_LAST_ACTIVITY);
    if (!raw) return null;
    const value = Number(raw);
    return Number.isFinite(value) ? value : null;
  } catch {
    return null;
  }
}

/** Stamp "now" as the last activity. Callers throttle (see
 * IDLE_ACTIVITY_WRITE_INTERVAL_MS) so a mousemove storm does not
 * write storage on every event. */
export function recordActivity(now: number): void {
  try {
    sessionStorage.setItem(SESSION_KEY_LAST_ACTIVITY, String(now));
  } catch {
    // sessionStorage unavailable (private mode) — expiry then falls
    // back to "no stamp": the caller treats a missing stamp as
    // not-expired until the first recorded activity.
  }
}

/** True when the session has been idle longer than the configured
 * timeout. A missing stamp or an unknown timeout (null) never
 * expires: the timeout is fetched from /status after login, and a
 * tab that never recorded activity has not been idle yet. */
export function isIdleExpired(
  idleTimeoutSeconds: number | null,
  lastActivity: number | null,
  now: number,
): boolean {
  if (idleTimeoutSeconds === null || lastActivity === null) return false;
  if (idleTimeoutSeconds <= 0) return false;
  return now - lastActivity > idleTimeoutSeconds * 1000;
}
