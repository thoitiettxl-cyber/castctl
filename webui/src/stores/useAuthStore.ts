/** Auth store: sessionStorage token only (design §5). No persistence,
 * no obfuscation, no token in localStorage. 401 → logout via the
 * `unauthorized` event emitted by the fetch wrapper.
 */

import { create } from 'zustand';
import type { AuthState } from '@/types';
import type { ApiError } from '@/types';
import { clearAuthToken, getAuthToken, setAuthToken } from '@/services/api/client';
import { statusApi } from '@/services/api';
import { isIdleExpired, lastActivityAt, recordActivity } from '@/utils/idle';

interface AuthStore extends AuthState {
  /** Effective session_idle_timeout_seconds from /status, or null
   * until the first status fetch after login/restore. */
  sessionIdleTimeoutSeconds: number | null;
  login: (managementKey: string) => Promise<{ success: boolean; error?: string }>;
  logout: () => void;
  restore: () => void;
  setSessionIdleTimeout: (seconds: number) => void;
  /** Discard the token when the tab has been idle past the timeout.
   * Returns true when it expired (and logged out). */
  checkIdleExpiry: (now?: number) => boolean;
}

export const useAuthStore = create<AuthStore>((set, get) => ({
  isAuthenticated: false,
  managementKey: '',
  serverVersion: null,
  serverBuildDate: null,
  sessionIdleTimeoutSeconds: null,

  login: async (managementKey: string) => {
    setAuthToken(managementKey);
    try {
      const status = await statusApi.get();
      recordActivity(Date.now());
      set({
        isAuthenticated: true,
        managementKey,
        serverVersion: status.version,
        serverBuildDate: null,
        sessionIdleTimeoutSeconds: status.session_idle_timeout_seconds,
      });
      return { success: true };
    } catch (err) {
      clearAuthToken();
      set({ isAuthenticated: false, managementKey: '', serverVersion: null, sessionIdleTimeoutSeconds: null });
      // A 429 is the login rate limiter (5 failed verifications per
      // 5 minutes by default): say so, instead of "invalid token".
      if ((err as ApiError).status === 429) return { success: false, error: 'login.rate_limited' };
      return { success: false, error: 'login.invalid_token' };
    }
  },

  logout: () => {
    clearAuthToken();
    set({ isAuthenticated: false, managementKey: '', serverVersion: null, serverBuildDate: null, sessionIdleTimeoutSeconds: null });
  },

  restore: () => {
    const token = getAuthToken();
    if (token) {
      set({ isAuthenticated: true, managementKey: token });
    }
  },

  setSessionIdleTimeout: (seconds: number) => {
    set({ sessionIdleTimeoutSeconds: seconds });
  },

  checkIdleExpiry: (now = Date.now()) => {
    const { sessionIdleTimeoutSeconds } = get();
    if (isIdleExpired(sessionIdleTimeoutSeconds, lastActivityAt(), now)) {
      get().logout();
      return true;
    }
    return false;
  },
}));

if (typeof window !== 'undefined') {
  window.addEventListener('unauthorized', () => {
    useAuthStore.getState().logout();
  });
}
