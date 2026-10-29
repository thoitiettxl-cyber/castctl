/** Auth store: sessionStorage token only (design §5). No persistence,
 * no obfuscation, no token in localStorage. 401 → logout via the
 * `unauthorized` event emitted by the fetch wrapper.
 */

import { create } from 'zustand';
import type { AuthState } from '@/types';
import { clearAuthToken, getAuthToken, setAuthToken } from '@/services/api/client';
import { statusApi } from '@/services/api';

interface AuthStore extends AuthState {
  login: (managementKey: string) => Promise<{ success: boolean; error?: string }>;
  logout: () => void;
  restore: () => void;
}

export const useAuthStore = create<AuthStore>((set) => ({
  isAuthenticated: false,
  managementKey: '',
  serverVersion: null,
  serverBuildDate: null,

  login: async (managementKey: string) => {
    setAuthToken(managementKey);
    try {
      const status = await statusApi.get();
      set({
        isAuthenticated: true,
        managementKey,
        serverVersion: status.version,
        serverBuildDate: null,
      });
      return { success: true };
    } catch {
      clearAuthToken();
      set({ isAuthenticated: false, managementKey: '', serverVersion: null });
      return { success: false, error: 'login.invalid_token' };
    }
  },

  logout: () => {
    clearAuthToken();
    set({ isAuthenticated: false, managementKey: '', serverVersion: null, serverBuildDate: null });
  },

  restore: () => {
    const token = getAuthToken();
    if (token) {
      set({ isAuthenticated: true, managementKey: token });
    }
  },
}));

if (typeof window !== 'undefined') {
  window.addEventListener('unauthorized', () => {
    useAuthStore.getState().logout();
  });
}
