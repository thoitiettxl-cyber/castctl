/** Navigation/sidebar UI state (desktop collapse + mobile drawer). */

import { create } from 'zustand';

interface NavigationState {
  isCollapsed: boolean;
  isMobileOpen: boolean;
  toggleCollapse: () => void;
  setMobileOpen: (open: boolean) => void;
  closeMobile: () => void;
}

export const useNavigationStore = create<NavigationState>((set) => ({
  isCollapsed: false,
  isMobileOpen: false,
  toggleCollapse: () => set((state) => ({ isCollapsed: !state.isCollapsed })),
  setMobileOpen: (open: boolean) => set({ isMobileOpen: open }),
  closeMobile: () => set({ isMobileOpen: false }),
}));
