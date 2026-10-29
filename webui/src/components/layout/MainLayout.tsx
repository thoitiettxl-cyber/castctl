import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type RefObject,
  type SVGProps,
} from 'react';
import { NavLink, Route, Routes, useLocation, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import type { Language, Theme } from '@/types';
import { LANGUAGE_LABEL_KEYS, LANGUAGE_ORDER } from '@/utils/constants';
import {
  useAuthStore,
  useLanguageStore,
  useNavigationStore,
  useThemeStore,
} from '@/stores';
import { Button } from '@/components/ui/Button';
import { PageTransition } from '@/components/common/PageTransition';
import {
  IconBot,
  IconFileText,
  IconInfo,
  IconKey,
  IconNetwork,
  IconPlug,
  IconScrollText,
  IconSettings,
  IconShield,
} from '@/components/ui/icons';
import { DashboardPage } from '@/pages/DashboardPage';
import { ProfilesPage } from '@/pages/ProfilesPage';
import { ProfileDetailPage } from '@/pages/ProfileDetailPage';
import { OutboundsPage } from '@/pages/OutboundsPage';
import { EndpointsPage } from '@/pages/EndpointsPage';
import { ConfigPage } from '@/pages/ConfigPage';
import { LogsPage } from '@/features/logs/LogsPage';
import { SystemPage } from '@/pages/SystemPage';
import { SettingsPage } from '@/pages/SettingsPage';
import { ScreencastLoginPage } from '@/pages/ScreencastLoginPage';

const SCREENCAST_LOGIN_ENABLED: boolean =
  typeof __CASTCTL_SCREENCAST_LOGIN__ !== 'undefined' && __CASTCTL_SCREENCAST_LOGIN__;

// Header action icons — copied from upstream MainLayout (inline SVGs, not in
// icons.tsx there either). Header triggers are icon-only upstream; the text
// labels ("EN"/"Auto"/"Forget") were fork additions that made the floating
// pill overflow its 38px-square .btn styling.
const headerIconProps: SVGProps<SVGSVGElement> = {
  width: 16,
  height: 16,
  viewBox: '0 0 24 24',
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 2,
  strokeLinecap: 'round',
  strokeLinejoin: 'round',
  'aria-hidden': 'true',
  focusable: 'false',
};

const headerIcons = {
  menu: (
    <svg {...headerIconProps}>
      <path d="M4 7h16" />
      <path d="M4 12h16" />
      <path d="M4 17h16" />
    </svg>
  ),
  close: (
    <svg {...headerIconProps}>
      <path d="M18 6 6 18" />
      <path d="m6 6 12 12" />
    </svg>
  ),
  chevronLeft: (
    <svg {...headerIconProps}>
      <path d="m14 18-6-6 6-6" />
    </svg>
  ),
  chevronRight: (
    <svg {...headerIconProps}>
      <path d="m10 6 6 6-6 6" />
    </svg>
  ),
  language: (
    <svg {...headerIconProps}>
      <circle cx="12" cy="12" r="10" />
      <path d="M2 12h20" />
      <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
    </svg>
  ),
  sun: (
    <svg {...headerIconProps}>
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2v2" />
      <path d="M12 20v2" />
      <path d="m4.93 4.93 1.41 1.41" />
      <path d="m17.66 17.66 1.41 1.41" />
      <path d="M2 12h2" />
      <path d="M20 12h2" />
      <path d="m6.34 17.66-1.41 1.41" />
      <path d="m19.07 4.93-1.41 1.41" />
    </svg>
  ),
  moon: (
    <svg {...headerIconProps}>
      <path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9z" />
    </svg>
  ),
  whiteTheme: (
    <svg {...headerIconProps}>
      <circle cx="12" cy="12" r="7" />
      <circle cx="12" cy="12" r="3" fill="currentColor" stroke="none" />
    </svg>
  ),
  autoTheme: (
    <svg {...headerIconProps}>
      <defs>
        <clipPath id="mainLayoutAutoThemeSunLeftHalf">
          <rect x="0" y="0" width="12" height="24" />
        </clipPath>
      </defs>
      <circle cx="12" cy="12" r="4" />
      <circle
        cx="12"
        cy="12"
        r="4"
        clipPath="url(#mainLayoutAutoThemeSunLeftHalf)"
        fill="currentColor"
      />
      <path d="M12 2v2" />
      <path d="M12 20v2" />
      <path d="M4.93 4.93l1.41 1.41" />
      <path d="M17.66 17.66l1.41 1.41" />
      <path d="M2 12h2" />
      <path d="M20 12h2" />
      <path d="M6.34 17.66l-1.41 1.41" />
      <path d="M19.07 4.93l-1.41 1.41" />
    </svg>
  ),
  logout: (
    <svg {...headerIconProps}>
      <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
      <path d="m16 17 5-5-5-5" />
      <path d="M21 12H9" />
    </svg>
  ),
};

// Theme-picker swatch cards, copied verbatim from upstream MainLayout.
const THEME_CARDS: Array<{
  key: Theme;
  labelKey: string;
  colors: { bg: string; card: string; border: string; text: string; textMuted: string };
}> = [
  {
    key: 'auto',
    labelKey: 'theme.auto',
    colors: {
      bg: 'linear-gradient(135deg, #ffffff 0 50%, #111111 50% 100%)',
      card: 'linear-gradient(135deg, #ffffff 0 50%, #1a1a1a 50% 100%)',
      border: '#bdbdbd',
      text: '#2d2a26',
      textMuted: 'linear-gradient(135deg, #c9c9c9 0 50%, #5a5a5a 50% 100%)',
    },
  },
  {
    key: 'white',
    labelKey: 'theme.white',
    colors: {
      bg: '#ffffff',
      card: '#ffffff',
      border: '#e5e5e5',
      text: '#2d2a26',
      textMuted: '#a29c95',
    },
  },
  {
    key: 'light',
    labelKey: 'theme.light',
    colors: {
      bg: '#faf9f5',
      card: '#f0eee8',
      border: '#e3e1db',
      text: '#2d2a26',
      textMuted: '#a29c95',
    },
  },
  {
    key: 'dark',
    labelKey: 'theme.dark',
    colors: {
      bg: '#151412',
      card: '#1d1b18',
      border: '#3a3530',
      text: '#f6f4f1',
      textMuted: '#9c958d',
    },
  },
];

/** Close a popover menu on outside pointer-down or Escape — upstream useMenuDismiss. */
function useMenuDismiss(
  open: boolean,
  menuRef: RefObject<HTMLDivElement | null>,
  onClose: () => void,
) {
  useEffect(() => {
    if (!open) {
      return;
    }

    const handlePointerDown = (event: MouseEvent) => {
      if (!menuRef.current?.contains(event.target as Node)) {
        onClose();
      }
    };

    const handleEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        onClose();
      }
    };

    document.addEventListener('mousedown', handlePointerDown);
    document.addEventListener('keydown', handleEscape);

    return () => {
      document.removeEventListener('mousedown', handlePointerDown);
      document.removeEventListener('keydown', handleEscape);
    };
  }, [open, menuRef, onClose]);
}

type NavEntry = {
  to: string;
  icon: (props: { size?: number }) => React.ReactElement;
  labelKey: string;
  metaKey: string;
  end?: boolean;
};

const NAV_GROUPS: { labelKey: string; entries: NavEntry[] }[] = [
  {
    labelKey: 'nav_groups.operate',
    entries: [
      { to: '/', icon: IconBot, labelKey: 'nav.dashboard', metaKey: 'nav_meta.dashboard', end: true },
      { to: '/profiles', icon: IconKey, labelKey: 'nav.profiles', metaKey: 'nav_meta.profiles' },
      ...(SCREENCAST_LOGIN_ENABLED
        ? [{ to: '/login-browser', icon: IconShield, labelKey: 'nav.login', metaKey: 'nav_meta.login' }]
        : []),
    ],
  },
  {
    labelKey: 'nav_groups.gateway',
    entries: [
      { to: '/outbounds', icon: IconPlug, labelKey: 'nav.outbounds', metaKey: 'nav_meta.outbounds' },
      { to: '/endpoints', icon: IconNetwork, labelKey: 'nav.endpoints', metaKey: 'nav_meta.endpoints' },
    ],
  },
  {
    labelKey: 'nav_groups.control',
    entries: [
      { to: '/config', icon: IconFileText, labelKey: 'nav.config_management', metaKey: 'nav_meta.config_management' },
      { to: '/settings', icon: IconSettings, labelKey: 'nav.settings', metaKey: 'nav_meta.settings' },
    ],
  },
  {
    labelKey: 'nav_groups.observe',
    entries: [
      { to: '/logs', icon: IconScrollText, labelKey: 'nav.logs', metaKey: 'nav_meta.logs' },
      { to: '/system', icon: IconInfo, labelKey: 'nav.system_info', metaKey: 'nav_meta.system_info' },
    ],
  },
];

export function MainLayout() {
  const { t } = useTranslation();
  const location = useLocation();
  const navigate = useNavigate();
  const logout = useAuthStore((state) => state.logout);
  const isCollapsed = useNavigationStore((state) => state.isCollapsed);
  const isMobileOpen = useNavigationStore((state) => state.isMobileOpen);
  const toggleCollapse = useNavigationStore((state) => state.toggleCollapse);
  const setMobileOpen = useNavigationStore((state) => state.setMobileOpen);
  const closeMobile = useNavigationStore((state) => state.closeMobile);
  const theme = useThemeStore((state) => state.theme);
  const setTheme = useThemeStore((state) => state.setTheme);
  const language = useLanguageStore((state) => state.language);
  const setLanguage = useLanguageStore((state) => state.setLanguage);
  const [languageMenuOpen, setLanguageMenuOpen] = useState(false);
  const [themeMenuOpen, setThemeMenuOpen] = useState(false);
  const languageMenuRef = useRef<HTMLDivElement | null>(null);
  const themeMenuRef = useRef<HTMLDivElement | null>(null);

  const closeLanguageMenu = useCallback(() => setLanguageMenuOpen(false), []);
  const closeThemeMenu = useCallback(() => setThemeMenuOpen(false), []);
  useMenuDismiss(languageMenuOpen, languageMenuRef, closeLanguageMenu);
  useMenuDismiss(themeMenuOpen, themeMenuRef, closeThemeMenu);

  const toggleLanguageMenu = useCallback(() => {
    setLanguageMenuOpen((v) => !v);
    setThemeMenuOpen(false);
  }, []);
  const toggleThemeMenu = useCallback(() => {
    setThemeMenuOpen((v) => !v);
    setLanguageMenuOpen(false);
  }, []);

  useEffect(() => {
    closeMobile();
  }, [location.pathname, closeMobile]);

  const handleLogout = () => {
    logout();
    navigate('/login', { replace: true });
  };

  const sidebarCls = ['sidebar', isMobileOpen ? 'open' : '', isCollapsed ? 'collapsed' : '']
    .filter(Boolean)
    .join(' ');

  return (
    <div className={`app-shell${isCollapsed ? ' sidebar-is-collapsed' : ''}`}>
      <div className="top-gradient-blur" aria-hidden="true" />

      <header className="main-header">
        <Button
          type="button"
          variant="ghost"
          className="sidebar-toggle-floating"
          aria-label={isCollapsed ? t('sidebar.expand') : t('sidebar.collapse')}
          onClick={toggleCollapse}
        >
          {isCollapsed ? headerIcons.chevronRight : headerIcons.chevronLeft}
        </Button>
        <div className="mobile-sidebar-actions">
          <Button
            className="mobile-menu-btn"
            variant="ghost"
            size="sm"
            aria-label={t('sidebar.toggle_expand')}
            onClick={() => setMobileOpen(!isMobileOpen)}
          >
            {isMobileOpen ? headerIcons.close : headerIcons.menu}
          </Button>
        </div>
        <div className="header-actions">
          <div className={`language-menu ${languageMenuOpen ? 'open' : ''}`} ref={languageMenuRef}>
            <Button
              variant="ghost"
              size="sm"
              title={t('language.switch')}
              aria-label={t('language.switch')}
              aria-haspopup="menu"
              aria-expanded={languageMenuOpen}
              onClick={toggleLanguageMenu}
            >
              {headerIcons.language}
            </Button>
            {languageMenuOpen && (
              <div className="language-menu-popover" role="menu" aria-label={t('language.switch')}>
                {LANGUAGE_ORDER.map((lang: Language) => (
                  <Button
                    key={lang}
                    type="button"
                    variant="plain"
                    role="menuitemradio"
                    aria-checked={language === lang}
                    className={`language-menu-option ${language === lang ? 'active' : ''}`}
                    onClick={() => {
                      setLanguage(lang);
                      setLanguageMenuOpen(false);
                    }}
                  >
                    <span>{t(LANGUAGE_LABEL_KEYS[lang])}</span>
                    {language === lang && <span className="language-menu-check">✓</span>}
                  </Button>
                ))}
              </div>
            )}
          </div>
          <div className={`theme-menu ${themeMenuOpen ? 'open' : ''}`} ref={themeMenuRef}>
            <Button
              variant="ghost"
              size="sm"
              title={t('theme.switch')}
              aria-label={t('theme.switch')}
              aria-haspopup="menu"
              aria-expanded={themeMenuOpen}
              onClick={toggleThemeMenu}
            >
              {theme === 'auto'
                ? headerIcons.autoTheme
                : theme === 'dark'
                  ? headerIcons.moon
                  : theme === 'white'
                    ? headerIcons.whiteTheme
                    : headerIcons.sun}
            </Button>
            {themeMenuOpen && (
              <div className="theme-menu-popover" role="menu" aria-label={t('theme.switch')}>
                {THEME_CARDS.map((tc) => (
                  <Button
                    key={tc.key}
                    type="button"
                    variant="plain"
                    role="menuitemradio"
                    aria-checked={theme === tc.key}
                    className={`theme-card ${theme === tc.key ? 'active' : ''}`}
                    onClick={() => {
                      setTheme(tc.key);
                      setThemeMenuOpen(false);
                    }}
                  >
                    <div
                      className="theme-card-preview"
                      style={{
                        background: tc.colors.bg,
                        border: `1px solid ${tc.colors.border}`,
                      }}
                    >
                      <div
                        className="theme-card-header"
                        style={{
                          background: tc.colors.card,
                          borderBottom: `1px solid ${tc.colors.border}`,
                        }}
                      />
                      <div className="theme-card-body">
                        <div
                          className="theme-card-sidebar"
                          style={{
                            background: tc.colors.card,
                            borderRight: `1px solid ${tc.colors.border}`,
                          }}
                        />
                        <div className="theme-card-content" style={{ background: tc.colors.bg }}>
                          <div
                            className="theme-card-line"
                            style={{ background: tc.colors.textMuted }}
                          />
                          <div
                            className="theme-card-line short"
                            style={{ background: tc.colors.textMuted }}
                          />
                        </div>
                      </div>
                    </div>
                    <span className="theme-card-label">{t(tc.labelKey)}</span>
                  </Button>
                ))}
              </div>
            )}
          </div>
          <Button
            variant="ghost"
            size="sm"
            title={t('header.logout')}
            aria-label={t('header.logout')}
            onClick={handleLogout}
          >
            {headerIcons.logout}
          </Button>
        </div>
      </header>

      <div className="main-body">
        <Button
          type="button"
          variant="plain"
          aria-label={t('sidebar.toggle_collapse')}
          className={`sidebar-backdrop ${isMobileOpen ? 'visible' : ''}`}
          onClick={closeMobile}
        />
        <aside className={sidebarCls} aria-label={t('title.full')}>
          <div className="sidebar-header">
            <div className="sidebar-brand">
              <span className="sidebar-brand-logo" aria-hidden="true">C</span>
              <span className="sidebar-brand-text">
                <span className="sidebar-brand-title">castctl</span>
                <span className="sidebar-brand-subtitle">{t('sidebar.subtitle')}</span>
              </span>
            </div>
          </div>
          <nav className="nav-section">
            {NAV_GROUPS.map((group) => (
              <div className="nav-group" key={group.labelKey}>
                <div className="nav-group-label">{t(group.labelKey)}</div>
                {group.entries.map((entry) => (
                  <NavLink
                    key={entry.to}
                    to={entry.to}
                    end={entry.end}
                    className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
                    title={t(entry.metaKey)}
                  >
                    <span className="nav-icon">
                      <entry.icon size={18} />
                    </span>
                    <span className="nav-text">
                      <span className="nav-label">{t(entry.labelKey)}</span>
                    </span>
                  </NavLink>
                ))}
              </div>
            ))}
          </nav>
        </aside>
        <main className="main-content">
          <PageTransition
            render={(location) => (
              <Routes location={location}>
                <Route path="/" element={<DashboardPage />} />
                <Route path="/profiles" element={<ProfilesPage />} />
                <Route path="/profiles/:name" element={<ProfileDetailPage />} />
                <Route path="/outbounds" element={<OutboundsPage />} />
                <Route path="/endpoints" element={<EndpointsPage />} />
                <Route path="/config" element={<ConfigPage />} />
                <Route path="/logs" element={<LogsPage />} />
                <Route path="/system" element={<SystemPage />} />
                <Route path="/settings" element={<SettingsPage />} />
                {SCREENCAST_LOGIN_ENABLED && (
                  <Route path="/login-browser" element={<ScreencastLoginPage />} />
                )}
                <Route path="*" element={<DashboardPage />} />
              </Routes>
            )}
          />
        </main>
      </div>
    </div>
  );
}
