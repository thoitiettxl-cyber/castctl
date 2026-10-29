import { useEffect, useState } from 'react';
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
import { PageTransition } from '@/components/common/PageTransition';
import {
  IconBot,
  IconChevronLeft,
  IconFileText,
  IconInfo,
  IconKey,
  IconNetwork,
  IconPlug,
  IconScrollText,
  IconSettings,
  IconShield,
  IconX,
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
      <div className="main-body">
        <button
          type="button"
          aria-label={t('sidebar.toggle_collapse')}
          className="sidebar-backdrop"
          style={{ display: isMobileOpen ? 'block' : undefined, opacity: isMobileOpen ? 1 : undefined, pointerEvents: isMobileOpen ? 'auto' : undefined }}
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
            <button
              type="button"
              className="mobile-menu-btn"
              aria-label={t('sidebar.toggle_collapse')}
              onClick={closeMobile}
            >
              <IconX size={18} />
            </button>
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
          <button
            type="button"
            className="sidebar-toggle-floating"
            aria-label={isCollapsed ? t('sidebar.expand') : t('sidebar.collapse')}
            onClick={toggleCollapse}
          >
            <IconChevronLeft size={18} />
          </button>
        </aside>
        <main className="main-content">
          <header className="main-header">
            <div className="mobile-sidebar-actions">
              <button
                type="button"
                className="mobile-menu-btn"
                aria-label={t('sidebar.toggle_expand')}
                onClick={() => setMobileOpen(true)}
              >
                ☰
              </button>
            </div>
            <div className="header-actions">
              <div className="language-menu">
                <button
                  type="button"
                  aria-label={t('language.switch')}
                  onClick={() => {
                    setLanguageMenuOpen((v) => !v);
                    setThemeMenuOpen(false);
                  }}
                >
                  {language.toUpperCase()}
                </button>
                {languageMenuOpen && (
                  <div className="language-menu-popover" role="menu">
                    {LANGUAGE_ORDER.map((lang: Language) => (
                      <button
                        key={lang}
                        type="button"
                        role="menuitem"
                        className="language-menu-option"
                        onClick={() => {
                          setLanguage(lang);
                          setLanguageMenuOpen(false);
                        }}
                      >
                        <span>{t(LANGUAGE_LABEL_KEYS[lang])}</span>
                        {language === lang && <span className="language-menu-check">✓</span>}
                      </button>
                    ))}
                  </div>
                )}
              </div>
              <div className="language-menu">
                <button
                  type="button"
                  aria-label={t('theme.switch')}
                  onClick={() => {
                    setThemeMenuOpen((v) => !v);
                    setLanguageMenuOpen(false);
                  }}
                >
                  {t(`theme.${theme}`)}
                </button>
                {themeMenuOpen && (
                  <div className="language-menu-popover" role="menu">
                    {(['light', 'white', 'dark', 'auto'] as Theme[]).map((value) => (
                      <button
                        key={value}
                        type="button"
                        role="menuitem"
                        className="language-menu-option"
                        onClick={() => {
                          setTheme(value);
                          setThemeMenuOpen(false);
                        }}
                      >
                        <span>{t(`theme.${value}`)}</span>
                        {theme === value && <span className="language-menu-check">✓</span>}
                      </button>
                    ))}
                  </div>
                )}
              </div>
              <button type="button" onClick={handleLogout}>
                {t('header.logout')}
              </button>
            </div>
          </header>
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
