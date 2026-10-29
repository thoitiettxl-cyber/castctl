import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Button } from '@/components/ui/Button';
import { Card } from '@/components/ui/Card';

/**
 * Screencast login shell — FEATURE-FLAGGED (build-time
 * VITE_ENABLE_SCREENCAST_LOGIN; route + nav hidden when off).
 * Design §6.3 shell only: NO CDP, NO WebSocket screencast, NO keeper.
 * With mocks on, renders a mock frame for screenshots. In production
 * builds without mocks, shows the intro + fallback copy only.
 * Browser-optional: with no browser on the server, the user falls back
 * to `auth import` (see the Muse login card on the profile page).
 */
export function ScreencastLoginPage() {
  const { t } = useTranslation();
  const [started, setStarted] = useState(false);
  const mocksOn =
    typeof __CASTCTL_USE_MOCKS__ !== 'undefined' && __CASTCTL_USE_MOCKS__;

  return (
    <div className="page-root" style={{ display: 'flex', flexDirection: 'column', gap: 16, maxWidth: 860 }}>
      <Card title={t('screencast_login.title')}>
        <p style={{ marginTop: 0 }}>{t('screencast_login.intro')}</p>
        <p>{t('screencast_login.remote_note')}</p>
        <p>{t('screencast_login.no_browser')}</p>
        {!started ? (
          <Button onClick={() => setStarted(true)}>{t('screencast_login.start')}</Button>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {mocksOn ? (
              <div
                aria-label={t('screencast_login.mock_frame')}
                style={{
                  aspectRatio: '9 / 16',
                  maxWidth: 420,
                  border: '1px solid var(--border-color)',
                  borderRadius: 8,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  padding: 16,
                  textAlign: 'center',
                  background: 'var(--bg-secondary)',
                }}
              >
                {t('screencast_login.mock_frame')}
              </div>
            ) : (
              <p>{t('screencast_login.flag_off')}</p>
            )}
            <div style={{ display: 'flex', gap: 8 }}>
              <Button variant="secondary" onClick={() => setStarted(false)}>
                {t('screencast_login.cancel')}
              </Button>
              <Button onClick={() => setStarted(false)}>{t('screencast_login.done')}</Button>
            </div>
          </div>
        )}
      </Card>
    </div>
  );
}
