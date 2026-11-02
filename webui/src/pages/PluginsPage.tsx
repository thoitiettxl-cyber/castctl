import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { pluginsApi } from '@/services/api';
import type { PluginsStatus } from '@/types';
import { getErrorMessage } from '@/utils/helpers';
import { Button } from '@/components/ui/Button';
import { Card } from '@/components/ui/Card';
import { EmptyState } from '@/components/ui/EmptyState';
import { LoadingSpinner } from '@/components/ui/LoadingSpinner';

/** Plugins page (gated unavailable, D1/Q1 option b).
 *
 * The server advertises `available: false` with a reason and an empty
 * list. This page shows that state honestly: no plugin is listed, no
 * enable/disable control is offered, no data is faked. The follow-up
 * that wires the real plugin loader reuses the page structure and
 * the pluginsApi.status fetch; it must version the contract before
 * adding list/enable/disable calls.
 */
export function PluginsPage() {
  const { t } = useTranslation();
  const [status, setStatus] = useState<PluginsStatus | null>(null);
  const [error, setError] = useState('');
  const [loaded, setLoaded] = useState(false);

  const load = async () => {
    setError('');
    try {
      setStatus(await pluginsApi.status());
      setLoaded(true);
    } catch (err) {
      setError(getErrorMessage(err, t('common.error')));
    }
  };

  useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (!loaded && !error) {
    return (
      <div className="page-root">
        <h1>{t('plugins.title')}</h1>
        <LoadingSpinner />
        <p>{t('common.loading')}</p>
      </div>
    );
  }

  return (
    <div className="page-root">
      <h1>{t('plugins.title')}</h1>
      {error && (
        <div className="error-box" role="alert">
          {error}{' '}
          <Button variant="secondary" size="sm" onClick={() => void load()}>
            {t('common.retry')}
          </Button>
        </div>
      )}
      {status && (
        <Card title={status.available ? t('plugins.title') : t('plugins.unavailable_title')}>
          <p>{status.reason}</p>
          {/* No list is rendered in either case: this build has no
              list/enable/disable contract. An available:true from a
              future build must not render as "no plugins" — the
              follow-up versions the contract and adds the list. */}
          {!status.available && (
            <EmptyState title={t('plugins.empty')} description={t('plugins.unavailable_hint')} />
          )}
        </Card>
      )}
    </div>
  );
}
