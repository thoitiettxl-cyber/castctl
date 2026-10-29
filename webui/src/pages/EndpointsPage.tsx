import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Button } from '@/components/ui/Button';
import { Card } from '@/components/ui/Card';
import { EmptyState } from '@/components/ui/EmptyState';
import { LoadingSpinner } from '@/components/ui/LoadingSpinner';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/Table';
import { endpointsApi } from '@/services/api';
import type { EndpointSummary } from '@/types';

/** Read-only list of endpoints (design §2, §4.3).
 * Summaries arrive redacted from the server and are rendered verbatim;
 * nothing here parses secrets out of them. Writes live in the Config
 * Editor. The wg-quick import note below is text only: import itself is
 * a future write, so there is no import implementation or file parsing
 * on this page.
 */
export function EndpointsPage() {
  const { t } = useTranslation();
  const [endpoints, setEndpoints] = useState<EndpointSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [failed, setFailed] = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    const load = async () => {
      setLoading(true);
      setFailed(false);
      try {
        setEndpoints(await endpointsApi.list(controller.signal));
      } catch {
        // AbortError (via the client's plain Error) is not a failure:
        // the effect was cleaned up. Server errors surface only as the
        // generic message below, never with a raw error body.
        if (controller.signal.aborted) return;
        setFailed(true);
      } finally {
        if (!controller.signal.aborted) setLoading(false);
      }
    };
    void load();
    return () => controller.abort();
  }, [refreshKey]);

  const refresh = () => setRefreshKey((key) => key + 1);

  if (loading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <LoadingSpinner />
        <span>{t('common.loading')}</span>
      </div>
    );
  }

  if (failed) {
    return (
      <Card title={t('endpoints.list.title')}>
        <p style={{ marginTop: 0 }}>{t('common.error')}</p>
        <Button variant="secondary" onClick={refresh}>
          {t('common.retry')}
        </Button>
      </Card>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <Card
        title={t('endpoints.list.title')}
        extra={
          <Button variant="secondary" size="sm" onClick={refresh}>
            {t('common.refresh')}
          </Button>
        }
      >
        {endpoints.length === 0 ? (
          <EmptyState title={t('endpoints.list.empty')} />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('common.name')}</TableHead>
                <TableHead>{t('common.type')}</TableHead>
                <TableHead>{t('outbounds.list.summary')}</TableHead>
                <TableHead>{t('endpoints.list.used_by')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {endpoints.map((endpoint) => (
                <TableRow key={endpoint.tag}>
                  <TableCell>{endpoint.tag}</TableCell>
                  <TableCell>{endpoint.type}</TableCell>
                  <TableCell>{endpoint.summary}</TableCell>
                  <TableCell>
                    {endpoint.used_by.length === 0
                      ? t('outbounds.list.none')
                      : endpoint.used_by.join(', ')}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Card>
      <Card title={t('endpoints.list.import_preview')}>
        <p style={{ margin: 0 }}>{t('endpoints.list.import_hint')}</p>
      </Card>
    </div>
  );
}
