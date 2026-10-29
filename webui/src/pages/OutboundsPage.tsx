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
import { outboundsApi } from '@/services/api';
import type { OutboundSummary } from '@/types';

/** Read-only list of shared outbounds (design §2, §4.3).
 * Summaries arrive redacted from the server and are rendered verbatim;
 * nothing here parses secrets out of them. Writes live in the Config
 * Editor, so this page offers no add/edit actions.
 */
export function OutboundsPage() {
  const { t } = useTranslation();
  const [outbounds, setOutbounds] = useState<OutboundSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [failed, setFailed] = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    const load = async () => {
      setLoading(true);
      setFailed(false);
      try {
        setOutbounds(await outboundsApi.list(controller.signal));
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
      <Card title={t('outbounds.list.title')} className="page-root">
        <p style={{ marginTop: 0 }}>{t('common.error')}</p>
        <Button variant="secondary" onClick={refresh}>
          {t('common.retry')}
        </Button>
      </Card>
    );
  }

  return (
    <Card
      title={t('outbounds.list.title')}
      className="page-root"
      extra={
        <Button variant="secondary" size="sm" onClick={refresh}>
          {t('common.refresh')}
        </Button>
      }
    >
      {outbounds.length === 0 ? (
        <EmptyState title={t('outbounds.list.empty')} />
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t('common.name')}</TableHead>
              <TableHead>{t('common.type')}</TableHead>
              <TableHead>{t('outbounds.list.summary')}</TableHead>
              <TableHead>{t('outbounds.list.used_by')}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {outbounds.map((outbound) => (
              <TableRow key={outbound.tag}>
                <TableCell>{outbound.tag}</TableCell>
                <TableCell>{outbound.type}</TableCell>
                <TableCell>{outbound.summary}</TableCell>
                <TableCell>
                  {outbound.used_by.length === 0
                    ? t('outbounds.list.none')
                    : outbound.used_by.join(', ')}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </Card>
  );
}
