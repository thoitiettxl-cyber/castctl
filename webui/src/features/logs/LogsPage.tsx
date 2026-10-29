import { useCallback, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { logsApi } from '@/services/api';
import type { LogEntry } from '@/types';
import { copyToClipboard } from '@/utils/clipboard';
import { getErrorMessage } from '@/utils/helpers';
import { useInterval } from '@/hooks/useInterval';
import { Button } from '@/components/ui/Button';
import { Card } from '@/components/ui/Card';
import { EmptyState } from '@/components/ui/EmptyState';
import { LoadingSpinner } from '@/components/ui/LoadingSpinner';
import { Select } from '@/components/ui/Select';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/Table';
import { ToggleSwitch } from '@/components/ui/ToggleSwitch';

type LevelFilter = 'all' | 'info' | 'warn' | 'error';

const LEVELS: LevelFilter[] = ['all', 'info', 'warn', 'error'];
const PAGE_LIMIT = 100;
const POLL_INTERVAL_MS = 5000;

/** Server event log (design §2): cursor polling via the frozen logsApi
 * client, level filter, cursor pagination with "load more".
 *
 * Auto-scroll choice: there is NO auto-scroll and NO follow-to-bottom.
 * The list renders in normal page flow (newest page as the server
 * returns it) and polling only replaces the first page while
 * auto-refresh is on; the user pauses polling with the toggle instead
 * of the page yanking the viewport. Poll ticks never run while a
 * load-more fetch is in flight, so an append is never clobbered by a
 * refresh. Entry order is whatever order the server returns.
 */
export function LogsPage() {
  const { t } = useTranslation();
  const [entries, setEntries] = useState<LogEntry[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [more, setMore] = useState(false);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState('');
  const [level, setLevel] = useState<LevelFilter>('all');
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  const inFlightRef = useRef(false);
  const copiedTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(
    () => () => {
      if (copiedTimerRef.current !== null) {
        clearTimeout(copiedTimerRef.current);
      }
    },
    []
  );

  const fetchFirst = useCallback(async () => {
    if (inFlightRef.current) return;
    inFlightRef.current = true;
    setError('');
    try {
      const page = await logsApi.list({
        limit: PAGE_LIMIT,
        level: level === 'all' ? undefined : level,
      });
      setEntries(page.entries);
      setNextCursor(page.next_cursor);
      setMore(page.more);
    } catch (err) {
      setError(getErrorMessage(err, t('common.error')));
    } finally {
      inFlightRef.current = false;
      setLoading(false);
    }
  }, [level, t]);

  useEffect(() => {
    setEntries([]);
    setNextCursor(null);
    setMore(false);
    setLoading(true);
    void fetchFirst();
  }, [fetchFirst]);

  useInterval(
    () => {
      void fetchFirst();
    },
    autoRefresh ? POLL_INTERVAL_MS : null
  );

  const handleLoadMore = async () => {
    if (!nextCursor || loadingMore || inFlightRef.current) return;
    inFlightRef.current = true;
    setLoadingMore(true);
    setError('');
    try {
      const page = await logsApi.list({
        cursor: nextCursor,
        limit: PAGE_LIMIT,
        level: level === 'all' ? undefined : level,
      });
      setEntries((prev) => [...prev, ...page.entries]);
      setNextCursor(page.next_cursor);
      setMore(page.more);
    } catch (err) {
      setError(getErrorMessage(err, t('common.error')));
    } finally {
      inFlightRef.current = false;
      setLoadingMore(false);
    }
  };

  const handleCopy = async (entry: LogEntry, index: number) => {
    const copied = await copyToClipboard(
      `${entry.ts} [${entry.level}] ${entry.kind} ${entry.message}`
    );
    if (!copied) return;
    setCopiedIndex(index);
    if (copiedTimerRef.current !== null) {
      clearTimeout(copiedTimerRef.current);
    }
    copiedTimerRef.current = setTimeout(() => {
      setCopiedIndex((current) => (current === index ? null : current));
    }, 2000);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <Card title={t('logs.title')}>
        <div
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            alignItems: 'center',
            gap: 12,
            marginBottom: 12,
          }}
        >
          <span>{t('logs.filter')}</span>
          <Select
            value={level}
            options={LEVELS.map((value) => ({
              value,
              label: value === 'all' ? t('logs.level_all') : value,
            }))}
            onChange={(value) => setLevel(value as LevelFilter)}
            ariaLabel={t('logs.level')}
            fullWidth={false}
            size="sm"
          />
          <ToggleSwitch
            checked={autoRefresh}
            onChange={setAutoRefresh}
            label={t('logs.auto_refresh')}
            ariaLabel={t('logs.auto_refresh')}
          />
          <Button variant="secondary" size="sm" onClick={() => setAutoRefresh((value) => !value)}>
            {autoRefresh ? t('logs.pause') : t('logs.resume')}
          </Button>
          <Button variant="ghost" size="sm" onClick={() => void fetchFirst()} disabled={loading}>
            {t('common.refresh')}
          </Button>
        </div>
        {error && (
          <div className="error-box" role="alert" style={{ marginBottom: 12 }}>
            {error}
          </div>
        )}
        {loading && entries.length === 0 ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <LoadingSpinner />
            <span>{t('common.loading')}</span>
          </div>
        ) : entries.length === 0 ? (
          <EmptyState title={t('logs.empty')} />
        ) : (
          <>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>ts</TableHead>
                  <TableHead>{t('logs.level')}</TableHead>
                  <TableHead>kind</TableHead>
                  <TableHead>message</TableHead>
                  <TableHead>{t('common.actions')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {entries.map((entry, index) => (
                  // No id field exists on LogEntry; ts+index is the only
                  // available row identity.
                  <TableRow key={`${entry.ts}-${index}`}>
                    <TableCell style={{ whiteSpace: 'nowrap' }}>{entry.ts}</TableCell>
                    <TableCell style={{ whiteSpace: 'nowrap' }}>{entry.level}</TableCell>
                    <TableCell style={{ whiteSpace: 'nowrap' }}>{entry.kind}</TableCell>
                    <TableCell style={{ overflowWrap: 'anywhere', wordBreak: 'break-word' }}>
                      {entry.message}
                    </TableCell>
                    <TableCell>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => void handleCopy(entry, index)}
                      >
                        {copiedIndex === index ? t('logs.copied') : t('logs.copy')}
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            {more && nextCursor && (
              <div style={{ display: 'flex', justifyContent: 'center', marginTop: 12 }}>
                <Button
                  variant="secondary"
                  onClick={() => void handleLoadMore()}
                  loading={loadingMore}
                  disabled={loadingMore}
                >
                  {t('logs.load_more')}
                </Button>
              </div>
            )}
          </>
        )}
      </Card>
    </div>
  );
}
