import { useCallback, useEffect, useLayoutEffect, useRef, useState, type UIEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { logsApi } from '@/services/api';
import type { LogEntry } from '@/types';
import { copyToClipboard } from '@/utils/clipboard';
import { getErrorMessage } from '@/utils/helpers';
import { AUTO_SCROLL_THRESHOLD_PX, isNearBottom } from './autoScroll';
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
 * Auto-scroll (Boss order — this OVERRIDES the earlier fork decision
 * of no auto-scroll / no follow-to-bottom): the table lives in its
 * own scroll container (inline maxHeight, no .scss change) and
 * follows new entries to the bottom ONLY while the user is at/near
 * the bottom (near-bottom rule in autoScroll.ts). Scrolling up pauses
 * following immediately; scrolling back to near-bottom resumes it,
 * as does turning auto-refresh back on (Resume). The Pause/Resume
 * control and the toggle keep their existing meaning — they
 * pause/resume POLLING (5s); resuming polling also re-enables
 * following. Poll ticks never run while a load-more fetch is in
 * flight, so an append is never clobbered by a refresh. Entry order
 * is whatever order the server returns (the mock fixture is
 * oldest-first, newest at the bottom, which is what following pins
 * to). Load-more appends also re-pin while following, since the
 * button sits below the container and the newest tail stays in view.
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
  // Follow-to-bottom: true while the user is at/near the bottom of the
  // scroll container. Scrolling up clears it; scrolling back down or
  // resuming auto-refresh sets it again (see handleScroll /
  // handleAutoRefreshChange).
  const [following, setFollowing] = useState(true);
  const scrollRef = useRef<HTMLDivElement | null>(null);
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
    // A fresh list starts following again from the bottom.
    setFollowing(true);
    void fetchFirst();
  }, [fetchFirst]);

  useInterval(
    () => {
      void fetchFirst();
    },
    autoRefresh ? POLL_INTERVAL_MS : null
  );

  // Pin the scroll container to the bottom after new entries render,
  // but only while following. Layout effect (before paint) so a poll
  // replace never flashes the top of the list. Instant jump, no
  // smooth scrolling: a 5s poll must not animate, and a programmatic
  // smooth scroll would fight the user's own scrolling.
  useLayoutEffect(() => {
    if (!following || entries.length === 0) return;
    const container = scrollRef.current;
    if (container) container.scrollTop = container.scrollHeight;
  }, [entries, following]);

  const handleAutoRefreshChange = (next: boolean) => {
    setAutoRefresh(next);
    // Resuming polling also resumes following: the layout effect
    // above re-pins to the bottom on the `following` change, even
    // before the next poll tick arrives. Pausing leaves `following`
    // untouched — with polling stopped no entries arrive to follow.
    if (next) setFollowing(true);
  };

  const handleScroll = (event: UIEvent<HTMLDivElement>) => {
    setFollowing(isNearBottom(event.currentTarget, AUTO_SCROLL_THRESHOLD_PX));
  };

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
            onChange={handleAutoRefreshChange}
            label={t('logs.auto_refresh')}
            ariaLabel={t('logs.auto_refresh')}
          />
          <Button variant="secondary" size="sm" onClick={() => handleAutoRefreshChange(!autoRefresh)}>
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
            {/* Dedicated scroll container (inline styles only — no
                .scss change; 60vh follows the ConfigPage diff-view
                precedent). overscrollBehavior contain keeps a swipe
                over the list from chaining into page scroll.
                tabIndex + aria-label make the scrollable region
                keyboard-reachable; the label reuses logs.title, so
                no new i18n key is needed. */}
            <div
              ref={scrollRef}
              onScroll={handleScroll}
              tabIndex={0}
              aria-label={t('logs.title')}
              style={{ overflowY: 'auto', overscrollBehavior: 'contain', maxHeight: '60vh' }}
            >
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
            </div>
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
