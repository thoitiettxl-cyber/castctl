/** Live log entries for the dev mock (Node, Vite dev server only).
 *
 * The real backend serves `GET /api/v1/logs` from an in-memory ring
 * (design draft §2: last 500 entries) that grows as the server runs.
 * The mock used to return the same static fixture on every poll, so
 * LogsPage's follow-to-bottom behaviour on ARRIVING entries could
 * never be observed. The mock handler (mockServer.ts) now appends
 * exactly one entry per `GET /logs` poll after the first, through the
 * same endpoint/handler LogsPage polls — no timer, no separate path,
 * so the 5s poll semantics (POLL_INTERVAL_MS in LogsPage.tsx) are
 * preserved: one new row per poll tick, oldest-first, newest at the
 * bottom, exactly as the page's replace-on-poll expects.
 *
 * Everything here is pure and deterministic (no Date.now, no random):
 * the timestamp advances 1s per appended entry from the previous
 * entry, and the message cycles through plausible server/profile/
 * outbound/gateway events. Determinism is what makes the append
 * logic unit-testable; the mock handler owns only the mutable ring
 * and the append counter.
 *
 * Entry shape intentionally mirrors `LogEntry` in src/types/api.ts
 * ({ts, level, kind, message}) but is declared locally so dev-mocks
 * stays Node-only and is never bundled into dist.
 */

export interface MockLogEntry {
  ts: string;
  level: string;
  kind: string;
  message: string;
}

/** Ring cap from the design draft (§2 logs: in-memory ring, last 500). */
export const MAX_LIVE_LOG_ENTRIES = 500;

/** Seed timestamp when appending onto an empty ring (e.g. after DELETE). */
export const EMPTY_RING_SEED_TS = '2026-10-29T05:00:05Z';

const LOG_LEVELS = ['info', 'warn', 'error'] as const;

interface LiveLogTemplate {
  level: string;
  kind: string;
  message: (index: number) => string;
}

/**
 * Rotating plausible events. Durations/counts vary deterministically
 * with the append index so consecutive live rows are distinguishable
 * in the UI without ever repeating the fixture's legacy warning as
 * if it were a fresh event.
 */
const LIVE_LOG_TEMPLATES: LiveLogTemplate[] = [
  {
    level: 'info',
    kind: 'profile',
    message: () => 'profile muse01: login status checked, logged in',
  },
  {
    level: 'info',
    kind: 'outbound',
    message: (index) => `outbound proxy-eu: test passed in ${780 + ((index * 37) % 240)}ms`,
  },
  {
    level: 'info',
    kind: 'server',
    message: (index) => `gateway heartbeat ok (${index + 1} polls served)`,
  },
  {
    level: 'warn',
    kind: 'gateway',
    message: (index) => `gateway: slow response from profile work, retry ${1 + (index % 3)}`,
  },
  {
    level: 'info',
    kind: 'config',
    message: () => 'config: no changes on disk since last poll',
  },
  {
    level: 'error',
    kind: 'gateway',
    message: () => 'profile work: auth check failed (logged_out)',
  },
];

export const LIVE_LOG_TEMPLATE_COUNT = LIVE_LOG_TEMPLATES.length;

function formatTs(date: Date): string {
  // Fixture format: ISO seconds, no millis, trailing Z.
  return date.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function nextTs(previousTs: string | undefined, fallbackTs: string): string {
  const previous = previousTs === undefined ? NaN : Date.parse(previousTs);
  const base = Number.isNaN(previous) ? Date.parse(fallbackTs) : previous;
  return formatTs(new Date(base + 1000));
}

/** Build the single next live entry after `previous` (or the seed). */
export function nextLiveLogEntry(
  previous: MockLogEntry | undefined,
  index: number,
): MockLogEntry {
  const template = LIVE_LOG_TEMPLATES[((index % LIVE_LOG_TEMPLATES.length) + LIVE_LOG_TEMPLATES.length) % LIVE_LOG_TEMPLATES.length];
  return {
    ts: nextTs(previous?.ts, EMPTY_RING_SEED_TS),
    level: template.level,
    kind: template.kind,
    message: template.message(index),
  };
}

/**
 * Append `count` new live entries to `entries`, oldest-first, capped
 * at MAX_LIVE_LOG_ENTRIES (oldest dropped first). `startIndex` is the
 * running append ordinal owned by the mock handler; it selects the
 * rotating template and keeps the cycle continuous across polls.
 * The input array is never mutated.
 */
export function appendLiveLogEntries(
  entries: readonly MockLogEntry[],
  count: number,
  startIndex: number,
): MockLogEntry[] {
  let result: MockLogEntry[] = [...entries];
  for (let i = 0; i < count; i++) {
    const previous = result.length === 0 ? undefined : result[result.length - 1];
    result = [...result, nextLiveLogEntry(previous, startIndex + i)];
  }
  if (result.length > MAX_LIVE_LOG_ENTRIES) {
    result = result.slice(result.length - MAX_LIVE_LOG_ENTRIES);
  }
  return result;
}

/** Level filter as the real `GET /logs?level=` query applies it. */
export function filterLogEntriesByLevel(
  entries: readonly MockLogEntry[],
  level: string | undefined,
): MockLogEntry[] {
  if (level === undefined || level === '' || level === 'all') return [...entries];
  return entries.filter((entry) => entry.level === level);
}

/** Guard used by tests: every live level is one the UI filters on. */
export function isKnownLogLevel(level: string): boolean {
  return (LOG_LEVELS as readonly string[]).includes(level);
}
