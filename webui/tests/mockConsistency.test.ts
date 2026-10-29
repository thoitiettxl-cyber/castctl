import { describe, expect, it } from 'vitest';
import { deriveConfigSource } from '../dev-mocks/configSource';
import { configFixture, logsFixture, profilesFixture, statusFixture } from '../dev-mocks/fixtures';
import {
  EMPTY_RING_SEED_TS,
  LIVE_LOG_TEMPLATE_COUNT,
  MAX_LIVE_LOG_ENTRIES,
  appendLiveLogEntries,
  filterLogEntriesByLevel,
  isKnownLogLevel,
  nextLiveLogEntry,
} from '../dev-mocks/liveLogs';

/**
 * Mock-consistency pins. The mock is dev-only (never bundled), but it
 * is the only stand-in for the real backend in `bun run dev:mocks`,
 * so a mock that contradicts itself teaches the wrong behaviour:
 * the dashboard warning and the config source must agree, and polls
 * must deliver arriving entries through the same GET /logs handler.
 * The handler wiring itself (append-on-poll in mockServer.ts) is
 * verified by the parent's live check, not here — see the report.
 */

describe('config source consistency (workstream C)', () => {
  it('derives single / legacy / mixed from per-profile sources', () => {
    expect(deriveConfigSource([])).toBe('single');
    expect(deriveConfigSource(['single-file'])).toBe('single');
    expect(deriveConfigSource(['single', 'single-file'])).toBe('single');
    expect(deriveConfigSource(['legacy'])).toBe('legacy');
    expect(deriveConfigSource(['legacy', 'legacy'])).toBe('legacy');
    expect(deriveConfigSource(['single-file', 'legacy'])).toBe('mixed');
    expect(deriveConfigSource(['legacy', 'single-file', 'single-file'])).toBe('mixed');
  });

  it('status config_source and config source are the same derived aggregate', () => {
    const derived = deriveConfigSource(profilesFixture.map((p) => p.source));
    expect(statusFixture.config_source).toBe(derived);
    expect(configFixture.source).toBe(derived);
    expect(statusFixture.config_source).toBe(configFixture.source);
  });

  it('the fixture set is mixed: two single-file profiles + one legacy profile', () => {
    expect(profilesFixture.map((p) => p.name)).toEqual(['muse01', 'work', 'legacy-note']);
    expect(profilesFixture.map((p) => p.source)).toEqual(['single-file', 'single-file', 'legacy']);
    expect(deriveConfigSource(profilesFixture.map((p) => p.source))).toBe('mixed');
  });

  it('dashboard warning condition and config source can no longer disagree', () => {
    // Replicates the page rule verbatim (DashboardPage.tsx:106 and
    // ProfilesPage.tsx:139): hasLegacy = profiles.some(source === 'legacy').
    const hasLegacy = profilesFixture.some((p) => p.source === 'legacy');
    const source = statusFixture.config_source;
    expect(hasLegacy).toBe(source === 'legacy' || source === 'mixed');
    // And the config page shows the same value.
    expect(hasLegacy).toBe(configFixture.source === 'legacy' || configFixture.source === 'mixed');
  });
});

describe('live log entries (workstream D)', () => {
  it('appends one entry per call with the fixture shape and monotonic timestamps', () => {
    const grown = appendLiveLogEntries(logsFixture, 1, 0);
    expect(grown).toHaveLength(logsFixture.length + 1);
    const added = grown[grown.length - 1];
    expect(Object.keys(added).sort()).toEqual(['kind', 'level', 'message', 'ts']);
    expect(added.ts > logsFixture[logsFixture.length - 1].ts).toBe(true);
    expect(isKnownLogLevel(added.level)).toBe(true);
    expect(added.kind.length).toBeGreaterThan(0);
    expect(added.message.length).toBeGreaterThan(0);
  });

  it('timestamps stay strictly monotonic across many appends', () => {
    let entries = [...logsFixture];
    let nextIndex = 0;
    for (let poll = 0; poll < 10; poll++) {
      entries = appendLiveLogEntries(entries, 1, nextIndex);
      nextIndex += 1;
    }
    expect(entries).toHaveLength(logsFixture.length + 10);
    for (let i = 1; i < entries.length; i++) {
      expect(entries[i].ts > entries[i - 1].ts).toBe(true);
    }
  });

  it('cycles plausible levels/sources and never repeats a message back-to-back', () => {
    let entries = [...logsFixture];
    const seen = new Set<string>();
    for (let i = 0; i < LIVE_LOG_TEMPLATE_COUNT * 2; i++) {
      const before = entries[entries.length - 1];
      entries = appendLiveLogEntries(entries, 1, i);
      const added = entries[entries.length - 1];
      expect(added.message).not.toBe(before.message);
      seen.add(`${added.level}/${added.kind}`);
    }
    expect(seen.has('info/profile')).toBe(true);
    expect(seen.has('info/outbound')).toBe(true);
    expect(seen.has('info/server')).toBe(true);
    expect(seen.has('error/gateway')).toBe(true);
  });

  it('is deterministic: same inputs produce identical entries', () => {
    const first = appendLiveLogEntries(logsFixture, 3, 0);
    const second = appendLiveLogEntries(logsFixture, 3, 0);
    expect(first).toEqual(second);
    expect(nextLiveLogEntry(logsFixture[logsFixture.length - 1], 2)).toEqual(
      nextLiveLogEntry(logsFixture[logsFixture.length - 1], 2),
    );
  });

  it('does not mutate the input array', () => {
    const input = [...logsFixture];
    const snapshot = [...input];
    appendLiveLogEntries(input, 2, 0);
    expect(input).toEqual(snapshot);
  });

  it('caps the ring at 500, dropping the oldest entries first', () => {
    const full = appendLiveLogEntries(logsFixture, MAX_LIVE_LOG_ENTRIES, 0);
    expect(full).toHaveLength(MAX_LIVE_LOG_ENTRIES);
    const oldestBefore = full[0];
    const capped = appendLiveLogEntries(full, 1, MAX_LIVE_LOG_ENTRIES);
    expect(capped).toHaveLength(MAX_LIVE_LOG_ENTRIES);
    expect(capped[0]).not.toEqual(oldestBefore);
    expect(capped[capped.length - 1].ts > capped[capped.length - 2].ts).toBe(true);
  });

  it('seeds from a fixed timestamp onto an empty ring', () => {
    const seeded = appendLiveLogEntries([], 2, 0);
    expect(seeded).toHaveLength(2);
    expect(seeded[0].ts > EMPTY_RING_SEED_TS).toBe(true);
    expect(seeded[1].ts > seeded[0].ts).toBe(true);
  });

  it('level filter keeps only that level, including freshly appended entries', () => {
    let entries = appendLiveLogEntries(logsFixture, LIVE_LOG_TEMPLATE_COUNT, 0);
    const errors = filterLogEntriesByLevel(entries, 'error');
    expect(errors.length).toBeGreaterThan(1);
    expect(errors.every((e) => e.level === 'error')).toBe(true);
    expect(filterLogEntriesByLevel(entries, undefined)).toHaveLength(entries.length);
    expect(filterLogEntriesByLevel(entries, 'all')).toHaveLength(entries.length);
    expect(filterLogEntriesByLevel(entries, 'info').every((e) => e.level === 'info')).toBe(true);
    entries = appendLiveLogEntries(entries, 1, LIVE_LOG_TEMPLATE_COUNT);
    // The appended entry is still reachable through its own level filter.
    const level = entries[entries.length - 1].level;
    expect(filterLogEntriesByLevel(entries, level)).toContainEqual(entries[entries.length - 1]);
  });
});
