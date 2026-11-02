// @vitest-environment jsdom
import { afterEach, describe, expect, it } from 'vitest';
import { isIdleExpired, lastActivityAt, recordActivity } from '../src/utils/idle';
import { SESSION_KEY_LAST_ACTIVITY } from '../src/utils/constants';

/** Frontend idle expiry (webui.session_idle_timeout): pure
 * boundary rules + the sessionStorage stamp round-trip. The 12h
 * default itself is a server config value, covered by the Go
 * profile tests — this file pins only the frontend's use of it. */

describe('isIdleExpired', () => {
  const now = 1_800_000_000_000;

  it('never expires without a known timeout or stamp', () => {
    expect(isIdleExpired(null, now - 10 ** 9, now)).toBe(false);
    expect(isIdleExpired(43200, null, now)).toBe(false);
    expect(isIdleExpired(null, null, now)).toBe(false);
  });

  it('never expires for a non-positive timeout', () => {
    expect(isIdleExpired(0, 0, now)).toBe(false);
    expect(isIdleExpired(-5, 0, now)).toBe(false);
  });

  it('expires strictly past the timeout', () => {
    const timeout = 60; // seconds
    expect(isIdleExpired(timeout, now - 60_000, now)).toBe(false);
    expect(isIdleExpired(timeout, now - 60_001, now)).toBe(true);
    expect(isIdleExpired(timeout, now - 61_000, now)).toBe(true);
  });

  it('uses the configured timeout, not a hardcoded one', () => {
    // 12h default: idle for 11h is fine, 13h expires.
    expect(isIdleExpired(43200, now - 11 * 3600_000, now)).toBe(false);
    expect(isIdleExpired(43200, now - 13 * 3600_000, now)).toBe(true);
    // A shorter configured timeout expires sooner.
    expect(isIdleExpired(300, now - 6 * 60_000, now)).toBe(true);
  });
});

describe('activity stamp', () => {
  afterEach(() => {
    sessionStorage.removeItem(SESSION_KEY_LAST_ACTIVITY);
  });

  it('round-trips through sessionStorage', () => {
    expect(lastActivityAt()).toBeNull();
    recordActivity(123456789);
    expect(lastActivityAt()).toBe(123456789);
  });

  it('ignores a non-numeric stamp', () => {
    sessionStorage.setItem(SESSION_KEY_LAST_ACTIVITY, 'not-a-number');
    expect(lastActivityAt()).toBeNull();
  });
});
