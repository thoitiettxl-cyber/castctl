import { describe, expect, it } from 'vitest';
import {
  AUTO_SCROLL_THRESHOLD_PX,
  isNearBottom,
  pinTargetOnArrival,
} from '../src/features/logs/autoScroll';

describe('isNearBottom', () => {
  it('pins the threshold value used by LogsPage', () => {
    expect(AUTO_SCROLL_THRESHOLD_PX).toBe(48);
  });

  it('is true exactly at the bottom (distance 0)', () => {
    expect(isNearBottom({ scrollTop: 600, scrollHeight: 1000, clientHeight: 400 })).toBe(true);
  });

  it('is true exactly at the threshold boundary (distance == 48)', () => {
    // 1000 - 552 - 400 = 48
    expect(isNearBottom({ scrollTop: 552, scrollHeight: 1000, clientHeight: 400 })).toBe(true);
  });

  it('is false one pixel past the threshold (distance == 49)', () => {
    // 1000 - 551 - 400 = 49
    expect(isNearBottom({ scrollTop: 551, scrollHeight: 1000, clientHeight: 400 })).toBe(false);
  });

  it('is false when scrolled well up', () => {
    expect(isNearBottom({ scrollTop: 0, scrollHeight: 1000, clientHeight: 400 })).toBe(false);
    expect(isNearBottom({ scrollTop: 300, scrollHeight: 1000, clientHeight: 400 })).toBe(false);
  });

  it('is true for empty content', () => {
    expect(isNearBottom({ scrollTop: 0, scrollHeight: 0, clientHeight: 0 })).toBe(true);
    expect(isNearBottom({ scrollTop: 0, scrollHeight: 0, clientHeight: 400 })).toBe(true);
  });

  it('is true when the content fits without scrolling (short list)', () => {
    expect(isNearBottom({ scrollTop: 0, scrollHeight: 200, clientHeight: 400 })).toBe(true);
    expect(isNearBottom({ scrollTop: 0, scrollHeight: 399, clientHeight: 400 })).toBe(true);
  });

  it('is true on overscroll past the bottom (negative distance, e.g. iOS bounce)', () => {
    // 1000 - 650 - 400 = -50
    expect(isNearBottom({ scrollTop: 650, scrollHeight: 1000, clientHeight: 400 })).toBe(true);
  });

  it('honours an explicit custom threshold', () => {
    const metrics = { scrollTop: 500, scrollHeight: 1000, clientHeight: 400 }; // distance 100
    expect(isNearBottom(metrics, 100)).toBe(true);
    expect(isNearBottom(metrics, 99)).toBe(false);
    expect(isNearBottom(metrics)).toBe(false);
    expect(isNearBottom({ scrollTop: 600, scrollHeight: 1000, clientHeight: 400 }, 0)).toBe(true);
    expect(isNearBottom({ scrollTop: 599, scrollHeight: 1000, clientHeight: 400 }, 0)).toBe(false);
  });
});

describe('pinTargetOnArrival + follow sequences (LogsPage layout effect)', () => {
  // These model the exact sequence LogsPage runs: handleScroll sets
  // `following` from isNearBottom; the layout effect applies
  // pinTargetOnArrival after new entries render. One log row is ~44px.
  const CLIENT_HEIGHT = 400;

  it('arrival while following pins to the new bottom', () => {
    // At the bottom before arrival: 1000 - 600 - 400 = 0.
    const before = { scrollTop: 600, scrollHeight: 1000, clientHeight: CLIENT_HEIGHT };
    expect(isNearBottom(before)).toBe(true);
    // One entry arrives: content grows by a row.
    const afterArrival = { scrollTop: 600, scrollHeight: 1044, clientHeight: CLIENT_HEIGHT };
    expect(pinTargetOnArrival(afterArrival, true)).toBe(1044);
    // Applying the target leaves the view at the bottom.
    expect(isNearBottom({ ...afterArrival, scrollTop: 1044 })).toBe(true);
  });

  it('arrival while scrolled up does NOT jump and following stays off', () => {
    // User scrolled up: 1000 - 300 - 400 = 300 > 48.
    const scrolledUp = { scrollTop: 300, scrollHeight: 1000, clientHeight: CLIENT_HEIGHT };
    const following = isNearBottom(scrolledUp);
    expect(following).toBe(false);
    // Two arrivals: the target is null both times, so scrollTop is
    // never rewritten and following is never silently restored.
    const first = { scrollTop: 300, scrollHeight: 1044, clientHeight: CLIENT_HEIGHT };
    expect(pinTargetOnArrival(first, following)).toBeNull();
    const second = { scrollTop: 300, scrollHeight: 1088, clientHeight: CLIENT_HEIGHT };
    expect(pinTargetOnArrival(second, following)).toBeNull();
    expect(isNearBottom(second)).toBe(false);
  });

  it('resume: scroll to bottom re-pins on the next arrival', () => {
    // Scrolled up, then the user scrolls back to the bottom.
    const atBottom = { scrollTop: 644, scrollHeight: 1044, clientHeight: CLIENT_HEIGHT };
    expect(isNearBottom(atBottom)).toBe(true);
    const following = isNearBottom(atBottom);
    // Next arrival grows the list; the view pins to the new bottom.
    const afterArrival = { scrollTop: 644, scrollHeight: 1088, clientHeight: CLIENT_HEIGHT };
    expect(pinTargetOnArrival(afterArrival, following)).toBe(1088);
  });

  it('pins when the list fits without scrolling (trivially at bottom)', () => {
    const fits = { scrollTop: 0, scrollHeight: 200, clientHeight: CLIENT_HEIGHT };
    expect(isNearBottom(fits)).toBe(true);
    expect(pinTargetOnArrival({ ...fits, scrollHeight: 244 }, true)).toBe(244);
  });

  it('pin target is null exactly when following is off, regardless of geometry', () => {
    expect(pinTargetOnArrival({ scrollTop: 600, scrollHeight: 1000, clientHeight: 400 }, false)).toBeNull();
    expect(pinTargetOnArrival({ scrollTop: 0, scrollHeight: 0, clientHeight: 400 }, false)).toBeNull();
    expect(pinTargetOnArrival({ scrollTop: 600, scrollHeight: 1000, clientHeight: 400 }, true)).toBe(1000);
  });
});
