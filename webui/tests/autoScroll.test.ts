import { describe, expect, it } from 'vitest';
import { AUTO_SCROLL_THRESHOLD_PX, isNearBottom } from '../src/features/logs/autoScroll';

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
