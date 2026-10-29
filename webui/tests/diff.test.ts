import { describe, expect, it } from 'vitest';
import { diffStats, lineDiff } from '../src/utils/diff';

describe('lineDiff', () => {
  it('identical inputs produce only context lines', () => {
    const lines = lineDiff('a\nb', 'a\nb');
    expect(lines).toEqual([
      { kind: ' ', text: 'a' },
      { kind: ' ', text: 'b' },
    ]);
    expect(diffStats(lines)).toEqual({ additions: 0, deletions: 0 });
  });

  it('marks a changed middle line as -/+', () => {
    const lines = lineDiff('a\nb\nc', 'a\nB\nc');
    expect(lines).toEqual([
      { kind: ' ', text: 'a' },
      { kind: '-', text: 'b' },
      { kind: '+', text: 'B' },
      { kind: ' ', text: 'c' },
    ]);
    expect(diffStats(lines)).toEqual({ additions: 1, deletions: 1 });
  });

  it('handles appends and empty input', () => {
    expect(lineDiff('', 'x')).toEqual([
      { kind: '-', text: '' },
      { kind: '+', text: 'x' },
    ]);
    expect(lineDiff('a', 'a\nb')).toEqual([
      { kind: ' ', text: 'a' },
      { kind: '+', text: 'b' },
    ]);
  });
});
