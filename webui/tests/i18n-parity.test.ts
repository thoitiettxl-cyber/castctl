import { describe, expect, it } from 'vitest';
import en from '../src/i18n/locales/en.json';
import vi from '../src/i18n/locales/vi.json';

function flatten(obj: Record<string, unknown>, prefix = ''): string[] {
  const keys: string[] = [];
  for (const [k, v] of Object.entries(obj)) {
    const path = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      keys.push(...flatten(v as Record<string, unknown>, path));
    } else {
      keys.push(path);
    }
  }
  return keys.sort();
}

describe('i18n parity', () => {
  it('en and vi key sets match exactly', () => {
    const enKeys = flatten(en as Record<string, unknown>);
    const viKeys = flatten(vi as Record<string, unknown>);
    expect(viKeys).toEqual(enKeys);
    expect(enKeys.length).toBeGreaterThan(0);
  });

  it('every leaf value is a non-empty string', () => {
    const check = (obj: Record<string, unknown>) => {
      for (const v of Object.values(obj)) {
        if (v && typeof v === 'object') check(v as Record<string, unknown>);
        else expect(typeof v).toBe('string');
      }
    };
    check(en as Record<string, unknown>);
    check(vi as Record<string, unknown>);
  });
});
