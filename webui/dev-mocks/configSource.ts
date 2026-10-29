/** Aggregate config-layout source, derived from per-profile sources.
 *
 * Dev-mock only (Node, Vite dev server). The real backend computes this
 * aggregate itself: design draft §2 names the dashboard "config source"
 * as single/legacy/mixed, and the go-port plan pins the aggregate as
 * `source: single|legacy|mixed` over the profile list. The frontend
 * must never re-derive it from per-profile `source` values in one place
 * while displaying a hard-coded aggregate in another — that is exactly
 * how the mock disagreed with itself (status/config said `single-file`
 * while one profile said `legacy`). The mock therefore derives both
 * aggregate fields (`GET /status` `config_source` and `GET /config`
 * `source`) from the same profile fixture via this one function, so
 * the dashboard warning condition (`some(profile.source === 'legacy')`,
 * DashboardPage.tsx / ProfilesPage.tsx) and the config source can no
 * longer disagree: `some legacy` is true exactly when the aggregate
 * is `legacy` or `mixed`.
 *
 * Per-profile vocabulary is `single-file` | `legacy` (as the fixtures
 * and the frozen API types already use it); the aggregate vocabulary
 * is `single` | `legacy` | `mixed`. `single-file`/`single` both mean
 * "not legacy" here.
 */

export type ConfigSourceValue = 'single' | 'legacy' | 'mixed';

/** Derive the aggregate layout from per-profile source values. */
export function deriveConfigSource(sources: readonly string[]): ConfigSourceValue {
  let hasSingle = false;
  let hasLegacy = false;
  for (const source of sources) {
    if (source === 'legacy') {
      hasLegacy = true;
    } else {
      hasSingle = true;
    }
  }
  if (hasLegacy && hasSingle) return 'mixed';
  if (hasLegacy) return 'legacy';
  return 'single';
}
