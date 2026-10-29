/** Pure near-bottom decision for the logs follow-to-bottom behaviour.
 *
 * `LogsPage` keeps a `following` flag: while it is on, new entries pin
 * the scroll container to the bottom; the moment the user scrolls up
 * out of the near-bottom zone, following turns off. This module owns
 * only the geometry — no DOM access, no React — so the rule is
 * unit-testable without rendering the page.
 */

export interface ScrollMetrics {
  scrollTop: number;
  scrollHeight: number;
  clientHeight: number;
}

/**
 * Distance (px) from the bottom within which the view still counts as
 * "at the bottom". One log row is ~44px tall (12px cell padding top
 * and bottom + ~20px of 13px/1.5 text), so 48px means "within a row
 * of the bottom": sub-pixel rounding and a finger's overshoot do not
 * silently drop the user out of following, while scrolling a full row
 * or more up does.
 */
export const AUTO_SCROLL_THRESHOLD_PX = 48;

export function isNearBottom(
  metrics: ScrollMetrics,
  thresholdPx: number = AUTO_SCROLL_THRESHOLD_PX,
): boolean {
  const { scrollTop, scrollHeight, clientHeight } = metrics;
  // Content that fits without scrolling has no "away from bottom"
  // state: the whole list is visible, so the view is trivially at the
  // bottom and following stays on.
  if (scrollHeight <= clientHeight) return true;
  return scrollHeight - scrollTop - clientHeight <= thresholdPx;
}

/**
 * Scroll target to apply after new entries render, or `null` for
 * "do not move". While following, the target is the new bottom
 * (scrollHeight): the view stays pinned as entries arrive. While the
 * user has scrolled up (following off), it is `null`: an arrival must
 * NOT jump the view, and the user's scrollTop is left untouched.
 * `LogsPage` calls this from its layout effect on every entries
 * change; the following flag itself comes from `isNearBottom` on
 * scroll events (scroll up clears it, scroll-to-bottom restores it)
 * and from re-enabling auto-refresh.
 */
export function pinTargetOnArrival(
  metrics: ScrollMetrics,
  following: boolean,
): number | null {
  if (!following) return null;
  return metrics.scrollHeight;
}
