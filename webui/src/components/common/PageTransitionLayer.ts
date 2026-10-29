import { createContext, useContext } from 'react';
import type { Location } from 'react-router-dom';

export type LayerStatus = 'current' | 'exiting' | 'stacked';

export type PageTransitionLayerContextValue = {
  status: LayerStatus;
  isCurrentLayer: boolean;
  isAnimating: boolean;
};

export const PageTransitionLayerContext = createContext<PageTransitionLayerContextValue | null>(
  null
);

export const PAGE_TRANSITION_LAYER_CONTEXT_VALUES: Record<
  LayerStatus,
  PageTransitionLayerContextValue
> = {
  current: { status: 'current', isCurrentLayer: true, isAnimating: false },
  stacked: { status: 'stacked', isCurrentLayer: false, isAnimating: false },
  exiting: { status: 'exiting', isCurrentLayer: false, isAnimating: false },
};

export function usePageTransitionLayer() {
  return useContext(PageTransitionLayerContext);
}

/**
 * Layer identity. Must NOT be `location.key` alone: every history entry
 * the router did not stamp (initial load, external goto, Back to the
 * initial entry, `location.hash =`) carries the same fallback key
 * `"default"` (react-router history.ts: `state.key || "default"`), so
 * two layers in one transition stack would share a React key and the
 * current/exiting refs would collide. The route path disambiguates:
 * layers coexisting in a stack always denote different routes.
 */
export function pageTransitionLayerKey(location: Location): string {
  return `${location.key}:${location.pathname}${location.search}${location.hash}`;
}

/**
 * Route identity for transition purposes. A location key is NOT route
 * identity: unrelated external navigations share the fallback key
 * `"default"`, and treating key equality as "same route" drops every
 * hashchange-driven navigation after the first. What makes two
 * locations the same route is the path they render (pathname + search
 * + hash); the key is ignored.
 */
export function isSameRouteLocation(
  location: Location,
  current: PageTransitionLayer | Location | undefined,
): boolean {
  if (!current) return false;
  const currentLocation =
    'location' in current ? current.location : (current as Location);
  return (
    location.pathname === currentLocation.pathname &&
    location.search === currentLocation.search &&
    location.hash === currentLocation.hash
  );
}

/**
 * One rendered page in the transition stack. `location` is frozen at the
 * moment the navigation started: `<Routes location={layer.location}>`
 * renders the page that was current then, not the live router location.
 */
export type PageTransitionLayer = {
  key: string;
  location: Location;
  status: LayerStatus;
};

export type TransitionDirection = 'forward' | 'backward';

export type TransitionVariant = 'vertical' | 'ios';

/** A navigation that arrived while a transition was still animating. */
export type PendingPageTransition = {
  location: Location;
  variant: TransitionVariant;
  direction: TransitionDirection;
  shouldSkipExitLayer: boolean;
};

export type PageTransitionState = {
  layers: PageTransitionLayer[];
  isAnimating: boolean;
  /** What `layers` collapses to when the running animation completes. */
  settledLayers: PageTransitionLayer[] | null;
  pending: PendingPageTransition | null;
};

export type PageTransitionAction =
  | {
      type: 'navigate';
      location: Location;
      variant: TransitionVariant;
      direction: TransitionDirection;
      shouldSkipExitLayer: boolean;
    }
  | { type: 'finish' };

export function createInitialPageTransitionState(
  location: Location,
): PageTransitionState {
  return {
    layers: [{ key: pageTransitionLayerKey(location), location, status: 'current' }],
    isAnimating: false,
    settledLayers: null,
    pending: null,
  };
}

function buildTransitionLayers(
  prev: PageTransitionLayer[],
  location: Location,
  variant: TransitionVariant,
  direction: TransitionDirection,
  shouldSkipExitLayer: boolean,
): { layers: PageTransitionLayer[]; settled: PageTransitionLayer[] } {
  const previousCurrentIndex = prev.findIndex((layer) => layer.status === 'current');
  const resolvedCurrentIndex =
    previousCurrentIndex >= 0 ? previousCurrentIndex : prev.length - 1;
  const previousCurrent = prev[resolvedCurrentIndex];
  const previousStack: PageTransitionLayer[] = prev
    .filter((_, idx) => idx !== resolvedCurrentIndex)
    .map((layer): PageTransitionLayer => ({ ...layer, status: 'stacked' }));

  const nextCurrent: PageTransitionLayer = {
    key: pageTransitionLayerKey(location),
    location,
    status: 'current',
  };

  if (!previousCurrent) {
    return { layers: [nextCurrent], settled: [nextCurrent] };
  }

  if (variant === 'ios') {
    if (direction === 'forward') {
      const exitingLayer: PageTransitionLayer = { ...previousCurrent, status: 'exiting' };
      const stackedLayer: PageTransitionLayer = { ...previousCurrent, status: 'stacked' };
      return {
        layers: [...previousStack, exitingLayer, nextCurrent],
        settled: [...previousStack, stackedLayer, nextCurrent],
      };
    }

    const targetIndex = prev.findIndex(
      (layer) => layer.key === pageTransitionLayerKey(location),
    );
    if (targetIndex !== -1) {
      const targetStack: PageTransitionLayer[] = prev
        .slice(0, targetIndex + 1)
        .map((layer, idx): PageTransitionLayer => {
          const isTarget = idx === targetIndex;
          return {
            ...layer,
            location: isTarget ? location : layer.location,
            status: isTarget ? 'current' : 'stacked',
          };
        });

      if (shouldSkipExitLayer) {
        return { layers: targetStack, settled: targetStack };
      }

      const exitingLayer: PageTransitionLayer = { ...previousCurrent, status: 'exiting' };
      return { layers: [...targetStack, exitingLayer], settled: targetStack };
    }
  }

  if (shouldSkipExitLayer) {
    return { layers: [nextCurrent], settled: [nextCurrent] };
  }

  const exitingLayer: PageTransitionLayer = { ...previousCurrent, status: 'exiting' };
  return { layers: [exitingLayer, nextCurrent], settled: [nextCurrent] };
}

function currentLayerOf(
  layers: PageTransitionLayer[],
): PageTransitionLayer | undefined {
  return (
    layers.find((layer) => layer.status === 'current') ?? layers[layers.length - 1]
  );
}

function isSameRoute(
  location: Location,
  current: PageTransitionLayer | undefined,
): boolean {
  return isSameRouteLocation(location, current);
}

/**
 * Pure transition state machine (no DOM, no animation library).
 *
 * Liveness contract: a navigation that arrives while `isAnimating` is
 * recorded as `pending` instead of being dropped, and `finish` starts
 * the pending navigation instead of only collapsing the stack. Without
 * this, a navigation whose animation never completes (its `finished`
 * promise never settles, e.g. after the animation was stopped) strands
 * `isAnimating=true` forever: the new layer stays at inline opacity 0,
 * the old layer stays visible, and every later navigation is ignored
 * until a full reload — the URL changes, `<main>` does not.
 */
export function pageTransitionReducer(
  state: PageTransitionState,
  action: PageTransitionAction,
): PageTransitionState {
  switch (action.type) {
    case 'navigate': {
      const current = currentLayerOf(state.layers);
      if (isSameRoute(action.location, current)) return state;
      const pending: PendingPageTransition = {
        location: action.location,
        variant: action.variant,
        direction: action.direction,
        shouldSkipExitLayer: action.shouldSkipExitLayer,
      };
      // Mid-animation: record, do not drop. `finish` starts it.
      if (state.isAnimating) return { ...state, pending };
      const { layers, settled } = buildTransitionLayers(
        state.layers,
        action.location,
        action.variant,
        action.direction,
        action.shouldSkipExitLayer,
      );
      return { layers, isAnimating: true, settledLayers: settled, pending: null };
    }
    case 'finish': {
      if (!state.isAnimating) return state;
      const settled =
        state.settledLayers ?? state.layers.filter((layer) => layer.status !== 'exiting');
      const pending = state.pending;
      if (!pending) {
        return { layers: settled, isAnimating: false, settledLayers: null, pending: null };
      }
      // The pending target may have become the settled route meanwhile
      // (e.g. same pathname pushed twice): then there is nothing to start.
      if (isSameRoute(pending.location, currentLayerOf(settled))) {
        return { layers: settled, isAnimating: false, settledLayers: null, pending: null };
      }
      const { layers, settled: nextSettled } = buildTransitionLayers(
        settled,
        pending.location,
        pending.variant,
        pending.direction,
        pending.shouldSkipExitLayer,
      );
      return { layers, isAnimating: true, settledLayers: nextSettled, pending: null };
    }
  }
}
