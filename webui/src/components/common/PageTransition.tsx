import { ReactNode, useCallback, useLayoutEffect, useReducer, useRef } from 'react';
import { useLocation, type Location } from 'react-router-dom';
import { animate } from 'motion/mini';
import type { AnimationPlaybackControlsWithThen } from 'motion-dom';
import {
  PAGE_TRANSITION_LAYER_CONTEXT_VALUES,
  PageTransitionLayerContext,
  createInitialPageTransitionState,
  pageTransitionReducer,
  type TransitionDirection,
  type TransitionVariant,
} from './PageTransitionLayer';
import './PageTransition.scss';

interface PageTransitionProps {
  render: (location: Location) => ReactNode;
  getRouteOrder?: (pathname: string) => number | null;
  getTransitionVariant?: (fromPathname: string, toPathname: string) => TransitionVariant;
  scrollContainerRef?: React.RefObject<HTMLElement | null>;
}

// Premium personality: enter > exit, decelerate-in / accelerate-out.
const VERTICAL_ENTER_DURATION = 0.36;
const VERTICAL_EXIT_DURATION = 0.22;
const VERTICAL_ENTER_DISTANCE = 28;
const VERTICAL_EXIT_DISTANCE = 12;
const REDUCED_MOTION_DURATION = 0.15;
// Upper bound for any transition above (longest: iOS 0.44s) plus margin.
// Completion must not depend solely on motion's `finished` promise: it
// never settles once an animation was stopped, which would strand
// isAnimating=true (new layer at opacity 0, old layer visible) forever.
const TRANSITION_COMPLETION_WATCHDOG_MS = 1000;

const IOS_TRANSITION_DURATION = 0.44;
const IOS_ENTER_FROM_X_PERCENT = 100;
const IOS_EXIT_TO_X_PERCENT_FORWARD = -22;
const IOS_EXIT_TO_X_PERCENT_BACKWARD = 100;
const IOS_ENTER_FROM_X_PERCENT_BACKWARD = -22;
const IOS_BACKGROUND_SCALE = 0.96;
const IOS_BACKGROUND_OPACITY = 0.5;
const IOS_SHADOW_VALUE = '-20px 0 36px rgba(0, 0, 0, 0.20)';

// easeOutQuart: powerful but elegant deceleration for hero entrances.
const easeOutQuart = (progress: number) => 1 - (1 - progress) ** 4;
// easeInQuad: gentle start, accelerates away — exits should not linger.
const easeInQuad = (progress: number) => progress * progress;
// easeOutCubic: smooth Apple-style settle for iOS push/pop.
const easeOutCubic = (progress: number) => 1 - (1 - progress) ** 3;

const prefersReducedMotion = () =>
  typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;

const buildVerticalTransform = (y: number) => `translate3d(0px, ${y}px, 0px)`;
const buildIosTransform = (xPercent: number, y: number, scale = 1) =>
  scale === 1
    ? `translate3d(${xPercent}%, ${y}px, 0px)`
    : `translate3d(${xPercent}%, ${y}px, 0px) scale(${scale})`;

const clearLayerStyles = (element: HTMLElement | null) => {
  if (!element) return;
  element.style.removeProperty('transform');
  element.style.removeProperty('opacity');
  element.style.removeProperty('box-shadow');
};

export function PageTransition({
  render,
  getRouteOrder,
  getTransitionVariant,
  scrollContainerRef,
}: PageTransitionProps) {
  const location = useLocation();
  const currentLayerRef = useRef<HTMLDivElement>(null);
  const exitingLayerRef = useRef<HTMLDivElement>(null);
  const transitionDirectionRef = useRef<TransitionDirection>('forward');
  const transitionVariantRef = useRef<TransitionVariant>('vertical');
  const exitScrollOffsetRef = useRef(0);
  const enterScrollOffsetRef = useRef(0);
  const scrollPositionsRef = useRef(new Map<string, number>());

  const [transitionState, dispatchTransition] = useReducer(
    pageTransitionReducer,
    location,
    createInitialPageTransitionState,
  );
  const { layers, isAnimating } = transitionState;
  const currentLayer =
    layers.find((layer) => layer.status === 'current') ?? layers[layers.length - 1];
  const currentLayerKey = currentLayer?.key ?? location.key;
  const currentLayerPathname = currentLayer?.location.pathname;

  const resolveScrollContainer = useCallback(() => {
    if (scrollContainerRef?.current) return scrollContainerRef.current;
    if (typeof document === 'undefined') return null;
    return document.scrollingElement as HTMLElement | null;
  }, [scrollContainerRef]);

  useLayoutEffect(() => {
    if (isAnimating) return;
    if (location.key === currentLayerKey) return;
    if (currentLayerPathname === location.pathname) return;
    const scrollContainer = resolveScrollContainer();
    const exitScrollOffset = scrollContainer?.scrollTop ?? 0;
    exitScrollOffsetRef.current = exitScrollOffset;
    scrollPositionsRef.current.set(currentLayerKey, exitScrollOffset);

    enterScrollOffsetRef.current = scrollPositionsRef.current.get(location.key) ?? 0;
    const resolveOrderIndex = (pathname?: string) => {
      if (!getRouteOrder || !pathname) return null;
      const index = getRouteOrder(pathname);
      return typeof index === 'number' && index >= 0 ? index : null;
    };
    const fromIndex = resolveOrderIndex(currentLayerPathname);
    const toIndex = resolveOrderIndex(location.pathname);
    const nextVariant: TransitionVariant = getTransitionVariant
      ? getTransitionVariant(currentLayerPathname ?? '', location.pathname)
      : 'vertical';

    let nextDirection: TransitionDirection =
      fromIndex === null || toIndex === null || fromIndex === toIndex
        ? 'forward'
        : toIndex > fromIndex
          ? 'forward'
          : 'backward';

    // When using iOS-style stacking, history POP within the same "section" can have equal route order.
    // In that case, prefer treating navigation to an existing layer as a backward (pop) transition.
    if (nextVariant === 'ios' && layers.some((layer) => layer.key === location.key)) {
      nextDirection = 'backward';
    }

    transitionDirectionRef.current = nextDirection;
    transitionVariantRef.current = nextVariant;

    const shouldSkipExitLayer = (() => {
      if (nextVariant !== 'ios' || nextDirection !== 'backward') return false;
      const normalizeSegments = (pathname: string) =>
        pathname
          .split('/')
          .filter(Boolean)
          .filter((segment) => segment.length > 0);
      const fromSegments = normalizeSegments(currentLayerPathname ?? '');
      const toSegments = normalizeSegments(location.pathname);
      if (!fromSegments.length || !toSegments.length) return false;
      return fromSegments[0] === toSegments[0] && toSegments.length === 1;
    })();

    // The reducer records this navigation as pending when a transition is
    // already animating, instead of dropping it; `finish` starts it.
    dispatchTransition({
      type: 'navigate',
      location,
      variant: nextVariant,
      direction: nextDirection,
      shouldSkipExitLayer,
    });
  }, [
    isAnimating,
    location,
    currentLayerKey,
    currentLayerPathname,
    getRouteOrder,
    getTransitionVariant,
    resolveScrollContainer,
    layers,
  ]);

  // Run Motion animation when animating starts. Re-runs when the current
  // layer changes so a pending navigation started by `finish` gets its
  // own animation and completion registration.
  useLayoutEffect(() => {
    if (!isAnimating) return;

    const currentLayerEl = currentLayerRef.current;
    const exitingLayerEl = exitingLayerRef.current;
    const transitionVariant = transitionVariantRef.current;

    clearLayerStyles(currentLayerEl);
    clearLayerStyles(exitingLayerEl);

    const scrollContainer = resolveScrollContainer();
    const exitScrollOffset = exitScrollOffsetRef.current;
    const enterScrollOffset = enterScrollOffsetRef.current;
    if (scrollContainer && exitScrollOffset !== enterScrollOffset) {
      scrollContainer.scrollTo({ top: enterScrollOffset, left: 0, behavior: 'auto' });
    }

    const transitionDirection = transitionDirectionRef.current;
    const isForward = transitionDirection === 'forward';
    const enterFromY = isForward ? VERTICAL_ENTER_DISTANCE : -VERTICAL_ENTER_DISTANCE;
    const exitToY = isForward ? -VERTICAL_EXIT_DISTANCE : VERTICAL_EXIT_DISTANCE;
    const exitBaseY = enterScrollOffset - exitScrollOffset;
    const reduceMotion = prefersReducedMotion();
    const activeAnimations: AnimationPlaybackControlsWithThen[] = [];
    let cancelled = false;
    let completed = false;
    const completeTransition = () => {
      if (completed) return;
      completed = true;

      // The reducer collapses to the settled layers and starts a pending
      // navigation, if one was recorded while animating.
      dispatchTransition({ type: 'finish' });

      clearLayerStyles(currentLayerEl);
      clearLayerStyles(exitingLayerEl);
    };

    // No element to animate: collapse the stack instead of stranding
    // isAnimating=true with no completion path.
    if (!currentLayerEl) {
      completeTransition();
      return;
    }

    if (reduceMotion) {
      // Accessibility: skip spatial motion entirely, fall back to a quick crossfade.
      if (exitingLayerEl) {
        exitingLayerEl.style.transform =
          transitionVariant === 'ios'
            ? buildIosTransform(0, exitBaseY)
            : buildVerticalTransform(exitBaseY);
        activeAnimations.push(
          animate(
            exitingLayerEl,
            { opacity: [1, 0] },
            { duration: REDUCED_MOTION_DURATION, ease: easeOutCubic }
          )
        );
      }
      currentLayerEl.style.opacity = '0';
      activeAnimations.push(
        animate(
          currentLayerEl,
          { opacity: [0, 1] },
          { duration: REDUCED_MOTION_DURATION, ease: easeOutCubic }
        )
      );
    } else if (transitionVariant === 'ios') {
      const exitToXPercent = isForward
        ? IOS_EXIT_TO_X_PERCENT_FORWARD
        : IOS_EXIT_TO_X_PERCENT_BACKWARD;
      const enterFromXPercent = isForward
        ? IOS_ENTER_FROM_X_PERCENT
        : IOS_ENTER_FROM_X_PERCENT_BACKWARD;

      // Background layer (the one being pushed back / coming forward from behind) gets
      // scale + opacity dim to read as "behind". Top layer is the one sliding fully on/off.
      const exitScaleTo = isForward ? IOS_BACKGROUND_SCALE : 1;
      const exitOpacityTo = isForward ? IOS_BACKGROUND_OPACITY : 1;
      const enterScaleFrom = isForward ? 1 : IOS_BACKGROUND_SCALE;
      const enterOpacityFrom = isForward ? 1 : IOS_BACKGROUND_OPACITY;

      if (exitingLayerEl) {
        exitingLayerEl.style.transform = buildIosTransform(0, exitBaseY, 1);
        exitingLayerEl.style.opacity = '1';
      }

      currentLayerEl.style.transform = buildIosTransform(enterFromXPercent, 0, enterScaleFrom);
      currentLayerEl.style.opacity = String(enterOpacityFrom);

      // Shadow sits on whichever layer is visually in front of the other during the slide.
      const topLayerEl = isForward ? currentLayerEl : exitingLayerEl;
      if (topLayerEl) {
        topLayerEl.style.boxShadow = IOS_SHADOW_VALUE;
      }

      if (exitingLayerEl) {
        activeAnimations.push(
          animate(
            exitingLayerEl,
            {
              transform: [
                buildIosTransform(0, exitBaseY, 1),
                buildIosTransform(exitToXPercent, exitBaseY, exitScaleTo),
              ],
              opacity: [1, exitOpacityTo],
            },
            {
              duration: IOS_TRANSITION_DURATION,
              ease: easeOutCubic,
            }
          )
        );
      }

      activeAnimations.push(
        animate(
          currentLayerEl,
          {
            transform: [
              buildIosTransform(enterFromXPercent, 0, enterScaleFrom),
              buildIosTransform(0, 0, 1),
            ],
            opacity: [enterOpacityFrom, 1],
          },
          {
            duration: IOS_TRANSITION_DURATION,
            ease: easeOutCubic,
          }
        )
      );
    } else {
      // Vertical: split timing — exit leaves quickly (accelerate), enter settles slowly (decelerate).
      if (exitingLayerEl) {
        exitingLayerEl.style.transform = buildVerticalTransform(exitBaseY);
        activeAnimations.push(
          animate(
            exitingLayerEl,
            {
              transform: [
                buildVerticalTransform(exitBaseY),
                buildVerticalTransform(exitBaseY + exitToY),
              ],
              opacity: [1, 0],
            },
            {
              duration: VERTICAL_EXIT_DURATION,
              ease: easeInQuad,
            }
          )
        );
      }

      currentLayerEl.style.transform = buildVerticalTransform(enterFromY);
      currentLayerEl.style.opacity = '0';
      activeAnimations.push(
        animate(
          currentLayerEl,
          {
            transform: [buildVerticalTransform(enterFromY), buildVerticalTransform(0)],
            opacity: [0, 1],
          },
          {
            duration: VERTICAL_ENTER_DURATION,
            ease: easeOutQuart,
          }
        )
      );
    }

    if (!activeAnimations.length) {
      completeTransition();
    } else {
      void Promise.all(
        activeAnimations.map((animation) => animation.finished.catch(() => undefined))
      ).then(() => {
        if (cancelled) return;
        completeTransition();
      });
      // Watchdog: motion's `finished` never settles once an animation
      // was stopped, and a paused animation timeline may never finish.
      // Bound completion so a stalled transition can never strand the
      // new layer at opacity 0 with the old layer visible.
      const watchdogId = setTimeout(() => {
        if (cancelled) return;
        completeTransition();
      }, TRANSITION_COMPLETION_WATCHDOG_MS);
      const cleanupAnimations = () => {
        clearTimeout(watchdogId);
        activeAnimations.forEach((animation) => animation.stop());
      };
      return () => {
        cancelled = true;
        cleanupAnimations();
      };
    }

    return () => {
      cancelled = true;
      activeAnimations.forEach((animation) => animation.stop());
    };
  }, [isAnimating, resolveScrollContainer, currentLayerKey]);

  return (
    <div className={`page-transition${isAnimating ? ' page-transition--animating' : ''}`}>
      {(() => {
        const currentIndex = layers.findIndex((layer) => layer.status === 'current');
        const resolvedCurrentIndex = currentIndex === -1 ? layers.length - 1 : currentIndex;
        const keepStackedIndex = layers
          .slice(0, resolvedCurrentIndex)
          .map((layer, index) => ({ layer, index }))
          .reverse()
          .find(({ layer }) => layer.status === 'stacked')?.index;

        return layers.map((layer, index) => {
          const shouldKeepStacked = layer.status === 'stacked' && index === keepStackedIndex;
          return (
            <div
              key={layer.key}
              className={[
                'page-transition__layer',
                layer.status === 'exiting' ? 'page-transition__layer--exit' : '',
                layer.status === 'stacked' ? 'page-transition__layer--stacked' : '',
                shouldKeepStacked ? 'page-transition__layer--stacked-keep' : '',
              ]
                .filter(Boolean)
                .join(' ')}
              aria-hidden={layer.status !== 'current'}
              inert={layer.status !== 'current'}
              ref={
                layer.status === 'exiting'
                  ? exitingLayerRef
                  : layer.status === 'current'
                    ? currentLayerRef
                    : undefined
              }
            >
              <PageTransitionLayerContext.Provider
                value={{
                  ...PAGE_TRANSITION_LAYER_CONTEXT_VALUES[layer.status],
                  isAnimating,
                }}
              >
                {render(layer.location)}
              </PageTransitionLayerContext.Provider>
            </div>
          );
        });
      })()}
    </div>
  );
}
