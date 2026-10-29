import { describe, expect, it } from 'vitest';
import type { Location } from 'react-router-dom';
import {
  createInitialPageTransitionState,
  pageTransitionReducer,
} from '../src/components/common/PageTransitionLayer';

const makeLocation = (pathname: string, key: string): Location => ({
  pathname,
  search: '',
  hash: '',
  state: null,
  key,
});

const profiles = makeLocation('/profiles', 'k-profiles');
const loginBrowser = makeLocation('/login-browser', 'k-login');
const config = makeLocation('/config', 'k-config');
const system = makeLocation('/system', 'k-system');

describe('pageTransitionReducer', () => {
  it('starts a transition on idle navigation', () => {
    const initial = createInitialPageTransitionState(profiles);
    const next = pageTransitionReducer(initial, {
      type: 'navigate',
      location: loginBrowser,
      variant: 'vertical',
      direction: 'forward',
      shouldSkipExitLayer: false,
    });

    expect(next.isAnimating).toBe(true);
    expect(next.pending).toBeNull();
    expect(next.layers).toEqual([
      { key: 'k-profiles:/profiles', location: profiles, status: 'exiting' },
      { key: 'k-login:/login-browser', location: loginBrowser, status: 'current' },
    ]);
    expect(next.settledLayers).toEqual([
      { key: 'k-login:/login-browser', location: loginBrowser, status: 'current' },
    ]);
  });

  it('records a navigation that arrives mid-animation instead of dropping it', () => {
    const initial = createInitialPageTransitionState(profiles);
    const animating = pageTransitionReducer(initial, {
      type: 'navigate',
      location: loginBrowser,
      variant: 'vertical',
      direction: 'forward',
      shouldSkipExitLayer: false,
    });
    const next = pageTransitionReducer(animating, {
      type: 'navigate',
      location: config,
      variant: 'vertical',
      direction: 'forward',
      shouldSkipExitLayer: false,
    });

    // Layers and the settled target are untouched; the new navigation
    // is remembered. The old code returned the state unchanged here,
    // so the navigation was lost and only a reload could recover it.
    expect(next.layers).toEqual(animating.layers);
    expect(next.settledLayers).toEqual(animating.settledLayers);
    expect(next.isAnimating).toBe(true);
    expect(next.pending?.location).toEqual(config);
  });

  it('finish starts the pending navigation (strand recovery)', () => {
    const initial = createInitialPageTransitionState(profiles);
    const animating = pageTransitionReducer(initial, {
      type: 'navigate',
      location: loginBrowser,
      variant: 'vertical',
      direction: 'forward',
      shouldSkipExitLayer: false,
    });
    const pending = pageTransitionReducer(animating, {
      type: 'navigate',
      location: config,
      variant: 'vertical',
      direction: 'forward',
      shouldSkipExitLayer: false,
    });
    const next = pageTransitionReducer(pending, { type: 'finish' });

    expect(next.isAnimating).toBe(true);
    expect(next.pending).toBeNull();
    expect(next.layers).toEqual([
      { key: 'k-login:/login-browser', location: loginBrowser, status: 'exiting' },
      { key: 'k-config:/config', location: config, status: 'current' },
    ]);
    expect(next.settledLayers).toEqual([
      { key: 'k-config:/config', location: config, status: 'current' },
    ]);
  });

  it('finish without a pending navigation collapses to the settled layer', () => {
    const initial = createInitialPageTransitionState(profiles);
    const animating = pageTransitionReducer(initial, {
      type: 'navigate',
      location: loginBrowser,
      variant: 'vertical',
      direction: 'forward',
      shouldSkipExitLayer: false,
    });
    const next = pageTransitionReducer(animating, { type: 'finish' });

    expect(next).toEqual({
      layers: [{ key: 'k-login:/login-browser', location: loginBrowser, status: 'current' }],
      isAnimating: false,
      settledLayers: null,
      pending: null,
    });
  });

  it('finish is a no-op when idle (completion guard)', () => {
    const initial = createInitialPageTransitionState(profiles);
    expect(pageTransitionReducer(initial, { type: 'finish' })).toBe(initial);
  });

  it('ignores same-key and same-pathname navigations, including mid-animation', () => {
    const initial = createInitialPageTransitionState(profiles);
    expect(
      pageTransitionReducer(initial, {
        type: 'navigate',
        location: profiles,
        variant: 'vertical',
        direction: 'forward',
        shouldSkipExitLayer: false,
      }),
    ).toBe(initial);
    expect(
      pageTransitionReducer(initial, {
        type: 'navigate',
        location: makeLocation('/profiles', 'k-other'),
        variant: 'vertical',
        direction: 'forward',
        shouldSkipExitLayer: false,
      }),
    ).toBe(initial);

    const animating = pageTransitionReducer(initial, {
      type: 'navigate',
      location: loginBrowser,
      variant: 'vertical',
      direction: 'forward',
      shouldSkipExitLayer: false,
    });
    const withPending = pageTransitionReducer(animating, {
      type: 'navigate',
      location: config,
      variant: 'vertical',
      direction: 'forward',
      shouldSkipExitLayer: false,
    });
    // Same pathname as the layer being entered: must not overwrite pending.
    const next = pageTransitionReducer(withPending, {
      type: 'navigate',
      location: makeLocation('/login-browser', 'k-login-again'),
      variant: 'vertical',
      direction: 'forward',
      shouldSkipExitLayer: false,
    });
    expect(next.pending?.location).toEqual(config);
  });

  it('the latest pending navigation wins', () => {
    const initial = createInitialPageTransitionState(profiles);
    const animating = pageTransitionReducer(initial, {
      type: 'navigate',
      location: loginBrowser,
      variant: 'vertical',
      direction: 'forward',
      shouldSkipExitLayer: false,
    });
    const pendingConfig = pageTransitionReducer(animating, {
      type: 'navigate',
      location: config,
      variant: 'vertical',
      direction: 'forward',
      shouldSkipExitLayer: false,
    });
    const pendingSystem = pageTransitionReducer(pendingConfig, {
      type: 'navigate',
      location: system,
      variant: 'vertical',
      direction: 'forward',
      shouldSkipExitLayer: false,
    });
    const next = pageTransitionReducer(pendingSystem, { type: 'finish' });

    expect(next.layers.at(-1)?.location).toEqual(system);
    expect(next.settledLayers).toEqual([
      { key: 'k-system:/system', location: system, status: 'current' },
    ]);
  });

  it('a pending navigation to the settled pathname is dropped on finish', () => {
    const initial = createInitialPageTransitionState(profiles);
    const animating = pageTransitionReducer(initial, {
      type: 'navigate',
      location: loginBrowser,
      variant: 'vertical',
      direction: 'forward',
      shouldSkipExitLayer: false,
    });
    // Same pathname pushed twice with a fresh key while animating.
    const next = pageTransitionReducer(animating, {
      type: 'navigate',
      location: makeLocation('/login-browser', 'k-login-again'),
      variant: 'vertical',
      direction: 'forward',
      shouldSkipExitLayer: false,
    });
    expect(next.pending).toBeNull();
    const finished = pageTransitionReducer(next, { type: 'finish' });
    expect(finished.isAnimating).toBe(false);
    expect(finished.layers).toEqual([
      { key: 'k-login:/login-browser', location: loginBrowser, status: 'current' },
    ]);
  });

  it('ios forward keeps the previous layer stacked after finish', () => {
    const initial = createInitialPageTransitionState(profiles);
    const animating = pageTransitionReducer(initial, {
      type: 'navigate',
      location: loginBrowser,
      variant: 'ios',
      direction: 'forward',
      shouldSkipExitLayer: false,
    });
    expect(animating.layers).toEqual([
      { key: 'k-profiles:/profiles', location: profiles, status: 'exiting' },
      { key: 'k-login:/login-browser', location: loginBrowser, status: 'current' },
    ]);
    expect(animating.settledLayers).toEqual([
      { key: 'k-profiles:/profiles', location: profiles, status: 'stacked' },
      { key: 'k-login:/login-browser', location: loginBrowser, status: 'current' },
    ]);
    const finished = pageTransitionReducer(animating, { type: 'finish' });
    expect(finished.layers).toEqual(animating.settledLayers);
    expect(finished.isAnimating).toBe(false);
  });
});
