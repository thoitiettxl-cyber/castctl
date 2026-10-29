import { describe, expect, it, vi } from 'vitest';
import type { Location } from 'react-router-dom';
import { UNSAFE_createHashHistory as createHashHistory } from 'react-router-dom';
import {
  createInitialPageTransitionState,
  isSameRouteLocation,
  pageTransitionLayerKey,
  pageTransitionReducer,
} from '../src/components/common/PageTransitionLayer';
import {
  hashRoutePath,
  installHashHistorySync,
  isRouterLocationInSyncWithHash,
  parseHashRoute,
} from '../src/router/hashHistorySync';

const makeLocation = (
  pathname: string,
  key: string,
  search = '',
  hash = '',
): Location => ({ pathname, search, hash, state: null, key });

/**
 * Fake window implementing just enough of the browser history API for
 * react-router's createHashHistory: entries with state, pushState /
 * replaceState / go, popstate + hashchange listeners, and a location
 * object derived from the current entry's URL.
 *
 * `navigateExternally` mirrors a same-document fragment navigation as
 * performed by the browser chrome, a pasted/bookmarked link activation,
 * or a CDP `goto` to a URL that differs only in the hash: the browser
 * appends a NEW history entry whose state is null (the router never
 * stamped it), then fires popstate and/or hashchange. `firePopstate`
 * models the two real behaviours: a traversal whose entry state changed
 * fires popstate before hashchange; a traversal between two null-state
 * entries fires hashchange only (HTML spec "traverse the history":
 * popstate fires only "if state changed is true").
 */
class FakeWindow {
  entries: { url: string; state: unknown }[] = [
    { url: 'http://127.0.0.1:5173/#/', state: null },
  ];
  index = 0;
  listeners = new Map<string, Set<() => void>>();
  document = { querySelector: () => null };

  location = {
    href: 'http://127.0.0.1:5173/#/',
    origin: 'http://127.0.0.1:5173',
    pathname: '/',
    search: '',
    hash: '#/',
  };

  history = {
    get state() {
      return this.owner.entries[this.owner.index].state;
    },
    owner: this as FakeWindow,
    pushState: (state: unknown, _title: string, url: string) => {
      this.entries.splice(this.index + 1);
      this.entries.push({ url: new URL(url, this.location.href).href, state });
      this.index = this.entries.length - 1;
      this.syncLocation();
    },
    replaceState: (state: unknown, _title: string, url: string) => {
      this.entries[this.index] = {
        url: url ? new URL(url, this.location.href).href : this.entries[this.index].url,
        state,
      };
      this.syncLocation();
    },
    go: (delta: number) => {
      const next = Math.min(Math.max(this.index + delta, 0), this.entries.length - 1);
      if (next === this.index) return;
      this.index = next;
      this.syncLocation();
      this.dispatch('popstate');
      this.dispatch('hashchange');
    },
  };

  constructor() {
    this.history.owner = this;
  }

  syncLocation() {
    const url = new URL(this.entries[this.index].url);
    this.location.href = url.href;
    this.location.origin = url.origin;
    this.location.pathname = url.pathname;
    this.location.search = url.search;
    this.location.hash = url.hash;
  }

  addEventListener(type: string, listener: () => void) {
    const set = this.listeners.get(type) ?? new Set();
    set.add(listener);
    this.listeners.set(type, set);
  }

  removeEventListener(type: string, listener: () => void) {
    this.listeners.get(type)?.delete(listener);
  }

  dispatch(type: string) {
    for (const listener of [...(this.listeners.get(type) ?? [])]) listener();
  }

  navigateExternally(url: string, firePopstate: boolean) {
    this.entries.splice(this.index + 1);
    this.entries.push({ url: new URL(url, this.location.href).href, state: null });
    this.index = this.entries.length - 1;
    this.syncLocation();
    if (firePopstate) this.dispatch('popstate');
    this.dispatch('hashchange');
  }

  setHashOnly(hash: string) {
    // `location.hash = ...`: new null-state entry, hashchange only.
    const url = new URL(this.location.href);
    url.hash = hash;
    this.navigateExternally(url.href, false);
  }
}

/** Minimal stand-in for the data router: state only moves via the history
 *  listener (POP) or via navigate() (PUSH/REPLACE), mirroring createRouter. */
class FakeRouter {
  state: { location: Location };
  navigateCalls: { to: string; replace: boolean }[] = [];

  constructor(private history: ReturnType<typeof createHashHistory>) {
    this.state = { location: history.location };
    history.listen(({ location }) => {
      this.state.location = location;
    });
  }

  async navigate(to: string, opts?: { replace?: boolean }) {
    this.navigateCalls.push({ to, replace: opts?.replace ?? false });
    if (opts?.replace) this.history.replace(to);
    else this.history.push(to);
    this.state.location = this.history.location;
  }
}

describe('parseHashRoute / hash sync decision (pure)', () => {
  it('parses a hash-router URL the way createHashHistory does', () => {
    expect(parseHashRoute('#/profiles')).toEqual({ pathname: '/profiles', search: '', hash: '' });
    expect(parseHashRoute('#/logs?level=error')).toEqual({
      pathname: '/logs',
      search: '?level=error',
      hash: '',
    });
    expect(parseHashRoute('#/profiles?tab=a#sec')).toEqual({
      pathname: '/profiles',
      search: '?tab=a',
      hash: '#sec',
    });
    expect(parseHashRoute('#profiles')).toEqual({ pathname: '/profiles', search: '', hash: '' });
    expect(parseHashRoute('#')).toEqual({ pathname: '/', search: '', hash: '' });
    expect(parseHashRoute('')).toEqual({ pathname: '/', search: '', hash: '' });
  });

  it('hashRoutePath round-trips the parsed route', () => {
    expect(hashRoutePath('#/config?x=1#frag')).toBe('/config?x=1#frag');
    expect(hashRoutePath('#/')).toBe('/');
  });

  it('reports in-sync only when pathname, search and hash all match', () => {
    const routerLocation = makeLocation('/profiles', 'k1', '?tab=a', '#sec');
    expect(isRouterLocationInSyncWithHash(routerLocation, '#/profiles?tab=a#sec')).toBe(true);
    expect(isRouterLocationInSyncWithHash(routerLocation, '#/config?tab=a#sec')).toBe(false);
    expect(isRouterLocationInSyncWithHash(routerLocation, '#/profiles?tab=b#sec')).toBe(false);
    expect(isRouterLocationInSyncWithHash(routerLocation, '#/profiles?tab=a')).toBe(false);
    // Key is deliberately NOT part of the comparison: external entries
    // all carry the fallback key "default".
    expect(
      isRouterLocationInSyncWithHash(makeLocation('/profiles', 'default', '?tab=a', '#sec'), '#/profiles?tab=a#sec'),
    ).toBe(true);
  });
});

describe('real createHashHistory with a fake window (router-level reproduction)', () => {
  it('a router push gets a fresh random key; an external goto gets the fallback key "default"', () => {
    const win = new FakeWindow();
    const history = createHashHistory({ window: win as never });
    const seen: Location[] = [];
    history.listen(({ location }) => seen.push(location));

    history.push('/profiles');
    expect(history.location.pathname).toBe('/profiles');
    expect(history.location.key).not.toBe('default');

    win.navigateExternally('http://127.0.0.1:5173/#/config', true);
    expect(history.location.pathname).toBe('/config');
    // The entry was created by the browser, not by the router, so no
    // router-stamped key exists in history.state.
    expect(history.location.key).toBe('default');
    expect(win.history.state).toBeNull();
    expect(seen.at(-1)?.pathname).toBe('/config');
  });

  it('a hashchange-only traversal never reaches the history listener (popstate-only listening)', () => {
    const win = new FakeWindow();
    const history = createHashHistory({ window: win as never });
    const listener = vi.fn();
    history.listen(listener);

    // First external goto: entry state {idx} -> null, popstate fires.
    win.navigateExternally('http://127.0.0.1:5173/#/profiles', true);
    expect(listener).toHaveBeenCalledTimes(1);

    // Second external goto: null -> null, hashchange only. The router's
    // only listener is popstate, so it never learns the URL changed,
    // even though history.location (re-read) shows the new pathname.
    win.navigateExternally('http://127.0.0.1:5173/#/config', false);
    expect(listener).toHaveBeenCalledTimes(1);
    expect(history.location.pathname).toBe('/config');
    expect(win.location.hash).toBe('#/config');
  });

  it('history back/forward restores router-stamped keys via popstate', () => {
    const win = new FakeWindow();
    const history = createHashHistory({ window: win as never });
    history.push('/profiles');
    const profilesKey = history.location.key;
    history.push('/config');
    expect(history.location.key).not.toBe(profilesKey);

    win.history.go(-1);
    expect(history.location.pathname).toBe('/profiles');
    expect(history.location.key).toBe(profilesKey);

    win.history.go(1);
    expect(history.location.pathname).toBe('/config');

    // Back to the initial entry: its state was never router-stamped.
    win.history.go(-2);
    expect(history.location.pathname).toBe('/');
    expect(history.location.key).toBe('default');
  });
});

describe('installHashHistorySync', () => {
  it('does nothing when popstate already synced the router (no double navigation)', () => {
    const win = new FakeWindow();
    const history = createHashHistory({ window: win as never });
    const router = new FakeRouter(history);
    const cleanup = installHashHistorySync(router, win as never);
    try {
      win.navigateExternally('http://127.0.0.1:5173/#/profiles', true);
      expect(router.state.location.pathname).toBe('/profiles');
      expect(router.navigateCalls).toEqual([]);
    } finally {
      cleanup();
    }
  });

  it('adopts a hashchange-only navigation with replace (no extra history entry)', () => {
    const win = new FakeWindow();
    const history = createHashHistory({ window: win as never });
    const router = new FakeRouter(history);
    const cleanup = installHashHistorySync(router, win as never);
    try {
      win.navigateExternally('http://127.0.0.1:5173/#/profiles', true);
      expect(router.navigateCalls).toEqual([]);

      // Consecutive external goto: hashchange only, router is blind.
      const entriesBeforeSync = win.entries.length;
      win.navigateExternally('http://127.0.0.1:5173/#/config', false);
      expect(router.navigateCalls).toEqual([{ to: '/config', replace: true }]);
      expect(router.state.location.pathname).toBe('/config');
      // Replace: the browser already created the entry; sync must not
      // add a second one or Back would need two presses.
      expect(win.entries.length).toBe(entriesBeforeSync + 1);

      // A repeat hashchange for the same hash is a no-op.
      win.dispatch('hashchange');
      expect(router.navigateCalls).toHaveLength(1);
    } finally {
      cleanup();
    }
  });

  it('adopts a direct location.hash assignment', () => {
    const win = new FakeWindow();
    const history = createHashHistory({ window: win as never });
    const router = new FakeRouter(history);
    const cleanup = installHashHistorySync(router, win as never);
    try {
      win.setHashOnly('#/system');
      expect(router.state.location.pathname).toBe('/system');
      expect(router.navigateCalls).toEqual([{ to: '/system', replace: true }]);
    } finally {
      cleanup();
    }
  });

  it('stops syncing after cleanup', () => {
    const win = new FakeWindow();
    const history = createHashHistory({ window: win as never });
    const router = new FakeRouter(history);
    const cleanup = installHashHistorySync(router, win as never);
    cleanup();
    win.navigateExternally('http://127.0.0.1:5173/#/logs', false);
    expect(router.navigateCalls).toEqual([]);
    expect(router.state.location.pathname).toBe('/');
  });

  it('a goto chain through the sync ends on the last route, reachable by Back', () => {
    const win = new FakeWindow();
    const history = createHashHistory({ window: win as never });
    const router = new FakeRouter(history);
    const cleanup = installHashHistorySync(router, win as never);
    try {
      // Dashboard (initial) -> profiles -> config -> system, each an
      // external hash-only goto, as in the parent-measured symptom.
      win.navigateExternally('http://127.0.0.1:5173/#/profiles', false);
      win.navigateExternally('http://127.0.0.1:5173/#/config', false);
      win.navigateExternally('http://127.0.0.1:5173/#/system', false);
      expect(router.state.location.pathname).toBe('/system');
      expect(router.navigateCalls.map((c) => c.to)).toEqual(['/profiles', '/config', '/system']);

      win.history.go(-1);
      expect(router.state.location.pathname).toBe('/config');
      win.history.go(-1);
      expect(router.state.location.pathname).toBe('/profiles');
      win.history.go(2);
      expect(router.state.location.pathname).toBe('/system');
    } finally {
      cleanup();
    }
  });
});

describe('isSameRouteLocation: key equality must not mean same route', () => {
  it('same fallback key, different pathname is a different route', () => {
    expect(
      isSameRouteLocation(
        makeLocation('/profiles', 'default'),
        makeLocation('/', 'default'),
      ),
    ).toBe(false);
  });

  it('same pathname with different keys is the same route', () => {
    expect(
      isSameRouteLocation(makeLocation('/profiles', 'k-a'), makeLocation('/profiles', 'k-b')),
    ).toBe(true);
  });

  it('same pathname but different search or hash is a different route', () => {
    expect(
      isSameRouteLocation(
        makeLocation('/logs', 'k-a', '?level=error'),
        makeLocation('/logs', 'k-a', '?level=warn'),
      ),
    ).toBe(false);
    expect(
      isSameRouteLocation(
        makeLocation('/profiles', 'k-a', '', '#a'),
        makeLocation('/profiles', 'k-a', '', '#b'),
      ),
    ).toBe(false);
  });

  it('undefined current layer is never the same route', () => {
    expect(isSameRouteLocation(makeLocation('/profiles', 'default'), undefined)).toBe(false);
  });
});

describe('pageTransitionReducer on the hashchange path (fallback key "default")', () => {
  it('starts a transition when only the hash changed the pathname, key still "default"', () => {
    const initial = createInitialPageTransitionState(makeLocation('/', 'default'));
    const next = pageTransitionReducer(initial, {
      type: 'navigate',
      location: makeLocation('/profiles', 'default'),
      variant: 'vertical',
      direction: 'forward',
      shouldSkipExitLayer: false,
    });

    // Before the fix the reducer returned the state unchanged here
    // (key equality counted as same route), so <main> stayed on the
    // Dashboard layer forever until a reload.
    expect(next).not.toBe(initial);
    expect(next.isAnimating).toBe(true);
    expect(next.layers.at(-1)?.location.pathname).toBe('/profiles');
  });

  it('consecutive hashchange navigations each start a transition and keep distinct layer keys', () => {
    const initial = createInitialPageTransitionState(makeLocation('/', 'default'));
    const toProfiles = pageTransitionReducer(initial, {
      type: 'navigate',
      location: makeLocation('/profiles', 'default'),
      variant: 'vertical',
      direction: 'forward',
      shouldSkipExitLayer: false,
    });
    const settled = pageTransitionReducer(toProfiles, { type: 'finish' });
    const toConfig = pageTransitionReducer(settled, {
      type: 'navigate',
      location: makeLocation('/config', 'default'),
      variant: 'vertical',
      direction: 'forward',
      shouldSkipExitLayer: false,
    });

    expect(toConfig.isAnimating).toBe(true);
    expect(toConfig.layers.at(-1)?.location.pathname).toBe('/config');
    // Two layers sharing one React key break reconciliation and the
    // current/exiting refs; keys must be unique per layer even when
    // location.key repeats.
    const keys = toConfig.layers.map((layer) => layer.key);
    expect(new Set(keys).size).toBe(keys.length);
    expect(pageTransitionLayerKey(makeLocation('/profiles', 'default'))).not.toBe(
      pageTransitionLayerKey(makeLocation('/config', 'default')),
    );
  });

  it('history back to the initial entry (key "default") then forward still transitions', () => {
    const initial = createInitialPageTransitionState(makeLocation('/', 'default'));
    const pushed = pageTransitionReducer(initial, {
      type: 'navigate',
      location: makeLocation('/profiles', 'k-profiles'),
      variant: 'vertical',
      direction: 'forward',
      shouldSkipExitLayer: false,
    });
    const settled = pageTransitionReducer(pushed, { type: 'finish' });
    // Back: POP restores the initial entry, whose key is "default".
    const back = pageTransitionReducer(settled, {
      type: 'navigate',
      location: makeLocation('/', 'default'),
      variant: 'vertical',
      direction: 'backward',
      shouldSkipExitLayer: false,
    });
    expect(back.isAnimating).toBe(true);
    expect(back.layers.at(-1)?.location.pathname).toBe('/');
    const backSettled = pageTransitionReducer(back, { type: 'finish' });
    // Forward again to the router-stamped entry.
    const forward = pageTransitionReducer(backSettled, {
      type: 'navigate',
      location: makeLocation('/profiles', 'k-profiles'),
      variant: 'vertical',
      direction: 'forward',
      shouldSkipExitLayer: false,
    });
    expect(forward.isAnimating).toBe(true);
    expect(forward.layers.at(-1)?.location.pathname).toBe('/profiles');
  });

  it('a hashchange navigation arriving mid-animation is recorded as pending and started by finish', () => {
    const initial = createInitialPageTransitionState(makeLocation('/', 'default'));
    const animating = pageTransitionReducer(initial, {
      type: 'navigate',
      location: makeLocation('/profiles', 'k-profiles'),
      variant: 'vertical',
      direction: 'forward',
      shouldSkipExitLayer: false,
    });
    // Hashchange goto while the click transition is still animating:
    // same fallback-free path as a click, key "default".
    const pending = pageTransitionReducer(animating, {
      type: 'navigate',
      location: makeLocation('/system', 'default'),
      variant: 'vertical',
      direction: 'forward',
      shouldSkipExitLayer: false,
    });
    expect(pending.pending?.location.pathname).toBe('/system');
    const next = pageTransitionReducer(pending, { type: 'finish' });
    expect(next.isAnimating).toBe(true);
    expect(next.layers.at(-1)?.location.pathname).toBe('/system');
  });

  it('ios backward POP finds its stacked target by composite layer key, including the "default" initial entry', () => {
    const initial = createInitialPageTransitionState(makeLocation('/', 'default'));
    const toProfiles = pageTransitionReducer(initial, {
      type: 'navigate',
      location: makeLocation('/profiles', 'k-profiles'),
      variant: 'ios',
      direction: 'forward',
      shouldSkipExitLayer: false,
    });
    const settledProfiles = pageTransitionReducer(toProfiles, { type: 'finish' });
    const toConfig = pageTransitionReducer(settledProfiles, {
      type: 'navigate',
      location: makeLocation('/config', 'k-config'),
      variant: 'ios',
      direction: 'forward',
      shouldSkipExitLayer: false,
    });
    const settledConfig = pageTransitionReducer(toConfig, { type: 'finish' });
    expect(settledConfig.layers.map((l) => l.location.pathname)).toEqual([
      '/',
      '/profiles',
      '/config',
    ]);

    // POP back to /profiles (router-stamped key restored by the browser).
    const backToProfiles = pageTransitionReducer(settledConfig, {
      type: 'navigate',
      location: makeLocation('/profiles', 'k-profiles'),
      variant: 'ios',
      direction: 'backward',
      shouldSkipExitLayer: false,
    });
    expect(backToProfiles.settledLayers?.map((l) => l.location.pathname)).toEqual([
      '/',
      '/profiles',
    ]);
    // Layers end with the exiting layer; the POP target is the layer
    // whose status is 'current'.
    expect(
      backToProfiles.layers.find((l) => l.status === 'current')?.location.pathname,
    ).toBe('/profiles');
    expect(backToProfiles.layers.at(-1)?.status).toBe('exiting');

    // POP back to the initial entry, whose key is the fallback "default".
    const backSettled = pageTransitionReducer(backToProfiles, { type: 'finish' });
    const backToRoot = pageTransitionReducer(backSettled, {
      type: 'navigate',
      location: makeLocation('/', 'default'),
      variant: 'ios',
      direction: 'backward',
      shouldSkipExitLayer: false,
    });
    expect(backToRoot.settledLayers?.map((l) => l.location.pathname)).toEqual(['/']);
    expect(
      backToRoot.layers.find((l) => l.status === 'current')?.location.pathname,
    ).toBe('/');
  });
});
