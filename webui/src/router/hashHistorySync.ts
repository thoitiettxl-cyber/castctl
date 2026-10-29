/**
 * Hash/history sync: keep the data router in step with same-document
 * fragment navigations that never reach it through `popstate`.
 *
 * react-router's hash history listens ONLY to `popstate`
 * (react-router 7.18.4, lib/router/history.ts: `getUrlBasedHistory`
 * registers `PopStateEventType` and nothing else). A fragment navigation
 * whose history entry state did not change — e.g. consecutive external
 * gotos / `location.hash =` assignments between two entries whose state
 * is already null — fires `hashchange` only, so `useLocation()` never
 * updates and the URL changes while `<main>` does not. Back/Forward and
 * address-bar edits whose entry state changed DO fire `popstate`, so
 * this sync must be a guarded no-op in that case: it compares the live
 * hash against `router.state.location` at event time and only navigates
 * when they disagree, with `replace: true` because the browser already
 * created the history entry (a push would make one Back press need two).
 *
 * `router.navigate(replaceState)` fires neither event, so the sync
 * cannot loop. NavLink clicks use `history.pushState`, which fires
 * neither event either, so in-app navigation is untouched.
 */

export type HashRoute = {
  pathname: string;
  search: string;
  hash: string;
};

/** Minimal structural view of the data router this sync needs. */
export interface HashSyncRouter {
  readonly state: {
    readonly location: { pathname: string; search: string; hash: string };
  };
  navigate: (to: string, opts?: { replace?: boolean }) => Promise<void> | void;
}

/** Minimal structural view of the window this sync needs. */
export interface HashSyncWindow {
  readonly location: { readonly hash: string };
  addEventListener: (type: 'hashchange', listener: () => void) => void;
  removeEventListener: (type: 'hashchange', listener: () => void) => void;
}

function parsePath(path: string): { pathname?: string; search?: string; hash?: string } {
  const parsed: { pathname?: string; search?: string; hash?: string } = {};
  if (path) {
    let rest = path;
    const hashIndex = rest.indexOf('#');
    if (hashIndex >= 0) {
      parsed.hash = rest.substring(hashIndex);
      rest = rest.substring(0, hashIndex);
    }
    const searchIndex = rest.indexOf('?');
    if (searchIndex >= 0) {
      parsed.search = rest.substring(searchIndex);
      rest = rest.substring(0, searchIndex);
    }
    if (rest) {
      parsed.pathname = rest;
    }
  }
  return parsed;
}

/**
 * Parse `window.location.hash` exactly the way
 * `createHashHistory`'s `createHashLocation` does: strip the leading
 * `#`, parse the remainder as a path, default the pathname to `/`,
 * and force a leading `/` for bare fragments like `#profiles`.
 */
export function parseHashRoute(hash: string): HashRoute {
  const { pathname = '/', search = '', hash: fragment = '' } = parsePath(
    hash.startsWith('#') ? hash.substring(1) : hash,
  );
  const normalizedPathname =
    pathname.startsWith('/') || pathname.startsWith('.') ? pathname : `/${pathname}`;
  return { pathname: normalizedPathname, search, hash: fragment };
}

/** The router path (`/profiles?tab=a#sec`) the given hash denotes. */
export function hashRoutePath(hash: string): string {
  const route = parseHashRoute(hash);
  return `${route.pathname}${route.search}${route.hash}`;
}

/** True when the router already points at the route the hash denotes. */
export function isRouterLocationInSyncWithHash(
  location: { pathname: string; search: string; hash: string },
  hash: string,
): boolean {
  const route = parseHashRoute(hash);
  return (
    route.pathname === location.pathname &&
    route.search === location.search &&
    route.hash === location.hash
  );
}

/**
 * Install the `hashchange` listener. Returns a cleanup that removes it.
 * The router is read synchronously at event time (`router.state`), so a
 * `popstate` that already synced the router in the same task sequence
 * is always observed as in-sync, even before React re-renders.
 */
export function installHashHistorySync(
  router: HashSyncRouter,
  win: HashSyncWindow,
): () => void {
  const onHashChange = () => {
    if (isRouterLocationInSyncWithHash(router.state.location, win.location.hash)) {
      return;
    }
    void router.navigate(hashRoutePath(win.location.hash), { replace: true });
  };
  win.addEventListener('hashchange', onHashChange);
  return () => {
    win.removeEventListener('hashchange', onHashChange);
  };
}
