/** Dev-only mock API middleware (Node, Vite dev server only).
 * Answers every /api/v1 endpoint from fixtures. Bearer check: any
 * non-empty Authorization header is accepted; missing → 401, so the
 * login/logout flow behaves like the real server. Never bundled.
 *
 * DIVERGENCES from the Go server (dev-only, deliberate): auth
 * accepts any non-empty token (Go compares SHA-256 + constant
 * time against the configured token); PATCH profile shallow-merges
 * the body onto the stored entry (Go merges only the allowlisted
 * fingerprint/outbound fields through the guarded save); login
 * import returns verified:true with a fake vm_id_prefix (Go
 * returns verified:false — no live verification — and a null
 * prefix). The PR body lists these divergences.
 */
import type { Connect } from 'vite';
import {
  handleGetConfig,
  handleGetDns,
  handlePutConfig,
  handlePutDns,
  handleValidateConfig,
} from './configStore.ts';
import {
  endpointsFixture,
  keeperFixture,
  legacyProfileEntryFixture,
  loginStatusFixture,
  logsFixture,
  outboundsFixture,
  profileDetailFixture,
  profileTestFixture,
  profilesFixture,
  statusFixture,
  telegramFixture,
} from './fixtures.ts';
import { redactValue } from './redact.ts';

import {
  appendLiveLogEntries,
  filterLogEntriesByLevel,
  type MockLogEntry,
} from './liveLogs.ts';

const ok = (res: Connect.ServerResponse, data: unknown) => {
  res.statusCode = 200;
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify({ data }));
};

const err = (res: Connect.ServerResponse, status: number, type: string, message: string) => {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify({ error: { type, message } }));
};

// Live log ring (dev-server lifetime only; a server restart reseeds
// it from the fixture). The FIRST GET /logs returns the fixture
// verbatim so the initial page load is stable; every later GET —
// i.e. every 5s poll tick, Refresh, or level-filter fetch — appends
// exactly one new entry before responding, through this same
// handler LogsPage polls. No timer: the poll IS the clock, so the
// page can never observe entries arriving faster than it polls.
let liveLogEntries: MockLogEntry[] = [...logsFixture];
let liveLogNextIndex = 0;
let liveLogPollCount = 0;

/** Stored-form entry for a profile; the legacy profile's entry lives outside config.json (D3). */
function storedEntryFor(name: string): Record<string, unknown> {
  return name === 'legacy-note'
    ? (legacyProfileEntryFixture as unknown as Record<string, unknown>)
    : (profileDetailFixture.entry as unknown as Record<string, unknown>);
}

/** Profile detail as served: entry redacted (C3), never the stored form. */
function servedProfileDetail(name: string) {
  return { ...profileDetailFixture, name, entry: redactValue(storedEntryFor(name)) };
}

/** Redacted wg-quick import preview (C6): keys never shown as values. */
export const ENDPOINT_IMPORT_PREVIEW =
  '[Interface]\nAddress = 10.2.0.2/32\n# secrets redacted';

export function registerMockApi(middlewares: Connect.Server) {
  middlewares.use('/api/v1', (req, res, next) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');
    const path = url.pathname.replace(/^\/api\/v1/, '') || '/';
    const method = req.method ?? 'GET';

    if (!req.headers.authorization) {
      err(res, 401, 'unauthorized', 'Missing management token');
      return;
    }

    let body = '';
    req.on('data', (chunk: Buffer) => {
      body += chunk.toString();
    });
    req.on('end', () => {
      // A malformed body must never throw out of the handler (which
      // would hang or crash the dev server) and must never be echoed:
      // fail closed with a generic, path-free 400.
      let json: Record<string, unknown>;
      try {
        json = body ? (JSON.parse(body) as Record<string, unknown>) : {};
      } catch {
        err(res, 400, 'validation_failed', 'Invalid JSON in request body');
        return;
      }

      if (method === 'GET' && path === '/status') return ok(res, statusFixture);
      if (method === 'GET' && path === '/profiles') return ok(res, profilesFixture);
      if (method === 'POST' && path === '/profiles') {
        const created = { name: String(json.name ?? 'new'), default: false, source: 'single-file', has_cookies: false, outbound_tag: null, fingerprint: 'chrome', dir: '' };
        return ok(res, created);
      }
      const profileMatch = path.match(/^\/profiles\/([^/]+)(.*)$/);
      if (profileMatch) {
        const name = decodeURIComponent(profileMatch[1]);
        const rest = profileMatch[2];
        if (rest === '' && method === 'GET') return ok(res, servedProfileDetail(name));
        if (rest === '' && method === 'PATCH') {
          // DIVERGENCE: shallow-merge of the body onto the stored
          // entry. The Go handler merges only fingerprint/outbound
          // through the guarded save; the mock keeps the shape
          // for dev editing.
          return ok(res, {
            ...profileDetailFixture,
            name,
            entry: redactValue({ ...storedEntryFor(name), ...(json as Record<string, unknown>) }),
          });
        }
        if (rest === '' && method === 'DELETE') {
          if (json.confirm !== true || json.name !== name) {
            return err(res, 400, 'validation_failed', 'Delete requires {confirm: true, name}');
          }
          return ok(res, { deleted: true });
        }
        if (rest === '/login/status' && method === 'GET') return ok(res, loginStatusFixture);
        if (rest === '/login/import' && method === 'POST') {
          // DIVERGENCE: the Go server returns verified:false
          // (no live verification) with a null vm_id_prefix;
          // the mock returns a fake verified result so the dev
          // login flow can be exercised end to end.
          return ok(res, { saved: true, verified: true, vm_id_prefix: 'vm_9f2c' });
        }
        if (rest === '/login/restore' && method === 'POST') return ok(res, { restored: true });
        if (rest === '/test' && method === 'POST') return ok(res, { ...profileTestFixture, profile: name });
        if (rest === '/set-default' && method === 'POST') return ok(res, { default_profile: name });
        if (rest === '/rename' && method === 'POST') {
          return ok(res, servedProfileDetail(String(json.to ?? name)));
        }
      }
      if (method === 'GET' && path === '/outbounds') return ok(res, outboundsFixture);
      if (method === 'POST' && path === '/outbounds/validate') return ok(res, { valid: true, errors: [] });
      const outboundMatch = path.match(/^\/outbounds\/([^/]+)(.*)$/);
      if (outboundMatch) {
        const tag = decodeURIComponent(outboundMatch[1]);
        const rest = outboundMatch[2];
        if (rest === '/test' && method === 'POST') {
          return ok(res, {
            tag,
            overall: 'pass',
            egress_ip: '203.0.113.42',
            phases: [
              { phase: 'dns', status: 'pass', duration_ms: 120 },
              { phase: 'tls', status: 'pass', duration_ms: 310 },
              { phase: 'http', status: 'pass', duration_ms: 180 },
              { phase: 'egress', status: 'pass', duration_ms: 95 },
            ],
          });
        }
        if (rest === '' && method === 'GET') return ok(res, outboundsFixture[0]);
        if (rest === '' && method === 'DELETE') return ok(res, { deleted: true });
      }
      if (method === 'GET' && path === '/endpoints') return ok(res, endpointsFixture);
      if (method === 'POST' && path === '/endpoints/import') {
        if (json.save === true) return ok(res, endpointsFixture[0]);
        return ok(res, { preview: ENDPOINT_IMPORT_PREVIEW });
      }
      const endpointMatch = path.match(/^\/endpoints\/([^/]+)$/);
      if (endpointMatch) {
        if (method === 'GET') return ok(res, endpointsFixture[0]);
        if (method === 'DELETE') return ok(res, { deleted: true });
      }
      if (method === 'GET' && path === '/config') return ok(res, handleGetConfig());
      if (method === 'PUT' && path === '/config') {
        const result = handlePutConfig(json as { content?: unknown; base_sha256?: unknown });
        if (result.ok) return ok(res, result.data);
        return err(res, result.error.status, result.error.type, result.error.message);
      }
      if (method === 'POST' && path === '/config/validate')
        return ok(res, handleValidateConfig(json as { content?: unknown }));
      if (method === 'GET' && path === '/dns') return ok(res, handleGetDns());
      if (method === 'PUT' && path === '/dns') {
        const result = handlePutDns(json as { dns?: unknown; base_sha256?: unknown });
        if (result.ok) return ok(res, result.data);
        return err(res, result.error.status, result.error.type, result.error.message);
      }
      if (method === 'GET' && path === '/settings/telegram') return ok(res, telegramFixture);
      if (method === 'PUT' && path === '/settings/telegram') return ok(res, telegramFixture);
      if (method === 'GET' && path === '/logs') {
        liveLogPollCount += 1;
        if (liveLogPollCount > 1) {
          liveLogEntries = appendLiveLogEntries(liveLogEntries, 1, liveLogNextIndex);
          liveLogNextIndex += 1;
        }
        const filtered = filterLogEntriesByLevel(liveLogEntries, url.searchParams.get('level') ?? undefined);
        const limit = Number(url.searchParams.get('limit'));
        const entries = Number.isFinite(limit) && limit > 0 ? filtered.slice(-limit) : filtered;
        return ok(res, { entries, next_cursor: null, more: false });
      }
      if (method === 'DELETE' && path === '/logs') {
        // The Go server never truncates a live log file: 405.
        return err(res, 405, 'method_not_allowed', 'Log clearing is not supported');
      }
      if (method === 'GET' && path === '/keeper') return ok(res, keeperFixture);
      if (method === 'GET' && path === '/screencast/status') {
        // The mock has no browser and no WebSocket relay: the page
        // shows the unavailable state, exactly as the Go default
        // build (without with_chromedp) does.
        return ok(res, {
          available: false,
          reason: 'screencast unavailable in mock mode (no browser attached)',
          profile: String(url.searchParams.get('profile') ?? ''),
        });
      }
      if (method === 'POST' && /^\/screencast\/[^/]+\/start$/.test(path)) {
        return err(res, 501, 'unavailable', 'screencast unavailable in mock mode (no browser attached)');
      }
      next();
    });
  });
}
