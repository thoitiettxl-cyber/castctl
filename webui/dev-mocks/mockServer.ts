/** Dev-only mock API middleware (Node, Vite dev server only).
 * Answers every /api/v1 endpoint from fixtures. Bearer check: any
 * non-empty Authorization header is accepted; missing → 401, so the
 * login/logout flow behaves like the real server. Never bundled.
 */
import type { Connect } from 'vite';
import {
  configFixture,
  dnsFixture,
  endpointsFixture,
  loginStatusFixture,
  logsFixture,
  outboundsFixture,
  profileDetailFixture,
  profileTestFixture,
  profilesFixture,
  statusFixture,
  telegramFixture,
} from './fixtures.ts';

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

export function registerMockApi(middlewares: Connect.Server) {
  middlewares.use('/api/v1', (req, res, next) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');
    const path = url.pathname.replace(/^\/api\/v1/, '') || '/';
    const method = req.method ?? 'GET';

    if (path !== '/status' && !req.headers.authorization) {
      err(res, 401, 'unauthorized', 'Missing management token');
      return;
    }

    let body = '';
    req.on('data', (chunk: Buffer) => {
      body += chunk.toString();
    });
    req.on('end', () => {
      const json = body ? (JSON.parse(body) as Record<string, unknown>) : {};

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
        if (rest === '' && method === 'GET') return ok(res, { ...profileDetailFixture, name });
        if (rest === '' && method === 'PATCH') {
          return ok(res, {
            ...profileDetailFixture,
            name,
            entry: { ...profileDetailFixture.entry, ...(json as Record<string, unknown>) },
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
          return ok(res, { saved: true, verified: true, vm_id_prefix: 'vm_9f2c' });
        }
        if (rest === '/login/restore' && method === 'POST') return ok(res, { restored: true });
        if (rest === '/test' && method === 'POST') return ok(res, { ...profileTestFixture, profile: name });
        if (rest === '/set-default' && method === 'POST') return ok(res, { default_profile: name });
        if (rest === '/rename' && method === 'POST') {
          return ok(res, { ...profileDetailFixture, name: String(json.to ?? name) });
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
        return ok(res, { preview: '[Interface]\nAddress = 10.2.0.2/32\n# secrets redacted' });
      }
      const endpointMatch = path.match(/^\/endpoints\/([^/]+)$/);
      if (endpointMatch) {
        if (method === 'GET') return ok(res, endpointsFixture[0]);
        if (method === 'DELETE') return ok(res, { deleted: true });
      }
      if (method === 'GET' && path === '/config') return ok(res, configFixture);
      if (method === 'PUT' && path === '/config') return ok(res, { sha256: 'CASTCTL_MOCK_FIXTURE' });
      if (method === 'POST' && path === '/config/validate') return ok(res, { valid: true, errors: [] });
      if (method === 'GET' && path === '/dns') return ok(res, dnsFixture);
      if (method === 'PUT' && path === '/dns') return ok(res, {});
      if (method === 'GET' && path === '/settings/telegram') return ok(res, telegramFixture);
      if (method === 'PUT' && path === '/settings/telegram') return ok(res, telegramFixture);
      if (method === 'GET' && path === '/logs') {
        return ok(res, { entries: logsFixture, next_cursor: null, more: false });
      }
      if (method === 'DELETE' && path === '/logs') return ok(res, { cleared: true });
      next();
    });
  });
}
