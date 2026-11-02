import { EventEmitter } from 'node:events';
import { describe, expect, it } from 'vitest';
import { registerMockApi } from '../dev-mocks/mockServer';

/**
 * Mock-server body robustness (F8.5, red-team R-H). The handler
 * wiring itself is exercised here through a fake Connect server
 * and fake req/res objects — no HTTP server is started. All secret
 * examples use FAKE values. No real secret appears here.
 */

type Middleware = (req: unknown, res: unknown, next: () => void) => void;

let captured: Middleware | null = null;
registerMockApi({
  use: (_path: string, fn: Middleware) => {
    captured = fn;
  },
} as unknown as Parameters<typeof registerMockApi>[0]);

interface CallResult {
  status: number;
  body: string;
}

function callMockApi(options: {
  method: string;
  url: string;
  headers?: Record<string, string>;
  bodyText?: string;
}): Promise<CallResult> {
  const handler = captured;
  if (handler === null) throw new Error('mock middleware was not registered');
  return new Promise<CallResult>((resolve) => {
    const req = Object.assign(new EventEmitter(), {
      url: options.url,
      method: options.method,
      headers: options.headers ?? {},
    });
    let status = 0;
    let body = '';
    const res = {
      statusCode: 0,
      setHeader: (_name: string, _value: string) => {},
      end: (chunk: string) => {
        status = res.statusCode;
        body = chunk;
        resolve({ status, body });
      },
    };
    handler(req, res, () => {
      resolve({ status: 0, body: 'next() called' });
    });
    if (options.bodyText !== undefined) {
      req.emit('data', Buffer.from(options.bodyText));
    }
    req.emit('end');
  });
}

describe('malformed request bodies (R-H)', () => {
  it('returns 400 validation_failed without echoing the body and without throwing', async () => {
    const planted = 'FAKE-SECRET-PLANTED-VALUE';
    const result = await callMockApi({
      method: 'PUT',
      url: '/api/v1/config',
      headers: { authorization: 'Bearer FAKE-MANAGEMENT-TOKEN' },
      bodyText: `{not json, "password": "${planted}"`,
    });
    expect(result.status).toBe(400);
    const parsed = JSON.parse(result.body) as { error: { type: string; message: string } };
    expect(parsed.error.type).toBe('validation_failed');
    expect(result.body).not.toContain(planted);
    expect(result.body).not.toContain('not json');
  });

  it('still routes a valid JSON body', async () => {
    const result = await callMockApi({
      method: 'POST',
      url: '/api/v1/profiles',
      headers: { authorization: 'Bearer FAKE-MANAGEMENT-TOKEN' },
      bodyText: JSON.stringify({ name: 'probe-profile' }),
    });
    expect(result.status).toBe(200);
    expect(JSON.parse(result.body)).toEqual({ data: expect.objectContaining({ name: 'probe-profile' }) });
  });

  it('still routes a bodyless request', async () => {
    const result = await callMockApi({
      method: 'GET',
      url: '/api/v1/status',
      headers: { authorization: 'Bearer x' },
    });
    expect(result.status).toBe(200);
  });

  it('requires auth on /status like every other route (Go parity)', async () => {
    const result = await callMockApi({ method: 'GET', url: '/api/v1/status' });
    expect(result.status).toBe(401);
  });
});

describe('keeper + screencast mocks (Go parity)', () => {
  const auth = { authorization: 'Bearer <redacted>' };
  it('serves keeper entries', async () => {
    const result = await callMockApi({ method: 'GET', url: '/api/v1/keeper', headers: auth });
    expect(result.status).toBe(200);
    const parsed = JSON.parse(result.body) as { data: Array<{ tag: string }> };
    expect(parsed.data[0].tag).toBe('k1');
  });
  it('reports screencast unavailable in mock mode', async () => {
    const result = await callMockApi({
      method: 'GET',
      url: '/api/v1/screencast/status?profile=muse01',
      headers: auth,
    });
    expect(result.status).toBe(200);
    const parsed = JSON.parse(result.body) as { data: { available: boolean; profile: string } };
    expect(parsed.data.available).toBe(false);
    expect(parsed.data.profile).toBe('muse01');
  });
  it('refuses screencast start in mock mode', async () => {
    const result = await callMockApi({
      method: 'POST',
      url: '/api/v1/screencast/muse01/start',
      headers: auth,
      bodyText: '{}',
    });
    expect(result.status).toBe(501);
  });
  it('refuses log clearing with 405 like Go', async () => {
    const result = await callMockApi({ method: 'DELETE', url: '/api/v1/logs', headers: auth });
    expect(result.status).toBe(405);
  });
});

describe('chats + plugins + section-editor mocks (management upgrade)', () => {
  const auth = { authorization: 'Bearer <redacted>' };
  it('serves the idle timeout on /status', async () => {
    const result = await callMockApi({ method: 'GET', url: '/api/v1/status', headers: auth });
    const parsed = JSON.parse(result.body) as { data: { session_idle_timeout_seconds: number } };
    expect(parsed.data.session_idle_timeout_seconds).toBe(43200);
  });
  it('reports plugins unavailable with an empty list', async () => {
    const result = await callMockApi({ method: 'GET', url: '/api/v1/plugins', headers: auth });
    expect(result.status).toBe(200);
    const parsed = JSON.parse(result.body) as { data: { available: boolean; plugins: unknown[] } };
    expect(parsed.data.available).toBe(false);
    expect(parsed.data.plugins).toEqual([]);
  });
  it('serves chat sessions without a main-chat row', async () => {
    const result = await callMockApi({ method: 'GET', url: '/api/v1/chats/muse01', headers: auth });
    const parsed = JSON.parse(result.body) as { data: Array<{ id: string }> };
    expect(parsed.data.map((s) => s.id)).toEqual(['s-1', 's-2']);
  });
  it('serves chat history honouring limit', async () => {
    const result = await callMockApi({
      method: 'GET',
      url: '/api/v1/chats/muse01/main?limit=1',
      headers: auth,
    });
    const parsed = JSON.parse(result.body) as { data: Array<{ seq: number }> };
    expect(parsed.data).toHaveLength(1);
    expect(parsed.data[0].seq).toBe(1);
  });
  it('answers send with a completed job (mock divergence: Go polls)', async () => {
    const result = await callMockApi({
      method: 'POST',
      url: '/api/v1/chats/muse01/main/send',
      headers: auth,
      bodyText: JSON.stringify({ text: 'hi' }),
    });
    expect(result.status).toBe(200);
    const parsed = JSON.parse(result.body) as { data: { status: string; result: { outcome: string } } };
    expect(parsed.data.status).toBe('done');
    expect(parsed.data.result.outcome).toBe('done');
  });
  it('serves a job poll by id', async () => {
    const result = await callMockApi({ method: 'GET', url: '/api/v1/chats/jobs/job-9', headers: auth });
    const parsed = JSON.parse(result.body) as { data: { job_id: string } };
    expect(parsed.data.job_id).toBe('job-9');
  });
  it('serves keeper settings with entries + hash', async () => {
    const result = await callMockApi({ method: 'GET', url: '/api/v1/settings/keeper', headers: auth });
    const parsed = JSON.parse(result.body) as {
      data: { entries: Array<{ tag: string }>; sha256: string };
    };
    expect(parsed.data.entries[0].tag).toBe('k1');
    expect(parsed.data.sha256).toMatch(/^[0-9a-f]{64}$/);
  });
  it('serves webui settings write-only (token_set + masked, no token value)', async () => {
    const result = await callMockApi({ method: 'GET', url: '/api/v1/settings/webui', headers: auth });
    const parsed = JSON.parse(result.body) as {
      data: { token_set: boolean; masked: string; session_idle_timeout: string };
    };
    expect(parsed.data.token_set).toBe(true);
    expect(parsed.data.masked).toBe('***');
    expect(parsed.data.session_idle_timeout).toBe('12h');
    expect(result.body).not.toContain('token":');
  });
});

/**
 * Settings shape contract (D-WEBUI-GET, fix loop 3). The dev mock
 * once returned the flat webui shape while the real server wrapped
 * it under a nested "settings" key, so frontend tests passed and
 * the real editor failed to load. These runtime field assertions
 * (not just tsc) pin the mock's served payloads to the same
 * shared field list the Go contract test pins server-side
 * (internal/webui/settings_shape_test.go):
 *
 *   GET /dns               -> {dns: object, sha256}
 *                             (inline type, src/services/api/index.ts:129)
 *   GET /settings/telegram -> TelegramSettings (src/types/api.ts:121)
 *   GET /settings/keeper   -> KeeperSettings (src/types/api.ts:265)
 *   GET /settings/webui    -> WebUISettings (src/types/api.ts:273)
 *
 * The mock carries exactly the TS-declared fields. The server
 * additionally emits the sanctioned *_seconds additive fields
 * (webui session_idle_timeout_seconds + window_seconds, keeper
 * entry interval_seconds); those are asserted Go-side only.
 * A field added to one side without the other fails at least
 * one of the two checks.
 */
describe('settings shape contract (dev mock matches TS types)', () => {
  const auth = { authorization: 'Bearer <redacted>' };

  async function getSettingsData(url: string): Promise<Record<string, unknown>> {
    const result = await callMockApi({ method: 'GET', url, headers: auth });
    expect(result.status).toBe(200);
    const parsed = JSON.parse(result.body) as { data: Record<string, unknown> };
    expect(parsed.data).toBeTypeOf('object');
    return parsed.data;
  }

  it('GET /dns carries dns + sha256', async () => {
    const data = await getSettingsData('/api/v1/dns');
    expect(Object.keys(data).sort()).toEqual(['dns', 'sha256']);
    expect(data.dns).toBeTypeOf('object');
    expect(data.sha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it('GET /settings/telegram matches TelegramSettings', async () => {
    const data = await getSettingsData('/api/v1/settings/telegram');
    expect(Object.keys(data).sort()).toEqual([
      'allowed_user_ids',
      'auto_allow_once',
      'auto_approve',
      'configured',
      'masked',
      'profile',
    ]);
    expect(data.configured).toBe(true);
    expect(data.masked).toBe('***');
    expect(data.profile).toBe('muse01');
    expect(data.allowed_user_ids).toEqual([1403530267]);
    expect(data.auto_approve).toBe(false);
    expect(data.auto_allow_once).toBe(false);
  });

  it('GET /settings/keeper matches KeeperSettings', async () => {
    const data = await getSettingsData('/api/v1/settings/keeper');
    expect(Object.keys(data).sort()).toEqual(['entries', 'sha256']);
    expect(data.sha256).toMatch(/^[0-9a-f]{64}$/);
    const entries = data.entries as Array<Record<string, unknown>>;
    expect(entries).toHaveLength(1);
    expect(Object.keys(entries[0]).sort()).toEqual(['browser', 'interval', 'notify', 'profile', 'tag']);
    expect(entries[0].tag).toBe('k1');
    expect(entries[0].profile).toBe('muse01');
    expect(entries[0].browser).toBe('http://127.0.0.1:9226');
    expect(entries[0].interval).toBe('24h');
    expect(entries[0].notify).toBe('telegram');
  });

  it('GET /settings/webui matches WebUISettings, flat (no settings key)', async () => {
    const data = await getSettingsData('/api/v1/settings/webui');
    expect(Object.keys(data).sort()).toEqual([
      'listen',
      'login_rate_limit',
      'masked',
      'session_idle_timeout',
      'sha256',
      'token_set',
      'ui_dir',
    ]);
    expect(data).not.toHaveProperty('settings');
    expect(data.listen).toBe('127.0.0.1:8317');
    expect(data.ui_dir).toBe('');
    expect(data.session_idle_timeout).toBe('12h');
    expect(data.token_set).toBe(true);
    expect(data.masked).toBe('***');
    expect(data.sha256).toMatch(/^[0-9a-f]{64}$/);
    const limit = data.login_rate_limit as Record<string, unknown>;
    expect(Object.keys(limit).sort()).toEqual(['attempts', 'window']);
    expect(limit.attempts).toBe(5);
    expect(limit.window).toBe('5m');
  });
});
