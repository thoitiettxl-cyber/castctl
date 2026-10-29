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
    const result = await callMockApi({ method: 'GET', url: '/api/v1/status' });
    expect(result.status).toBe(200);
  });
});
