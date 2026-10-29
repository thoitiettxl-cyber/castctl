/** Fetch wrapper for the castctl /api/v1 management API (design §4.3).
 *
 * Same-origin only: no apiBase input, no hard-coded host. Bearer token from
 * sessionStorage. Envelope: success `{data}` / error `{error: {type,
 * message}}`. 401 emits an `unauthorized` event (store listens, logs out).
 * AbortError is re-thrown as a plain Error('Request aborted') so callers
 * never surface AbortError text.
 */

import {
  MANAGEMENT_API_PREFIX,
  REQUEST_TIMEOUT_MS,
  SESSION_KEY_TOKEN,
} from '@/utils/constants';
import type { ApiError, ApiErrorEnvelope, ApiEnvelope } from '@/types';

export const getAuthToken = (): string | null => {
  try {
    return sessionStorage.getItem(SESSION_KEY_TOKEN);
  } catch {
    return null;
  }
};

export const setAuthToken = (token: string) => {
  sessionStorage.setItem(SESSION_KEY_TOKEN, token);
};

export const clearAuthToken = () => {
  try {
    sessionStorage.removeItem(SESSION_KEY_TOKEN);
  } catch {
    // sessionStorage unavailable (private mode) — nothing to clear.
  }
};

export const getAuthHeaders = (): Record<string, string> => {
  const token = getAuthToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
};

function buildApiError(status: number, body: unknown, fallback: string): ApiError {
  const error = new Error(fallback) as ApiError;
  error.status = status;
  if (body && typeof body === 'object' && 'error' in body) {
    const envelope = body as ApiErrorEnvelope;
    if (envelope.error?.type) {
      error.apiCode = envelope.error.type;
      error.code = envelope.error.type;
    }
    if (envelope.error?.message) {
      error.message = envelope.error.message;
    }
  }
  error.data = body;
  return error;
}

export async function apiRequest<T>(
  path: string,
  options: RequestInit & { timeout?: number; signal?: AbortSignal } = {},
): Promise<T> {
  const { timeout = REQUEST_TIMEOUT_MS, ...init } = options;
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);
  const signal = options.signal ?? controller.signal;

  try {
    const response = await fetch(`${MANAGEMENT_API_PREFIX}${path}`, {
      ...init,
      headers: {
        'Content-Type': 'application/json',
        ...getAuthHeaders(),
        ...(init.headers || {}),
      },
      signal,
    });

    if (response.status === 401) {
      window.dispatchEvent(new CustomEvent('unauthorized'));
      throw buildApiError(401, null, 'Unauthorized');
    }

    const body = await response.json().catch(() => null);

    if (!response.ok) {
      throw buildApiError(response.status, body, `Request failed with status ${response.status}`);
    }

    return (body as ApiEnvelope<T>).data;
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') {
      // eslint-disable-next-line preserve-caught-error -- ES2020 lib has no Error cause option; an abort carries no useful cause.
      throw new Error('Request aborted');
    }
    throw error;
  } finally {
    clearTimeout(timeoutId);
  }
}

// Verb helpers.
export const apiGet = <T>(path: string, signal?: AbortSignal): Promise<T> =>
  apiRequest<T>(path, { method: 'GET', signal });

export const apiPost = <T>(path: string, body?: unknown, signal?: AbortSignal): Promise<T> =>
  apiRequest<T>(path, { method: 'POST', body: JSON.stringify(body ?? {}), signal });

export const apiPut = <T>(path: string, body: unknown, signal?: AbortSignal): Promise<T> =>
  apiRequest<T>(path, { method: 'PUT', body: JSON.stringify(body), signal });

export const apiDelete = <T>(
  path: string,
  body?: unknown,
  signal?: AbortSignal,
): Promise<T> =>
  apiRequest<T>(path, {
    method: 'DELETE',
    body: body === undefined ? undefined : JSON.stringify(body),
    signal,
  });

export const apiPatch = <T>(path: string, body: unknown, signal?: AbortSignal): Promise<T> =>
  apiRequest<T>(path, { method: 'PATCH', body: JSON.stringify(body), signal });
