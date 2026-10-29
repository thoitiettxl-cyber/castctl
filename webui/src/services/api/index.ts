/** Domain API modules — frozen signatures for the page writers.
 * Every path/method matches design §4.3. Do not add paths without updating
 * the design table and the mock server together.
 *
 * NOTE: there is NO global auto-approve endpoint — per-profile
 * auto_approve/auto_allow_once live on PATCH /profiles/{name} (design §2).
 * Settings must not invent a /settings/defaults endpoint.
 */

import { apiDelete, apiGet, apiPatch, apiPost, apiPut } from './client';
import type {
  ConfigContent,
  LoginImportResult,
  LoginStatus,
  LogsPage,
  OutboundSummary,
  EndpointSummary,
  ProfileDetail,
  ProfileSummary,
  ProfileTestPhase,
  ProfileTestResult,
  StatusInfo,
  TelegramSettings,
} from '@/types';

export interface OutboundTestResult {
  tag: string;
  phases: ProfileTestPhase[];
  egress_ip?: string;
  overall: string;
}

export interface EndpointImportPreview {
  preview: string;
}

export const statusApi = {
  get: (signal?: AbortSignal) => apiGet<StatusInfo>('/status', signal),
};

export const profilesApi = {
  list: (signal?: AbortSignal) => apiGet<ProfileSummary[]>('/profiles', signal),
  get: (name: string, signal?: AbortSignal) =>
    apiGet<ProfileDetail>(`/profiles/${encodeURIComponent(name)}`, signal),
  create: (body: { name: string; cookies_file?: string; outbound?: string; set_default?: boolean }) =>
    apiPost<ProfileSummary>('/profiles', body),
  patch: (
    name: string,
    body: { auto_approve?: boolean; auto_allow_once?: boolean; outbound?: string; fingerprint?: string },
  ) => apiPatch<ProfileDetail>(`/profiles/${encodeURIComponent(name)}`, body),
  rename: (name: string, body: { to: string }) =>
    apiPost<ProfileSummary>(`/profiles/${encodeURIComponent(name)}/rename`, body),
  remove: (name: string) =>
    apiDelete<{ deleted: boolean }>(`/profiles/${encodeURIComponent(name)}`, {
      confirm: true,
      name,
    }),
  setDefault: (name: string) =>
    apiPost<{ default_profile: string }>(`/profiles/${encodeURIComponent(name)}/set-default`),
  test: (name: string) =>
    apiPost<ProfileTestResult>(`/profiles/${encodeURIComponent(name)}/test`, {}),
  loginStatus: (name: string, signal?: AbortSignal) =>
    apiGet<LoginStatus>(`/profiles/${encodeURIComponent(name)}/login/status`, signal),
  loginImport: (name: string, body: { format: 'text' | 'file'; content: string }) =>
    apiPost<LoginImportResult>(`/profiles/${encodeURIComponent(name)}/login/import`, body),
  loginRestore: (name: string) =>
    apiPost<{ restored: boolean }>(`/profiles/${encodeURIComponent(name)}/login/restore`, {}),
};

export const outboundsApi = {
  list: (signal?: AbortSignal) => apiGet<OutboundSummary[]>('/outbounds', signal),
  get: (tag: string, signal?: AbortSignal) =>
    apiGet<Record<string, unknown>>(`/outbounds/${encodeURIComponent(tag)}`, signal),
  create: (body: { outbound: Record<string, unknown> }) =>
    apiPost<OutboundSummary>('/outbounds', body),
  patch: (tag: string, body: { outbound: Record<string, unknown> }) =>
    apiPatch<OutboundSummary>(`/outbounds/${encodeURIComponent(tag)}`, body),
  remove: (tag: string) => apiDelete<{ deleted: boolean }>(`/outbounds/${encodeURIComponent(tag)}`),
  validate: (body: { outbound: Record<string, unknown> }) =>
    apiPost<{ valid: boolean; errors: string[] }>('/outbounds/validate', body),
  test: (tag: string) =>
    apiPost<OutboundTestResult>(`/outbounds/${encodeURIComponent(tag)}/test`, {}),
};

export const endpointsApi = {
  list: (signal?: AbortSignal) => apiGet<EndpointSummary[]>('/endpoints', signal),
  get: (tag: string, signal?: AbortSignal) =>
    apiGet<Record<string, unknown>>(`/endpoints/${encodeURIComponent(tag)}`, signal),
  create: (body: { endpoint: Record<string, unknown> }) =>
    apiPost<EndpointSummary>('/endpoints', body),
  patch: (tag: string, body: { endpoint: Record<string, unknown> }) =>
    apiPatch<EndpointSummary>(`/endpoints/${encodeURIComponent(tag)}`, body),
  remove: (tag: string) => apiDelete<{ deleted: boolean }>(`/endpoints/${encodeURIComponent(tag)}`),
  importPreview: (body: { tag: string; conf_text: string; save: boolean }) =>
    apiPost<EndpointImportPreview | EndpointSummary>('/endpoints/import', body),
};

export const configApi = {
  get: (signal?: AbortSignal) => apiGet<ConfigContent>('/config', signal),
  save: (body: { content: string; base_sha256: string }) =>
    apiPut<{ sha256: string }>('/config', body),
  validate: (body: { content: string }) =>
    apiPost<{ valid: boolean; errors: string[] }>('/config/validate', body),
};

export const dnsApi = {
  get: (signal?: AbortSignal) => apiGet<{ dns: Record<string, unknown> }>('/dns', signal),
  save: (body: { dns: Record<string, unknown> }) => apiPut<unknown>('/dns', body),
};

export const settingsApi = {
  getTelegram: (signal?: AbortSignal) => apiGet<TelegramSettings>('/settings/telegram', signal),
  saveTelegram: (body: Record<string, unknown>) =>
    apiPut<TelegramSettings>('/settings/telegram', body),
};

export const logsApi = {
  list: (params: { cursor?: string; limit?: number; level?: string }, signal?: AbortSignal) => {
    const qs = new URLSearchParams();
    if (params.cursor) qs.set('cursor', params.cursor);
    if (params.limit) qs.set('limit', String(params.limit));
    if (params.level) qs.set('level', params.level);
    const suffix = qs.toString() ? `?${qs}` : '';
    return apiGet<LogsPage>(`/logs${suffix}`, signal);
  },
  clear: () => apiDelete<{ cleared: boolean }>('/logs'),
};
