import { beforeEach, describe, expect, it } from 'vitest';
import {
  handleGetConfig,
  handleGetDns,
  handlePutConfig,
  handlePutDns,
  handleValidateConfig,
  resetConfigStore,
  snapshotLegacyProfileEntry,
} from '../dev-mocks/configStore';
import {
  configFixture,
  dnsFixture,
  endpointsFixture,
  legacyProfileEntryFixture,
  logsFixture,
  outboundsFixture,
  profileDetailFixture,
  sha256Hex,
  storedConfigDocument,
} from '../dev-mocks/fixtures';
import { appendLiveLogEntries } from '../dev-mocks/liveLogs';
import { ENDPOINT_IMPORT_PREVIEW } from '../dev-mocks/mockServer';
import { REDACTED_SENTINEL, redactValue } from '../dev-mocks/redact';

/**
 * Mock-handler tests (§E.4 #7, #11, #13, #14 + D1/D3 pins).
 * All secret examples use FAKE values. No real secret appears here.
 */

beforeEach(() => {
  resetConfigStore();
});

function currentConfig(): { content: string; sha256: string } {
  return handleGetConfig();
}

describe('hash guard (R8 order, §d)', () => {
  it('sha256Hex matches the known SHA-256 answer', () => {
    expect(sha256Hex('abc')).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    expect(sha256Hex('')).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });

  it('initial served state agrees with the static fixtures', () => {
    expect(currentConfig().content).toBe(configFixture.content);
    expect(currentConfig().sha256).toBe(configFixture.sha256);
    expect(handleGetDns().sha256).toBe(configFixture.sha256);
    expect(handleGetDns().dns).toEqual(dnsFixture.dns);
    expect(currentConfig().sha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it('stale base_sha256 -> 409 config_changed, no write', () => {
    const before = currentConfig();
    const edited = JSON.parse(before.content) as Record<string, unknown>;
    edited.default_profile = 'work';
    const result = handlePutConfig({
      content: JSON.stringify(edited),
      base_sha256: '0'.repeat(64),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.status).toBe(409);
      expect(result.error.type).toBe('config_changed');
      expect(result.error.message).not.toContain('FAKE');
    }
    expect(currentConfig()).toEqual(before);
  });

  it('current hash -> write; returned hash is the next read hash', () => {
    const before = currentConfig();
    const edited = JSON.parse(before.content) as Record<string, unknown>;
    edited.default_profile = 'work';
    const result = handlePutConfig({ content: JSON.stringify(edited), base_sha256: before.sha256 });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.data.sha256).toMatch(/^[0-9a-f]{64}$/);
      expect(result.data.sha256).not.toBe(before.sha256);
      expect(currentConfig().sha256).toBe(result.data.sha256);
      expect((JSON.parse(currentConfig().content) as Record<string, unknown>).default_profile).toBe('work');
    }
  });

  it('a secret-only stored change changes the hash while the redacted view is identical', () => {
    const before = currentConfig();
    // Re-enter the trojan password as a DIFFERENT literal value.
    const edited = JSON.parse(before.content) as Record<string, unknown>;
    const outbounds = edited.outbounds as Record<string, unknown>[];
    const trojan = outbounds.find((o) => o.tag === 'trojan-1') as Record<string, unknown>;
    trojan.password = 'FAKE-SECRET-ROTATED-PW';
    const result = handlePutConfig({ content: JSON.stringify(edited), base_sha256: before.sha256 });
    expect(result.ok).toBe(true);
    const after = currentConfig();
    expect(after.sha256).not.toBe(before.sha256);
    expect(after.content).toBe(before.content);
  });
});

describe('new-sentinel reject through the handler (R2, C9)', () => {
  it('400 validation_failed, file untouched, error names the path only', () => {
    const before = currentConfig();
    const edited = JSON.parse(before.content) as Record<string, unknown>;
    const outbounds = edited.outbounds as Record<string, unknown>[];
    outbounds.push({ tag: 'new-1', type: 'trojan', server: 'example.com', password: REDACTED_SENTINEL });
    const result = handlePutConfig({ content: JSON.stringify(edited), base_sha256: before.sha256 });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.status).toBe(400);
      expect(result.error.type).toBe('validation_failed');
      expect(result.error.message).toContain('outbounds');
      expect(result.error.message).not.toContain('FAKE');
      expect(result.error.message).not.toContain(REDACTED_SENTINEL);
    }
    expect(currentConfig()).toEqual(before);
  });

  it('error bodies never echo a submitted secret value', () => {
    const before = currentConfig();
    const edited = JSON.parse(before.content) as Record<string, unknown>;
    (edited as Record<string, unknown>).outbounds = [
      ...((edited.outbounds as unknown[]) ?? []),
      { tag: 'new-2', type: 'trojan', password: 'FAKE-SECRET-ATTEMPTED' },
    ];
    // Force a rejection elsewhere: a second new outbound with a sentinel.
    const outbounds = edited.outbounds as Record<string, unknown>[];
    outbounds.push({ tag: 'new-3', type: 'trojan', password: REDACTED_SENTINEL });
    const result = handlePutConfig({ content: JSON.stringify(edited), base_sha256: before.sha256 });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.message).not.toContain('FAKE-SECRET-ATTEMPTED');
    }
    const validated = handleValidateConfig({ content: 'not json{' });
    expect(validated.valid).toBe(false);
    expect(validated.errors.join(' ')).not.toContain('FAKE');
  });
});

describe('structural validation of the merged document (R8)', () => {
  it('rejects invalid JSON with a generic message', () => {
    const before = currentConfig();
    const result = handlePutConfig({ content: '{oops', base_sha256: before.sha256 });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.status).toBe(400);
      expect(result.error.message).toBe('Invalid JSON in submitted config');
    }
    expect(currentConfig()).toEqual(before);
  });

  it('rejects an unknown top-level key and a profile-level cookies key', () => {
    const before = currentConfig();
    const edited = JSON.parse(before.content) as Record<string, unknown>;
    edited.bogus_top = {};
    expect(handlePutConfig({ content: JSON.stringify(edited), base_sha256: before.sha256 }).ok).toBe(false);
    const edited2 = JSON.parse(before.content) as Record<string, unknown>;
    const profiles = edited2.profiles as Record<string, Record<string, unknown>>;
    profiles.muse01.cookies = 'FAKE-SECRET-INLINE-COOKIES';
    const result2 = handlePutConfig({ content: JSON.stringify(edited2), base_sha256: before.sha256 });
    expect(result2.ok).toBe(false);
    if (!result2.ok) expect(result2.error.message).toContain('profiles.muse01.cookies');
    expect(currentConfig()).toEqual(before);
  });

  it('validate endpoint dry-runs the merge without writing', () => {
    const before = currentConfig();
    const edited = JSON.parse(before.content) as Record<string, unknown>;
    edited.default_profile = 'work';
    expect(handleValidateConfig({ content: JSON.stringify(edited) })).toEqual({ valid: true, errors: [] });
    expect(currentConfig()).toEqual(before);
    const bad = JSON.parse(before.content) as Record<string, unknown>;
    (bad.outbounds as Record<string, unknown>[]).push({
      tag: 'new-9',
      type: 'trojan',
      password: REDACTED_SENTINEL,
    });
    const validated = handleValidateConfig({ content: JSON.stringify(bad) });
    expect(validated.valid).toBe(false);
    expect(validated.errors.join(' ')).toContain('outbounds');
    expect(currentConfig()).toEqual(before);
  });
});

describe('DNS editor contract (D1)', () => {
  it('GET /dns returns the redacted slice with the stored-file hash', () => {
    const dns = handleGetDns();
    expect(dns.sha256).toBe(currentConfig().sha256);
    expect(JSON.stringify(dns.dns)).not.toContain('FAKE-SECRET');
    expect(JSON.stringify(dns.dns)).not.toContain('FAKE-USERINFO');
    expect(dns.dns).toEqual(dnsFixture.dns);
  });

  it('PUT /dns enforces the 409 guard and merges against the stored dns section', () => {
    const before = currentConfig();
    const dns = handleGetDns();
    const editedDns = JSON.parse(JSON.stringify(dns.dns)) as Record<string, unknown>;
    editedDns.final = 'dns-userinfo';
    const stale = handlePutDns({ dns: editedDns, base_sha256: '0'.repeat(64) });
    expect(stale.ok).toBe(false);
    if (!stale.ok) expect(stale.error.status).toBe(409);
    expect(currentConfig()).toEqual(before);

    const result = handlePutDns({ dns: editedDns, base_sha256: dns.sha256 });
    expect(result.ok).toBe(true);
    const after = currentConfig();
    expect((JSON.parse(after.content) as Record<string, unknown>).dns).toEqual(
      expect.objectContaining({ final: 'dns-userinfo' }),
    );
    // The rest of the document is untouched by the DNS save.
    const beforeDoc = JSON.parse(before.content) as Record<string, unknown>;
    const afterDoc = JSON.parse(after.content) as Record<string, unknown>;
    expect(afterDoc.profiles).toEqual(beforeDoc.profiles);
    expect(afterDoc.outbounds).toEqual(beforeDoc.outbounds);
    expect(afterDoc.endpoints).toEqual(beforeDoc.endpoints);
  });

  it('PUT /dns keeps a stored userinfo URL when the submitted slice shows the sentinel form', () => {
    const dns = handleGetDns();
    const editedDns = JSON.parse(JSON.stringify(dns.dns)) as Record<string, unknown>;
    const servers = editedDns.servers as Record<string, unknown>[];
    const userinfoServer = servers.find((s) => s.tag === 'dns-userinfo') as Record<string, unknown>;
    userinfoServer.address = 'https://<redacted>@dns.example.org/dns-query';
    const result = handlePutDns({ dns: editedDns, base_sha256: dns.sha256 });
    expect(result.ok).toBe(true);
    // The stored userinfo is restored, the edited host applies.
    const afterDns = handleGetDns().dns as Record<string, unknown>;
    const afterServers = afterDns.servers as Record<string, unknown>[];
    const afterServer = afterServers.find((s) => s.tag === 'dns-userinfo') as Record<string, unknown>;
    expect(afterServer.address).toBe('https://<redacted>@dns.example.org/dns-query');
  });

  it('PUT /dns rejects a new sentinel in the dns section (400, file untouched)', () => {
    const before = currentConfig();
    const dns = handleGetDns();
    const editedDns = JSON.parse(JSON.stringify(dns.dns)) as Record<string, unknown>;
    (editedDns.servers as unknown[]).push({ tag: 'dns-new', password: REDACTED_SENTINEL });
    const result = handlePutDns({ dns: editedDns, base_sha256: dns.sha256 });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.status).toBe(400);
      expect(result.error.type).toBe('validation_failed');
    }
    expect(currentConfig()).toEqual(before);
  });
});

describe('fixture coverage: every surveyed shape, all redacted (§E.4 #13)', () => {
  it('the served config view redacts every secret path and keeps every survivor', () => {
    const served = JSON.parse(configFixture.content) as Record<string, unknown>;
    expect(configFixture.content).not.toContain('FAKE-SECRET');
    expect(configFixture.content).not.toContain('FAKE-USERINFO');
    const sentinelPaths = [
      'profiles.muse01.vm_id',
      'profiles.muse01.node_id',
      'profiles.muse01.subscription_action_id',
      'profiles.muse01.outbound.password',
      'outbounds.0.password',
      'outbounds.2.password',
      'outbounds.3.uuid',
      'outbounds.4.uuid',
      'outbounds.4.tls.reality.public_key',
      'outbounds.4.tls.reality.short_id',
      'outbounds.5.password',
      'outbounds.6.password',
      'outbounds.6.obfs',
      'outbounds.7.uuid',
      'outbounds.7.password',
      'outbounds.8.password',
      'outbounds.9.password',
      'outbounds.10.private_key',
      'outbounds.10.private_key_passphrase',
      'outbounds.11.psk',
      'outbounds.11.userkey',
      'outbounds.12.password',
      'outbounds.12.extra_headers.Authorization',
      'outbounds.13.client_key_password',
      'outbounds.13.mca_key',
      'outbounds.13.cookie',
      'outbounds.13.secret',
      'outbounds.14.static_key',
      'outbounds.14.client_key',
      'outbounds.15.mesh_psk',
      'outbounds.16.tls.client_key',
      'outbounds.16.tls.certificate',
      'outbounds.16.tls.acme.dns01_challenge.api_token',
      'outbounds.16.tls.acme.external_account.mac_key',
      'outbounds.16.tls.certificate_provider.account_key',
      'outbounds.16.users.0.password',
      'outbounds.16.headers.Authorization',
      'endpoints.0.private_key',
      'endpoints.0.peers.0.public_key',
      'endpoints.0.peers.0.pre_shared_key',
    ];
    // NOTE: array indices are dot-path segments, resolved below.
    expect(served).toBeTruthy();
    // Resolve paths with numeric segments as array indices.
    const resolve = (path: string): unknown => {
      let node: unknown = served;
      for (const part of path.split('.')) {
        node = (node as Record<string, unknown>)[part];
      }
      return node;
    };
    for (const path of sentinelPaths) {
      expect(resolve(path), path).toBe(REDACTED_SENTINEL);
    }
    // Header names survive; benign header values are redacted wholesale.
    expect(resolve('outbounds.12.extra_headers.X-Custom')).toBe(REDACTED_SENTINEL);
    expect(resolve('outbounds.16.headers.X-Keep-Name')).toBe(REDACTED_SENTINEL);
    // Survivors stay byte-identical.
    expect(configFixture.content).toContain('FAKE-USER');
    expect(configFixture.content).toContain('FAKE-KEY-ID');
    expect(configFixture.content).toContain('FAKE-ACCESS-KEY-ID');
    // D2 boundary pins: query token and Bearer text display verbatim.
    expect(configFixture.content).toContain('FAKE-QUERY-TOKEN');
    expect(configFixture.content).toContain('FAKE-BEARER-TOKEN');
    // Userinfo scrub form.
    expect(configFixture.content).toContain('https://<redacted>@proxy.example.com:8080/path');
    // The stored document still holds the FAKE secrets (fixture intact).
    expect(JSON.stringify(storedConfigDocument)).toContain('FAKE-SECRET-SOCKS-PW');
    expect(JSON.stringify(storedConfigDocument)).toContain('FAKE-SECRET-WG-PRIVKEY');
  });
});

describe('surfaces (§E.4 #14, C3/C4/C6/C8/C9)', () => {
  it('profile entries (incl. legacy) serve redacted, with the path intact', () => {
    for (const entry of [profileDetailFixture.entry, legacyProfileEntryFixture]) {
      const served = JSON.stringify(redactValue(entry));
      expect(served).not.toContain('FAKE-SECRET');
      expect(served).toContain('cookies.txt');
    }
    const servedEntry = redactValue(profileDetailFixture.entry) as Record<string, unknown>;
    const outbound = servedEntry.outbound as Record<string, unknown>;
    expect(outbound.password).toBe(REDACTED_SENTINEL);
    expect(servedEntry.cookies_file).toBe('~/.config/castctl/profiles/muse01/cookies.txt');
  });

  it('outbound/endpoint summaries and the import preview contain no secret values', () => {
    expect(JSON.stringify(outboundsFixture)).not.toContain('FAKE-SECRET');
    expect(JSON.stringify(endpointsFixture)).not.toContain('FAKE-SECRET');
    expect(ENDPOINT_IMPORT_PREVIEW).toContain('redacted');
    expect(ENDPOINT_IMPORT_PREVIEW).not.toContain('FAKE');
    expect(ENDPOINT_IMPORT_PREVIEW).not.toContain('PrivateKey');
  });

  it('log fixtures and live-log templates contain no secret values', () => {
    expect(JSON.stringify(logsFixture)).not.toContain('FAKE');
    const grown = appendLiveLogEntries(logsFixture, 30, 0);
    expect(JSON.stringify(grown)).not.toContain('FAKE');
    expect(grown.length).toBe(logsFixture.length + 30);
  });
});

describe('legacy entry untouched by config saves (D3)', () => {
  it('config and DNS saves never mutate the stored legacy profile entry', () => {
    const beforeLegacy = snapshotLegacyProfileEntry();
    const beforeFixture = JSON.parse(JSON.stringify(legacyProfileEntryFixture)) as unknown;
    expect(JSON.stringify(beforeLegacy)).toContain('FAKE-SECRET-LEGACY-VM-ID');

    const before = currentConfig();
    const edited = JSON.parse(before.content) as Record<string, unknown>;
    edited.default_profile = 'work';
    expect(handlePutConfig({ content: JSON.stringify(edited), base_sha256: before.sha256 }).ok).toBe(true);
    const dns = handleGetDns();
    const editedDns = JSON.parse(JSON.stringify(dns.dns)) as Record<string, unknown>;
    editedDns.final = 'dns-userinfo';
    expect(handlePutDns({ dns: editedDns, base_sha256: dns.sha256 }).ok).toBe(true);

    expect(snapshotLegacyProfileEntry()).toEqual(beforeLegacy);
    expect(legacyProfileEntryFixture).toEqual(beforeFixture);
    expect(JSON.stringify(legacyProfileEntryFixture)).toContain('FAKE-SECRET-LEGACY-VM-ID');
  });
});
