import { describe, expect, it } from 'vitest';
import {
  REDACTED_SENTINEL,
  SentinelRejectionError,
  isSecretKey,
  mergeConfig,
  redactURLUserinfo,
  redactValue,
} from '../dev-mocks/redact';
import { lineDiff } from '../src/utils/diff';

/**
 * RED-FIRST core (TDD): key parity + keep-on-save. Written before the
 * implementation in ../dev-mocks/redact.ts existed; the first run must
 * FAIL (module missing). See ~/workspace/tmp/pr2-hold-fixes/red-first.log.
 *
 * All secret examples use FAKE values. No real secret appears here.
 */

describe('redaction key parity (Go 37-key set, verbatim)', () => {
  it('redacts all 37 Go secret keys, whatever the value type', () => {
    const keys = [
      'access_key_secret',
      'account_key',
      'api_token',
      'auth',
      'auth_key',
      'auth_str',
      'authorization',
      'certificate',
      'client_certificate',
      'client_key',
      'client_key_password',
      'cookie',
      'key',
      'mac_key',
      'mca_key',
      'mca_key_password',
      'mesh_psk',
      'node_id',
      'obfs',
      'origin_ca_key',
      'password',
      'pre_shared_key',
      'private_key',
      'private_key_passphrase',
      'psk',
      'public_key',
      'secret',
      'security_token',
      'short_id',
      'static_key',
      'submission_key',
      'subscription_action_id',
      'token',
      'userkey',
      'uuid',
      'vm_id',
      'zone_token',
    ];
    expect(keys).toHaveLength(37);
    for (const key of keys) {
      expect(isSecretKey(key)).toBe(true);
      expect(redactValue({ [key]: 'FAKE-SECRET-VALUE' })).toEqual({ [key]: REDACTED_SENTINEL });
    }
    // Whole-value replacement whatever the JSON type, incl. nil -> sentinel.
    expect(redactValue({ password: { nested: 'FAKE-SECRET-VALUE' } })).toEqual({
      password: REDACTED_SENTINEL,
    });
    expect(redactValue({ password: ['FAKE-SECRET-VALUE'] })).toEqual({
      password: REDACTED_SENTINEL,
    });
    expect(redactValue({ password: 42 })).toEqual({ password: REDACTED_SENTINEL });
    expect(redactValue({ password: null })).toEqual({ password: REDACTED_SENTINEL });
    expect(REDACTED_SENTINEL).toBe('<redacted>');
  });

  it('does not match near-miss keys; survivors stay byte-identical', () => {
    for (const key of [
      'my_token',
      'tokenize',
      'password2',
      'vmid',
      'vmId',
      'auth-token',
      'obfs_password',
      'api_token2',
      'my_api_token',
      'client_key_path',
      'key_id',
      'access_key_id',
      'username',
      'user',
      '',
    ]) {
      expect(isSecretKey(key)).toBe(false);
    }
    expect(
      redactValue({ username: 'FAKE-USER', key_id: 'FAKE-KEY-ID', password2: 'FAKE-SECRET-VALUE' }),
    ).toEqual({ username: 'FAKE-USER', key_id: 'FAKE-KEY-ID', password2: 'FAKE-SECRET-VALUE' });
  });

  it('matches case variants, never whitespace-padded keys', () => {
    expect(isSecretKey('Password')).toBe(true);
    expect(isSecretKey('PRIVATE_KEY')).toBe(true);
    expect(isSecretKey('Uuid')).toBe(true);
    expect(isSecretKey(' password ')).toBe(false);
    expect(redactValue({ Password: 'FAKE-SECRET-VALUE' })).toEqual({
      Password: REDACTED_SENTINEL,
    });
    expect(redactValue({ ' password ': 'FAKE-SECRET-VALUE' })).toEqual({
      ' password ': 'FAKE-SECRET-VALUE',
    });
  });
});

describe('keep-on-save merge (R1)', () => {
  it('restores the stored secret verbatim when the submitted value is the sentinel', () => {
    const stored = {
      profiles: { muse01: { vm_id: 'FAKE-SECRET-VM-ID' } },
      outbounds: [
        {
          tag: 'proxy-eu',
          type: 'trojan',
          server: 'example.com',
          password: 'FAKE-SECRET-PW',
        },
      ],
    };
    const submitted = {
      profiles: { muse01: { vm_id: REDACTED_SENTINEL } },
      outbounds: [
        {
          tag: 'proxy-eu',
          type: 'trojan',
          server: 'example.org',
          password: REDACTED_SENTINEL,
        },
      ],
    };
    const merged = mergeConfig(stored, submitted) as typeof stored;
    expect(merged.profiles.muse01.vm_id).toBe('FAKE-SECRET-VM-ID');
    expect(merged.outbounds[0].password).toBe('FAKE-SECRET-PW');
    // The unrelated edit survives; the sentinel never reaches the merged doc.
    expect(merged.outbounds[0].server).toBe('example.org');
    expect(JSON.stringify(merged)).not.toContain(REDACTED_SENTINEL);
  });

  it('keeps a whole secret subtree (obfs object, array-valued key) verbatim', () => {
    const stored = {
      outbounds: [
        {
          tag: 'hyst',
          type: 'hysteria2',
          password: 'FAKE-SECRET-PW',
          obfs: { type: 'salamander', password: 'FAKE-SECRET-OBFS' },
        },
      ],
      endpoints: [
        {
          tag: 'wg-home',
          type: 'wireguard',
          client_key: ['FAKE-SECRET-KEY-1', 'FAKE-SECRET-KEY-2'],
        },
      ],
    };
    const submitted = {
      outbounds: [{ tag: 'hyst', type: 'hysteria2', password: REDACTED_SENTINEL, obfs: REDACTED_SENTINEL }],
      endpoints: [{ tag: 'wg-home', type: 'wireguard', client_key: REDACTED_SENTINEL }],
    };
    const merged = mergeConfig(stored, submitted) as typeof stored;
    expect(merged.outbounds[0].obfs).toEqual({ type: 'salamander', password: 'FAKE-SECRET-OBFS' });
    expect(merged.endpoints[0].client_key).toEqual(['FAKE-SECRET-KEY-1', 'FAKE-SECRET-KEY-2']);
    expect(JSON.stringify(merged)).not.toContain(REDACTED_SENTINEL);
  });
});

describe('recursion, headers, userinfo (redactValue basics)', () => {
  it('redacts secrets nested 3 levels deep and inside arrays', () => {
    const value = {
      outbounds: [
        {
          tag: 'x',
          tls: { reality: { public_key: 'FAKE-SECRET-PUB', short_id: 'FAKE-SECRET-SHORT' } },
          users: [{ username: 'FAKE-USER', password: 'FAKE-SECRET-PW' }],
        },
      ],
    };
    expect(redactValue(value)).toEqual({
      outbounds: [
        {
          tag: 'x',
          tls: { reality: { public_key: REDACTED_SENTINEL, short_id: REDACTED_SENTINEL } },
          users: [{ username: 'FAKE-USER', password: REDACTED_SENTINEL }],
        },
      ],
    });
  });

  it('redacts every header-map value wholesale, whatever the header name', () => {
    expect(
      redactValue({ headers: { Authorization: 'FAKE-SECRET-HDR', 'X-Custom': 'benign' } }),
    ).toEqual({ headers: { Authorization: REDACTED_SENTINEL, 'X-Custom': REDACTED_SENTINEL } });
    expect(redactValue({ extra_headers: { 'X-A': 'FAKE-SECRET-HDR' } })).toEqual({
      extra_headers: { 'X-A': REDACTED_SENTINEL },
    });
    // custom_headers is NOT a header map (pinned Go behaviour).
    expect(redactValue({ custom_headers: { 'X-A': 'kept' } })).toEqual({
      custom_headers: { 'X-A': 'kept' },
    });
    // Nil header map stays nil.
    expect(redactValue({ headers: null })).toEqual({ headers: null });
  });

  it('scrubs URL userinfo in every string value (Go regex semantics)', () => {
    expect(redactURLUserinfo('https://FAKE-USERINFO-USER:FAKE-USERINFO-PASS@host.example/x')).toBe(
      'https://<redacted>@host.example/x',
    );
    expect(redactURLUserinfo('socks5://user:pass@host:1080')).toBe('socks5://<redacted>@host:1080');
    // Last @ before the first / ? # delimits the userinfo.
    expect(redactURLUserinfo('https://a@b@host.example/x')).toBe('https://<redacted>@host.example/x');
    // Plain email and userinfo-free URLs are untouched.
    expect(redactURLUserinfo('contact bob@example.com')).toBe('contact bob@example.com');
    expect(redactURLUserinfo('https://example.com/@user')).toBe('https://example.com/@user');
    expect(redactURLUserinfo('https://example.com/x')).toBe('https://example.com/x');
    expect(redactValue({ proxy_url: 'https://u:p@h.example/', note: 'bob@example.com' })).toEqual({
      proxy_url: 'https://<redacted>@h.example/',
      note: 'bob@example.com',
    });
  });
});

describe('new-sentinel reject, rename/move, array identity (R2-R4)', () => {
  it('rejects a sentinel in a new field, naming the path only', () => {
    const stored = { outbounds: [{ tag: 'a', type: 'trojan', server: 'example.com' }] };
    const submitted = {
      outbounds: [{ tag: 'a', type: 'trojan', server: 'example.com', password: REDACTED_SENTINEL }],
    };
    let caught: unknown;
    try {
      mergeConfig(stored, submitted);
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(SentinelRejectionError);
    expect((caught as SentinelRejectionError).path).toBe('outbounds[0].password');
    // The rejection carries the path only, never a value.
    expect((caught as Error).message).not.toContain('FAKE');
    expect(JSON.stringify(stored)).toBe(
      JSON.stringify({ outbounds: [{ tag: 'a', type: 'trojan', server: 'example.com' }] }),
    );
  });

  it('rejects a sentinel under a new header name, and a sentinel in a new array element', () => {
    expect(() =>
      mergeConfig(
        { outbounds: [{ tag: 'a', headers: { 'X-A': 'kept' } }] },
        { outbounds: [{ tag: 'a', headers: { 'X-A': 'kept', 'X-New': REDACTED_SENTINEL } }] },
      ),
    ).toThrow(SentinelRejectionError);
    expect(() =>
      mergeConfig({ outbounds: [] }, { outbounds: [{ tag: 'b', password: REDACTED_SENTINEL }] }),
    ).toThrow(SentinelRejectionError);
  });

  it('rejects rename/move of a secret field carrying the sentinel', () => {
    // Rename: old key deleted, new key with sentinel.
    expect(() =>
      mergeConfig(
        { password: 'FAKE-SECRET-PW' },
        { passwd: REDACTED_SENTINEL },
      ),
    ).toThrow(SentinelRejectionError);
    // Move: secret moved from outbounds[0] to outbounds[1] with sentinel.
    expect(() =>
      mergeConfig(
        {
          outbounds: [
            { tag: 'a', type: 'trojan', password: 'FAKE-SECRET-PW' },
            { tag: 'b', type: 'trojan', server: 'example.com' },
          ],
        },
        {
          outbounds: [
            { tag: 'a', type: 'trojan' },
            { tag: 'b', type: 'trojan', server: 'example.com', password: REDACTED_SENTINEL },
          ],
        },
      ),
    ).toThrow(SentinelRejectionError);
  });

  it('rejects swapping two outbounds whose passwords are sentinels (R4 identity guard)', () => {
    const stored = {
      outbounds: [
        { tag: 'a', type: 'trojan', password: 'FAKE-SECRET-PW-A' },
        { tag: 'b', type: 'trojan', password: 'FAKE-SECRET-PW-B' },
      ],
    };
    const swapped = {
      outbounds: [
        { tag: 'b', type: 'trojan', password: REDACTED_SENTINEL },
        { tag: 'a', type: 'trojan', password: REDACTED_SENTINEL },
      ],
    };
    expect(() => mergeConfig(stored, swapped)).toThrow(SentinelRejectionError);
    // Same reorder with all secrets re-entered literally is allowed.
    const reentered = {
      outbounds: [
        { tag: 'b', type: 'trojan', password: 'FAKE-SECRET-PW-B' },
        { tag: 'a', type: 'trojan', password: 'FAKE-SECRET-PW-A' },
      ],
    };
    expect(mergeConfig(stored, reentered)).toEqual(reentered);
  });
});

describe('header per-value merge (R5)', () => {
  it('keeps, rejects, deletes, and replaces header values per name', () => {
    const stored = {
      headers: { Authorization: 'FAKE-SECRET-HDR', 'X-Keep': 'old', 'X-Drop': 'gone' },
    };
    const submitted = {
      headers: { Authorization: REDACTED_SENTINEL, 'X-Keep': 'new-value' },
    };
    expect(mergeConfig(stored, submitted)).toEqual({
      headers: { Authorization: 'FAKE-SECRET-HDR', 'X-Keep': 'new-value' },
    });
  });
});

describe('userinfo splice and tampered sentinel (R6-R7)', () => {
  const storedUrl = 'https://FAKE-USERINFO-USER:FAKE-USERINFO-PASS@proxy.example.com:8080/path?q=1';

  it('keeps the stored userinfo when only the host changes (R6)', () => {
    const merged = mergeConfig(
      { proxy_url: storedUrl },
      { proxy_url: 'https://<redacted>@proxy.example.org:8080/path?q=1' },
    ) as { proxy_url: string };
    expect(merged.proxy_url).toBe(
      'https://FAKE-USERINFO-USER:FAKE-USERINFO-PASS@proxy.example.org:8080/path?q=1',
    );
  });

  it('keeps the stored userinfo when only the query changes (R6)', () => {
    const merged = mergeConfig(
      { proxy_url: storedUrl },
      { proxy_url: 'https://<redacted>@proxy.example.com:8080/path?q=2' },
    ) as { proxy_url: string };
    expect(merged.proxy_url).toBe(
      'https://FAKE-USERINFO-USER:FAKE-USERINFO-PASS@proxy.example.com:8080/path?q=2',
    );
  });

  it('treats a tampered or removed userinfo segment as a new literal (R6)', () => {
    const tampered = mergeConfig(
      { proxy_url: storedUrl },
      { proxy_url: 'https://eve@proxy.example.com:8080/path?q=1' },
    ) as { proxy_url: string };
    expect(tampered.proxy_url).toBe('https://eve@proxy.example.com:8080/path?q=1');
    expect(tampered.proxy_url).not.toContain('FAKE-USERINFO');
    const removed = mergeConfig(
      { proxy_url: storedUrl },
      { proxy_url: 'https://proxy.example.com:8080/path?q=1' },
    ) as { proxy_url: string };
    expect(removed.proxy_url).toBe('https://proxy.example.com:8080/path?q=1');
    expect(removed.proxy_url).not.toContain('FAKE-USERINFO');
  });

  it('treats a tampered sentinel as a literal, never restoring the old secret (R7)', () => {
    const stored = { password: 'FAKE-SECRET-PW' };
    for (const tampered of ['<redacted>!', 'prefix<redacted>', '<REDACTED>', ' <redacted> ']) {
      const merged = mergeConfig(stored, { password: tampered }) as { password: string };
      expect(merged.password).toBe(tampered);
      expect(merged.password).not.toBe('FAKE-SECRET-PW');
    }
  });
});

describe('deletion, empty, null distinct from keep (R9)', () => {
  it('deletes an absent key, keeps empty string and null as literals', () => {
    const stored = { password: 'FAKE-SECRET-PW', token: 'FAKE-SECRET-TOKEN', uuid: 'FAKE-SECRET-UUID' };
    expect(mergeConfig(stored, { token: 'FAKE-SECRET-TOKEN' })).toEqual({
      token: 'FAKE-SECRET-TOKEN',
    });
    expect(mergeConfig(stored, { password: '', token: 'FAKE-SECRET-TOKEN', uuid: 'FAKE-SECRET-UUID' })).toEqual({
      password: '',
      token: 'FAKE-SECRET-TOKEN',
      uuid: 'FAKE-SECRET-UUID',
    });
    expect(mergeConfig(stored, { password: null, token: 'FAKE-SECRET-TOKEN', uuid: 'FAKE-SECRET-UUID' })).toEqual({
      password: null,
      token: 'FAKE-SECRET-TOKEN',
      uuid: 'FAKE-SECRET-UUID',
    });
  });

  it('keeps stored null when the sentinel stands for a nil secret value', () => {
    expect(mergeConfig({ password: null }, { password: REDACTED_SENTINEL })).toEqual({
      password: null,
    });
  });
});

describe('sentinel scope, duplicate keys, Go-parity boundary (R8, C-R5, D2)', () => {
  it('allows a literal <redacted> at a non-secret position', () => {
    expect(mergeConfig({ note: 'old' }, { note: REDACTED_SENTINEL })).toEqual({
      note: REDACTED_SENTINEL,
    });
    expect(redactValue({ note: REDACTED_SENTINEL })).toEqual({ note: REDACTED_SENTINEL });
  });

  it('operates on the parsed shape: duplicate keys collapse, last wins', () => {
    const storedText = '{"password": "FAKE-SECRET-OLD", "password": "FAKE-SECRET-LAST"}';
    const submittedText = '{"password": "<redacted>", "password": "<redacted>"}';
    const merged = mergeConfig(JSON.parse(storedText), JSON.parse(submittedText)) as Record<string, unknown>;
    expect(Object.keys(merged)).toEqual(['password']);
    expect(merged.password).toBe('FAKE-SECRET-LAST');
  });

  it('does not mutate either input', () => {
    const stored = { outbounds: [{ tag: 'a', password: 'FAKE-SECRET-PW' }] };
    const submitted = { outbounds: [{ tag: 'a', password: REDACTED_SENTINEL }] };
    const storedBefore = JSON.stringify(stored);
    const submittedBefore = JSON.stringify(submitted);
    mergeConfig(stored, submitted);
    expect(JSON.stringify(stored)).toBe(storedBefore);
    expect(JSON.stringify(submitted)).toBe(submittedBefore);
  });

  it('leaves ?token=, fragment, and Bearer text inside plain strings verbatim (D2, Go parity)', () => {
    // Go's Value deliberately does not strip these; only URL userinfo
    // is scrubbed. Any change belongs in Go first.
    const value = {
      description: 'https://host.example/x?token=FAKE-QUERY-TOKEN&other=1',
      note: 'Bearer FAKE-BEARER-TOKEN',
      fragment: 'https://host.example/x#token=FAKE-FRAGMENT-TOKEN',
    };
    expect(redactValue(value)).toEqual(value);
  });
});

describe('diff safety (C2)', () => {
  it('a diff of redacted base vs edited text never shows the old secret', () => {
    const stored = { password: 'FAKE-SECRET-PW', server: 'example.com' };
    const redactedBase = JSON.stringify(redactValue(stored), null, 2);
    const edited = JSON.stringify(
      { password: REDACTED_SENTINEL, server: 'example.org' },
      null,
      2,
    );
    const lines = lineDiff(redactedBase, edited);
    const text = lines.map((line) => line.text).join('\n');
    expect(text).not.toContain('FAKE-SECRET-PW');
    expect(lines.every((line) => !line.text.includes('FAKE-SECRET-PW'))).toBe(true);
    // The sentinel line itself is unchanged context, not a deletion.
    expect(lines.some((line) => line.text.includes(REDACTED_SENTINEL))).toBe(true);
  });
});
