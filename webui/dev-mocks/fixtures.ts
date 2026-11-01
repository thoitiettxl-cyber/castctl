/** Dev-only fixtures for the mock API (VITE_USE_MOCKS=true).
 * Node-only: imported by the Vite dev-server plugin, never bundled.
 * Marker string CASTCTL_MOCK_FIXTURE must never appear in production dist.
 *
 * Secrets discipline (Fix 1): `storedConfigDocument`,
 * `profileDetailFixture.entry`, and `legacyProfileEntryFixture` hold the
 * STORED form with FAKE secret values only — never real values. Served
 * views are derived from them through redactValue (see configStore.ts
 * and mockServer.ts): `configFixture.content`, `dnsFixture.dns`, and
 * profile entries returned by the mock are redacted, and the mock
 * store hashes the stored bytes. Tests assert no FAKE-SECRET-* value
 * appears in any served view. `bundle_sha256` in statusFixture is the
 * UI bundle hash placeholder, unrelated to the config-file hash.
 */

import { createHash } from 'node:crypto';
import { deriveConfigSource } from './configSource.ts';
import { redactValue, stringifyConfigDocument } from './redact.ts';

export const CASTCTL_MOCK_FIXTURE = 'CASTCTL_MOCK_FIXTURE';

/** Lowercase hex SHA-256 of `text` (Node, dev mock only). */
export function sha256Hex(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

export const profilesFixture = [
  {
    name: 'muse01',
    default: true,
    source: 'single-file',
    has_cookies: true,
    outbound_tag: 'proxy-eu',
    fingerprint: 'chrome',
    dir: '~/.config/castctl/profiles/muse01',
  },
  {
    name: 'work',
    default: false,
    source: 'single-file',
    has_cookies: false,
    outbound_tag: null,
    fingerprint: 'chrome',
    dir: '~/.config/castctl/profiles/work',
  },
  {
    name: 'legacy-note',
    default: false,
    source: 'legacy',
    has_cookies: true,
    outbound_tag: null,
    fingerprint: 'chrome',
    dir: '~/.config/castctl/profiles/legacy-note',
  },
];

// Aggregate config layout, DERIVED from profilesFixture (see
// configSource.ts) — never hard-coded separately. Two single-file
// profiles + one legacy profile => 'mixed', so the dashboard legacy
// warning and the config source agree. Changing a profile's `source`
// above automatically moves this aggregate (and configFixture.source
// below) with it.
export const statusFixture = {
  version: '0.1.0-dev',
  go_version: 'go1.27.3',
  singbox_version: 'v1.14.4',
  listen_addr: '127.0.0.1:8317',
  remote_exposure: false,
  config_path: '~/.config/castctl/config.json',
  config_source: deriveConfigSource(profilesFixture.map((p) => p.source)),
  default_profile: 'muse01',
  profile_count: 3,
  outbound_count: 3,
  endpoint_count: 1,
  bundle_sha256: 'CASTCTL_MOCK_FIXTURE',
};

/**
 * Stored-form profile entry for muse01 (FAKE values). Served redacted
 * by mockServer.ts. The inline `outbound` object exercises the
 * profile-entry redaction path (C3): vm_id, node_id,
 * subscription_action_id, and a full outbound with a password and a
 * header map. `cookies_file` is a path, never redacted.
 */
export const profileDetailFixture = {
  name: 'muse01',
  default: true,
  source: 'single-file',
  has_cookies: true,
  outbound_tag: 'proxy-eu',
  fingerprint: 'chrome',
  dir: '~/.config/castctl/profiles/muse01',
  entry: {
    cookies_file: '~/.config/castctl/profiles/muse01/cookies.txt',
    vm_id: 'FAKE-SECRET-VM-ID',
    node_id: 'FAKE-SECRET-NODE-ID',
    subscription_action_id: 'FAKE-SECRET-SUB-ACTION-ID',
    outbound: {
      type: 'trojan',
      tag: 'proxy-eu',
      server: 'example.com',
      server_port: 443,
      password: 'FAKE-SECRET-PROFILE-PW',
      headers: { Authorization: 'FAKE-SECRET-PROFILE-HDR' },
    },
    fingerprint: 'chrome',
  },
  paths: {
    config: '~/.config/castctl/config.json',
    cookies: '~/.config/castctl/profiles/muse01/cookies.txt',
    dir: '~/.config/castctl/profiles/muse01',
  },
  warnings: [],
};

/**
 * Stored-form entry for the legacy-layout profile. It lives outside
 * the single-file document: config/DNS saves must never touch it
 * (coordinator decision D3). Served redacted by mockServer.ts.
 */
export const legacyProfileEntryFixture = {
  cookies_file: '~/.config/castctl/profiles/legacy-note/cookies.txt',
  vm_id: 'FAKE-SECRET-LEGACY-VM-ID',
  node_id: 'FAKE-SECRET-LEGACY-NODE-ID',
  fingerprint: 'chrome',
};

export const loginStatusFixture = {
  logged_in: true,
  vm_id_prefix: 'vm_9f2c',
  expiry: '2026-11-05T10:00:00Z',
  cookies_present: true,
  cookies_format: 'netscape',
  last_checked_at: '2026-10-29T05:00:00Z',
};

export const outboundsFixture = [
  { tag: 'proxy-eu', type: 'trojan', summary: 'trojan example.com:443', used_by: ['muse01'] },
  { tag: 'proxy-us', type: 'vless', summary: 'vless + reality example.net:443', used_by: [] },
  { tag: 'direct', type: 'direct', summary: 'direct', used_by: ['work', 'legacy-note'] },
];

export const endpointsFixture = [
  { tag: 'wg-home', type: 'wireguard', summary: 'wireguard 10.2.0.2/32', used_by: ['proxy-eu'] },
];

/**
 * The STORED config.json document (FAKE values only). Every
 * secret-bearing shape from the Go redaction survey is present: all
 * attested outbound types, the WireGuard endpoint, nested TLS/ACME
 * material, `users[]`, header maps, URL userinfo, and the DNS section.
 * Non-secret survivors are pinned alongside: `username`, `key_id`,
 * `access_key_id` must survive redaction. The `description` /
 * `note` strings pin the Go-parity boundary (D2): `?token=` and Bearer
 * text inside plain string values are displayed verbatim (only URL
 * userinfo is scrubbed).
 */
export const storedConfigDocument = {
  default_profile: 'muse01',
  profiles: {
    muse01: {
      cookies_file: '~/.config/castctl/profiles/muse01/cookies.txt',
      vm_id: 'FAKE-SECRET-VM-ID',
      node_id: 'FAKE-SECRET-NODE-ID',
      subscription_action_id: 'FAKE-SECRET-SUB-ACTION-ID',
      fingerprint: 'chrome',
      outbound: {
        type: 'trojan',
        tag: 'profile:muse01',
        server: '203.0.113.10',
        server_port: 443,
        password: 'FAKE-SECRET-INLINE-PW',
      },
    },
    work: { outbound: 'proxy-eu', fingerprint: 'chrome' },
  },
  outbounds: [
    {
      tag: 'socks-1',
      type: 'socks',
      server: '127.0.0.1',
      server_port: 1080,
      version: '5',
      username: 'FAKE-USER',
      password: 'FAKE-SECRET-SOCKS-PW',
      description: 'https://host.example/x?token=FAKE-QUERY-TOKEN',
    },
    {
      tag: 'http-1',
      type: 'http',
      server: '127.0.0.1',
      server_port: 8080,
      username: 'FAKE-USER',
      password: 'FAKE-SECRET-HTTP-PW',
      proxy_url: 'https://FAKE-USERINFO-USER:FAKE-USERINFO-PASS@proxy.example.com:8080/path',
    },
    { tag: 'ss-1', type: 'shadowsocks', method: 'aes-256-gcm', password: 'FAKE-SECRET-SS-PW' },
    { tag: 'vmess-1', type: 'vmess', uuid: 'FAKE-SECRET-VMESS-UUID', security: 'auto' },
    {
      tag: 'vless-1',
      type: 'vless',
      uuid: 'FAKE-SECRET-VLESS-UUID',
      tls: { reality: { public_key: 'FAKE-SECRET-REALITY-PUB', short_id: 'FAKE-SECRET-REALITY-SHORT' } },
    },
    { tag: 'trojan-1', type: 'trojan', server: 'example.com', server_port: 443, password: 'FAKE-SECRET-TROJAN-PW' },
    {
      tag: 'hysteria2-1',
      type: 'hysteria2',
      password: 'FAKE-SECRET-HYSTERIA-PW',
      obfs: { type: 'salamander', password: 'FAKE-SECRET-HYSTERIA-OBFS' },
    },
    { tag: 'tuic-1', type: 'tuic', uuid: 'FAKE-SECRET-TUIC-UUID', password: 'FAKE-SECRET-TUIC-PW' },
    { tag: 'anytls-1', type: 'anytls', password: 'FAKE-SECRET-ANYTLS-PW' },
    { tag: 'shadowtls-1', type: 'shadowtls', password: 'FAKE-SECRET-SHADOWTLS-PW' },
    {
      tag: 'ssh-1',
      type: 'ssh',
      user: 'FAKE-USER',
      private_key: 'FAKE-SECRET-SSH-KEY',
      private_key_passphrase: 'FAKE-SECRET-SSH-PASSPHRASE',
    },
    { tag: 'snell-1', type: 'snell', psk: 'FAKE-SECRET-SNELL-PSK', userkey: 'FAKE-SECRET-SNELL-USERKEY' },
    {
      tag: 'naive-1',
      type: 'naive',
      password: 'FAKE-SECRET-NAIVE-PW',
      extra_headers: { 'X-Custom': 'benign', Authorization: 'FAKE-SECRET-NAIVE-HDR' },
    },
    {
      tag: 'openconnect-1',
      type: 'openconnect',
      client_key_password: 'FAKE-SECRET-OC-KEY-PW',
      mca_key: 'FAKE-SECRET-OC-MCA-KEY',
      mca_key_password: 'FAKE-SECRET-OC-MCA-KEY-PW',
      submission_key: 'FAKE-SECRET-OC-SUBMISSION',
      client_key: 'FAKE-SECRET-OC-CLIENT-KEY',
      client_certificate: 'FAKE-SECRET-OC-CLIENT-CERT',
      cookie: 'FAKE-SECRET-OC-COOKIE',
      secret: 'FAKE-SECRET-OC-SECRET',
    },
    {
      tag: 'openvpn-1',
      type: 'openvpn',
      static_key: 'FAKE-SECRET-OVPN-STATIC',
      client_key: 'FAKE-SECRET-OVPN-CLIENT-KEY',
      client_certificate: 'FAKE-SECRET-OVPN-CLIENT-CERT',
    },
    { tag: 'tailscale-1', type: 'tailscale', mesh_psk: 'FAKE-SECRET-TS-MESH-PSK' },
    {
      tag: 'tls-nested-1',
      type: 'trojan',
      server: 'tls.example.com',
      tls: {
        client_key: ['FAKE-SECRET-TLS-KEY-1', 'FAKE-SECRET-TLS-KEY-2'],
        client_certificate: ['FAKE-SECRET-TLS-CERT-1'],
        certificate: 'FAKE-SECRET-TLS-CERTIFICATE',
        key: 'FAKE-SECRET-TLS-KEY',
        acme: {
          dns01_challenge: {
            api_token: 'FAKE-SECRET-ACME-API-TOKEN',
            access_key_secret: 'FAKE-SECRET-ACME-ACCESS-SECRET',
            security_token: 'FAKE-SECRET-ACME-SECURITY-TOKEN',
            zone_token: 'FAKE-SECRET-ACME-ZONE-TOKEN',
          },
          external_account: { mac_key: 'FAKE-SECRET-ACME-MAC-KEY' },
        },
        certificate_provider: {
          account_key: 'FAKE-SECRET-CP-ACCOUNT-KEY',
          origin_ca_key: 'FAKE-SECRET-CP-ORIGIN-CA-KEY',
        },
      },
      users: [
        { username: 'FAKE-USER', password: 'FAKE-SECRET-TLS-USER-PW' },
        { username: 'FAKE-USER-2', password: 'FAKE-SECRET-TLS-USER-PW-2' },
      ],
      headers: { Authorization: 'FAKE-SECRET-TLS-HDR', 'X-Keep-Name': 'benign-value' },
      key_id: 'FAKE-KEY-ID',
      access_key_id: 'FAKE-ACCESS-KEY-ID',
      note: 'Bearer FAKE-BEARER-TOKEN stays verbatim (D2 boundary)',
    },
    {
      tag: 'selector-1',
      type: 'selector',
      outbounds: ['trojan-1', 'direct'],
      default: 'trojan-1',
    },
  ],
  endpoints: [
    {
      type: 'wireguard',
      tag: 'wg-home',
      address: ['10.0.0.2/32'],
      private_key: 'FAKE-SECRET-WG-PRIVKEY',
      peers: [
        {
          address: '203.0.113.10',
          port: 51820,
          public_key: 'FAKE-SECRET-WG-PUBKEY',
          pre_shared_key: 'FAKE-SECRET-WG-PSK',
          allowed_ips: ['0.0.0.0/0'],
        },
      ],
    },
  ],
  dns: {
    servers: [
      { type: 'https', tag: 'dns-remote', server: '1.1.1.1', server_port: 443, path: '/dns-query', detour: 'trojan-1' },
      { tag: 'dns-userinfo', address: 'https://FAKE-USERINFO-DNS-USER:FAKE-USERINFO-DNS-PASS@dns.example.com/dns-query' },
    ],
    final: 'dns-remote',
  },
  // All current top-level blocks (FAKE values). No per-profile dns:
  // a profile dns alongside top-level dns is invalid under G1.
  log: { level: 'info', output: 'castctl.log', timestamp: true },
  telegram: {
    profile: 'muse01',
    token: '123456789:FAKE-SECRET-TELEGRAM-TOKEN-AAAAAAAAAAAAAAAA',
    allowed_user_ids: [1403530267],
    auto_approve: false,
    auto_allow_once: false,
  },
  keeper: [
    { tag: 'k1', profile: 'muse01', browser: 'http://127.0.0.1:9226', interval: '24h', notify: 'telegram' },
  ],
  webui: { listen: '127.0.0.1:8317', token: 'FAKE-SECRET-WEBUI-TOKEN' },
};

/** Served redacted view of the stored document + its stored-bytes hash. */
export const configFixture = {
  content: stringifyConfigDocument(redactValue(storedConfigDocument)),
  sha256: sha256Hex(stringifyConfigDocument(storedConfigDocument)),
  // Same derived aggregate as statusFixture.config_source: the
  // config layout is 'mixed' while a legacy profile remains.
  source: deriveConfigSource(profilesFixture.map((p) => p.source)),
};

/** Served redacted DNS slice + the stored-file hash (D1). */
export const dnsFixture = {
  dns: redactValue(storedConfigDocument.dns),
  sha256: sha256Hex(stringifyConfigDocument(storedConfigDocument)),
};

/** Served Telegram settings (Go shape): masked is exactly '***'
 * when a token is stored; no owner_id/watch fields exist in Go. */
export const telegramFixture = {
  configured: true,
  masked: '***',
  profile: 'muse01',
  allowed_user_ids: [1403530267],
  auto_approve: false,
  auto_allow_once: false,
};

/** Served keeper entries with state-file status (name-only records). */
export const keeperFixture = [
  {
    tag: 'k1',
    profile: 'muse01',
    browser: 'http://127.0.0.1:9226',
    interval_seconds: 86400,
    notify: 'telegram',
    status: {
      tag: 'k1',
      profile: 'muse01',
      logged_out: false,
      keeper_stopped: false,
      last_checked_at: '2026-10-29T05:00:00Z',
      last_tick_outcome: 'healthy',
      earliest_expiry: '2026-11-05T10:00:00Z',
      next_check_at: '2026-10-30T05:00:00Z',
    },
  },
];

export const defaultsFixture = { auto_approve: false, auto_allow_once: false, watch: true };

export const logsFixture = [
  { ts: '2026-10-29T05:00:01Z', level: 'info', kind: 'server', message: 'castctl web UI started on 127.0.0.1:8317' },
  { ts: '2026-10-29T05:00:02Z', level: 'info', kind: 'profile', message: 'profile muse01: login status checked, logged in' },
  { ts: '2026-10-29T05:00:03Z', level: 'warn', kind: 'config', message: 'profile legacy-note uses the legacy layout' },
  { ts: '2026-10-29T05:00:04Z', level: 'info', kind: 'outbound', message: 'outbound proxy-eu: test passed in 812ms' },
  { ts: '2026-10-29T05:00:05Z', level: 'error', kind: 'gateway', message: 'profile work: auth check failed (logged_out)' },
];

export const profileTestFixture = {
  profile: 'muse01',
  overall: 'pass',
  egress_ip: '203.0.113.42',
  phases: [
    { phase: 'dns', status: 'pass', duration_ms: 120, detail: 'resolved via outbound' },
    { phase: 'tls', status: 'pass', duration_ms: 310 },
    { phase: 'http', status: 'pass', duration_ms: 180 },
    { phase: 'egress', status: 'pass', duration_ms: 95 },
    { phase: 'noise', status: 'pass', duration_ms: 240, detail: 'handshake then close' },
  ],
};
