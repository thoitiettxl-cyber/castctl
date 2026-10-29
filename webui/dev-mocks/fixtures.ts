/** Dev-only fixtures for the mock API (VITE_USE_MOCKS=true).
 * Node-only: imported by the Vite dev-server plugin, never bundled.
 * Marker string CASTCTL_MOCK_FIXTURE must never appear in production dist.
 * Secrets are redacted placeholders only — never real values.
 */

import { deriveConfigSource } from './configSource.ts';

export const CASTCTL_MOCK_FIXTURE = 'CASTCTL_MOCK_FIXTURE';

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
    outbound: 'proxy-eu',
    fingerprint: 'chrome',
    node_id: '<redacted>',
  },
  paths: {
    config: '~/.config/castctl/config.json',
    cookies: '~/.config/castctl/profiles/muse01/cookies.txt',
    dir: '~/.config/castctl/profiles/muse01',
  },
  warnings: [],
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

export const configFixture = {
  content: JSON.stringify(
    {
      default_profile: 'muse01',
      profiles: {
        muse01: { outbound: 'proxy-eu', fingerprint: 'chrome' },
        work: {},
      },
      outbounds: [{ tag: 'proxy-eu', type: 'trojan', server: 'example.com', server_port: 443, password: '<redacted>' }],
      endpoints: [],
      dns: { servers: [{ tag: 'remote', address: 'https://dns.example.com/dns-query' }] },
    },
    null,
    2,
  ),
  sha256: 'CASTCTL_MOCK_FIXTURE',
  // Same derived aggregate as statusFixture.config_source: the
  // config layout is 'mixed' while a legacy profile remains.
  source: deriveConfigSource(profilesFixture.map((p) => p.source)),
};

export const dnsFixture = {
  dns: { servers: [{ tag: 'remote', address: 'https://dns.example.com/dns-query' }] },
};

export const telegramFixture = {
  configured: true,
  masked: 'bot123456:AA***',
  owner_id: 1403530267,
  allowed_user_ids: [1403530267],
  auto_approve: false,
  auto_allow_once: false,
  watch: true,
};

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
