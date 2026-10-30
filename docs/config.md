# Config

Single-file config: one `config.json` holding every profile, plus
shared `outbounds`, `endpoints`, and (interim, global) `dns`.
Location: `--config`, then `CASTCTL_CONFIG`, then `XDG_CONFIG_HOME`
via `os.UserConfigDir` semantics. When the `castctl` home does not
exist but the pre-migration `muse-cli` home does, the old home is
used with a one-line warning; nothing is moved or deleted (the
directory fallback — the config *directory* only; see
[Migration](#migration) for the per-profile file layout, which is
refused, never read).

## Single-file schema

Top-level keys (exactly these five; unknown keys are rejected):

| Key | Value |
|---|---|
| `default_profile` | string: name of the default profile |
| `profiles` | object: profile name → profile entry (below) |
| `outbounds` | array of sing-box outbound objects (shared, tag-addressed) |
| `endpoints` | array of sing-box endpoint objects (e.g. WireGuard, tag-addressed) |
| `dns` | object: the interim global DNS section (below) |

A profile entry accepts exactly these nine keys (unknown keys,
including `dns`, are rejected — see [Per-profile DNS](#per-profile-dns)):

| Key | Value |
|---|---|
| `cookies_file` | string: path to the cookie file (relative paths resolve under `CONFIG_DIR`) |
| `vm_id` | string |
| `node_id` | string |
| `auto_approve` | `"always"` or `"off"` only — any other value, including `"on"`, is a config error |
| `auto_allow_once` | bool |
| `subscription_action_id` | string |
| `fingerprint` | string (browser fingerprint preset name) |
| `tls_engine` | string (`utls`, `cronet`, …; storage-only in the current build) |
| `outbound` | string tag (shared outbound/endpoint), an inline outbound object, or absent (= direct) |

Strictness: the file is parsed strictly — unknown fields anywhere
in the config are rejected, including inside `dns` servers and
rules. A malformed single file is an error (exit 2), never a
silent fallback. Cookies are never inline in the config:
`cookies`/`cookie` keys are rejected.

A profile with no entry in `profiles` and no config file of its
own still exists (its directory is its home) and loads with
defaults (`SourceNone`, direct, `auto_approve` off). A profile
directory with no config file is *not* a legacy layout.

## The `dns` section — INTERIM, GLOBAL, SINGLE-PROFILE-ONLY

> **INTERIM.** The current `dns` section is global: one section
> serves every profile in the file. That is an interim shape only.
> The final model is a per-profile `dns` block inside each profile
> entry (see [Per-profile DNS](#per-profile-dns)). Do not design
> multi-profile DNS behaviour around the global section: it cannot
> express per-profile resolvers, and a later migration will
> distribute it into profile entries (verbatim where a profile
> already has one, rewrite/refuse where it does not fit — gated
> decision G4). Hand-writing a global section for a multi-profile
> file means every profile shares one resolver and one detour.

The section is parsed by sing-box (v1.14) `option.DNSOptions`.
No field is required at parse level; an empty section (`{}`) is
accepted by the parser but fails at runtime (see Semantics).
Fields:

| Field | Type | Notes |
|---|---|---|
| `servers` | array of server objects | see below |
| `rules` | array of rule objects | see below |
| `final` | string | tag of the server used when no rule matches |
| `reverse_mapping` | bool | reverse (PTR) mapping |
| `strategy` | string | `""` (default), `as_is`, `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only`; anything else is a parse error |
| `timeout` | string duration, e.g. `"5s"` | per-query timeout |
| `disable_cache` | bool | disable the DNS cache |
| `disable_expire` | bool | serve expired cache entries |
| `independent_cache` | bool | **deprecated** in sing-box: accepted, only a deprecation is reported; do not rely on any other effect |
| `cache_capacity` | int | cache size |
| `optimistic` | bool or `{"enabled": bool, "timeout": duration}` | optimistic (stale-while-revalidate) answers |
| `client_subnet` | string | EDNS client subnet sent with queries |

### Servers

`type` is one of: `udp`, `tcp`, `tls`, `https`, `quic`, `h3`,
`local`, `hosts`, `fakeip`, `dhcp`, `mdns`, `tailscale`,
`openconnect`, `openvpn`. An empty or `legacy` type is rejected
with a migration message. Availability depends on the build:
`quic`/`h3` need the `with_quic` tag (present in the canonical
castctl build); `dhcp` needs `with_dhcp` (absent — a `dhcp`
server fails at transport creation); `tailscale`/`openconnect`/
`openvpn` are stubs unless built with their tags. There is no
`resolved` DNS transport type.

Common fields (all servers): the dialer options — `detour`,
`bind_interface`, `inet4_bind_address`, `inet6_bind_address`,
`bind_address_no_port`, `protect_path`, `routing_mark`,
`reuse_addr`, `netns`, `connect_timeout`, `tcp_fast_open`,
`tcp_multi_path`, `disable_tcp_keep_alive`, `tcp_keep_alive*`,
`udp_fragment`, `domain_resolver`, `network_strategy`,
`network_type`, `fallback_network_type`, `fallback_delay`
(plus the deprecated `domain_strategy`). `detour` names the
outbound/endpoint tag DNS traffic travels through; it must
resolve to a tag in the config's tag namespace (shared
`outbounds`, `endpoints`, or an inline profile outbound — the
runtime-only `"direct"` outbound and the synthetic
`"castctl-dialer"` are NOT valid detour tags).

Per-type fields:

| Type | Fields |
|---|---|
| `udp`, `tcp` | `server` (required: hostname or IP), `server_port` (default 53) |
| `tls` | remote fields + TLS options (`tls.enabled`, `server_name`, `insecure`, `alpn`, certificates); `server_port` default 853 |
| `https` | TLS fields + `path` (default `/dns-query`), `method`, `headers`; TLS is forced on for `https` transports; `server_port` default 443 |
| `local` | `prefer_go` (bool), `neighbor_domain`; **no** `server` field — it queries the system resolver |
| `hosts` | `path`, `predefined` (static host mappings) |
| `fakeip` | `inet4_range`, `inet6_range` |
| `dhcp`, `mdns` | local fields + `interface` |

### Rules

A rule has `type` (`default` or `logical`) plus match fields,
and an action. Match fields include: `inbound`, `ip_version`
(4/6), `query_type`, `query_client_subnet`, `query_dnssec`,
`network` (`tcp`/`udp`), `auth_user`, `protocol`, `domain`,
`domain_suffix`, `domain_keyword`, `domain_regex`,
`source_ip_cidr`, `source_ip_is_private`, `source_port`,
`source_port_range`, `port`, `port_range`, `process_name`,
`process_path`, `process_path_regex`, `package_name`,
`package_name_regex`, `user`, `user_id`, `outbound`,
`clash_mode`, `network_type`, `network_is_expensive`,
`network_is_constrained`, `wifi_ssid`, `wifi_bssid`,
`interface_address`, `network_interface_address`,
`default_interface_address`, `source_mac_address`,
`source_hostname`, `preferred_by`, `rule_set`,
`rule_set_ip_cidr_match_source`, `match_response`, `ip_cidr`,
`ip_is_private`, `ip_accept_any`, `response_rcode`,
`response_answer`, `response_ns`, `response_extra`, `invert`
(plus deprecated geosite/geoip fields).

Actions (`action`): `route` (with `server` + `speculative`),
`evaluate`, `respond`, `route-options`, `reject`, `predefined`.

Rule `inbound` matching: castctl defines no inbounds, so how an
`inbound` match field behaves in this build is
[UNVERIFIED] — do not assume it is inert, rejected, or
match-all; verify against a live run before relying on it.

### Semantics (current build)

- **No `dns` section → no DNS client.** Domain destinations
  fail closed with `outbound: no DNS resolver registered`
  (`ErrNoResolver`); IP-literal destinations still work. There
  is no silent fallback to the system resolver.
- **Empty `servers` list → construction error** (`dns: no DNS
  servers configured: refusing to fall back to the system
  resolver`).
- DNS is built and registered before outbounds, and started
  before the outbound manager starts; one DNS client per
  invocation/profile.
- **Bootstrap is the sole system-resolver use.** A remote
  server addressed by domain name is bootstrapped through the
  system resolver so its address can be dialled through the
  detour. IP-literal servers need no bootstrap. `local`,
  `hosts`, and `fakeip` servers are unaffected by bootstrap.
- **WireGuard key-sharing check includes global dns detours.**
  A dns server whose detour is a WireGuard endpoint participates
  in the same private-key comparison as profile outbounds: two
  profiles (or a profile and the dns section) sharing one
  WireGuard private key are rejected.

## Per-profile DNS

Not in this build. A `dns` key inside a profile entry is
rejected (unknown profile key). The per-profile model — a `dns`
block per profile, with the gated default precedence below —
lands in a later PR, with live proof, before release. Until
then, the only `dns` section is the interim global one above.

## Migration

The legacy per-profile layout — flat `config.json` files
(`config.json` at the config dir, `profiles/<name>/config.json`)
— is **refused, never read**. Any command that loads a profile
from an unmigrated layout exits 2 with:

```
profile: legacy layout found at "<path>"; run `castctl config migrate --write` first
```

The message names the migration command and the legacy file
path only — never file contents, cookie/token/key values, or
identifiers. The old files are never deleted or modified by any
command; they are the backup. Migrate itself is the only reader
of legacy files, deliberately, through a migrate-only parser.

Procedure:

```sh
castctl config migrate            # dry-run: print the plan, write nothing
castctl config migrate --write    # migrate atomically (mode 0600)
```

Properties (all tested): dry-run by default; `--write` writes
atomically under a config lock held across decide+write (mode
0600, temp file + rename; no `.bak` file is kept for
`config.json` — the old files are left untouched and are the
backup; `.bak` exists only for cookies files); refuse-overwrite
— an existing single file that differs from the migration
result refuses with exit 2 (there is no `--overwrite`);
idempotent — re-running after a successful migration reports
`already-migrated`; all-or-nothing — any profile error aborts
the whole migration and nothing is written; existing
single-file `outbounds`, `endpoints`, `dns`, and
`default_profile` are carried verbatim; no outbound is ever
invented; `node_id` is generated only on `--write` when no
single file exists yet.

### Migrating from a different directory (`--from`)

`--from <dir>` separates the migration source from the
destination: legacy profiles are read ONLY from `<dir>`, and the
single config is written ONLY to the `--config` file's directory
(or the default config directory when no `--config` is given).
The source directory is never written, locked, or modified in
any way — verify this by hash before and after; the old files
stay in the source as the backup. Cookies files stay in the
source too: migrated entries point at them by absolute path.
A missing source directory exits 2 and writes nothing anywhere.
Refuse-overwrite applies at the destination. When `--from`
names the destination directory itself, behaviour is exactly
the in-directory behaviour above. The dry-run plan reports
`source_dir` and `destination_dir` (paths only, no file
contents) and writes nothing to either directory.

```sh
castctl --config ~/.config/castctl/config.json config migrate --from ~/.config/muse-cli            # dry-run: plan only
castctl --config ~/.config/castctl/config.json config migrate --from ~/.config/muse-cli --write     # migrate into the new directory
```

Note on the `source` label in the plan: migrate enumerates
profiles by directory discovery and reports every profile it
builds from the old layout as `source: "legacy"` — including a
profile whose directory holds no config file at all (defaults
only). That label is a discovery label, not a finding that a
legacy config file exists: the load refusal and the
`profile add` block fire only on an actual legacy config file
(a flat base `config.json` without the `profiles` marker, or a
`profiles/<name>/config.json`), never on a bare directory alone.

### DNS authoring by `config migrate`

When the migrated config has no `dns` section, `config migrate`
may author the interim global section — but only in one shape:

- **Only** when every profile shares one outbound tag to detour
  through (a single profile, or all profiles referencing the
  same tag / inline non-direct outbound / endpoint tag).
- **Only** onto a config that is otherwise already migrated
  (the existing single file, ignoring `dns`, equals the
  migration result).

The authored section is the gated default (3) only:

```json
{"servers":[{"tag":"castctl-doh","type":"https","server":"1.1.1.1","server_port":443,"path":"/dns-query","detour":"<shared tag>"}],"final":"castctl-doh"}
```

DoH to 1.1.1.1, `https`, IP-literal (no bootstrap hostname),
detour = the shared outbound tag. No `tls` override is authored.
Its live behaviour (SNI/`server_name` acceptance for the
IP-literal server) is [UNVERIFIED until live proof].

Otherwise no `dns` section is written and the result records
why in `dns_refusal` (JSON field; also shown by the command),
naming the profile: a direct-only profile has no outbound tag
to detour through — a fresh legacy migration is always
direct-only, so it always records a refusal and migrates
without a `dns` section. A tag that resolves to a direct
outbound (in `outbounds`, `endpoints`, or an inline profile
outbound) counts the same way: naming it as a detour would
write a config sing-box refuses at runtime, so it records a
refusal instead. The migration itself still succeeds.
A differing single config still refuses to overwrite, with no
authoring attempted. An existing `dns` section is carried
verbatim, never rewritten. Authoring is validated with the
same checks a hand-written section faces; a validation failure
records a refusal instead of writing an invalid config.

## Gated default precedence (future model — NOT current behaviour)

The following precedence is the gated, decided model for the
per-profile DNS PR. **It is not implemented today**: today, no
`dns` section means no resolver (fail-closed, above). Do not
describe this precedence as current behaviour.

When a profile has no explicit resolver, the default resolver
is synthesised at runtime (never written into the config), in
this order:

1. The profile's own `dns` block (per-profile model; later PR).
2. Else the WireGuard endpoint's imported-config DNS servers,
   reached through that tunnel. WireGuard `DNS=` import capture
   is NOT implemented in this PR and is carried to the
   per-profile PR — docs must not claim it exists.
3. Else DoH to 1.1.1.1 (`https`, IP-literal, no bootstrap),
   with detour = the profile's outbound.

`local` is **never** the default: it is explicit-only. A
`local` server queries the system resolver — [UNVERIFIED until
live proof: on systemd-resolved hosts that may bypass the
tunnel via D-Bus unless the resolver is reached through the
detour, and live traversal of `local`+detour is unproven].
The gated model documents `prefer_go=false` for `local`
servers (the Go resolver path stays off). Until the
per-profile PR lands with live proof, prefer an explicit
`https`/`tls` server with a detour over `local`.
