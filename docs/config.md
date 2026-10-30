# Config

Single-file config: one `config.json` holding every profile, plus
shared `outbounds`, `endpoints`, per-profile `dns`, and the
(interim, global-compat) top-level `dns` and `wireguard_dns`
sections below.
Location: `--config`, then `CASTCTL_CONFIG`, then `XDG_CONFIG_HOME`
via `os.UserConfigDir` semantics. An explicit `--config` path must
name a `config.json` file (a directory, or a file with another
basename, is an error — see the `--config` help text). When the `castctl` home does not
exist but the pre-migration `muse-cli` home does, the old home is
used with a one-line warning; nothing is moved or deleted (the
directory fallback — the config *directory* only; see
[Migration](#migration) for the per-profile file layout, which
profile loading refuses (only `config migrate` reads it)).

## Single-file schema

Top-level keys (exactly these seven; unknown keys are rejected):

| Key | Value |
|---|---|
| `default_profile` | string: name of the default profile |
| `profiles` | object: profile name → profile entry (below) |
| `outbounds` | array of sing-box outbound objects (shared, tag-addressed) |
| `endpoints` | array of sing-box endpoint objects (e.g. WireGuard, tag-addressed) |
| `dns` | object: the interim global DNS section (below, compat fallback only) |
| `wireguard_dns` | object: endpoint tag → array of DNS server addresses read by branch 2 (see [Per-profile DNS](#per-profile-dns)); castctl-side state, not a sing-box field — hand-written/preserved, not imported: no import-path wiring from a wg-quick `DNS=` line exists yet (follow-up) |
| `log` | object: logging settings (see [The `log` section](#the-log-section)) |

A profile entry accepts exactly these ten keys (unknown keys
are rejected — see [Per-profile DNS](#per-profile-dns)):

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
| `dns` | object: the profile's own DNS section, parsed exactly like the top-level section (see [Per-profile DNS](#per-profile-dns)) |

Strictness: the file is parsed strictly — unknown fields anywhere
in the config are rejected, including inside `dns` servers and
rules. A malformed single file is an error (exit 2), never a
silent fallback. Cookies are never inline in the config:
`cookies`/`cookie` keys are rejected.

A profile with no entry in `profiles` and no config file of its
own still exists (its directory is its home) and loads with
defaults (`SourceNone`, direct, `auto_approve` off). A profile
directory with no config file is *not* a legacy layout.

## The `log` section

The top-level `log` block configures castctl's logging, following
sing-box's `LogOptions` semantics exactly WHEN THE BLOCK IS
PRESENT (see `docs/provenance.md` §1 for the upstream
citations). One resolved level governs every emission —
sing-box's own logs and castctl's own events — through a single
factory. The block is optional; all four fields are optional.
An absent field means the sing-box default below. An absent
BLOCK is different: see the off-gate rule below. There is no
hardcoded default log path — the user sets `output` freely, or
leaves it empty for stderr.

**Off-gate (castctl rule on top of sing-box defaults, Boss
decision 2026-10-30):** when the config has NO `log` block AND
no `--log-level` flag was given, logging is OFF: stderr carries
only the typed JSON error, exactly as before the `log` block
existed, and no log file is written. A present block — including
an empty `{}` block — turns logging ON at sing-box defaults
(level `trace`, output stderr). `--log-level` with no block
also turns logging ON, at that level with stderr output. A
block with `"disabled": true` stays off even with `--log-level`.

| Field | Type | Default | Meaning |
|---|---|---|---|
| `disabled` | bool | `false` | `true` suppresses ALL log output (castctl and sing-box), including fatal/panic lines. Normal command output (stdout JSON/text) and config errors are unaffected. |
| `level` | string | `"trace"` | One of `trace`, `debug`, `info`, `warn`, `error`, `fatal`, `panic`. sing-box's `"warning"` spelling is accepted as an alias for `warn`. Any other value (including `"TRACE"`) is a config error (exit 2), and the value is never echoed. An empty level means trace, exactly as sing-box parses it. |
| `output` | string | `""` (stderr) | `""` or `"stderr"` writes to stderr; `"stdout"` writes to stdout; any other string is a file path, opened for append. |
| `timestamp` | bool | `false` | Timestamp format, sing-box style: console output carries a full timestamp when `true` and a relative elapsed-seconds prefix when `false`; file output carries no timestamp when `false` and a full timestamp when `true`. |

Precedence, when logging is on: the `--log-level LEVEL` global
CLI flag beats the config block, which beats the sing-box
default (`trace`). An invalid `--log-level` value exits 2 and
never echoes the value. There is no `--verbose`/`--debug` flag.

**Typed JSON on stderr:** error output is one JSON line
(`{"type": ..., "error": ...}`) written after every log line.
When logging is OFF (no block, no flag) it is the only stderr
line, so whole-stderr JSON parsing works. When logging is ON
with stderr output, log lines precede it and the JSON stays the
LAST stderr line, intact — that last-line rule is the contract
consumers can rely on in that case. When log output is a file,
stderr carries only the JSON.

File output: castctl owns log-file creation — files are created
with mode `0600` and appended to (never truncated); a
pre-existing file is appended to without any chmod (castctl
never changes the mode of a file it did not create). Parent
directories are not created; an uncreatable path is a startup
error (exit 2). There is no log rotation. Console colour follows
sing-box's default (coloured level labels on a terminal); there
is no `disable_color` field in the schema.

The only path guard: the factory refuses (exit 2, before
opening, and re-checked after opening) a log output whose file
IDENTITY equals castctl's own config file or any of its cookies
files — identity means the symlink-resolved location and the
file's dev/ino, so hardlinks and symlinks to not-yet-existing
targets are refused too. There are no other path restrictions:
symlinks to other targets and non-regular files are not
refused. A refused output is a startup error; the protected
file is left untouched, and a file the factory did not create
is never chmodded.

Secrets: log lines never carry cookies, tokens, URLs with query
credentials, WireGuard keys, or header values. Secret-bearing
fields are excluded from log emissions by construction, and
every free-form log field passes a redaction boundary
(`internal/logging`). Server response bodies are never
emitted in any error, diagnostic, or log emission — not in log
lines at any level including trace, not in stderr typed JSON,
not in error strings, and not in panic renderings. (Chat
replies, history, watch rows, raw and wake output, and
opt-in raw dumps are data output the user explicitly
requested, not error/diagnostic/log emissions, and are out
of scope for this rule.) Instead, an error carrying a server
body renders as an allowlist summary only: status code,
error class, body length (byte count), content-type (media
type, parameters dropped), and specific known-safe fields
parsed by key from known Muse response schemas — the `error`
field of the `{"ok":false,"error":...}` / `{"success":...,
"error":...}` envelopes, the `status` field of the
`/api/session` body (extracted only inside the summary
builder), and the `reason` field of the redeem response
(retained in the closed list, although no current producer
extracts it through the summary builder — the exact
producers are documented in `internal/gateway/summary.go`).
No other body key is ever emitted. Each extracted value is capped at 64
runes, still passed through the SafeString backstop, and a
value over the cap is replaced by `[omitted]` — never emitted
truncated. The trace level gets the same summary; there is
no trace allowance for body bytes. (Python parity on raw
payload bytes is waived; error-kind classification and retry
semantics are unchanged.) The events castctl emits at debug/trace
are: `dns_source` (resolved DNS source + first server tag),
`outbound_chain` (profile + detour-chain tags), dial
start/done with a per-connection ID, `tls_alpn` (negotiated
protocol string only), `ws_handshake` (parsed status code or
token only), and retries (attempt counter + summarised error).

`config migrate` carries an existing `log` block into the new
file verbatim and never invents one: a migrated file without a
`log` block stays without one.

## The `dns` section — INTERIM, GLOBAL, COMPAT-ONLY

> **INTERIM.** The top-level `dns` section is global: one section
> serves every profile in the file. That is a compat fallback
> only, kept for one cycle (see [Per-profile DNS](#per-profile-dns)
> for the implemented model and the precedence order). Do not design
> multi-profile DNS behaviour around the global section: it cannot
> express per-profile resolvers, and a later migration will
> distribute it into profile entries (verbatim where a profile
> already has one, rewrite/refuse where it does not fit — gated
> decision G4). A profile entry carrying its own `dns` block and
> a file carrying a top-level `dns` section together are a config
> error (exit 2): the two are never silently shadowed. The
> compat cycle ends in a hard error in a later PR (documented
> future step, not yet implemented).

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
`"castctl-dialer"` are NOT valid detour tags, except for the
per-profile synthesised direct tag, which is valid only as its
own direct profile's detour — see
[Per-profile DNS](#per-profile-dns)).

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

- **No single config file → no DNS client.** Domain
  destinations fail closed with `outbound: no DNS resolver
  registered` (`ErrNoResolver`); IP-literal destinations still
  work. There is no silent fallback to the system resolver.
  With a single config file, a resolver is always built: a
  profile with no resolver of its own gets the synthesised
  default (see [Per-profile DNS](#per-profile-dns)), never a
  nil client.
- **Empty `servers` list → construction error** (`dns: no DNS
  servers configured: refusing to fall back to the system
  resolver`). An explicitly present but empty per-profile
  `"dns": {}` is the same construction error, never a silent
  synthesis: presence distinguishes "configured badly" (error)
  from "configured nothing" (synthesised default).
- DNS is built and registered before outbounds, and started
  before the outbound manager starts; one DNS client per
  invocation/profile, with a per-client cache and per-manager
  detour resolution (no cross-profile cache/pool sharing).
- **Bootstrap is the sole system-resolver use.** A remote
  server addressed by domain name is bootstrapped through the
  system resolver so its address can be dialled through the
  detour. IP-literal servers need no bootstrap. `local`,
  `hosts`, and `fakeip` servers are unaffected by bootstrap.
- **WireGuard key-sharing check includes dns detours.**
  A dns server whose detour is a WireGuard endpoint participates
  in the same private-key comparison as profile outbounds: two
  profiles (or a profile and the dns section) sharing one
  WireGuard private key are rejected. Per-profile dns detours
  are checked per profile: a profile's own dns detour sharing a
  key with that profile's outbound (through a different tag) is
  an error naming the profile and `dns`; a dns detour naming
  the profile's own endpoint tag is one config, not an error.

## Per-profile DNS

A `dns` block inside a profile entry is the profile's own
resolver. It parses exactly like the top-level section
(sing-box `option.DNSOptions`, strict), is preserved verbatim
on save, and is shown by `profile show` (via the profile entry
rendering) and by `profile test` Phase 1 (first server tag plus
the source below).

**Validation (parse time, exit 2).** Each server's `detour`
must be non-empty (G2: an empty detour would dial the DNS
server directly, outside the profile's outbound) and must lie
in the owning profile's reachable set: the profile's outbound
tag (or inline tag), every tag reachable from it through
detour chains and selector/urltest member lists, plus — for
direct profiles only — the profile's synthesised direct tag
(below). A detour naming another profile's inline outbound, a
dangling tag, a duplicate server tag within the block, or a
`final` naming no server tag in the same block are all errors.
Server tags are scoped per profile: two profiles may both use
tag `dns1` with no collision.

**Precedence** for the active profile, in order
(`profile.ResolveProfileDNS`):

1. The profile's own `dns` block.
2. Else the WireGuard endpoint's DNS servers from the
   `wireguard_dns` state, reached through that tunnel (see
   below). When this branch fires while a top-level `dns`
   section is present, the section is shadowed, and a one-line
   stderr warning says so (same channel as the compat
   warning).
3. Else the top-level `dns` section, compat fallback for one
   cycle, with a one-line stderr warning telling the operator
   to distribute it into profile entries by hand (`config
   migrate` does not distribute for single configs and must
   not be pointed at as the distributor). Compat sits
   before the default deliberately: a config migrated by the
   removal PR carries an authored global section that must keep
   working for one cycle, and the warning must be observable
   (if the synthesised default always won, the compat branch
   could never fire). This ordering differs from the pre-gate
   design doc §3.3, which ordered synthesis before the global
   fallback; that order would make compat dead code.
4. Else the synthesised default: DoH to 1.1.1.1 (`https`,
   IP-literal, no bootstrap), with detour = the profile's
   outbound. It applies only when the file carries no resolver
   at all. Synthesised defaults are runtime-only and are never
   written into the config file.

**The synthesis mechanism, named explicitly.** For a direct
profile there is no config tag to detour to, and sing-box
rejects a detour to an empty direct outbound at transport
Start (`detour to an empty direct outbound makes no sense`).
The runtime therefore synthesises, per profile, a tagged
direct outbound named `castctl-direct:<profile>` — created in
`createOutbounds` (after the plain `"direct"` outbound, before
DNS Start, so the detour resolves by Start time) and only in
the active profile's own manager. It is made non-empty by
exactly one explicit dialer field, `udp_fragment: false`
(`SynthesizedDirectOutbound`): that field affects only UDP
packet dialing through this outbound, which carries
DNS-detour traffic only (never profile traffic, which dials
through `"direct"`), and for the DoH default (TCP/TLS) it
changes no dialing behaviour. No sing-box guard is weakened:
`DisableEmptyDirectCheck` is never set (it is `json:"-"` and
no DNS transport dialer sets it), the plain `"direct"`
outbound stays empty, and a detour naming `"direct"` still
fails exactly as before (pinned by
`internal/dns/gate2_test.go`). A direct profile's own `dns`
block may also detour to its synthesised tag; that is the
only way a hand-written block detours to a direct outbound.
The `castctl-direct:` prefix is reserved: any config
outbound, endpoint, or inline outbound tag carrying it is a
parse-time error (exit 2), and `createOutbounds` fails loudly
if the synthesised tag is already taken, so a config tag can
never capture the default DoH detour.

**WireGuard DNS (branch 2).** `wg-quick DNS=` has no field in
sing-box's `WireGuardEndpointOptions`. Branch 2 reads the
top-level `wireguard_dns` key (endpoint tag → server
addresses; each key must name a WireGuard endpoint in the same
file) — hand-written/preserved castctl-side state, NOT an
import: `outbound.ParseWireGuardConfWithDNS` can capture
`DNS=` from a wg-quick conf, but no production caller wires
that capture into `wireguard_dns` yet (import-path wiring is
a follow-up). Branch 2 builds one `udp` server (port 53) per
listed address, all detouring through that endpoint tag. The
legacy `ParseWireGuardConf` entry point still drops `DNS=`,
preserving its contract.

**`local` is never the default: explicit-only.** A hand-written
`local` server keeps sing-box's default `prefer_go=false`.
[UNVERIFIED until live proof: on systemd-resolved hosts, when
the system resolver reports `SystemdResolved` and `prefer_go`
is false, queries go via D-Bus to `org.freedesktop.resolve1`,
NOT through the detour — so `local`+detour leak-freedom is not
claimed here, and live traversal of `local`+detour is unproven.
Prefer an explicit `https`/`tls` server with a detour over
`local` until live proof exists.] `local` has no hermetic
fake-upstream test (it reads the OS resolver config); the
fake-upstream tests prove the `tcp` detour mechanism, not
`local`.

**Live proof (post-merge, not claimed from fake-upstream
tests).** For each profile: `profile test` Phase 1 `ok: true`
with the effective source shown (`profile` / `wireguard` /
`global-compat` / `default`), plus a real lookup through the
profile's outbound. A profile whose outbound is down must not
break another profile's `profile test`.

[UNVERIFIED-LIVE: sandbox blocks raw TCP] DNS live traversal is
NOT proven. The sandbox intercepts raw outbound TCP, so the
earlier `profile test` failure is not evidence against
castctl/config. Outside-sandbox live proof is deferred to the
end-to-end core test step; `other_tcp` is NOT flipped.

## Migration

The legacy per-profile layout — flat `config.json` files in
three shapes: `config.json` at the config dir (when no single
file exists), `profiles/<name>/config.json` for any named
profile, and `profiles/default/config.json` — is **refused by
profile loading, never read** by it. The refusal fires ONLY
for names WITHOUT a single-file entry, and for those it is
layout-wide: `LoadProfile` exits 2 for such a name — including
a ghost name with no file of its own — whenever ANY legacy
file exists anywhere in the layout — for example, a single
file holding `default` plus a leftover
`profiles/work/config.json` refuses even a load of `zzz` (no
entry). A name WITH a single-file entry loads wholly from
that entry, unaffected by leftover legacy files. The error is:

```
profile: legacy layout found at "<path>"; run `castctl config migrate --write` first
```

The message names the migration command and the legacy file
path only — never file contents, cookie/token/key values, or
identifiers. The old files are never deleted or modified by any
command; they are the backup. Migrate itself is the only reader
of legacy files, deliberately, through a migrate-only parser.

Symlink-to-file loud fail: a `profiles/<name>` entry that is a
symlink resolving to a regular file fails loudly (exit 2,
naming the path) and writes nothing — it is never silently
dropped and never replaced by a synthetic default (pinned by
`TestMigrateFromSymlinkedProfileFile`). A symlinked profile
*directory* is followed, not dropped.

On top of the `LoadProfile` refusal, the CLI's own guards
refuse two more shapes: `profile show` for a name with no
single-file entry, no own config file, and no profile
directory exits 2 ("does not exist"), and `profile add`
refuses when no single file exists and any legacy file is
present, or when the added name's own legacy file exists
(`profiles/default/config.json` counts as `default`'s own
legacy file). Only when a name has no single-file entry AND
no legacy file exists anywhere in the layout does
`LoadProfile` synthesise defaults — a bare profile directory
with no config file still synthesises.

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
names the destination directory itself, including through a
symlink, behaviour is exactly the in-directory behaviour above:
source and destination are one directory, and the run writes
the single config to that directory as usual. The
source-never-written guarantee applies only when `--from`
resolves to a different directory than the destination; when
either path cannot be resolved, the two are treated as
different directories. The dry-run plan reports
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

## Default precedence (implemented model)

The gated model is implemented as described in
[Per-profile DNS](#per-profile-dns): own block, then
WireGuard DNS (from `wireguard_dns` state), then the top-level section (compat
fallback, one cycle, with warning), then the synthesised DoH
default to 1.1.1.1 (`https`, IP-literal, no bootstrap) with
detour = the profile's outbound (for direct profiles, the
synthesised `castctl-direct:<profile>` outbound — see the
synthesis mechanism in [Per-profile DNS](#per-profile-dns)).
Synthesised defaults are runtime-only and are never written
into the config file.

`local` is **never** the default: it is explicit-only. A
`local` server queries the system resolver — [UNVERIFIED until
live proof: on systemd-resolved hosts that may bypass the
tunnel via D-Bus unless the resolver is reached through the
detour, and live traversal of `local`+detour is unproven].
The model documents `prefer_go=false` for `local` servers
(the Go resolver path stays off). Until live proof exists,
prefer an explicit `https`/`tls` server with a detour over
`local`. Live proof of DoH-via-detour on the real migrated
config is a post-merge step (see [Per-profile DNS](#per-profile-dns));
fake-upstream tests do not claim it.
