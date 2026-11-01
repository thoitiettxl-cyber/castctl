# Provenance

This file records where castctl's behavior, code, and assets come
from: which upstream works were copied, linked, or studied, and
exactly where each mapping lives in this tree and in the upstream.
Every factual sentence here is traceable to a file and line inspected
at a verified commit. The short summary for attribution and license
names is the root `NOTICE`; this file is the detailed record.

Castctl `file:line` citations in this file refer to the tree at
the head of the commit carrying this file, unless a citation says
otherwise. The measurements were taken against base commit
`1a738947ed6df8e8ae3ed7aa6704ef5ae2d2beaa` (main); the only cited
file that moved between the base and the head is
`docs/architecture.md` (three lines inserted before
`## Platforms`), and every `docs/architecture.md` citation below
was re-anchored to the head line numbers. If a
citation no longer matches the tree, the tree wins and this file
must be updated in the same PR as the change that moved it (see
§10).

## Status tags

- `VERIFIED` — both sides inspected, with `file:line` on each side.
- `[DOCS-ONLY]` — only a docs or comment sentence supports the claim;
  no code behind it was inspected.
- `[DESIGN-ONLY]` — a design doc or plan only; no code in the tree.
- `[UNVERIFIED]` — not inspected; the sentence says so.
- `[NOT FOUND]` — searched, absent.

## Scope boundary

This file covers load-bearing upstreams only: code or assets in the
tree, libraries the binary links (directly or through sing-box), and
designs the architecture docs explicitly follow. It is not a complete
inventory of every transitive module in `go.mod`/`go.sum` or every
package in `webui/bun.lock`. A complete, tool-generated license
inventory is the release PR's scope; until it exists, no sentence
here claims completeness. The npm dependency licenses bundled into
`webui/dist/index.html` were not checked (see §4, carried gap).

License-name caveat: three LICENSE files in the Go module cache
(flynn/noise, protobuf, utls) contain the three-clause
redistribution-conditions-plus-disclaimer text but no license
identifier string anywhere in the file. A fourth,
gorilla/websocket (22 lines), contains only two redistribution
conditions plus the disclaimer, and likewise no license
identifier string anywhere in the file. This file therefore
calls the first three "BSD-3-Clause-style template text" and
gorilla/websocket "BSD-2-Clause-style template text", rather
than asserting the SPDX identifier `BSD-3-Clause` or
`BSD-2-Clause` unqualified. The miekg/dns LICENSE names
"BSD 3-Clause License" on line 1, and the goleak LICENSE names
"The MIT License (MIT)" on line 1; those two are stated without the
caveat.

## 1. sing-box v1.14.4 — VERIFIED (linked library + config schema, no copied code)

Upstream: `github.com/sagernet/sing-box`, tag `v1.14.4`, commit
`c005f35300ce76427dc285481ec5695f5b179cd2` (verified with
`git describe --tags` in a research clone at that commit).
License: GPL-3.0-or-later plus an extra sentence. The 17-line
`LICENSE` in the module cache
(`github.com/sagernet/sing-box@v1.14.4/LICENSE`, sha256
`650d5e3b99a446fb38e820fa87a49562e0c79eab868fff58618ac487a58e554c`)
reads "Copyright (C) 2022 by nekohasekai", states the GPL-3.0 terms,
and adds: "In addition, no derivative work may use the name or imply
association with this application without prior consent." The extra
sentence exists only in sing-box's LICENSE: the `sagernet/sing`,
`sing-tun`, and `cronet-go` LICENSE files carry the same GPL-3.0
opening with zero occurrences of "In addition" (verified by grep).
The sing-box LICENSE text is not copied into the castctl tree.

Pinned version: `go.mod:1` declares module
`github.com/thoitiettxl-cyber/castctl`, `go 1.27.3`, with a direct
require of `github.com/sagernet/sing-box v1.14.4`.

What was taken: sing-box as a library, not copied source. 39 files
in the tree import `sagernet/sing-box` (counted with
`git grep -l`). Packages used include `adapter`, `adapter/endpoint`,
`adapter/outbound`, `dns`, `include`, `log`, `option`, and
`common/tls`. The `option.Outbound` / `option.Endpoint` /
`option.DNSOptions` types are the config schema: upstream
`option/outbound.go:22-28` defines `_Outbound` and `Outbound`;
castctl `internal/profile/config.go:25` declares
`Outbounds []option.Outbound`, `config.go:46-48` re-parses them in
`ParsedOutbounds`, and `internal/profile/outbound.go:10` imports
`sing-box/option`. Upstream `option/tls.go:107,134` defines
`OutboundTLSOptions` with a `UTLS` field; upstream
`option/dns.go:26` defines `DNSOptions`; upstream
`include/registry.go:48` defines `Context` and `:80` defines
`OutboundRegistry`.

Castctl mappings (`VERIFIED` except as tagged):

- `internal/outbound/context.go:54-79` — `registryOnce` guards the
  single process-global `include.Context()` call site
  (`RegistryContext`, `sync.Once`-guarded; the `!with_quic`
  global-mutation hazard is documented at `context.go:55-62`).
- `internal/outbound/manager.go:16-22` — imports `adapter/endpoint`,
  `adapter/outbound`, `dns`, `log`, `option`, and `sing/service`,
  building registry-only managers; no `box.Box` is involved.
- `internal/outbound/router_stub.go:18-32` — `stubRouter`
  implementing `adapter.Router` (upstream `adapter/router.go:18`
  defines the `Router` interface) for outbound-only operation.
- `internal/outbound/tls.go:35-46` — `GatewayTLSOptions` built from
  `option.OutboundTLSOptions`; the default uTLS fingerprint is
  `"chrome"`, and ALPN is deliberately not pinned in
  `GatewayTLSOptions`. (The gateway WebSocket dial separately pins
  ALPN to `["http/1.1"]` at its own call site,
  `internal/gateway/connector.go:240`; the HTTPS auth chain is
  untouched.)
- `internal/dns/client.go:5-6` — package doc: builds a profile DNS
  client on sing-box `dns.Router` + `dns.TransportManager` from
  `option.DNSOptions`.
- `internal/profile/fingerprint.go:37,40,44,45` —
  `DefaultFingerprint = "chrome"`, `DefaultTLSEngine = "utls"`;
  valid fingerprints are chrome/firefox/ios/safari and valid engines
  are cronet/stdlib/utls.
- `internal/outbound/wireguard_conf.go:17-18` and
  `internal/outbound/router_stub.go:13-15` import `sing-box/option`
  and `sing/common/*` respectively for WireGuard endpoint
  construction. `[PARTLY VERIFIED — import level only; file contents
  not read in detail.]`

Outbound dialability for the interim-DNS detour walk (loop 4) —
VERIFIED against the pinned module-cache source (no upstream code
copied; the walker is castctl's own static model of the upstream
runtime below, so NOTICE is unchanged). The question the walker
answers is: if migrate authors a dns detour to this tag, can a DNS
query dial through it? Upstream, a dns server detour resolves
through `common/dialer/detour.go:57` (`DetourDialer.init`) and
`:80` (`DialContext`): the init fails only when the detour tag
is missing or when the immediate target is an empty direct
outbound (`:72`, "detour to an empty direct outbound makes no
sense"); otherwise dialing delegates to the target's own
`DialContext`. The walker mirrors that: it follows `detour`
fields first, then decides per target type. Castctl mapping:
`internal/profile/migrate.go:808` (`detourNodeCanDial`),
`:776` (`selectorSelected`), `:902` (`detourTagForProfile`).

- `block`: never dials. Upstream
  `protocol/block/outbound.go:34` (`DialContext`) always returns
  `syscall.EPERM` (and `ListenPacket` likewise). Walker: `false`.
- `bridge`: never dials TCP/UDP. Upstream
  `protocol/bridge/outbound.go:128` (`DialContext`) always errors
  ("only L3 traffic is supported by bridge"). Walker: `false`.
- `direct`: dials, except as a detour target when empty, and
  except loopback-to-TUN-range destinations. Upstream
  `protocol/direct/outbound.go:52` (`NewOutbound`) forces
  `UDPFragmentDefault` true and `:269` (`IsEmpty`) compares
  against exactly that value; the field is `json:"-"` in
  `option/outbound.go`, so a parsed config can never set it and
  parsed-zero is exactly upstream-empty — the walker's zero
  comparison is upstream's check, not an approximation.
- `selector`: dials ONLY its selected member. Upstream
  `protocol/group/selector.go:162` (`DialContext`) dials
  `selected`, and `:79` (`Start`) selects cache-file, then
  `Default`, then the first member. Castctl registers no
  `CacheFile` service (`internal/outbound/context.go:110`
  `services()`), so in castctl runtime the selection is exactly
  Default-or-first, which is what `selectorSelected` walks. A
  Default naming a non-member, or an empty member list, is an
  upstream `Start` error ("default outbound not found",
  "missing tags"), so the walker returns `false`.
- `socks` and every other proxy type: dials through its own
  client/dialer, or through its `detour` chain (walked first).
  Upstream e.g. `protocol/socks/outbound.go` (`DialContext`)
  delegates to its client, whose dialer is a `DetourDialer` when
  a detour is set (`common/dialer/dialer.go:52`). Walker:
  default `true`, after following the detour.
- Endpoints (e.g. WireGuard): valid detour targets. Upstream
  `adapter/outbound/manager.go:153` (`Outbound`) falls back to
  the endpoint manager, and e.g.
  `transport/wireguard/endpoint.go:267` (`DialContext`) dials
  through the tunnel device. Walker: resolved by
  `lookupDetourNode` and default `true` (live WG dial validity
  stays [UNVERIFIED], as before).
- `dns` outbound: no walker case, deliberately. Upstream
  `protocol/dns/outbound.go:38` (`DialContext`) always returns
  `os.ErrInvalid`, but the case is unreachable anyway: sing-box
  1.14.4 rejects a `dns` outbound at parse time
  (`option/outbound.go:45`, removed in 1.13.0).

Walker-specific deviations (dialability only), each with castctl
evidence:

- `urltest` is refused as a detour target in castctl even
  though sing-box proper would dial its best-tested member
  (upstream `protocol/group/urltest.go:169` `DialContext` selects
  by URL test). Upstream `urltest` Start requires a URL test
  history storage service (`protocol/group/urltest.go:253`,
  "missing URL test history storage"), upstream `box` registers
  one (`box.go:166-167`), but castctl's manager context never
  does (`internal/outbound/context.go:110` `services()` lists
  Router, NetworkManager, OutboundManager, EndpointManager, and
  DNSTransportManager only), so a urltest outbound cannot start
  in castctl runtime at all. Refusal is the castctl-faithful
  answer; the upstream behavior is recorded here, not claimed.
- `direct` carrying a `detour` field is rejected at upstream
  construction (`protocol/direct/outbound.go:55`, "`detour` is
  not supported in direct context"), so such a config fails
  castctl runtime construction regardless of dns authoring and
  the walker's answer for it is moot. The walker still follows
  the detour field (preserving the pinned round-2 chain tests);
  rejecting direct-with-detour at config validation time is a
  follow-up, not done in this loop.

Gate-2 clearance for per-profile DNS (this PR) — VERIFIED
against the pinned module-cache source, plus a measured test
(no upstream code copied; NOTICE unchanged). The problem: a
direct profile's default DoH must detour, but sing-box
rejects a detour to an empty direct outbound. Upstream:
`common/dialer/detour.go:29-35` (`NewDetour`), `:57-78`
(`DetourDialer.init`, lazy via `sync.Once` in `Dialer()`):
missing tag → `outbound detour not found: <tag>` (`:63`);
`!defaultOutbound && !disableEmptyDirectCheck` and the target
implements `DirectDialer` (`:15-17`, `IsEmpty() bool`) and
`IsEmpty()` is true → `:72` (`detour to an empty direct
outbound makes no sense`). Emptiness: `protocol/direct/
outbound.go:52-77` (`NewOutbound` forces `UDPFragmentDefault`
true; `isEmpty` is `DeepEqual(DialerOptions,
{DialerOptions:{UDPFragmentDefault: true}})`), `:269-271`
(`IsEmpty()`). The gate fires at transport Start, not at
construction: every DNS transport's `Start` calls
`dialer.InitializeDetour` (`dns/transport/tcp.go:83-88`,
`tls.go:93`, `udp.go:87`, `https.go:157`, `quic/http3.go:146`,
`quic/quic.go:87`). The only switch that disables the check,
`DisableEmptyDirectCheck`, is `json:"-"` on the HTTP-client
options struct (`option/http.go:37`), forwarded only through
`common/dialer/dialer.go:26,52` and `common/httpclient/
client.go:25`; no DNS transport sets it
(`dns/transport_dialer.go:11-24` builds `dialer.Options`
with only `Context`, `Options`, `DirectResolver` /
`RemoteIsDomain`), and castctl's `dns.New` exposes no such
knob — so the clearance cannot be a flag flip. Castctl's
clearance: a runtime-only, per-profile direct outbound
(`castctl-direct:<profile>`) made non-empty by exactly one
explicit dialer field, `UDPFragment=false` (which affects only
UDP packet dialing through that outbound; the DoH default is
TCP/TLS, so it changes no dialing behaviour there), created
only in the active profile's own manager before DNS Start.
Castctl mapping: `internal/commands/runtime.go`
(`SynthesizedDirectOutbound`, `createOutbounds` synthesised
tag), `internal/profile/dns.go` (`SynthesizedDirectTag`,
`ResolveProfileDNS`). Measured proof:
`internal/dns/gate2_test.go` — empty-direct detour fails at
`client.Start()` with `dns: start transport manager (start):
start dns-transport: start dns/tcp[dns1]: detour to an empty
direct outbound makes no sense`; the synthesised non-empty
direct detour starts and resolves. No guard is weakened: the
plain `"direct"` outbound stays empty and a detour naming it
still fails as above.

Deviations from upstream, each with castctl evidence:

1. No `box.Box`. Upstream sing-box normally runs as a full box
   (inbounds + routing + DNS). Castctl builds registry-only managers
   plus a stub Router and never constructs a box
   (`manager.go:16-22`, `router_stub.go:18-32`, `context.go:79`).
2. Per-profile isolation (hard invariant). One outbound stack per
   profile; registries, managers, routers, DNS clients, and dialers
   are built per profile and shared data is immutable-only
   (`docs/architecture.md:76-103`). Caveat: `architecture.md:86-87`
   still phrases this as "one sing-box box instance per profile, or
   unique tags per profile" while the code uses registry-only
   managers; do not quote that sentence as describing the code
   without this caveat.
3. Fail-closed, no implicit direct fallback, no env-proxy shim
   (`context.go:9-12` package doc: no `http.DefaultClient`, no
   `net.Dial`, no system-resolver lookup except the single
   `BootstrapLookup` site).
4. uTLS fingerprint pinned to `chrome`; `random`/`randomized`
   rejected. Upstream `common/tls/utls_client.go:371-396`
   (`uTLSClientHelloID`) accepts `""` (Chrome_Auto), `chrome`,
   `firefox`, `edge`, `safari`, `360`, `qq`, `ios`, `android`,
   `random`, and `randomized`. Castctl accepts only
   chrome/firefox/ios/safari and rejects `random`/`randomized`
   (`fingerprint.go:37,40,44,45`, `tls.go:41-43`).
5. ALPN not pinned in `GatewayTLSOptions` (deliberate; `tls.go`
   comment) — this is about `GatewayTLSOptions` only. The gateway
   WebSocket dial separately pins ALPN to `["http/1.1"]` at
   `internal/gateway/connector.go:240`. `[VERIFIED — comment evidence only.]`

Not taken: no sing-box source file is copied into the tree (no
vendored `sing-box` directory; grep shows imports only). Inbounds,
routing rules, and the box lifecycle are unused by design.

Log package (wired by the logging PR; library API only, no copied
code). Upstream `log/log.go:22-71` defines `New`: `Disabled`
returns the NOP factory before level parsing (`:25-27`); the
output switch (`:32-45`) maps `""` to the default writer, and
`"stderr"`, `"stdout"`, or a file path; the formatter
(`:46-52`) sets `DisableColors: DisableColor || filePath != ""`,
`DisableTimestamp: !Timestamp && filePath != ""`,
`FullTimestamp: Timestamp`, and the literal timestamp format
`"-0700 2006-01-02 15:04:05"`; an empty level becomes
`LevelTrace` (`:67-69`) and an unknown level errors with
`"parse log level"` (`:61-65`). Upstream `log/level.go:7-17`
defines the levels Panic=0..Trace=6 and `ParseLevel` (`:40-58`)
is case-sensitive, accepting `"warn"` and `"warning"` for Warn.
Upstream `log/format.go:96-125` renders console output with a
full timestamp when timestamp is on and a relative
elapsed-seconds prefix (`LEVEL[SSSS] `) when off, and file
output with no timestamp when off; connection IDs appear as
`[<id> <elapsed>]` after the level/timestamp prefix
(`format.go:51-58,127-141`). Upstream
`log/observable.go:45-100,149-196` defines `NewDefaultFactory`
and the level gate `level <= f.level`, with Fatal exiting the
process and Panic panicking; `log/id.go:9-30` defines
`ContextWithNewID`/`IDFromContext` (a random uint32 carried in
the context). Upstream `log/nop.go` is the NOP factory.
Castctl deviations from sing-box, all deliberate and documented
in `docs/config.md`: log files are created by castctl at mode
0600 (sing-box's observable factory opens files at 0644,
`log/observable.go:79`), a pre-existing log file is never
chmodded, the factory refuses a log output equal to castctl's
own config/cookie files (no such guard exists upstream), every
formatted line passes the redaction boundary at the writer
(upstream has no redaction), and `DisableColor` is not exposed
in the schema. Defaults are sing-box's own (empty level means
trace, empty output means stderr, `"stdout"` accepted) — no
castctl-imposed level or path default exists. Mechanism: castctl does NOT call `log.New` (its
`"stderr"` branch writes the real `os.Stderr` unconditionally
and its file path opens at 0644 on `Start()`); it calls
`log.NewDefaultFactory` with a caller-supplied writer and owns
file creation itself (`internal/logging/factory.go`), keeping
sing-box's level, timestamp, colour, and ID formatting
unchanged. `internal/outbound/tls.go` reads
`NegotiatedProtocol` from sing-box's typed `tls.Conn`
(`common/tls` exposes `ConnectionState()`); uTLS appends
`http/1.1` after a lone `h2` offer
(`common/tls/utls_client.go:66-71`), so the logged ALPN is the
negotiated string only, never the offered list.

Follow-ups from the gateway WebSocket ALPN pin (unexamined,
unresolved, no code — recorded here, not implemented):

- ALPS chimera: the pin rewrites only the ALPN extension of the
  uTLS Chrome_133 preset hello. The same preset also advertises
  ALPS for h2, which the pin leaves untouched, so the post-fix
  WebSocket hello carries ALPN `["http/1.1"]` alongside ALPS `h2`
  and the rest of the Chrome_133 hello. Whether any peer or
  middlebox rejects or misroutes such a hello is unexamined.
  What would settle it: a full ClientHello extension capture of
  the pinned hello (loopback or live) plus live behaviour
  evidence.
- DialTLS fallback contract: passing `Enabled: true` in the
  WebSocket TLS options short-circuits the `DialTLS` fallback to
  the Dialer's stored TLS options (`internal/outbound/dialer.go`
  fallback), so any TLS options stored on the Dialer are dropped
  for the WebSocket dial. Today this has no live effect (the only
  production `NewDialer` call passes empty TLS options), but the
  seam contract is undocumented and untested for non-empty
  Dialer options. What would settle it: a decision (merge the pin
  into the Dialer's options, or document that WebSocket options
  are standalone) plus a test driving the junction with
  non-empty Dialer options.

## 2. CLIProxyAPI @90c447d — DESIGN-ONLY (studied, no code taken)

Upstream: `github.com/router-for-me/CLIProxyAPI`, commit
`90c447d3a8727d115aa7552ec93ce023736ed492` (research-clone HEAD,
verified against `git ls-remote`). License name: MIT (LICENSE at
that commit reads "MIT License / Copyright (c) 2025-2005.9 Luis
Pater / Copyright (c) 2025.9-present Router-For.ME" — the
"2025-2005.9" line is verbatim upstream text, not a typo to fix).

What was taken: nothing in code. Verified by grep: zero
`go-plugin` / `hashicorp` plugin-loader imports in any castctl
`.go` file (only `hashicorp/yamux` appears, as an indirect entry in
`go.sum`, pulled by another dependency — not a plugin loader);
zero `pluginhost`, zero `sdk/pluginabi` in the tree. The only
castctl-side artefacts are docs and comments. This item is
DESIGN-ONLY: studied, no code taken.

Castctl mapping (docs/comments only — `[DESIGN-ONLY]`):

- `docs/architecture.md:21-48` — "Core + plugins" section: castctl
  follows CLIProxyAPI's plugin model; toggles `plugins.enabled` +
  `plugins.configs.<id>.enabled` (`architecture.md:30-34`) are
  "changed through the Management API and the web UI"; "Plugins are
  trusted and in-process, with no sandbox, exactly like
  CLIProxyAPI, and only first-party CLIs (BQ1, closed). BQ2–B5 are
  parked… The plugin design draft is rationale only."
  (`architecture.md:41-48`).
- Idea comments only: `internal/gateway/doc.go:107`,
  `internal/gateway/lost.go:19`, `internal/gateway/phase.go:15`,
  `internal/outbound/failclosed_test.go:27`,
  `internal/profile/config.go:386`, `internal/profile/config_test.go:292`,
  `internal/profile/envproxy.go:28,43`,
  `internal/profile/guard.go:15`, `internal/profile/identity.go:14`.

Upstream files studied (inspected at `90c447d`):
`internal/pluginhost/abi.go` (`pluginHostABIVersion`,
`pluginClient` interface with `Call(ctx, method, request []byte)`,
`pluginLoader` interface with `Open(file, host)`),
`internal/pluginhost/loader_unix.go`, `loader_windows.go`,
`loader_unsupported.go`, and
`internal/config/config_types.go:28-52` (`PluginsConfig` struct:
`Enabled`, `Dir`, `StoreSources`, `StoreAuth`, `AuthRevision`,
`Configs map[string]PluginInstanceConfig`; `PluginInstanceConfig`:
`Enabled *bool`, `Priority`, `Raw yaml.Node`).

Config-schema caveat (must be worded exactly this way): castctl's
docs claim the *same* toggles (`plugins.enabled`,
`plugins.configs.<id>.enabled`). That claim is true only for the two
toggle names. Upstream's `PluginsConfig` additionally has `dir`,
`store-sources`, `store-auth`, `auth-revision`, and per-instance
`priority` plus raw-YAML preservation — castctl has no config
struct for these (no `plugins` key exists in
`internal/profile/config.go`). Status: `[DOCS-ONLY]` for the
toggles; `[NOT FOUND]` for any wider schema adoption. The full
schema is a parked BQ2–B5 matter.

Deviations (design-level, all `[DESIGN-ONLY]`): (a) per-profile
proxy + cookies handoff to plugins, never raw WireGuard keys
(`architecture.md:21-48`); (b) plugins must use core's per-profile
dialer, never dial directly (`architecture.md:21-48`); (c) trusted
in-process, no sandbox (BQ1 closed) — the same as CLIProxyAPI, so
not a deviation from upstream, but a deliberate departure from the
generic plugin-sandbox expectation; record it as "same as upstream,
deliberate". Red-team findings B1–B10 and BQ2–B5 are parked
(`architecture.md:42-44`); B3 stays parked. None of them is
described here as resolved.

Release workflow adaptation: VERIFIED (adapted YAML in the tree;
the plugin-design part of this section stays `[DESIGN-ONLY]`).
Upstream file `.github/workflows/release.yaml` at the same pinned
commit `90c447d3a8727d115aa7552ec93ce023736ed492`, re-verified
against `git ls-remote` at PR time: 717 lines, sha256
`a6cf031dbfee1650f2832b292248257f1806cf5b0836ce171c60a3f546ec1b34`.
The earlier reference note's 1071-line numbering for this file is
stale and must not be cited. License name: MIT, as read at the
§2 head. Category: (c) studied, with workflow YAML adapted (no Go
code taken from upstream for this item).

What was taken (mapping, upstream `release.yaml` line → castctl
`.github/workflows/release.yaml` line):

- Linux glibc docker build shape: upstream L235–369 (manylinux
  images, official Go tarball in-container, `CGO_ENABLED=1`,
  `-buildvcs=false`) → castctl `release.yaml:180–356` (same
  runners and image names; `go-version-file: go.mod` on the host,
  tarball version derived from `go.mod` in-container).
- GLIBC gate: upstream L309–317 → castctl `release.yaml:318–331`,
  plus a fail-closed delta (empty version list exits 1).
- No-plugin static build + no-interpreter gate: upstream L371–488
  (build L429–431, gate L433–437) → castctl
  `release.yaml:357–503`, plus an explicit pass echo.
- Archive naming pattern: upstream L285/L425 → castctl
  `release.yaml:341` / `:454` (`castctl_<ver>_linux_<arch>.tar.gz`
  and `..._no-plugin.tar.gz`, `<arch>` = `amd64`/`arm64`).
- Checksums ordering: upstream L716 (`sha256sum … | sort -k2`) ->
  castctl `release.yaml:555`.
- Release-notes asset wording: upstream heredoc L36–48 → README.md
  "Release assets" section (castctl names/assets; FreeBSD
  paragraph dropped; no blank line between the two Linux bullets,
  as upstream). No other upstream release-notes assembly was taken.

Deviations (each with castctl evidence):

- (a) `workflow_dispatch` dry-run + `pull_request` builds-only:
  upstream has no `workflow_dispatch` (trigger L3–7 is tag push
  only). Castctl adds `publish` (choice none/draft/prerelease,
  default none) + `tag_name` inputs (`release.yaml:51–62`); the
  shared publish predicate (`release.yaml:89`, `:347`, `:494`,
  `:513`) gates every publish step, and a `prepare` job
  (`release.yaml:86–178`) creates the release idempotently
  before any upload. Castctl also runs on `pull_request`
  targeting `main` (builds + gates only): on that event both
  predicate disjuncts are false, so `prepare`, both uploads,
  and `checksums` are skipped, while the build jobs run via
  the skipped-`prepare` disjunct; both `Generate Build Metadata`
  steps force `INPUT_PUBLISH=none` / `INPUT_TAG_NAME=""` on
  non-dispatch events (`release.yaml:225–228` / `:397–400`).
- (b) Zero artifact storage: upstream uses
  `actions/upload-artifact` (L186/L322/L441/L642) and
  `actions/download-artifact` (L700). Castctl has neither string
  in `.github/workflows/`; uploads use `gh release upload
  --clobber` and the checksums job downloads via `gh release
  download` (`release.yaml:546`).
- (c) Checksums job is success-only: upstream
  `publish-checksums` uses `if: always()` (L693). Castctl
  requires both build jobs `result == 'success'`
  (`release.yaml:513`) plus an exact-4 archive count check
  (`release.yaml:549–554`).
- (d) Go version: upstream pins `1.26.10` (L14). Castctl uses
  `go-version-file: go.mod` (`go 1.27.3`, `go.mod:3`).
- (e) Asset token `arm64`, not upstream `aarch64` (upstream
  matrix L251/L384); the manylinux image name stays `aarch64`
  (`release.yaml:203`) because that is the image's real name.
- (f) Added `-trimpath` and canonical tags
  `with_utls,with_quic,with_wireguard,with_gvisor` (upstream has
  neither); `-X` paths point at
  `github.com/thoitiettxl-cyber/castctl/internal/commands.Version/Commit/BuildDate`
  (vars added in this PR), not upstream's `main.*` paths
  (upstream L305–307/L429–431), which cannot work here because
  the castctl vars live in `internal/commands`.
- (g) Dropped: model-catalog refresh step (upstream L136/L263/
  L395/L522; castctl has no model catalog), FreeBSD/hosted jobs
  (upstream L94–233/L490–689; this PR ships Linux only), and
  upstream's per-job checksums refresh (racy re-uploads; replaced
  by the single final checksums job).
- (h) Archive file set: upstream ships `LICENSE README.md
  README_CN.md config.example.yaml` (L180/L320/L439/L640).
  Castctl ships `LICENSE` + `LICENSE.sing-box` + `NOTICE` +
  `README.md` (`release.yaml:342–344` / `:489–491`); there is no
  `README_CN.md` or `config.example.yaml` in this repo. Archives
  are built with reproducible tar flags (`--sort=name`,
  `--mtime="@${SOURCE_DATE_EPOCH}"`, `--owner=0`, `--group=0`;
  `SOURCE_DATE_EPOCH` derived from commit time in both
  `Generate Build Metadata` steps, `release.yaml:234–239` /
  `:406–411`).
- (i) No NOTICE change in this PR: no new upstream is introduced
  (CLIProxyAPI is already this §2; sing-box is already in
  NOTICE, whose recorded LICENSE sha256 the committed
  `LICENSE.sing-box` matches). The test workflow
  (`.github/workflows/test.yaml`) is castctl-original, not
  adapted from upstream.

## 3. Cli-Proxy-API-Management-Center (web UI fork) @64b4f5a — VERIFIED (copied + adapted code/assets in the tree)

Upstream: `github.com/router-for-me/Cli-Proxy-API-Management-Center`,
commit `64b4f5aed19b8f791eb21eb9e785ea379ea05b44` (research-clone
HEAD, verified against the remote; log message "docs(readme):
remove APIMart sponsor sections and assets", dated 2026-10-26,
verified from the clone log). License: MIT — upstream `LICENSE`
("MIT License / Copyright (c) 2026 Router-For.ME") is byte-identical
to `webui/LICENSE.upstream` (`cmp` exit 0). `webui/NOTICE` (50
lines) states the fork at `64b4f5a…`, the MIT license, and
kept/replaced/removed lists, consistent with the diff measured
below. Do not edit `webui/NOTICE` or `webui/LICENSE.upstream` in
the course of provenance work; they are part of the fork's
attribution.

Measurement (regenerated for this file with `git ls-files` on both
sides plus `cmp` per same-path file; method: list upstream files,
list `webui/` files with the prefix stripped, intersect, compare
each same-path pair byte-for-byte):

- Upstream research clone: 659 files. Castctl `webui/`: 131 files.
- Same-path files: 95, of which byte-identical: 58, adapted (same
  path, differs): 37.
- Fork-added (castctl-only): 36. Upstream-only (removed): 564.
- 95 + 36 = 131; 95 + 564 = 659; 58 + 37 = 95.

An earlier probe reported 89 / 56 / 33 / 35 / 570 for the same
quantities; the recount above is the one that reconciles with both
file lists, and it supersedes the earlier numbers for this file.
The locale counts below were recomputed with the same method and
agree with the earlier probe.

Byte-identical (58, including): `.prettierrc`,
`eslint.config.js`, most `components/ui/*`, hooks, styles,
`tsconfig*.json`, utils.

Adapted (37, key ones with what changed; castctl side at the paths
shown, upstream side at the same path at `64b4f5a`):

- `src/App.tsx` (upstream 59 lines → castctl 67 lines),
  `src/components/layout/MainLayout.tsx` (1216 → 536 lines —
  upstream provider/sidebar complexity removed).
- `src/components/ui/Button.tsx` — adds the `plain` variant
  (castctl `Button.tsx:7`: `ButtonVariant` includes `'plain'`) plus
  ref forwarding (castctl `Button.tsx:15`:
  `ref?: Ref<HTMLButtonElement>`); upstream `Button.tsx:3` defines
  `ButtonVariant` without `'plain'`, and no line in the file
  contains `plain`, `forwardRef`, or `Ref` (whole-file grep).
- `src/components/ui/Modal.tsx`, `Select.tsx`, `Sheet/Sheet.tsx` —
  tweaks (Select trigger, Modal scrim, Sheet);
  `Table/Table.tsx` is byte-identical, and the adapted Table file
  is `Table/Table.module.scss`.
- `src/features/logs/LogsPage.tsx`, `src/pages/LoginPage.tsx`,
  `src/pages/SystemPage.tsx` — trimmed to castctl's scope.
  (Upstream `src/pages/LogsPage.tsx` is only a one-line re-export
  of the features file; it does not exist on the castctl side.)
- `src/services/api/client.ts` (272 → 124 lines) — fetch wrapper
  vs upstream axios (upstream `client.ts:6,26` imports and creates
  an axios instance; castctl `client.ts:69` calls `fetch`), `/api/v1`
  prefix, sessionStorage token; zero axios in the castctl file.
- `src/stores/useAuthStore.ts` (253 → 58 lines).
- `vite.config.ts` — adds a mock-API plugin + `__CASTCTL_*`
  defines; the single-file plugin (`vite-plugin-singlefile`) is
  kept.
- `index.html` — lang zh-CN → en, title → `castctl`, new favicon.
- `package.json` — name `castctl-webui`, version 0.1.0; deps drop
  axios, yaml, @codemirror/lang-yaml, merge, @noble/hashes and add
  @codemirror/lang-json, @codemirror/search, @codemirror/state,
  @codemirror/view, jsdom, vitest; shared: react, zustand, i18next,
  motion, react-router-dom, @uiw/react-codemirror,
  vite-plugin-singlefile.
- `src/i18n/index.ts`, constants, language, styles, types,
  `.gitignore`, `bun.lock` (604 → 794 lines).

Locales (rewritten, not verbatim): castctl `en`/`vi` JSON files
have 21 top-level keys each; upstream `en.json` has 43. Top-level
key overlap: 14 shared (`common`, `connection`, `dashboard`,
`header`, `language`, `login`, `logs`, `nav`, `nav_groups`,
`nav_meta`, `notification`, `sidebar`, `theme`, `title`); 7
castctl-only (`config`, `endpoints`, `outbounds`, `profiles`,
`screencast_login`, `settings`, `system`); 29 upstream-only (all
`*_quota`, `oauth_*`, `plugin_*`, `providersPage`, etc.). Per-string
overlap was not checked: say "keys overlap, values rewritten /
trimmed — string-level diff `[UNVERIFIED]`", never that the shared
keys' strings are identical. (Upstream locale files are
`en.json`, `zh-CN.json`, `zh-TW.json`, `ru.json`, `vi.json`,
`ko.json`; only `en.json` was compared key-by-key.)

Fork-added (36, including): `LICENSE.upstream`, `NOTICE`,
`SECRETS-CONTRACT.md`, `dev-mocks/*` (6 files),
`dist/index.html` (committed built bundle — it contains
upstream-derived JS and is covered by the root NOTICE entry for
this fork), pages (`ConfigPage`, `DashboardPage`, `EndpointsPage`,
`OutboundsPage`, `ProfileDetailPage`, `ProfilesPage`,
`ScreencastLoginPage`, `SettingsPage`), `hashHistorySync.ts`,
`useNavigationStore.ts`, `codemirrorTheme.ts`, `diff.ts`,
`features/logs/autoScroll.ts`, and the `tests/*` files.

Removed (564 upstream-only): all `features/*` provider/OAuth/quota/
plugin pages, assets/icons, most services/stores/utils, and the
upstream test suite. The upstream domain (multi-provider OAuth,
quotas, plugin store) is entirely absent from the fork.

Deviations: all pages replaced with castctl's own
(profiles/outbounds/endpoints/config/screencast); API client
rewritten (fetch, `/api/v1`, write-only secrets per
`SECRETS-CONTRACT.md`); auth store simplified (sessionStorage
token); branding removed (title `castctl`, new favicon); i18n en+vi
only; tests replaced by vitest + jsdom; `dist/index.html`
committed.

Carried gap: the licenses of the npm packages bundled into
`webui/dist/index.html` were not checked. No license-checking tool
(`go-licenses`, `syft`, `trivy`, `license-checker`) is present on
the VM, there is no `webui/node_modules` directory, and installing
packages to run such a check was out of scope. The fork's NOTICE
covers the forked *source*; the bundled npm dependencies are a
separate question for the release PR. Do not claim their licenses
here until that check exists.

## 4. muse-cli 0.6.1 Python reference — VERIFIED (behavioral reference only; plus byte-identical descriptor assets)

Upstream/reference: `github.com/thoitiettxl-cyber/muse-cli`, main
at `b4dd8f5896f0217a5bf9abab1a942782969164cd`.
`src/muse_cli/__init__.py:3` reads `__version__ = "0.6.1"`.
License: MIT ("MIT License / Copyright (c) 2026 Nik Ships", from
the upstream LICENSE). Python is frozen at 0.6.1: no Python PRs or
fixes; 0.6.1 is the differential reference for the Go port.

Nature of the mapping: behavioral reference, not code reuse. The Go
tree reimplements the Python behavior; no Python code is copied.
`README.md:7` states the behavioral-reference relationship.

Castctl mappings (file:line, both sides re-read unless tagged):

- Version/contract: `internal/commands/telegram.go`
  (`telegram run` / `telegram status` wired to the `telegram`
  config block) and `internal/commands/commands.go`
  (command order); exit-code/JSON contract per `README.md:131`.
  `[DOCS-ONLY]` for the README contract sentence itself.
- Gateway framing: `internal/gateway/framing.go:27-28,36` and
  `internal/gateway/doc.go:172-173` cite Python `gateway.py:83-93`
  `join_chunks` — re-read and confirmed: `join_chunks(partial,
  ntf)` feeds one `NoiseTransportFrame`, returns the full payload
  once complete, `parts[i]` joined in `chunk_index` order,
  unbounded accumulation. Deviation (intentional, documented):
  Go caps accumulation (bounded, `README.md:331-332`); Python is
  unbounded. Status `VERIFIED`.
- Telegram caps: `internal/gateway/doc.go:178` and
  `framing.go:41` cite `tgapi.py:20` — re-read and confirmed:
  `DOWNLOAD_LIMIT = 20 * 1024 * 1024`. `tgapi.py:15-19` also
  re-read (`API`, `TEXT_LIMIT 4096`, `CHUNK 3800`,
  `CAPTION_LIMIT 1024`, `UPLOAD_LIMIT` 49 MiB).
- Node ID: `internal/wait/NODE_ID.md:6,120` cites
  `cli.py:151-175` — partially re-read: `cli.py:151-160` shows
  `load_config()` with the named-profile cookie rule ("A named
  profile never borrows another profile's login");
  `MUSE_NODE_ID` env precedence at `cli.py:167-168`. Lines
  161-166 and 169-175 were not re-read: cite the range as
  `[PARTLY VERIFIED — 151-160, 167-168 read]`.
- Wait/approvals: `internal/approvals/approvals.go:6` cites
  `wait.py`; `internal/gateway/clock.go:17` and `framing.go:27-28`
  cite `gateway.py`/`conn.py`. Python line ranges for these
  citations were not re-read: `[DOCS-ONLY]` at line level; the
  file-level correspondence is `VERIFIED` (the files exist in both
  trees).

Byte-identical assets (copied data, `VERIFIED` by sha256 on both
sides): `internal/proto/desc0.bin`,
`internal/proto/desc1.bin`, and `internal/proto/routes.json` are
byte-identical to `src/muse_cli/desc0.bin`, `desc1.bin`, and
`routes.json` in the muse-cli clone (sha256
`5479a20cd5a9bf817c2a7ba4eec56b354d8576f565d9096fd2a3a8223e820d00`,
`5ea3f209386a4d47d28ee06473a2defad35536725bf2d3d847d31b04ec1a8868`,
`f13e7ec63548edd9319b655be1ffc88e3580f19b4f4f016aaec63d553ed5f033`
respectively; recomputed for this file). `internal/proto/proto.go:8,17,32,38`
documents the verbatim embeds and the `routes.json` fidelity rules.
These three files are (a)-list NOTICE items (copied assets), not
library dependencies. Note the paths: after the go/-to-root
migration the assets live at `internal/proto/`, not
`internal/proto/generate/`.

Deviations from 0.6.1 (all `VERIFIED` in tree): bounded
`join_chunks` caps (above); legacy-config fallback (castctl-only,
`ResolveConfigLocation` — read the old `~/.config/muse-cli` dir,
log a one-line notice, never auto-move/delete; `README.md:216`,
`docs/architecture.md:65`); `CASTCTL_CONFIG`/`CASTCTL_PROFILE`
renames with `MUSE_AUTO_*`/`MUSE_NODE_ID`/`MUSE_VM_ID` kept;
GPL-3.0 headers (`SPDX-License-Identifier: GPL-3.0-or-later`,
"Copyright (C) 2026 muse-cli contributors") on Go files.

## 5. go-telegram/bot @f53bfe5 — WIRED (linked dependency, no code copied)

Upstream: `github.com/go-telegram/bot`, commit
`f53bfe55a30bb6d0c54327a4233e60d5bccb5604` (verified three ways:
`git ls-remote` HEAD/main tip, two research clones' rev-parse —
all identical; `go.mod` pins the pseudo-version
`v1.27.1-0.20261008103508-f53bfe55a30b`, whose commit suffix is
`f53bfe55a30b`). License name: MIT (LICENSE head at that commit:
"MIT License / Copyright (c) 2022 negasus"). Zero requires of
its own. No upstream source is copied into this tree: the
library is linked as a Go module dependency only.

Castctl side: `internal/telegram/` (`bot.go`, `dispatcher.go`,
`claims.go`, `text.go`, `approvals.go`) uses the library for
polling and the Bot API calls; `internal/commands/telegram.go`
wires `telegram run` / `telegram status` to the config block.
Behaviour is reimplemented from the 0.6.1 Python reference
(`src/muse_cli/tgbot.py`, `tgapi.py`, `wait.py`), not from the
library's examples: message splitting and Markdown-to-HTML
conversion (`tgapi.py:178-247`), the HTML-then-plain send/edit
fallback and 429 retry rule (`tgbot.py:703-758`,
`tgapi.py:116-130`), the sender-id allowlist gate
(`tgbot.py:643-648,989-1000`), approval description/options
(`wait.py:102-164`, `tgbot.py:1703-1723`), callback decide /
approve-all (`tgbot.py:1725-1747`), and the claim / notified
state machine (`tgbot.py:1505-1701`).

Evaluation conditions applied (from the libpin report, all
VERIFIED in tree): the bot is built with `WithHTTPClient` on a
writer-bound client whose Transport proxy is explicitly nil
(the library default client inherits the stdlib env proxy);
`WithNotAsyncHandlers` + `WithWorkers(1)` plus a writer
dispatcher owning one FIFO queue per chat (the library's
default dispatch is an unbounded goroutine per update);
a custom errors handler (the default logs errors verbatim,
including raw payloads; a default handler is registered but
unreachable behind the match-all handler); recover per update
(the library has none); update_id dedupe marked at enqueue.
The binder rejects non-`*http.Transport` transports,
env-proxy transports, and the default direct-dial shape, and
refuses redirects; errors leaving the bot are scrubbed copies
(token-free at the error-object level, preserving only the
429/migrate `errors.As` views and sentinel `errors.Is`);
bot log lines carrying error text render as class/length
summaries only, with no method field and no verbatim error
text at any size or shape; the remaining bot log lines carry
only numeric ids, fixed-vocabulary kinds, a gated
approval_id, or field lengths.
The dispatcher is bounded: a 1024-id dedupe window, 64-deep
per-chat queues with counted drops, 5-minute idle reaping,
and a 10-second shutdown drain deadline. Startup calls GetMe
(no `WithSkipGetMe`), mirroring Python's `Bot.run` getMe
(`tgbot.py:2465`); the fake-server tests assert exactly one
getMe at construction and none during polling.

Deliberate deviations from 0.6.1 (documented in code): the
update_id dedupe itself (Python has none — a redelivery would
be handled twice); offset/dedupe state in memory only, no state
file (Python persists the offset in `telegram-state.json`);
`telegram run` answers messages with an explicit placeholder
notice and fails approval decisions closed until the step-5
gateway wiring lands; `edit_plain` swallows all edit errors
(Python catches only Telegram/connection errors); the claim
storm is kept as surveyed (a slow decider with a short claim
wait lets every concurrent caller decide one id — a defect
of the mirrored protocol; gateway-side idempotency is
required in step 5).

## 6. cronet-go — EVALUATED-NOT-WIRED (graph-only; no code, no tag)

Upstream: `github.com/sagernet/cronet-go`. License:
GPL-3.0-or-later — the module-cache LICENSE carries the same
nekohasekai GPL-3.0-or-later opening as `sagernet/sing`, with no
"In addition" sentence (grep count 0, verified).

Version in the castctl graph: pseudo-version
`v0.0.0-20260912104727-0d28acc44093`, plus ~30 `lib/*` platform
submodules, all `// indirect` in `go.mod` (`go.mod:95-96` for the
root and `all` modules; 31 `cronet-go` lines in total). The
pseudo-version was resolved read-only for this file from a
temporary blobless clone (removed afterwards): it is commit
`0d28acc44093df24b2526dea3d6ffefd6b0a54f0`, "Generate all package",
2026-09-12 10:47:27 UTC — the timestamp matches the pseudo-version
exactly. That commit sits on the upstream `go` branch; it is not
an ancestor of the upstream main HEAD
(`049f2909701ca088c9569f6b303bba5376a2b2ff`). State the
pseudo-version verbatim alongside the resolved commit; do not
present the commit as a main-branch commit.

Castctl side: zero `cronet-go` imports in `.go` files; zero
`with_cronet` hits in `.go` files (the tag name appears only in
`README.md:281`). Mentions are limited to `go.mod` indirect lines,
`go.sum`, `README.md:277-286` (default `utls` on every platform;
`cronet` an opt-in build flavour for later: tag `with_cronet` plus
a hash-verified sidecar, only after a direct probe matches or comes
close to real Chrome of the same version),
`internal/commands/help.go:373,377,408,412` (TLS-engine storage
strings), and `internal/profile/fingerprint.go:45` (valid-engines
list includes `cronet`).

Status: EVALUATED-NOT-WIRED. It is in the module graph
(transitive, via sing-box's cronet support), so for NOTICE it
belongs in (b) with the explicit "present in the dependency graph,
no castctl code uses it" qualifier — not in (a). The opt-in
*design* belongs in (c): studied, no code taken. Do not list it
as a used library.

Decisions (all `[DOCS-ONLY]` except the storage-only code):
default `utls` on every platform (`fingerprint.go:45`,
`README.md:277-286`); `random` never; cronet opt-in requires the
`with_cronet` tag + hash-verified sidecar + a direct probe matching
real Chrome.

## 7. utls (metacubex/utls) — VERIFIED (transitive use via sing-box; no direct import)

Upstream: `github.com/metacubex/utls`, tag `v1.8.7`, commit
`f7d52c22f3a8d2f510ad1470f75cb6c3fe26aa37` (verified via
`git ls-remote --tags`). License: BSD-3-Clause-style template text
— the module-cache LICENSE (27 lines, read in full) carries the
three-clause text ("Copyright (c) 2009 The Go Authors", conditions
plus disclaimer) with no license identifier; see the caveat at the
top of this file. Version in the castctl graph: `v1.8.7`,
`// indirect` in `go.mod` (`go.mod:81`); no direct require.

Castctl side: no direct `metacubex/utls` import in any `.go` file.
The single mention is a comment,
`internal/outbound/isolation_test.go:29` (citing upstream
`handshake_client.go:423` and `:1095` — those upstream line numbers
were not verified: `[UNVERIFIED]`). uTLS reaches castctl only
through sing-box `common/tls` + `option.OutboundUTLSOptions`:
upstream `common/tls/reality_client.go:1,41` carries the
`with_utls` build tag and imports `metacubex/utls`.

Castctl mappings (`VERIFIED`): `internal/outbound/tls.go:41-43`
(`GatewayTLSOptions` defaults `Fingerprint: "chrome"`);
`internal/profile/fingerprint.go:37,40,44,45` (defaults + valid sets);
`README.md:277-286` (fingerprint/TLS-engine hold section).

Deviations (`VERIFIED`, same as §1 deviation 4): castctl pins
`chrome` and rejects `random`/`randomized`; upstream accepts
`""` → Chrome_Auto, `random`, `randomized`, plus `edge`/`360`/`qq`/
`android`, which castctl's valid set excludes. Castctl's
`GatewayTLSOptions` deliberately does not pin ALPN (`tls.go`
comment); the gateway WebSocket dial separately pins ALPN to
`["http/1.1"]` at `internal/gateway/connector.go:240`. The fingerprint
preset names (`chrome`, `firefox`, …) are sing-box/utls vocabulary
adopted as config values — record them as such, not as copied code.

Status: `VERIFIED` as transitive. For NOTICE: (b) linked
dependency (via sing-box), not (a).

## 8. Noise — VERIFIED (flynn/noise library + Python-derived descriptors; not a Noise-spec repo)

The Noise *library* is `github.com/flynn/noise`. The wire
*descriptors* come from muse-cli Python, not from any Noise repo
(§4). No sing-box Noise package is involved.

flynn/noise: direct require `github.com/flynn/noise v1.1.0`. Tag
`v1.1.0` = commit `4d9f71cd4ba1fe81415efac312664ccc4bc79b46` =
HEAD (verified via `git ls-remote --tags` and HEAD). License:
BSD-3-Clause-style template text — the module-cache LICENSE (29
lines, read in full) reads "Flynn® is a trademark of Prime
Directive, Inc. / Copyright (c) 2015 Prime Directive, Inc." plus
the three-clause text, with no license identifier; see the caveat
at the top of this file.

Castctl mapping (`VERIFIED`): `internal/gateway/gateway.go:24,148-158`
(read in full): `noise.NewCipherSuite(noise.DH25519,
noise.CipherAESGCM, noise.HashSHA256)`,
`noise.NewHandshakeState(noise.Config{Pattern: noise.HandshakeXX,
Initiator: true, StaticKeypair: <fresh ephemeral>})`, empty
payloads in all three messages, 20s handshake timeout; the comment
at `gateway.go:137-146` states "the msg2 payload is accepted at ANY
length and ignored — never asserted to be empty." Also
`internal/gateway/noise_test.go:12,82` (comment: tests run
"against the flynn/noise version used by the product code" —
version pinning by test).

Descriptors / protos (`VERIFIED`, source = muse-cli Python):
`internal/proto/generate/noise_envelope.proto` (package
`hatch.noise`, "recreated from verified FileDescriptorProto in
`desc1.bin`", sha256 `5ea3f209…`) and `noise_transport.proto`
(package `ingress_rev_proxy`, from `desc0.bin`, sha256
`5479a20c…`); `go_package` added solely for `protoc-gen-go`, wire
bytes unaffected. `desc0.bin`/`desc1.bin`/`routes.json` are
byte-identical to the muse-cli Python copies (§4). Generation:
nested module `internal/proto/generate/go.mod` requires
`bufbuild/protocompile v0.14.1`, `protobuf v1.36.12`, `x/sync
v0.8.0` (indirect); the main module pins `protobuf v1.36.11` —
promotion to 1.36.12 is a recorded job in the generate README, not
done. Generation entry points `compile.go` / `generate.sh` exist;
contents not read in detail: `[PARTLY VERIFIED]`.

Deviations: (a) msg2 payload ignored at any length (deliberate,
`gateway.go:137-146` comment; the Python behavior it mirrors was
not re-read at line level: `[DOCS-ONLY]` for the Python side);
(b) bounded chunk reassembly vs Python unbounded (§4); (c)
`go_package` option added (wire-neutral, stated in the `.proto`
comments). No deviation from the Noise XX pattern itself:
DH25519/AESGCM/SHA256 + XX + initiator role is the library's
standard usage. The XX pattern as a studied design is a (c) NOTICE
item: studied, no code taken; the pattern itself is a public
specification, not copied text.

Status: `VERIFIED` except as tagged.

## 9. Direct-dependency table (main module, go.mod at the base commit; licenses read from module-cache LICENSE files)

| Module | Version | License (as read) | In-tree code? |
|---|---|---|---|
| `github.com/flynn/noise` | `v1.1.0` | BSD-3-Clause-style template text | Yes — `internal/gateway/gateway.go` |
| `github.com/gorilla/websocket` | `v1.5.3` | BSD-2-Clause-style template text | Yes — WebSocket transport (`internal/gateway` only: `connector.go:16`, `gateway.go:16`, `keepalive.go:11`, `lost.go:14`) — import-level verified; exact call sites not enumerated |
| `github.com/miekg/dns` | `v1.1.72` | BSD 3-Clause License (named in file) | Yes — DNS (via `internal/dns`, sing-box DNS stack) — import-level verified |
| `github.com/sagernet/sing` | `v0.9.7-0.20261023115459-5dc452e537bf` | GPL-3.0-or-later (no extra sentence) | Yes — `sing/common/json`, `sing/common/network`, `sing/service` (import-level verified: `sing/common/json` in `internal/profile/outbound.go:11` and `internal/outbound/wireguard_conf.go:18`; `sing/common/network` in `internal/outbound/router_stub.go:15`; `sing/service` in `internal/dns/client.go:34`, `internal/outbound/context.go:51`, `internal/outbound/manager.go:22`) |
| `github.com/sagernet/sing-box` | `v1.14.4` | GPL-3.0-or-later + name/association sentence (§1) | Yes — 39 files (§1) |
| `github.com/sagernet/sing-tun` | `v0.9.7-0.20261023115432-040db71fcd33` | GPL-3.0-or-later (no extra sentence) | Yes — `internal/outbound/router_stub.go:13` imports `sing-tun` (import-level verified) |
| `go.uber.org/goleak` | `v1.3.0` | MIT License (named in file) | Test-only — verified: imported only from `internal/approvals/main_test.go:10`, `internal/conn/main_test.go:10`, `internal/gateway/main_test.go:10`, `internal/wait/main_test.go:10` |
| `google.golang.org/protobuf` | `v1.36.11` | BSD-3-Clause-style template text | Yes — generated `.pb.go` runtime |
| `github.com/chromedp/chromedp` | `v0.21.0` | MIT License (named in file) | Added by the session-keeper PR; `with_chromedp`-gated only — `internal/keeper` CDP attach/export/screencast (import-level verified) |
| `github.com/chromedp/cdproto` | `v0.157.8` | MIT License (named in file) | Added by the session-keeper PR; `with_chromedp`-gated only — CDP protocol types for `internal/keeper` |
| `github.com/go-json-experiment/json` | `v0.0.0-20260213210345-44df1a37e875` | BSD 3-Clause (LICENSE file, Copyright (c) 2020 The Go Authors) | Indirect (`go.mod`); license read from the module cache — added in loop 2; loop-1 verifier measured 0 occurrences in the tagged keeper `go list -deps` |

Indirect but load-bearing (from the `go.mod` indirect block;
licenses read from the module cache):

| Module | Version | License (as read) | Note |
|---|---|---|---|
| `github.com/metacubex/utls` | `v1.8.7` | BSD-3-Clause-style template text | Via sing-box `common/tls` (§7) |
| `github.com/sagernet/cronet-go` (+ ~30 `lib/*` submodules) | `v0.0.0-20260912104727-0d28acc44093` | GPL-3.0-or-later (no extra sentence) | In graph only; no code uses it (§6); pseudo-version commit resolved read-only to `0d28acc44093df24b2526dea3d6ffefd6b0a54f0` on the upstream `go` branch |
| All other indirect modules (quic-go, wireguard-go, gvisor, x/*, etc.) | per `go.mod`/`go.sum` | NOT CHECKED | Full inventory needs a license-inventory tool — release PR's scope. Do not claim a complete list. |

Nested module (`internal/proto/generate/go.mod`):
`bufbuild/protocompile v0.14.1` — Apache License 2.0 (named in
the file header, read); `google.golang.org/protobuf v1.36.12`
(same BSD-template text as above, assumed the same file —
`[NOT RE-READ]`); `golang.org/x/sync v0.8.0` (indirect) — license
`[NOT CHECKED]`.

JS dependencies (`webui/package.json` + `bun.lock`, 794 lockfile
lines): licenses NOT CHECKED (see §3, carried gap). The direct
dependencies are named in `webui/package.json` (react, zustand,
i18next, motion, react-router-dom, @uiw/react-codemirror, the
@codemirror packages, vite + vite-plugin-singlefile, vitest,
jsdom, and the dev tooling listed there); no license is asserted
for any of them here.

## 10. Maintenance rule

When porting new behavior from an upstream, update this file and
`NOTICE` in the same PR (AGENTS.md, rule 6). Record a new upstream
with all of the following, or say explicitly which part is
missing and why:

1. Upstream repository + the exact commit inspected (full hash),
   verified against the remote — never a version string alone, and
   never an asserted commit that was not inspected.
2. The license name as read from the upstream LICENSE file (full
   text read for template texts that carry no identifier; say so
   when the file names no license).
3. The mapping, with `file:line` on both sides (castctl + upstream
   commit), or an explicit `DESIGN-ONLY` / `DOCS-ONLY` /
   `[NOT FOUND]` tag when there is no code on one side.
4. The category: (a) copied/adapted code or assets in the tree,
   (b) linked dependency, or (c) studied only, with "studied, no
   code taken" wording for every (c) item so a reader cannot
   mistake a design influence for vendored code.
5. Deviations from the upstream, each with castctl evidence, and
   anything deliberately not taken.

## 11. cli-proxy-api KernelSU module template @f912a73 — STUDIED + COPIED (two files only)

Upstream: `github.com/thoitiettxl-cyber/cli-proxy-api`, commit
`f912a733f84a3157e6570d84c05e5a02439d3ff0` (verified against the
remote: `git ls-remote` HEAD resolves to the same hash; log
message "docs(plans): complete v1.2.0 release", dated 2026-08-28).
License: MIT — upstream `LICENSE` ("MIT License / Copyright (c)
2025 Hoang Nguyen"), read in full. The template's own
`AGENTS.md` governs the template repo, not castctl.

Category: mixed. (a) Copied, byte-identical, exactly two files
(listed below with hashes) into the former `module/`
directory, removed with the module. Everything else in
`module/` had been castctl-written code following the
template's patterns, i.e. (c) studied, no code taken: no
template shell code, Go code, or config text was copied
into the module scripts. The deviations record (formerly
`module/docs/ksu-module.md` §9) was removed with the module
and no longer applies; it is not summarised here beyond the
load-bearing items named below.

Copied files (both `cmp` exit 0 against the upstream commit,
into the former `module/` directory):

- `module/META-INF/com/google/android/update-binary` — the
  generic Magisk/KernelSU installer entry point, sha256
  `5f4afbcd6537e00e64c4b468373cfcdf0d0e1cb378527a5ac8afcc31553d8ce0`.
  Upstream: `META-INF/com/google/android/update-binary` at the
  pinned commit.
- `module/licenses/GLIBC-COPYING.LESSERv2` — the LGPL 2.1
  license text for the redistributed glibc libraries, sha256
  `20e50fe7aae3e56378ebf0417d9de904f55a0e61e4df315333e632a4d3555d95`.
  Upstream:
  `licenses/GLIBC-COPYING.LESSERv2` at the pinned commit. This
  is the glibc license text, not template code; it is recorded
  here because the file was copied from the template tree.

Studied patterns, with the historical mapping (former castctl
file ↔ upstream file at the pinned commit; no line counts are
cited — counts were stale twice after later edits and rot on
every loop, so the mapping names files only):

- Install-time publication: `module/customize.sh`
  ↔ `customize.sh` — SKIPUNZIP, ABI gate,
  checksum verification from the embedded manifest,
  content-addressed `releases/<id>-<sha>/` + atomic `current`
  symlink swap, plugin forward-copy from the old release
  layout, example-config-only copy, permission loop.
- Lifecycle controller: `module/scripts/castctl-ctl`
  ↔ `scripts/cpactl` — PID-file + cmdline
  matching, lifecycle lock outside the data tree, readiness
  wait, stop escalation, status/doctor/backup/purge-data
  commands, log helper shape.
- Boot hook: `module/service.sh` ↔ `service.sh`
  — single late-start hook, backgrounded subshell,
  boot_completed wait, disable check, watchdog.
- Manager button / removal: `module/action.sh` ↔
  `action.sh`; `module/uninstall.sh` ↔
  `uninstall.sh` — stop best-effort, keep data.
- Host packager: `module/build.sh` ↔ `build.sh`
  — pinned downloads with verify-before-rename,
  ELF/glibc validation, payload `checksums.sha256`
  self-verification, secret refusal, deterministic ZIP.
- Pins and manifest: `module/sources.lock` ↔
  `sources.lock`; `module/payload-manifest.txt`
  ↔ `payload-manifest.txt`. The castctl
  pins themselves (castctl v0.6.4 asset, glibc 2.44 `.deb`,
  CA bundle 20261020-r0) were re-verified by real download
  in the module work, not copied from the template's pins;
  the CA pin differs because the template's pin 404s
  (deviations record D15, removed with the module).

Deliberately not taken / changed (as recorded in the removed
deviations record): KernelSU-first busybox/PATH
(D1); `SKIPMOUNT=true` + no `PROPFILE` line, no `system/` dir
(D3/D4); bounded `boot_completed` polling instead of the
unbounded `resetprop -w` wait (D5); bounded `flock` (D6);
watchdog with exponential backoff (D7); log rotation + no
secrets in logs (D8); no 9999:3003 privilege drop — root in
module context (D9); no `update-core`/latest-following updater
(D10); no listener checks (D11); `CASTCTL_DATA_DIR` honoured
in both `customize.sh` and the controller, where the template
honours `CPA_DATA_DIR` in `cpactl:6` only and hardcodes the
path in `customize.sh` (D13); CA bundle from a pinned `.apk`
instead of a host file (D14). The template's
`system/bin/cpactl` shim, `system.prop` handling, and
`allow-root-core` marker have no castctl counterpart.

Nothing else in this tree is copied template code. In
particular, no template Go code, web UI code, or provider
logic is present in castctl; the `webui/` fork is covered
separately by §3.

## 12. SB-T @c03b73d — STUDIED + ADAPTED (no code copied)

Upstream: `github.com/thoitiettxl-cyber/SB-T`, commit
`c03b73d6577505c5e1e947d760a8b0638202cab5` (main, 2026-10-12;
verified against the remote: `git ls-remote` HEAD resolves to
the same hash).
License: Apache-2.0 — upstream `LICENSE` (Apache License,
Version 2.0, January 2004), read in full. No `license` field
in the SB-T `package.json` files was found; the repo-root
LICENSE file governs.

Category: (c) studied, no code taken — but the PATTERN had
been ported into the former module, so this section records
the historical mapping (AGENTS.md rule 6).
The following SB-T source files were read in the librarian
checkout (`~/.cache/checkouts/github.com/thoitiettxl-cyber/SB-T`):
`box/scripts/box.webui` (JSON envelope shape, `_ok`/`_err`,
backgrounded `service` returning `"triggered"`, `check-log`
type allowlist, `dashboard-url`), `box/scripts/box.want`
handling in `box/scripts/box` (`_do_start` writes it first,
deliberate stop removes it, never created by recovery or
install), `webui/src/lib/bridge.ts` (`exec` import from
`kernelsu@^3.0.2`, single-quote shell escaping, first-`{`
extraction, `JSON.parse`, throw on `ok:false`, 20 s/600 ms
poll after service actions, `globalThis['ksu']` presence
check), `action.sh` (toggle + status + raw log tail),
`box/sing-box/config.json` (`services[api].dashboard.path =
"ui"`, UI vendored at `box/sing-box/ui/`), and
`webroot/index.html` (built shell only; assets gitignored).

What had been followed in the former module (reimplemented,
no SB-T source copied):

- The former `module/scripts/castctl-ctl`, `webui-json` subcommand: the
  `{"ok":true,"command":"CMD","data":...}` /
  `{"ok":false,"command":"CMD","error":"..."}` envelope, the
  always-exit-0 discipline (the envelope is the sole channel),
  backgrounded start/stop/restart returning `"triggered"`,
  and the controller-log-only allowlist for `log`.
- The former `module/scripts/castctl-ctl`, want marker
  (`$DATA_DIR/state/want`): existence-only semantics, written
  first by a manual start, removed by a deliberate stop, never
  created or deleted by install. DIVERGENCE (deliberate,
  Boss-decided): SB-T does NOT gate boot on its marker — its
  `service.sh` starts unconditionally every boot, so a stop
  does not survive reboot and no desired state is reported.
  Castctl DID gate boot and watchdog starts on the marker
  and reported `desired: on|off` in status.
- The former `module/webroot/index.html`: a controller page
  calling the backend through the `kernelsu` exec bridge with
  the first-`{` extraction and `payload.ok` branching, polling
  status after actions. DIVERGENCE: SB-T's page is a
  Vite-built bundle; castctl's was a single self-contained
  file with no build step, rendering via `textContent` only.
  The plain-page `ksu.exec` callable spelling had been
  recorded as `[UNVERIFIED]` on the device manager build in
  the removed module docs (gate 25); the page itself has
  been removed with the module.
- The former `module/docs/ksu-module.md` §5 + `module/customize.sh` +
  `castctl-ctl ui-update`: the on-disk-UI idea behind
  `dashboard.path = "ui"` (serve a vendored frontend tree
  from disk instead of the embedded one). DIVERGENCE: SB-T
  vendors the UI under the sing-box tree and copies the old
  tree back OVER the new one on update (old files win on
  collision); castctl had staged the UI as `ui/` in the ZIP,
  installed it to `$DATA_DIR/ui` with its own checksum
  manifest, preserved it byte-identical across updates, and
  replaced it only via the explicit `ui-update` command.
- The former `module/action.sh`: toggle + status + log tail shape.
  DIVERGENCE: castctl's toggle had keyed on the want marker or
  any running service, printed the web UI URL from status
  (never a token), and showed the controller log only.

No SB-T code, config text, or assets were copied into the
tree: no shell function, TypeScript line, JSON shape literal
beyond the three envelope field names, or UI file originates
in SB-T. SB-T has no secrets and no redaction code; the
removed castctl backend's secrecy guarantees (fixed shapes,
allowlists, no token/cookie/config content in any field) had
been castctl-written hardening with no SB-T counterpart.

## Carried items (unresolved at the time of writing)

- npm license check: not run — no license-checking tool present,
  no `node_modules`, no installs performed. The release PR owns
  it. Until then, `webui/dist/index.html`'s bundled npm licenses
  are unknown; only the forked source is covered.
- Full indirect-dependency license inventory: not generated —
  release PR's scope (needs a license-inventory tool).
- String-level locale diff (fork vs upstream shared keys):
  `[UNVERIFIED]` — only top-level key overlap was compared.
- Upstream `handshake_client.go:423/:1095` line numbers cited in
  `internal/outbound/isolation_test.go:29`: `[UNVERIFIED]`.
- `wireguard_conf.go` / `dialer.go` contents and `generate.sh` /
  `compile.go` contents: import/existence level only.
- Python `wait.py` / `conn.py` / `chat.py` line-level citation
  checks: not done; file-level correspondence only (§4).
