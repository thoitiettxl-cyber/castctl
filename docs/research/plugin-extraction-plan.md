# Plugin extraction plan: runtime wiring, then `castctl-muse` as a plugin

Status: plan only. No code, no behaviour change. `file:line` citations in
§§1–2 and §6 name current code at the HEAD in §0 and were re-verified
by the plan author at that HEAD; citations in §§3–4 name the seam's cut
point in current code plus the proposed addition, which does not exist
yet and is marked `DECISION` or PROPOSAL. Claims that cannot be settled
from code alone are tagged `[NEEDS-MEASUREMENT]` with the measurement
that would settle them; nothing in this plan guesses at them.
Decisions proposed by this plan are marked `DECISION` — they are
proposals for review, not statements about current code. Revision 3
(this revision) incorporates the Phase 3 round-2 reviews: every
blocking finding is closed in the section named in §7, and every
corrected or added citation was re-opened in code at the HEAD in §0.
This plan does not claim agreement or disagreement with any Phase 1
research file: none is cited in this plan, and any promise to name
Phase 1 disagreements is withdrawn as unverifiable from the material
cited here. The one reframing of the Boss task's wording — the
session/cookie handoff split in §2.1 — is recorded as D-BOUNDARY-1, a
decision to review, not as a claim that the task's wording is satisfied
literally.

## 0. HEAD and method

- HEAD cited throughout: `b8ce56509e4fe5000e72ae2688560bfb3d2546d2`
  (`origin/main`, "Merge pull request #38"). All `file:line` citations were
  re-verified by the plan author in a fresh clone at this HEAD. If the
  extraction PRs land on a later HEAD, every citation in §§1–2 and §6 must
  be re-checked before it is quoted again; line numbers drift.
- Roadmap order and decision gate D-ROADMAP: `AGENTS.md:20-25` orders the
  work "E2E test pass of the whole core → plugin loader, then extract
  castctl-muse. No plugin code before the E2E pass." Two facts sit
  uneasily with that order: no E2E pass has been run for this plan (§5,
  M-5), and the plugin framework itself is already merged (PR #30), so
  `AGENTS.md:24-25` ("No plugin code before the E2E pass") is already
  superseded/stale as written and is flagged as such here pending the
  decision below. `DECISION D-ROADMAP` (Boss decision required BEFORE
  PR-1; PR-1's entry criteria require it): either (a) the E2E baseline
  is recorded on `main` first (M-5 closed) and PR-1 proceeds after it,
  or (b) Boss approves a reorder — the E2E pass becomes PR-1's exit
  gate — and `AGENTS.md:20-25` is amended in the same decision. This
  plan does NOT claim the decision is made, and no PR in §4 may proceed
  on an assumed reading. This plan covers only the second half of the
  roadmap step: loader wiring first, extraction second. It does not
  re-litigate the plugin framework, which is already implemented (see
  §1).
- Scope rule honoured by this plan: one `config.json`, sing-box-style
  modular blocks, every setting configurable, no hidden hardcoded paths
  (`docs/architecture.md:67`). Any new config surface proposed in §3 is
  therefore a named block proposal requiring approval, not a silent default.
- No secret values appear in this plan. Only symbol and field names are
  cited. The hard rules in `AGENTS.md` (never print/log/commit secrets;
  all profile traffic through the profile's outbound) bind every PR in §4.

## 1. Current state

### 1.1 The framework is implemented; the wiring does not exist

The contract lives in `internal/pluginabi/pluginabi.go` (294 lines):
ABI version exactly `1` (`internal/pluginabi/pluginabi.go:33`), schema
version exactly `1` (`internal/pluginabi/pluginabi.go:37`), single C entry
symbol `castctl_plugin_init` (`internal/pluginabi/pluginabi.go:43`),
method vocabulary `plugin.register`, `plugin.reconfigure`,
`plugin.quiesce`, `plugin.shutdown`, `provider.call`,
`command.register`, `command.execute`, `host.log`
(`internal/pluginabi/pluginabi.go:46-75`), one JSON envelope
(`internal/pluginabi/pluginabi.go:81-87`), exactly two capabilities,
`Provider` and `CommandProvider`, at least one required
(`internal/pluginabi/pluginabi.go:124-132`), and registration validation
that rejects a higher schema and requires metadata name/version/author
(`internal/pluginabi/pluginabi.go:216-258`).

The host lives in `internal/pluginhost/host.go` (954 lines). `Host` loads
nothing on construction (`internal/pluginhost/host.go:199-215`). `Desired`
carries tag, type, path, verbatim fragment, optional identity, optional
egress, optional egress proxy, optional manifest path — and no field for
a discovery root, enable flag, or timeout
(`internal/pluginhost/host.go:66-97`). `ApplyConfig` converges serially
(detach absent tags, same-path reconfigure with rollback, different-path
quiesce + replace with rollback, per-plugin failure warn-and-skip, never
failing the whole call) (`internal/pluginhost/host.go:369-534`). Images are
never unloaded; detach is logical only (comment at
`internal/pluginhost/loader_unix.go:177-183`). `Host.Call` is generic and
does not interpret `provider.call` payloads
(`internal/pluginhost/host.go:767-807`). The only reverse callback is
`host.log`; every other `host.*` method, including `host.auth.*`, is
rejected (`internal/pluginhost/host.go:911-916`; `dispatchHostCall` starts at `:911`, the `hostLogRequest` type precedes it).

Discovery (`internal/pluginhost/discovery.go:191-243`), shadow copy
(`internal/pluginhost/shadow.go:55-94`), the glibc compat gate
(`internal/pluginhost/compat.go:708-735`, called from the real loader at
`internal/pluginhost/loader_unix.go:161-169`), opt-in checksum manifests
(verified against shadow bytes at
`internal/pluginhost/loader_unix.go:152-159`), and the per-session egress
proxy (see §1.3) are all implemented. Loader availability is a build
property: `supportValue = "1"` on cgo unix
(`internal/pluginhost/loader_unix.go:114`) and Windows
(`internal/pluginhost/loader_windows.go:36`), `"0"` on the stub
(`internal/pluginhost/loader_stub.go:21`) and other
(`internal/pluginhost/loader_other.go:26`); there is no plugin build tag.
The `_no-plugin` flavour is `CGO_ENABLED=0`
(`.github/workflows/release.yaml:457-458`), which selects the stub loader.

The docs agree with the code. `docs/architecture.md:21-49` ("Core +
plugins") states the framework "is not yet wired into the runtime:
`ApplyConfig` is called only by `castctl plugin check` and tests, no Muse
code has moved into a plugin, and wiring is a later PR", and defines the
core as "profiles, per-profile outbound (sing-box), the cookie/session
store and keeper, config, the web UI, and Telegram. Screencast login stays
in core. Each platform is a plugin: castctl-muse first".
`docs/plugins.md:11-14` and `docs/plugins-spec.md:14-16` state the same.
The condensed normative spec is `docs/plugins-spec.md` (242 lines); the
full contract is `docs/plugins.md` (703 lines).

### 1.2 `ApplyConfig`: definition and every production caller

Definition: `func (h *Host) ApplyConfig(ctx context.Context, desired
[]Desired) ApplyReport` at `internal/pluginhost/host.go:369`.

Exhaustive grep for `ApplyConfig` over non-test Go code at this HEAD
returns exactly one production call site:

| Call site | What it does |
|---|---|
| `internal/commands/plugincheck.go:103` | `host.ApplyConfig(ctx, []pluginhost.Desired{{Tag: tag, Type: typ, Path: path, Fragment: []byte(`{}`)}})` — one explicitly-pathed binary, empty fragment, no `Identity`, no `Egress`, no `EgressProxy`, no `ManifestPath`. |

Caller chain for that site: `cmd/castctl/main.go` dispatches to
`internal/commands/commands.go` (`Run` at
`internal/commands/commands.go:788`; command table at
`internal/commands/commands.go:751`; order at
`internal/commands/commands.go:766`), which reaches `cmdPluginCheck` in
`internal/commands/plugincheck.go`; the host is constructed at
`internal/commands/plugincheck.go:90`, `ApplyConfig` runs at `:103`, one
`provider.call` probe with `{"input":"ping"}` runs at `:136`, and the host is closed at `:137` on the success path (failure paths close earlier, at `:108`, `:114`, and `:133`). All other `ApplyConfig` mentions are tests or
comments. `Host.Call` likewise has exactly one non-test caller
(`internal/commands/plugincheck.go:136`).

Negative results, also from grep at this HEAD (patterns stated so a
reviewer can repeat them):

- `pluginhost.Discover` (`internal/pluginhost/discovery.go:191`),
  `pluginhost.NewEgressProxy` (`internal/pluginhost/egress.go:89`),
  `pluginhost.NewPluginIdentity` / `StrippedOutboundHash`
  (`internal/pluginhost/identity.go:37`, `:48`): zero non-test callers
  outside `internal/pluginhost/` itself.
- `command.execute` (`MethodCommandExecute`,
  `internal/pluginabi/pluginabi.go:72`): zero dispatch sites anywhere
  outside its constant definition and doc comment.
- `SupportPlugins()` / `SupportValue()`
  (`internal/pluginhost/support.go:11-15`): zero non-test callers.
- `SingleConfig.Plugins` is parsed (`internal/profile/config.go:61`,
  parse at `:380-384`, validation at `:454`) and redacted wholesale
  (`internal/profile/redact.go:117-202`), but no non-test code outside
  parse/encode/redact reads it to build a `Desired` list. The `plugins`
  block is currently parse-and-preserve only.

`Runtime` (`internal/commands/runtime.go:38-55`) has no plugin field, no
`pluginhost.Host` field, and no reference to `SingleConfig.Plugins`.
`defaultBuildRuntime` (`internal/commands/runtime.go:195-370`) builds
manager → DNS → outbounds → dialer (`internal/commands/runtime.go:344-348`)
→ connector (`internal/commands/runtime.go:357`) → `conn.Muse`
(`internal/commands/runtime.go:360-366`, assigned at `:368`) and never
constructs a `Host`.

Verdict: the loader is **not wired** (not partially wired). The missing
piece is runtime wiring + the Muse-plugin implementation + the
`provider.call` operation schema (§3.5) + the lease/generation,
route-count/error-taxonomy, keeper-parametrisation, and shared-helper
work specified in §§2–3. The plan must not redo the framework.

### 1.3 Registration handoff: identity, egress, fragment

`RegisterRequest` carries exactly: verbatim `config_json` fragment,
`schema_version`, `tag`, `type`, optional `identity`, optional `egress`
(`internal/pluginabi/pluginabi.go:190-199`). The fragment is handed
verbatim; "core never scrubs it, never adds secrets to it", and a plugin
"must work when they [identity/egress] are absent"
(`internal/pluginabi/pluginabi.go:183-189`).

Identity is tag + secret-stripped hash only
(`internal/pluginabi/pluginabi.go:164-168`): "carries no secret value, no
cookie, no key, and no path". It must be built only via
`pluginhost.NewPluginIdentity` (`internal/pluginhost/identity.go:37-47`),
which hashes the secret-stripped canonical JSON
(`internal/pluginhost/identity.go:48-60`) using `redact.Value`, whose
secret-key set includes `private_key`, `public_key`, `pre_shared_key`
(`internal/redact/value.go:44-86`; `public_key` is at `:74`). The raw outbound hash must never reach
a plugin: `OutboundIdentityForConfig` "NOT FOR PLUGIN USE: the hash is over
the RAW outbound JSON" (`internal/profile/identity.go:80-86`; the warning comment is at `:80-85`, the function at `:86`). Yet the
current core runtime uses exactly that raw-hash helper for its reconnect
key (`internal/commands/runtime.go:167-183`). Wiring must therefore call
`NewPluginIdentity` separately; it cannot reuse the runtime's hash.

Egress is a loopback proxy description with ephemeral credentials
(`internal/pluginabi/pluginabi.go:174-180`). The proxy,
`pluginhost.EgressProxy`, listens on `127.0.0.1:0`
(`internal/pluginhost/egress.go:89-107`), mints random 24-byte credentials
per proxy (`internal/pluginhost/egress.go:147-153`), requires them (407
without, `internal/pluginhost/egress.go:237-251`), forwards absolute-form
requests through a caller-supplied upstream `http.RoundTripper`
(`internal/pluginhost/egress.go:89-96`), strips hop-by-hop headers and
`Set-Cookie` from responses (`internal/pluginhost/egress.go:299-347`), and
injects the session `Cookie` header only for hosts the plugin declared in
`cookie_hosts` (`internal/pluginhost/egress.go:316-321`, `cookieAllowed`
at `:141-145`). Empty declaration means no injection (fail-closed).
`SetCookieHosts` replaces the whole map
(`internal/pluginhost/egress.go:129-139`); scope is per-proxy,
last-writer-wins when two tags share one proxy pointer. CONNECT tunnels are
opaque: "core neither injects the session cookie nor inspects anything
inside the TLS stream" (`internal/pluginhost/egress.go:352-360`); cookie
scoping does not apply to CONNECT.

The host never creates an egress proxy and never imports
`internal/outbound`: "the upstream transport and the dial function are
injected by the wiring that owns the profile"
(`internal/pluginhost/egress.go:22-42`). The host adopts a
`Desired.EgressProxy` only when registration succeeds
(`internal/pluginhost/host.go:694-724`); on fresh-load failure the proxy
"stays caller-owned: the caller must close it"
(`internal/pluginhost/host.go:85-93`). `Host.Close` closes adopted proxies
(`internal/pluginhost/host.go:329-358`).

Trusted-plugin limit — carried verbatim in substance, not a gap to close
in wiring: "an in-process native plugin can still net.Dial, read the
environment, or read process memory" and proxy use is "by CONTRACT and
code review for first-party plugins, not an enforcement boundary"
(`internal/pluginhost/egress.go:22-42`; same limit in `docs/plugins.md`,
"Secrets and egress", and as known limit U6 in `docs/plugins.md:578-615`).
A plugin never receives "a `*Manager`, a `SingleConfig`/`Profile`, a cookie
path, environment passthrough, a raw WireGuard key, a token, real proxy
credentials, or a self-built `http.Client`"
(`docs/plugins.md:350-365`). Only identity hash + egress description +
verbatim fragment cross in `RegisterRequest`. Raw WireGuard keys, tokens,
and cookie values must never cross that boundary — the cookie value
reaches the plugin only indirectly, as an injected header on proxied
requests for declared hosts, never as data the plugin can read back
(`internal/pluginhost/egress.go:316-333` strips `Set-Cookie` so a rotated
cookie set upstream does not leak into plugin hands).

### 1.4 Muse code in core: inventory

There is no `internal/source/` directory. Muse code is spread across core
packages. The wire client is `internal/gateway` (29 non-test files): the
HTTPS auth chain (`FetchSessionInfo`, `FetchAccessToken`, `FetchHatchToken`
at `internal/gateway/auth.go:119-137`), cookie loading/parsing
(`internal/gateway/cookies.go:35-45`), the connector
(`internal/gateway/connector.go:131-199`, loading cookies at `:149`, WS
dial + Noise handshake at `:201-250`, WS upgrade with `Origin:
https://muse.ai` at `:250-295`), the gateway connection
(`internal/gateway/gateway.go:48-193`), framing, routes (258 methods in
`internal/proto/routes.json`, verified by count; `DefaultRoutes` at
`internal/gateway/routes.go:64`, `LookupRoute` at `:99`), streaming,
subscriptions, media, and the Next.js subscription/invite clients
(`internal/gateway/subscription.go:271`, `internal/gateway/invite.go:30`).
The wire format is `internal/proto` (embedded `routes.json` and protobuf
descriptors at `internal/proto/proto.go:32-39`).

`internal/conn` owns connection lifecycle only and "never dials, never
performs TLS or Noise handshakes, never frames or parses protobuf
envelopes, and never reads bytes from a socket"
(`internal/conn/doc.go:13-20`). Its `Gateway` interface has 14 methods
(`internal/conn/gateway.go:283-335`): `CallJSON`, `Request`,
`SubscribeRaw`, `SubscribeJSON`, `DownloadFile`, `Ping`, `OpenStream`,
`CancelStream`, `LookupRoute`, `Alive`, `Dead`, `LastRecv`, `LastUsed`,
`Close`; plus the separate `Leaser` interface
(`internal/conn/gateway.go:344-352`). `Muse` is the shared warm connection
for one profile (`internal/conn/conn.go:30`, constructor `:148`,
`Connect` `:576`, `Call` `:654`, `History` via `chat.history` `:676`,
`WithGateway` `:745`, heartbeat `:795`). Its `Config` is the 5-tuple
`CookiesFile, VMID, NodeID, OutboundTag, OutboundHash`
(`internal/conn/gateway.go:91-97`); its `Connector` is a func type
(`internal/conn/gateway.go:116`) implemented by `gateway.NewConnector`.

Consumers that import `internal/conn` and/or `internal/gateway` and/or
`internal/deliver`/`internal/wait` (import grep at this HEAD): CLI
commands (`chat.go`, `read.go`, `deliver.go`, `wait.go`, `fs.go`,
`profilecmd.go`, `keeper.go`, `authimport.go`, `commands.go`), Telegram
turn/preview/approval paths, web UI chats, keeper tick
(`internal/keeper/tick.go:18-19`), `internal/fsclient`, `internal/approvals`,
and `internal/shared`. Two further consumers complete the inventory
(both stay core-side under D-BOUNDARY-1): `internal/commands/
telegram_commands.go` (imports `internal/conn` and `internal/deliver`,
drives `chat.subscribe` at `:303`) and `internal/webui/handlers.go`
(imports `internal/gateway`, uses `gateway.ParseCookies` at `:646`). No file in `internal/gateway`, `internal/conn`,
`internal/proto`, `internal/deliver`, or `internal/wait` imports
`internal/pluginabi` or `internal/pluginhost`.

`internal/deliver` (session/stop/wake operations over a narrow `Gateway`
interface, `internal/deliver/gateway.go:17`; `SessionStart` at
`internal/deliver/session.go:80`, `SessionOp` at `:104`, `StopTurn` at
`internal/deliver/stop.go:26`, `Wake` at `internal/deliver/wake.go:89`)
and `internal/fsclient` (`fs.list`/`stat`/`read`/`search`/`write`/`mkdir`/
`rename`/`delete` at `internal/fsclient/fsclient.go:344-612`, narrow
`Gateway` interface at `:69`) consume the `Gateway` interface and contain
no wire code. `internal/wait` is turn-end detection over event maps; its
`Runner` consumes a `Subscriber` interface whose method string comes from
the caller (`internal/wait/runner.go:96-101`), and its `subscribeBody` is
only `capabilities` + `session_id` (`internal/wait/runner.go:572-578`) —
verified by the plan author, resolving the Phase 1 open question about
that function: the subscribe body is caller-parametrised (its capability names, `"chat_cancel"`/`"delta_stream"`, are Muse vocabulary, so it is not provider-generic); the Muse-specificity
is in the caller-supplied method string and in the event field names the
pure `Waiter` reads (`TaskStatusInfo` at `internal/wait/waiter.go:91-116`, `Feed` at `:414`, `FeedRecord` at `:671`). `internal/shared`
shapes Muse response payloads (pure functions, `internal/shared/doc.go:5`).
`internal/approvals` shapes Muse approval payloads and decides batches via
an injected `Decider` func (`internal/approvals/approvals.go:55-281`).

Keeper (`internal/keeper`, 20 files) is core mechanics (tick, state, jar,
backoff, run, notify, transport) plus Muse-hardcoded provider data: check
URLs (`internal/keeper/tick.go:27-28`), `GatewayChecker` running the cheap
chain via `FetchSessionInfoWithCookies`/`FetchAccessTokenWithCookies`
(`internal/keeper/tick.go:51-76`; helpers at
`internal/gateway/authcookies.go:99-128`), `FilteredDomains`
(`internal/keeper/jar.go:77`), `ExportURLs`
(`internal/keeper/export_cdp.go:77`), `exportHosts`
(`internal/keeper/export_cdp.go:159`), `screencastHosts`
(`internal/keeper/screencast.go:151`), the embedded login-contract fixture
(`internal/keeper/contract.go:33-35` embed, `DefaultLoginContract` at `:75`, matcher at `:194`), and the launch
URL (`internal/keeper/launch.go:190`). The keeper already exposes provider
seams as interfaces: `Checker` (`internal/keeper/tick.go:44`), `Exporter`
(`:167`), `ReloginDriver` (`internal/keeper/relogin.go:82`),
`ScreencastRunner` (`internal/keeper/login.go:98`), `Transport`
(`internal/keeper/transport.go:98`), `InboundBuilder`
(`internal/keeper/launch_types.go:27`), `Notifier`
(`internal/keeper/notify.go:76`), and the `TickDeps` wiring struct
(`internal/keeper/tick.go:201-209`).

Web UI (`internal/webui`) owns HTTP, jobs, and envelopes; Muse enters only
via injected `ChatDeps` (`internal/webui/chats.go:110`, shapes at `:62-94`,
handlers at `:380-594`). Its plugins endpoint is a gated placeholder:
`handleGetPlugins` returns `available: false`, empty list
(`internal/webui/plugins.go:33-39`). Its header comment claims "no
`plugins` config key or schema" — that claim is stale at this HEAD: the
block exists (`internal/profile/plugins.go:12-49`, schema at `:99`).
Likewise `README.md:352-359` says "The plugin loader is not implemented" —
imprecise at this HEAD: the framework is implemented, wiring is not.
Neither stale sentence may be repeated as fact by the extraction PRs; the
web UI comment must be corrected by the PR that wires the endpoint (§4,
PR-5).

Profile/config (`internal/profile`) stays core: `SingleConfig`
(`internal/profile/config.go:22`) with `Plugins *PluginsConfig` at `:61`;
`Profile` fields `VMID`, `NodeID`, `SubscriptionActionID`
(`internal/profile/profile.go:213-223`); the cookie store writers
(`internal/profile/cookies.go:49`); stored credentials readable only via
`CredentialForProfile` (`internal/profile/credentials.go:230`); and the
S2 proxy allowlist default naming Muse hosts first
(`internal/profile/keeper.go:283`). `internal/outbound` (per-profile
egress; `Dialer.HTTPClient()` at `internal/outbound/dialer.go:207`,
`DialContext` at `:127`) and `internal/dns` are generic core. The
`plugins` block schema is an array of `{tag, type, ...fields}` with no
`enabled` field; presence means active; tag/type are strictly validated;
every other key becomes the verbatim fragment, raw-preserved on save
(`internal/profile/plugins.go:12-86`, `FragmentJSON()` at `:77-85`,
parse at `:150-219`).

BD-C1 (decided, `docs/plugins.md:247-285`; `docs/plugins-spec.md:146-157`):
host-level values — shadow-dir root, egress bind `127.0.0.1:0` + timeouts
10s/120s, render cap 4096, check-output caps 200, `host.log` level
allowlist — are library defaults with no config surface "because no
runtime wiring reads config.json into a Host yet". "When runtime wiring
lands, these values move into a sing-box-style config.json block."
No top-level block is invented in the spec. The wiring PR must therefore
either invent that block (new config surface, approval required) or
explicitly defer it with the BD-C1 citation; it cannot leave the values
hardcoded silently.

## 2. Boundary: what moves, what stays, and why

`DECISION D-BOUNDARY-1` (the central boundary decision of this plan, to be
reviewed explicitly): the extraction boundary is drawn at the **wire**,
not at the method-name strings. Code that speaks the Muse wire protocol
(WebSocket/Noise, protobuf framing, the route table) moves into the
plugin. The HTTPS auth chain that produces the hatch token is
duplicated into the plugin (D-AUTHCHAIN, §2.5); the core copies stay
(§2.2). Code that consumes
the `conn.Gateway` interface and passes Muse method strings as data stays
in core for extraction v1, served by a core-owned adapter that translates
`Gateway` methods into `provider.call` operations (§3.5). Rationale: the
`Gateway` interface's method *names* name no Muse host
(`internal/conn/gateway.go:283-335`); its payloads are Muse method
strings as data (e.g. `"chat.subscribe"` at
`internal/wait/runner.go:556` and
`internal/commands/telegram_commands.go:303`), which is the recorded
cost below, not a hidden one. The
the narrow interfaces in `deliver`/`fsclient` already exist, and moving
every consumer would duplicate the interface across the ABI with no
additional isolation (the plugin is in-process and trusted, §1.3). Cost:
core retains Muse method strings as data and Muse-shaped response
shaping; a second provider reusing `deliver`/`wait`/`shared` would need
those shapes generalised. That cost is recorded, not hidden (see
UNDECIDED-3/4 below). If the §4 PR-2 schema review finds that method
strings leak wire semantics the adapter cannot carry, D-BOUNDARY-1 must be
revisited before PR-6 — that is PR-2's explicit stop condition,
extended in §3.5 to the subscribe-callback, lease/generation,
ConnectionDown, route-count, and framing-error semantics: if the schema
cannot express any of them, D-BOUNDARY-1 is revisited and extraction
stops.

### 2.1 MUST MOVE to `castctl-muse`

| Component | Why (ground) |
|---|---|
| `internal/gateway` transport: connector WS dial + Noise handshake, gateway connection, framing, calls, stream, routes, lease, keepalive, generation, shutdown (`internal/gateway/connector.go:131-199` (`NewConnector`, D-AUTHCHAIN, §2.5) + `:201-250`, `internal/gateway/gateway.go:48-193`, `internal/gateway/routes.go:64-107`, plus `calls.go`, `framing.go`, `stream.go`, `lease.go`, `keepalive.go`, `generation.go`, `phase.go`, `shutdown.go`, `transient.go`, `ended.go`, `lost.go`, `handshake_log.go`) | This is the Muse wire client; every file names Muse hosts, methods, or wire formats. |
| `internal/proto`: route table + protobuf wire types (`internal/proto/proto.go:32-39`, 258 routes) + `internal/proto/generate/` | The plugin needs the table and wire types to speak the protocol; nothing in ABI v1 shares them (see §3.5). |
| `internal/gateway/gatewaytest` fake harness — STAYS in core (exception to this table's heading; see §2.5) | Differential-test harness for the wire protocol; core tests depend on it, so moving it would strand the adapter/commands differential tests. The plugin tree must not import it in production code (test-only import rule, §2.5). |
| Session/cookie handoff specifics: the cookie-injection contract (declared `cookie_hosts`, fail-closed empty set), the egress-proxy usage contract, and the identity-hash construction inputs | These are provider knowledge today only as core code paths (`internal/commands/runtime.go:112-132` cookie load, `internal/commands/runtime.go:167-183` raw-hash reconnect key); after extraction the plugin receives them only through `RegisterRequest` (§1.3). The *mechanism* (proxy, hash helper) stays in core; the *provider data* (which hosts, which cookie names) comes from the plugin's registration. |
| Keeper provider data: check URLs, cookie domains, export URLs/hosts, screencast hosts, login-contract fixture, launch URL (§1.4 keeper list) | Each is a Muse literal in core code. They must become provider-supplied parameters (§3.7); the keeper matcher/mechanics stay. |

### 2.2 MUST STAY in core, and why

| Component | Why (ground) |
|---|---|
| Profile/outbound/DNS: `internal/profile`, `internal/outbound`, `internal/dns`; single `config.json` (`docs/architecture.md:67`) | The core contract is per-profile egress through sing-box outbounds (hard rule 2). The plugin must never construct its own dialer; `pluginhost` never imports `internal/outbound` (`internal/pluginhost/egress.go:22-42`). Raw WireGuard keys live only in `internal/profile` validation + `internal/outbound` conf parsing and never cross the boundary (§1.3). |
| Cookie store + keeper mechanics: `internal/profile/cookies.go`, `internal/keeper` tick/state/jar/backoff/run/notify/transport + all keeper interfaces (§1.4) | The session store is the core's; the keeper's cheap chain, CDP re-export, and re-login are core capabilities parametrised by provider data (§3.7). Credentials stay readable only via `CredentialForProfile` and are never exposed to plugins (`internal/profile/credentials.go:30-59`). |
| Config parsing/redaction: `internal/profile/plugins.go`, `internal/profile/redact.go` | The `plugins` block is core config surface; fragments are redacted wholesale on display but handed verbatim to the plugin (§1.2). A secret placed in a fragment would reach the plugin — a config-authoring rule, not a code guarantee. |
| Web UI shell + screencast relay: `internal/webui` server/routes/config surfaces, `internal/keeper/screencast.go` mechanics | Provider-neutral HTTP/jobs/envelopes; screencast login stays in core per `docs/architecture.md:47-49`. Muse enters via injected seams (`ChatDeps`, login-session checker/exporter). |
| Telegram transport: `internal/telegram` Bot/dispatcher/state | Generic Bot API client naming no Muse host; Muse handling enters via command-layer handlers (§2.3). |
| `internal/conn`: `Gateway` interface, `SharedConn`/lease semantics, error taxonomy, and the `Muse` shared-connection manager (`internal/conn/conn.go:30`, `internal/conn/gateway.go:283-352`) | `DECISION D-CONN`: keep in core for extraction v1. The plugin provides a `Gateway` implementation behind the §3.5 adapter; `rt.Muse` call sites are untouched. `History()` (`internal/conn/conn.go:676`) stays: it only sends the `chat.history` string as data. Revisit only if a second provider needs a different lifecycle — see UNDECIDED-2. |
| Session HTTP helpers — core copies (split of `internal/gateway`, §2.3; duplication decided in §2.5, D-AUTHCHAIN): `FetchSessionInfo`/`FetchAccessToken`/`FetchHatchToken`, `Fetch*WithCookies`, `LoadCookies`/`ParseCookies`, subscription/invite fetch, `CreateInvite`/`RedeemInviteCode`, `WakeVM` (`internal/gateway/auth.go:119-137`, `internal/gateway/authcookies.go:99-128`, `internal/gateway/cookies.go:35-45`, `internal/gateway/subscription.go:271`, `internal/gateway/invite.go:30-98` — `FetchInvite` at `:30`, `CreateInvite` at `:61`, `RedeemInviteCode` at `:98`, used by `internal/commands/read.go:214,290` — `internal/gateway/wake.go:52`) | These take a caller-supplied `*http.Client` + cookie string and perform no WS/Noise work. The keeper cheap chain, `auth import` validation, `usage`/`invite`/`wake` commands, and `Runtime.Cookies()` depend on them from core. The plugin carries its own copies for the connector path only (§2.5); the core copies stay (under their current package or a renamed core package — PR-6 decides the name; behaviour must not change). Moving the core copies into the plugin would strand the keeper. |
| `internal/deliver`, `internal/fsclient`, `internal/wait`, `internal/shared`, `internal/approvals` (consumers) | Per D-BOUNDARY-1: they consume `Gateway`/event interfaces and contain no wire code. Their Muse method strings become `provider.call` op payloads through the adapter. The pure `Waiter` stays for the same reason; its `subscribeBody` is caller-parametrised (§1.4). |
| `internal/logging`, `internal/redact` (including the `hatch_sess`/`datr` redaction vocabulary) | Core still handles cookie text after extraction (keeper, import, web UI); redaction must stay. |
| `auth import` / `auth status` commands; `auth login` / `auth observe-login` mechanism | Session-store operations, not wire operations. The `hatch_sess` validation rule (`internal/commands/authimport.go:130-150`) and the web UI import name scan (`internal/webui/handlers.go:652`) are provider session-cookie *data*: at extraction they should come from the provider's declared session-cookie names, or stay as documented core behaviour for the single session-cookie format — see UNDECIDED-5. The screencast/observe mechanism stays; page URL/hosts/contract become provider data (§3.7). |
| `plugin check`, `profile`/`config`, `keeper`, `update`, `webui serve` commands; `internal/pluginabi` + `internal/pluginhost` framework | Generic management + framework. `plugin check` remains the diagnostic path and must keep working unchanged. |

### 2.3 What moves behind dispatch (not by file relocation)

Telegram Muse handling (`telegram_turn.go`, `telegram_commands.go`,
`telegram_approvals.go`, `telegram_preview.go`, `gatewayDecider`) and the
Muse CLI command handlers (`chat`, `read`, `wait`/`send`, `approvals`,
`fs`, `raw`, `status`/`usage`/`invite`, session ops) stay in core as files
for v1 and are served through the §3.5 adapter. `DECISION D-COMMANDS`:
extraction v1 uses the `Provider` capability only; `command.execute`
dispatch is explicitly deferred (see UNDECIDED-1). The generic dispatch
table (`internal/commands/commands.go:751-788`, `registerCommand` at
`:759`) gains no plugin-command hook in v1. `raw` keeps working because
`LookupRoute` + `Total()` are adapter operations served from the §3.5
route snapshot, and the 258-route table's source of truth
(`internal/proto/routes.json`, embedded at `internal/proto/proto.go:32-39`)
moves with the plugin (§2.5).

### 2.4 UNDECIDED rows — explicit decisions, not silent defaults

- **UNDECIDED-1 — `command.execute` dispatch.** No dispatch path exists
  (§1.2). Options: (a) defer indefinitely, CLI stays core behind
  `provider.call` (this plan's recommendation, D-COMMANDS); (b) build
  dispatch in a later PR, with plugin-registered commands entering
  `commandTable` and exit-code mapping defined. Deciding (b) requires a
  separate design for help/flags/exit codes; it is out of scope for
  extraction v1 and must not be started inside PR-6.
- **UNDECIDED-2 — `conn.Muse` split.** Options: (a) move `Muse` into the
  plugin and have core own a renamed generic shared-connection manager;
  (b) keep `Muse` in core as the single-provider connection manager
  (this plan's recommendation, D-CONN). The code does not decide this;
  (a) is cleaner for a second provider, (b) is the smaller diff and keeps
  every call site working. No PR may move a `rt.Muse` call site until
  this is re-decided with a second provider in view.
- **UNDECIDED-3 — pure `Waiter`.** Stays in core per D-BOUNDARY-1. If a
  second provider reuses turn-end semantics, staying wins; if not, core
  holds a generic-in-name-only package. Record the residual honestly:
  "generic-shaped, single consumer" — no second provider exists in the
  tree, so any "provider-generic" claim is unproven by construction.
- **UNDECIDED-4 — web UI chat shapes.** `ChatSession`/`ChatEvent`/
  `ChatSendResult` (`internal/webui/chats.go:62-94`) stay as the core chat
  contract for v1; the frontend Chats page is unchanged. A second provider
  either reuses them or needs its own — decide with UNDECIDED-3, do not
  silently keep Muse shapes as "the" chat contract.
- **UNDECIDED-5 — profile provider fields.** No `provider`/`plugin` field
  exists on `Profile` or `KeeperEntry`, and the `plugins` block has no
  profile association. `DECISION D-ASSOC` (v1): a single Muse plugin
  entry serves all profiles; per-profile egress/identity are built per
  `Runtime` from that plugin's `Desired` (§3.2–3.4). `VMID`/`NodeID`/
  `SubscriptionActionID` stay as Muse-shaped data in the generic profile
  container. A profile↔plugin association schema is deferred until the
  second provider; inventing one in v1 would be speculative config.
- **UNDECIDED-6 — no-plugin flavour.** See §3.8. This is a Boss decision
  that gates PR-6; the plan recommends fail-closed (below) but does not
  presume it.
- **UNDECIDED-7 — provider↔profile association for keeper entries.**
  `KeeperEntry.Profile` is a profile *name*
  (`internal/profile/keeper.go:298`; the struct starts at `:296`). The keeper parametrisation (§3.7)
  must not invent a second association scheme; it reuses the profile name
  and D-ASSOC.

## 2.5 Layout, shared helpers, and the auth-chain duplication

`DECISION D-LAYOUT` (recommended by this plan; PR-2's design section
ratifies it before PR-3 starts, and PR-3 re-runs its load proof if the
ratified layout differs — see §4, PR-2/PR-3): the plugin is an
**in-repo plugin tree under the same Go module** (a new directory in the
castctl module, e.g. a plugin tree beside `internal/`, whose exact path
PR-2 fixes). Rationale, from the Go `internal/` rule: the moving gateway
files import `internal/conn`, `internal/proto`, `internal/logging`, and
`internal/redact` (import table below), which no separate-repo module
may import. The alternatives are (b) moving `proto`/`conn`-facing pieces
to public packages — a larger API-stability commitment than extraction
needs — or (c) duplicating the wire code — a drift risk for 258 routes
plus protobuf framing. Under (a) no dependency shedding is needed for
`conn`/`proto`/`logging`/`redact`; the one dependency that MUST be shed
is `internal/outbound`, for the handoff reason in §1.3. If Boss later
requires a separate repo, D-LAYOUT is revisited and (b)/(c) are
designed then; no PR in §4 may assume a separate repo. PR-6's entry
criterion requires PR-3's evidence to have been produced in the final
layout (§4, PR-6).

Per-file `internal/` imports of the moving files (verified by import
grep at this HEAD; stdlib-only files list no `internal/` import):

| File(s) | `internal/` imports | Shedding under D-LAYOUT |
|---|---|---|
| `internal/gateway/connector.go` | `internal/conn`, `internal/logging`, `internal/outbound` | Shed `internal/outbound` only: the `OutboundDialer` interface (`internal/gateway/connector.go:25-35`, `WebSocketDial` + `HTTPClient`) is replaced by a plugin-local dial surface fed by the host-provided egress proxy (§3.3/§3.6); the plugin never imports the outbound `Dialer`. Keep `conn` (error types, `Gateway`/`Leaser` conformance) and `logging`. |
| `internal/gateway/gateway.go`, `calls.go`, `routes.go`, `stream.go` | `internal/conn`, `internal/proto` | None: keep both under the same module. |
| `internal/gateway/framing.go`, `shutdown.go` | `internal/proto` | None. |
| `internal/gateway/subscription.go`, `invite.go`, `auth.go`, `authcookies.go`, `cookies.go`, `lease.go`, `phase.go`, `transient.go` | `internal/conn` | None. |
| `internal/gateway/redact.go` | `internal/logging`, `internal/redact` | None. |
| `internal/gateway/summary.go` | `internal/conn`, `internal/logging` | None. |
| `internal/gateway/clock.go`, `timings.go` | none (stdlib only) | MOVE with the connector/gateway (see per-helper table below). |
| `internal/gateway/jsonutil.go`, `redact.go`, `summary.go`, `transport.go`, `media.go` | `internal/conn` (`summary.go` only, via `GatewayError`); `internal/logging` + `internal/redact` (`redact.go`); none (others) | DUPLICATE or MOVE per the per-helper table below — not "move with the package" as a group. |
| `internal/gateway/doc.go` (264 lines, package doc) | none | Split, not moved whole: PR-6 rewrites it into a core-side doc (what stays) and a plugin-side doc (what moved); neither half may describe the other side's code as current. |
| `internal/gateway/lost.go`, `keepalive.go`, `ended.go`, `generation.go`, `handshake_log.go` | `internal/conn` (`lost.go`), gorilla only (`keepalive.go`), none (others) | None: move with the gateway package. |

Per-helper assignment (ratified in PR-2; usage verified by grep at this
HEAD — "MOVE" = file moves to the plugin tree, "STAY" = file stays in
the core session-helper package, "DUPLICATE" = identical copies in
both (modulo the package clause), core copy is the source of truth
and PR-6's file list asserts the copies agree):

| Helper file | Users (verified) | Assignment |
|---|---|---|
| `redact.go` (`redactErr`, `internal/gateway/redact.go:65`) | MOVE: `gateway.go` (handshake/frame errors); DUPLICATE copy: `auth.go` (auth chain); STAY: `subscription.go` (Next.js fetch) | DUPLICATE. |
| `jsonutil.go` (`decodeJSONValue`/`decodeJSONObject`/`ValidationError`, `internal/gateway/jsonutil.go:18,28,53`) | MOVE: `calls.go`, `stream.go` (`encodeBody`); DUPLICATE copy: `auth.go`, `authcookies.go`; STAY: `invite.go`, `wake.go` | DUPLICATE. Duplicated `ValidationError` types are distinct Go types: cross-boundary identity is by envelope error code (§3.5), never by `errors.As` on the plugin type. |
| `summary.go` (`summarizeBody`/`gatewayErrorFromSummary`, `internal/gateway/summary.go:213,247`) | MOVE: `calls.go`; DUPLICATE copy: `auth.go`, `authcookies.go`; STAY: `invite.go`, `wake.go`, `subscription.go` (`summarizeParsedBody` at `:345`) | DUPLICATE (both copies produce the shared `conn.GatewayError` type, so the typed error itself is identical). |
| `transport.go` (`wrapTransportError`, `internal/gateway/transport.go:56`) | MOVE: `connector.go`; DUPLICATE copy: `auth.go`; STAY: `subscription.go` | DUPLICATE. |
| `clock.go` (`Clock`/`Ticker`, `internal/gateway/clock.go:19-26`) | MOVE only: `connector.go`, `gateway.go`, `keepalive.go` (via `g.clk()`, `internal/gateway/keepalive.go:174`) | MOVE. No staying file uses it. |
| `timings.go` (`HandshakeTimings`, `internal/gateway/timings.go:29-39`) | MOVE only: `connector.go`, `gateway.go` | MOVE. |
| `media.go` (`MediaPath`) | MOVE only: `calls.go` (`internal/gateway/calls.go:231`) | MOVE. |

`doc.go` split home: `doc.go` (264 lines) is split, not moved whole
(table above). The `gatewaytest` differential-harness note at
`internal/gateway/doc.go:17` belongs to the CORE-side doc: the harness
stays in core (below), so the sentence is carried into the core-side
doc rewritten to name the harness's new proto import path, and does
not appear in the plugin-side doc.

Proto import path for the staying harness (PR-2 ratifies the exact
path): `internal/proto` moves to the plugin tree (e.g.
`<plugin-tree>/proto`, path fixed by PR-2 with D-LAYOUT). The staying
`gatewaytest` harness imports the MOVED proto package at its new
same-module path (`internal/gateway/gatewaytest/server.go:18` today
imports `internal/proto`; after the move it imports the plugin
tree's proto package). This is a TEST-ONLY import: `gatewaytest`
speaks the protobuf wire format via descriptors only and never reads
`routes.json` directly, so the plugin tree's `routes.json` remains
the single source of truth (§2.5). The moving gateway tests
(`internal/gateway/*_test.go`) move with the package and import the
same path. Production-vs-test distinction: no non-test core package
may import the plugin tree — the plugin-tree import is permitted
only in `gatewaytest` and in `_test.go` files, enforced by the
dependency-list test in the import allowlist below. If both a core
differential harness and a plugin-local test fake exist, they stay
consistent by sharing the single fixture corpus named in §2.5
D-AUTHCHAIN (one corpus location, run against both); the plugin
copy is a test fake only, never the core differential harness, and
a plugin fake that diverges from the corpus fails review.

Import allowlist for the plugin tree (safety OBS-3): the plugin
tree may import `internal/conn`, `internal/proto` (its own subtree),
`internal/logging`, and `internal/redact` only, plus stdlib and the
third-party wire libraries it already uses (gorilla, noise,
protobuf). It must NOT import `internal/profile` (credentials/cookie
store), `internal/keeper`, or `internal/outbound` by any path, nor
`internal/gateway/gatewaytest` in production code. PR-2 states the
allowlist; PR-6 adds a dependency-list test (e.g. `go list -deps`
over the plugin tree, asserted against the allowlist) that fails
the build on any other `internal/` import. The allowlist is the
compile-time counterpart of the §1.3 handoff rule (which forbids
*receiving* those objects); under the trusted model it is a
contract/review enforcement, not a sandbox.

`gatewaytest` ownership: `internal/gateway/gatewaytest` (fake server
speaking the protobuf wire format via `internal/proto`,
`internal/gateway/gatewaytest/server.go:18`) STAYS in core. Core tests
depend on it: `internal/commands/read_test.go`, `profile_test.go`,
`fs_test.go`, `commands_test.go`, `cmd/castctl/wait_test.go`,
`cmd/castctl/chat_test.go`, and `internal/wait/gateway_test.go` import
it. After `internal/proto` moves, it imports the moved proto package
at the new same-module path stated above (test-only import). PR-6 must
name a replacement/harness for any core test importer it displaces,
or leave the harness in place; duplicating it into the plugin tree
is permitted only as a plugin-local test fake, never as the core
differential harness. The two copies, if both exist, stay consistent
through the single shared fixture corpus (above): a plugin-local
fake is run against the same corpus files as the core harness, and
divergence fails review.

`DECISION D-AUTHCHAIN` (CONDITIONAL move — see the condition below):
`NewConnector` (`internal/gateway/connector.go:131-199`) MOVES with
the plugin, but ONLY in refactored form: the plugin-side connector
never calls `LoadCookies`, never receives a cookie string, and never
receives a cookie path. The lawful cookie-input mechanism is the
core-owned egress proxy, and it is the ONLY one: the plugin's
auth-chain HTTP client is an `*http.Client` whose transport routes
through the egress proxy described in the plugin's `RegisterRequest`
egress block (`internal/pluginabi/pluginabi.go:174-180`: loopback
proxy URL plus ephemeral username/password), and the plugin's
`Fetch*` calls run with an EMPTY cookie argument (`""`). The empty
argument is safe because `hatchHeaders`
(`internal/gateway/auth.go:29-43`) sets the `Cookie` header from it
and the proxy overwrites it: `serveForward` sets the session cookie
for declared hosts and deletes any plugin-sent `Cookie` header for
every other host (`internal/pluginhost/egress.go:318-322`), and
strips `Set-Cookie` from responses so a rotated cookie never leaks
into plugin hands (`internal/pluginhost/egress.go:329-333`). The
plugin must declare `muse.ai` in its registration `cookie_hosts`
for this to work; an empty declaration means no injection and the
auth chain fails closed. `LoadCookies`
(`internal/gateway/cookies.go:35-40`, file read at `:35-40`) and
`ParseCookies` (`internal/gateway/cookies.go:45`) do NOT move and
are NOT duplicated: they stay core-only (their core callers are
the keeper at `internal/keeper/tick.go:468`, the web UI import
scan at `internal/webui/handlers.go:646`, and `auth import` at
`internal/commands/authimport.go:140`). A plugin-side
`LoadCookies` call, a plugin-side cookies-file read, or any
cookie string/path reaching the plugin by any channel (including
through a `gateway.open` payload or a fragment field) fails review
and is a STOP. The plugin carries its own copies of the plain
fetchers `FetchSessionInfo`/`FetchAccessToken`/`FetchHatchToken`
(`internal/gateway/auth.go:119-137`) plus the raw helpers they
call (`doHatch`/`hatchHeaders`, `fetchSessionInfoRaw`/
`fetchAccessTokenRaw` at `internal/gateway/authcookies.go:58-126`)
and the summary/JSON/transport helpers they depend on (see the
per-helper table below); the core copies stay (§2.2) because the
keeper cheap chain (`internal/keeper/tick.go:51-76`) and the
`auth import`/`usage`/`invite`/`wake` commands depend on them. The
`Fetch*WithCookies` variants stay core-only: only
`FetchSessionInfoWithCookies` and `FetchAccessTokenWithCookies`
exist (`internal/gateway/authcookies.go:99,128`, both serving the
keeper chain that stays in core); there is no
`FetchHatchTokenWithCookies`, and the plugin duplicates no
`*WithCookies` variant. No handoff call can serve the plugin
instead: the only reverse callback is `host.log`
(`internal/pluginhost/host.go:911-916`), and a `host.auth.*`
surface is deliberately absent. CONDITION: if PR-3/PR-6 cannot
build the proxy-routed auth-chain client above (for example the
plugin cannot route its `*http.Client` through the egress proxy
with the ephemeral credentials), D-AUTHCHAIN is revisited and the
boundary moves — the connector does not move in unrefactored,
file-reading form. Sync rule for the duplicates: any change to the
chain's wire behaviour (URLs, headers, token handling, error
classes) must change both copies in the same PR and must be
covered by the same differential fixtures (see the mechanical
check below); a PR that changes one copy without the other fails
review. The sync rule governs the duplicated chain's wire
behaviour; it does not extend the §3.8 descriptor
URL-parameterisation to the out-of-scope call sites listed
there. The sync rule additionally requires BOTH copies to
preserve: (i) hatch-token non-retention — "No hatch token is
retained after the handshake" (`internal/gateway/connector.go:130`;
the hatch token travels only in the WS URL at `:189` and is never
stored); (ii) allowlist-summary-only auth errors — no error from
the chain carries body bytes (`internal/gateway/auth.go:113-117`;
`internal/gateway/authcookies.go:111-112`); (iii) `AuthError`
typing for auth failures — on the core side the cookie-file
failure is typed `AuthError` at
`internal/gateway/connector.go:149-168`, and on the plugin side
every `Fetch*` non-200 failure is typed `AuthError` with no
cookie-file failure path existing at all, while transport errors
are left untyped for the caller (see `doHatch`'s contract,
`internal/gateway/auth.go:50-66`). Mechanical check (F7, REQUIRED
in PR-2's D-AUTHCHAIN criterion): a single shared fixture corpus —
the differential fixtures both copies are tested against, held in
ONE corpus location named by PR-2 (the core `gatewaytest` harness
is the corpus runner for the core copy; the plugin copy is run
against the same corpus files, not a second, diverging corpus) —
is run against BOTH auth copies, and a behaviour-equality test in
the style of the §3.8 fixture option (ii) asserts byte/behaviour
equality of the two copies' wire behaviour (request URLs,
headers, error classes) for every corpus case. The core copy is
the source of truth: when the copies disagree, the core copy's
behaviour wins and the plugin copy is fixed to match it in the
same PR. A review-only "change both copies" rule with no such
check fails PR-2. PR-2/PR-3 criterion: a plugin-built gateway
completes the auth chain live on cue through the egress proxy
(PR-3, §4), or a stated decision is recorded that it cannot and
the boundary moves — the boundary is not left ambiguous into PR-6.

`routes.json` source of truth: the embedded table
(`internal/proto/routes.json`, via `RoutesJSON()` at
`internal/proto/proto.go:61`) has exactly one source — the plugin tree
after PR-6. Core holds no copy; core reads routes only through the
adapter operations in §3.5. PR-6's design section names the file's new
path; a second copy anywhere in core fails review.

## 3. Seams to add

Each seam names the cut point (`file:line`) where new code attaches and
what does not exist today. Nothing in this section claims a seam already
exists unless cited.

### 3.1 S1 — Runtime wiring seam

Cut point: `defaultBuildRuntime`, `internal/commands/runtime.go:195-370`,
specifically between dialer construction
(`internal/commands/runtime.go:344-348`) and `conn.Muse` construction
(`internal/commands/runtime.go:357-368`). Missing: construct a
`pluginhost.Host` with a lifetime owned by `Runtime` (closed in reverse
order with the existing `closeFuncs`), resolve the `Desired` list (§3.2),
build per-profile egress proxy + identity (§§3.3–3.4), call `ApplyConfig`,
and decide what `rt.Muse` becomes. Per D-CONN, `rt.Muse` stays a
`*conn.Muse`; what changes is its `Connector`: the connector becomes a
plugin-backed connector (via the §3.5 adapter) when a Muse plugin is
loaded, and remains `gateway.NewConnector` until extraction (PR-1 must
prove the wiring with a non-Muse plugin without touching the Muse path —
see §4, PR-1). `Runtime` gains exactly one new field (the host or a
plugin-connection holder); no other `Runtime` field changes shape in the
wiring PR. Close ordering `DECISION`: the host closeFunc is appended
BEFORE the `muse.Close()` closeFunc, so `Runtime.Close`'s reverse-order
run (`internal/commands/runtime.go:84-95`; `muse.Close()` appended last
at `:369`, hence run first) runs `muse.Close()` first — `StopHeartbeat`
+ `Reset`, which bumps the generation and closes the old gateway
(`internal/conn/conn.go:647-650`) — and `Host.Close` last, after every
in-flight gateway call has been closed or fused. PR-1 must test this
order explicitly, including the hang-plugin case in §3.7; appending the
host close after the muse close (so it would run first) is forbidden by
this decision.

### 3.2 S2 — Desired resolution / discovery root

Cut points: `SingleConfig.Plugins` (`internal/profile/config.go:61`),
`PluginEntry.FragmentJSON()` (`internal/profile/plugins.go:77-85`),
`Discover` (`internal/pluginhost/discovery.go:191-243`). Missing:

- (a) Plugin directory / discovery-root source. No config field exists.
  `DECISION D-DISCOVERY` (proposal, needs approval as new config
  surface): default root `<config-dir>/plugins`, overridable by a new
  `dir` field in the §3.12 host block; absent block means no discovery
  root and therefore no plugins loaded (fail-closed), except the
  explicit path in `plugin check`. No other default path may be invented
  silently.
- (b) Mapping `PluginEntry` → `Desired{Tag, Type, Path, Fragment}` via
  `FragmentJSON()` + `Discover` (version-preference selection, platform
  dir first, symlink entries skipped, missing root is an error —
  `internal/pluginhost/discovery.go:185-243`). Mapping rule
  (DECIDED here): a discovered `File` matches an entry if and only
  if `File.ID == PluginEntry.Tag`. `File.ID` is derived from the
  filename: the basename minus the platform extension, minus a
  `-v<version>` suffix when present
  (`internal/pluginhost/discovery.go:47-56,75-110,191-243`); the
  file carries no type, so `Type` comes from the entry alone and
  the tag≠type case needs no rule — a file named for the tag with
  any entry type matches. A discovered file matching NO entry is
  ignored: it is never loaded and is not an error. An entry with
  no matching file is unresolvable under (d). Check ordering
  (REQUIRED): the multi-entry fail-closed check in (e) and the
  per-entry resolution in this item run BEFORE any egress proxy is
  built (§3.3), before any stripped identity is constructed (§3.4),
  and before any `ApplyConfig` runs — resolving, counting, and
  rejecting happen on data only, so a rejected second entry never
  receives this profile's egress proxy or identity.
- (c) `ManifestPath` policy: none exists. `DECISION`: manifest verification
  stays opt-in and caller-supplied (as `Desired.ManifestPath`,
  `internal/pluginhost/host.go:94-97`); no store/download/registry/signing
  is added (BQ4, `docs/architecture.md:21-49`). The wiring PR must state
  the policy (manifest path from the host block, or none) — it cannot
  leave the field silently unset while claiming verification.
- (d) Absent `plugins` block (nil, `internal/profile/plugins.go:49-53`)
  means no plugins; present-but-unresolvable means fail-closed with exit
  2 naming the entry (not warn-and-skip at the `Runtime` level —
  warn-and-skip semantics in `ApplyConfig`,
  `internal/pluginhost/host.go:369-534`, apply when reconfiguring an
  already-loaded plugin, not to a first-load failure of the only
  provider: the distinction is caller-side — construction-time first
  load fails closed — because no runtime re-apply path exists today
  (`ApplyConfig`'s only production caller is `plugin check`, §1.2, and
  `Runtime` is built once per invocation,
  `internal/commands/runtime.go:195`). The wiring PR must write this
  rule down and test it; the current code does not state it.
- (e) Multi-entry and zero-file rules. `DECISION D-MULTIENTRY` (PR-1
  entry decision, before PR-1): a single-profile `Runtime`
  (`internal/commands/runtime.go:195`) with more than one resolved
  `Desired` entry fails closed with exit 2 naming the entries
  (single-entry-only for v1). Load-all is rejected for v1: it would
  hand every loaded plugin this profile's egress proxy and stripped
  identity, an over-exposure with no profile-to-plugin association to
  bound it (UNDECIDED-5). The over-exposure is recorded here as the
  reason, not hidden. Zero-file discovery is unresolvable: an entry
  whose discovery root exists but yields no binary for it is
  present-but-unresolvable under (d) (exit 2 naming the entry), never
  a silent empty `Desired` list — PR-1 must define the check against
  `Discover`'s result (`internal/pluginhost/discovery.go:191-243`,
  which errors on a missing root) and test it.

### 3.3 S3 — Per-profile egress proxy construction

Cut point: `NewEgressProxy(upstream, dial, cookie)`
(`internal/pluginhost/egress.go:89`). The wiring must supply all three,
and no production code supplies any of them today (§1.2):

- Upstream `http.RoundTripper`: derived from the profile outbound.
  Candidate source is `Dialer.HTTPClient()`
  (`internal/outbound/dialer.go:207`), which builds a fresh `*http.Client`
  with an inline `*http.Transport` on every call. `DECISION`: the wiring
  PR adds exactly one accessor on `Dialer` returning the outbound-derived
  `RoundTripper` (reusing the client's `Transport` field, or a new
  method — the PR decides, with the constraint that the egress proxy
  receives a `RoundTripper`, never a `*http.Client`, per
  `internal/pluginhost/egress.go:89-96`). It must not reuse
  `http.DefaultClient` (forbidden by `Runtime.HTTPClient`'s contract,
  `internal/commands/runtime.go:101-110`).
- Dial func for CONNECT: the egress dial signature is
  `func(ctx, network, addr string) (net.Conn, error)`
  (`internal/pluginhost/egress.go:89`). `Dialer.DialContext`
  (`internal/outbound/dialer.go:127`) takes `(ctx, network, host, port)` —
  an adapter splitting `addr` is required. `OutboundDialer.WebSocketDial`
  (`internal/gateway/connector.go:31-35`) is WebSocket-specific and is
  NOT a generic TCP dial; it must not be reused as the CONNECT dial.
  If no CONNECT dial is supplied, `serveConnect` returns 502
  (`internal/pluginhost/egress.go:352-360`) — PR-1 decides only the
  generic dial-adapter default (whether the wiring supplies a dial
  func at all, and the 502-on-absent behaviour as the default); the
  decision whether the Muse plugin needs CONNECT is PR-3's, on its
  §3.6 measurement, and PR-1 must not pre-decide it.
- Cookie string: `Runtime.Cookies()` (`internal/commands/runtime.go:112-132`,
  loading via `LoadCookies`, `internal/gateway/cookies.go:35`). The cookie
  VALUE is passed into `NewEgressProxy` in core; it never appears in any
  `RegisterRequest` (§1.3). Ownership/lifetime: host adopts only on
  successful registration (§1.3); the wiring owns all failure paths and
  must close unadopted proxies. One proxy per plugin session (per
  `Runtime`): sharing one proxy across tags makes cookie scope
  last-writer-wins (§1.3) — the wiring PR must not share proxies across
  profiles.

### 3.4 S4 — Stripped-hash identity construction

Cut point: `NewPluginIdentity(tag, outboundRawJSON)`
(`internal/pluginhost/identity.go:37`). Missing wiring: the RAW outbound
JSON bytes for the profile's resolved outbound. `OutboundIdentityForConfig`
resolves the tag but returns only the raw hash
(`internal/profile/identity.go:86-95`); the raw bytes are not exposed.
`DECISION`: the wiring PR adds one exported accessor in `internal/profile`
returning the resolved outbound's raw JSON bytes for the named profile
(reusing the existing resolution logic: the canonical-bytes path `canonicalOutboundBytes`/`rawOrMarshal` at `internal/profile/identity.go:137-163`), and calls `NewPluginIdentity` with
them. It must NOT reuse `OutboundIdentityForConfig`'s hash (§1.3). For
direct/inline profiles the same accessor must return the fixed-shape or
inline bytes the reconnect identity uses, so identity construction and
reconnect identity cannot silently diverge — the PR must test that the
stripped hash is blind to secret rotation (a secret-only edit leaves the
hash unchanged; a type change changes it, per `docs/plugins.md:350-365`). The accessor is wiring-internal-only:
its doc comment must say so, and PR-1 must add a test asserting its
output is never placed in a `Desired`/`RegisterRequest` field (the raw
bytes are secret-bearing; only the stripped hash from
`NewPluginIdentity` crosses, §1.3).

### 3.5 S5 — `provider.call` operation-schema gap (largest undefined surface)

Nothing exists. The ABI defines the envelope only
(`internal/pluginabi/pluginabi.go:59-61`); the only in-repo payload
example is the echo fixture's `{"input":"ping"}` →
`{"payload":"echo:ping"}` (`examples/plugin/echo/main.go:112-117`) and the
`plugin check` probe (`internal/commands/plugincheck.go:136`). There is no
Muse-operation schema anywhere in `pluginabi`, `pluginhost`, or the docs.

`DECISION D-SCHEMA` (to be settled in PR-2, before any extraction PR):
define a versioned JSON operation schema for `provider.call` requests in a
new spec section (an addition to `docs/plugins-spec.md`, not a rewrite).
Batching is a PROPOSAL for PR-2 to confirm, not settled design: the
claim that "no long-lived stream crosses the ABI" is withdrawn as a
decision until PR-2 confirms it against the callback contract below.
The schema must define, one operation per `Gateway` method (§1.4) plus
the operations the contract requires beyond the 14 methods:

- Gateway connect/open (REQUIRED). The plugin-backed `Connector`
  (`conn.Connector`, `internal/conn/gateway.go:116`) is invoked via
  `BoundedConnect` (`internal/conn/conn.go:330-401`), which runs the
  connector synchronously with a time bound and returns a live
  `Gateway` whose `Alive`/`Dead`/`LastRecv` are meaningful before any
  call. The schema therefore needs an explicit `gateway.open`
  operation — the establishment trigger for D-STATE (§3.7), which has
  no trigger without it — rather than an implicit-open rule: the
  adapter sends `gateway.open` once per `Connector` invocation and
  maps its result onto a live adapter `Gateway`; `Alive` before a
  successful open is false, and no unary/subscribe operation may be
  issued before open succeeds. `gateway.open` inputs, enumerated
  exhaustively: `VMID` and `NodeID` (the non-secret identity fields of
  `conn.Config`, `internal/conn/gateway.go:91-97`, built from the
  profile at `internal/commands/runtime.go:153-165`) and the TLS
  options channel defined below (§3.6, TLS-options channel). Explicitly
  NOT inputs: `CookiesFile`, the raw outbound hash produced by
  `OutboundIdentityForConfig` (`internal/profile/identity.go:80-86`;
  the adapter must never forward the raw hash the core
  `connectorConfig` computes at `internal/commands/runtime.go:153-165`
  — the stripped identity already crossed at registration, §1.3, and
  is not repeated here), any cookie value, any cookie path, any
  access/hatch token (tokens are produced inside the plugin by its
  auth chain and are never supplied, §2.5 D-AUTHCHAIN), and any
  outbound tag/hash field. The plugin's warm connection is owned by
  the open/close pair: `gateway.close` (below) is the only teardown
  operation, and the adapter's `Close()` is the exercised teardown
  path (§3.5, lease paragraph; §3.7).
- TLS-options channel for `gateway.open` (REQUIRED, defined by PR-2).
  The fingerprint name alone does not reproduce the profile's TLS
  options: `GatewayTLSOptions`
  (`internal/outbound/tls.go:15-43`, function at `:35-46`) takes the
  profile's full `option.OutboundTLSOptions` and fills the `"chrome"`
  uTLS default, and the WS dial applies the resulting options via
  `DialTLS` (`internal/outbound/dialer.go:252-257`) with only the
  ALPN pin overridden at the call site
  (`internal/gateway/connector.go:265`). PR-2 must therefore define
  a named core accessor — e.g. a `GatewayTLSOptionsForPlugin` accessor
  in `internal/outbound` returning the effective options with
  secret-bearing fields (any key/certificate material) stripped, plus
  the serialisation the open payload carries — and the open payload
  carries exactly that serialised, secret-free subset, never the raw
  profile TLS block. Until PR-2 names the accessor and the field
  allowlist, no fingerprint claim in §3.6 is a defined channel.
- Unary call, raw request, subscribe-JSON, download, ping, open/cancel
  stream (stream IDs held plugin-side, operations `stream.open`/
  `stream.cancel` + batched reads), route lookup, liveness
  (`Alive`/`Dead`/`LastRecv`/`LastUsed` as state queries), and close.
- Subscribe callbacks (REQUIRED — no schema without them).
  `SubscribeOptions` carries `OnRecord`, `ShouldStop`, and `OnOpen`
  (`internal/conn/gateway.go:184-206`; fields at `:204-206`), and the
  `wait` Runner depends on them (`internal/wait/runner.go:553-554`:
  `OnRecord: r.onRecord(ctx)`, `ShouldStop: r.shouldStop(ctx)`).
  `SubscribeRaw` blocks up to the overall timeout (120s default)
  draining records into the returned `[][]byte`
  (`internal/gateway/calls.go:261-275`). PR-2 must choose one of: (i)
  poll/halt operations — `subscribe.open` returns a subscription id,
  `subscribe.poll` returns newly arrived records plus open/closed
  state, `subscribe.halt` stops it, and the adapter drives
  `OnRecord`/`ShouldStop`/`OnOpen` from poll results on the calling
  goroutine (preserving the "callbacks run on the calling goroutine,
  must not block" rule at `internal/conn/gateway.go:184-193`); or (ii)
  one blocking `provider.call` per subscribe, with the callbacks
  unrepresentable — recorded explicitly as a behaviour change for
  `wait`/`watch` latency (records visible only when the call returns,
  early-stop losing its live effect) AND its shutdown/fuse
  consequences stated (a blocked call can be ended only by context
  cancellation, which fuses the plugin,
  `internal/pluginhost/host.go:820-860`). Model (i) is recommended;
  model (ii) without the recorded behaviour change fails review.
  Halt/cancel ordering (REQUIRED, both models): every `Host.Call`
  whose context is cancelled fuses the plugin
  (`callEnvelopeClient`, `internal/pluginhost/host.go:820-860`: ctx
  Done → fuse + return `ctx.Err()`). Under model (i) the adapter must
  therefore issue `subscribe.halt` on a context that is NOT the
  poll's cancellable context — or on a fresh context — BEFORE
  letting a poll context cancel, so a wait timeout or early stop
  ends the subscription cleanly instead of fusing the Muse plugin
  for the rest of the invocation; a poll whose context cancels
  before its halt is sent is a fuse, not a clean stop. Under model
  (ii) fuse-on-timeout/cancel is a recorded behaviour change with
  the same consequence stated explicitly. Either way the
  `SharedConn` retry interaction must be stated: `retryCall`
  (`internal/conn/shared.go:161-216`) retries only `ConnectionDown`
  and safe-to-repeat `ConnectionError`, never a fused-plugin
  fail-fast error, so after a fuse every subsequent call in the
  invocation fails fast until a different-path load — the adapter
  must map a fused-plugin error to a typed error `retryCall` does
  not retry, and must not present it as a retryable
  `ConnectionDown`.
- `Leaser` / close semantics (REQUIRED). The adapter MUST implement
  `Leaser` (`internal/conn/gateway.go:344-352`): the `Leaser` marker
  is what `Muse.Live`/`Connect` type-assert
  (`internal/conn/conn.go:543,581`) to decide shareability. The true
  causal chain is: no non-test code calls `.Lease()` anywhere in the
  repo — the only `Lease()` implementations are
  `Gateway.Lease()` (`internal/gateway/stream.go:431`, returning a
  lease view) and `SharedConn.Lease()` returning itself
  (`internal/conn/shared.go:128`) — and `Live`/`Connect` never call
  it; they install the raw gateway in the shared slot when it
  implements `Leaser` and return a `SharedConn` wrapper whose own
  `Close` is a no-op (`internal/conn/shared.go:127-131`). `Reset`/
  `Drop`/`Live` close the RAW gateway stored in the shared slot
  (`internal/conn/conn.go:634-650`), never a lease view. The adapter
  therefore needs the `Leaser` marker plus a `Lease()` implementation
  (returning an adapter lease view whose `Close` is a no-op, for any
  caller that does call it), but the path `conn` actually exercises
  on replacement is the adapter's own `Close()`: adapter `Close()`
  must close the underlying warm connection (via the plugin-side
  `gateway.close` operation) when invoked on the raw adapter, and
  must be idempotent and safe concurrent with blocked calls (the
  `Gateway` contract, `internal/conn/gateway.go:253-290`). The
  earlier formulation — that `Muse.Connect` returns a `SharedConn`
  because `Lease()` returns a no-op-close view — is withdrawn: the
  `SharedConn` wrapper, not any `Lease()` call, supplies the no-op
  close. Teardown ownership when both signals fire: adapter
  `Close()` (via `muse.Close()` → `Reset`, §3.1) owns connection
  teardown; `plugin.shutdown` (via `Host.Close`, §3.7) owns plugin
  shutdown and must be safe to run after adapter `Close()` has
  already closed the connection — both paths are idempotent, and
  neither may assume the other has not run. PR-2 exit (ii) tests
  the `Leaser` marker + `SharedConn` no-op-close behaviour and
  adapter `Close()` teardown, not an unexercised `Lease()`
  no-op-close path.
- Generation bump (REQUIRED, or an explicitly decided loss). The
  adapter MUST implement the `generationBumper` hook with exactly the
  `BumpGeneration()` signature (`internal/conn/gateway.go:381-404`;
  `internal/gateway/generation.go:51`), by sending a
  `generation.bump` operation; `conn` calls the hook on every
  replacement (`internal/conn/conn.go:640` in `Reset`) so stale queued
  frames are dropped. A `Gateway` without the hook is silently
  accepted and the bump becomes a no-op
  (`internal/conn/gateway.go:381-404` comment) — PR-2 must decide
  explicitly: the bump operation is REQUIRED (the adapter fails closed
  if the plugin does not implement it; recommended), or its loss is
  accepted and recorded as a behaviour change (stale-frame filtering
  silently degrades after extraction). Silence on this point fails
  review.
- ConnectionDown distinction (REQUIRED). The plugin must signal
  down-before-open vs down-after-open distinctly: `ConnectionDown`
  only when the stream never opened (retried by `SharedConn` for every
  method); once `OnOpen` has fired or a frame has arrived, connection
  loss surfaces as `ConnectionError` (or the records gathered so far
  plus a distinguishable error), never as `ConnectionDown`
  (`internal/conn/gateway.go:253-290`; `ConnectionDown` at
  `internal/conn/errors.go:199-216`, `ConnectionError` at `:241`).
  The adapter maps the plugin's error codes onto `conn.ConnectionDown`
  / `conn.ConnectionError` accordingly; a single undifferentiated
  transport error code fails review.
- Route count/list (REQUIRED). The adapter must serve `Total()` and
  connection-less `LookupRoute` (`internal/gateway/routes.go:107,99`;
  `SharedConn.LookupRoute` answers "without opening a connection" from
  a snapshot, `internal/conn/shared.go:119-126`): operations
  `routes.total` and `routes.list`, with the adapter caching a route
  snapshot at load so `cmdRaw`'s pre-connection validation (unknown
  method → exit 2 before any connection, message using `Total()`,
  `internal/commands/read.go:1022-1027`) keeps working without the
  plugin loaded-and-connected. A per-call-only lookup that requires
  the plugin loaded before validation is a recorded behaviour change,
  not the default.
- Framing/validation typed errors (REQUIRED, or a recorded exit-code
  change). The adapter must re-create the typed errors
  `classifyError` maps (`internal/commands/commands.go:305-327`):
  `gateway.ReassemblySizeError` (`internal/gateway/framing.go:135`,
  exit 3), `gateway.TooManyUnfinishedGroupsError`
  (`internal/gateway/framing.go:152`, exit 3), and
  `gateway.ValidationError` (`internal/gateway/jsonutil.go:18`, exit
  2). The plugin signals them via stable envelope error codes; the
  adapter re-creates the typed Go errors so `errors.As` matches. If
  framing/validation move into the plugin without this reconstruction,
  exit codes 3/2 silently change — that change must be recorded as a
  behaviour change, not discovered in e2e.
- `GatewayError` / `TimeoutError` reconstruction (REQUIRED, or a
  recorded exit-code change — the same treatment as the framing
  errors above). `classifyError`
  (`internal/commands/commands.go:268-337`; `GatewayError` → exit 3
  at `:301-304`, `TimeoutError` → exit 4 at `:313-316`) maps both,
  and both are produced by the moving gateway code: `GatewayError`
  via `gatewayErrorFromSummary`
  (`internal/gateway/summary.go:213`) and direct construction in
  the subscription fetch (`internal/gateway/subscription.go:316,350`)
  and the auth chain (`internal/gateway/authcookies.go:76,81,91`);
  `TimeoutError` via the handshake paths
  (`internal/gateway/gateway.go:201,220`) and the call path
  (`internal/gateway/calls.go:165`). The plugin must signal both
  via stable envelope error codes carrying the full
  `GatewayError` fields (status, allowlist-summary payload, body
  length/known, content type, error code — the fields
  `gatewayErrorFromSummary` fills at
  `internal/gateway/summary.go:213-222`) and the `TimeoutError`
  message; the adapter re-creates the typed Go errors so
  `errors.As` matches and exit codes 3/4 are preserved, and so
  `SharedConn` retry classification (`retryCall`,
  `internal/conn/shared.go:161-216`: neither type is retried) is
  unchanged. A single undifferentiated transport error code, or
  mapping either type onto `ConnectionError`, fails review unless
  the exit-code/retry change is recorded as a behaviour change.
- Error mapping and redaction: error mapping (envelope errors become
  Go errors via `parseEnvelope`, `internal/pluginhost/host.go:865-886`;
  the plugin never picks an exit code,
  `internal/pluginabi/pluginabi.go:87-90` — the adapter maps plugin
  errors onto castctl's typed exit codes and the
  `internal/conn/errors.go:39` taxonomy, including `AuthError`
  surfacing, since auth-error handling today lives in `conn`
  callbacks, `internal/conn/conn.go:33-36`); a fused-plugin error
  shape (typed error + exit code for `wait`/`send` callers, per §5);
  and redaction/capping of successful `provider.call` results (the
  host redacts envelope *errors* and `host.log` only — §1.3;
  successful-result redaction is the caller's job, and the adapter is
  that caller). The alternative — growing the ABI to a schema-2
  capability carrying the `Gateway` interface — is explicitly rejected
  for v1: it would duplicate the interface across a C ABI for one
  consumer. PR-2's stop condition: if the schema cannot express
  streaming + shared-connection lease semantics (S7) without inventing
  a second transport, D-BOUNDARY-1 is revisited and extraction stops.
  The same stop applies if the schema cannot express `gateway.open`,
  the `GatewayError`/`TimeoutError` reconstruction, or the
  halt/cancel ordering above.

The plugin side of the schema (the 258-route table,
`internal/proto/routes.json`, plus protobuf/Noise stack, §1.4) moves with
the plugin (§2.1); the core side is a new, small adapter (new file(s) in
`internal/commands` or a new package — PR-2 names the location)
implementing `conn.Gateway` over `Host.Call`. The adapter must be testable with `plugintest` fakes
(`internal/plugintest/fake.go:60-144`) without a real `.so`.

### 3.6 S6 — Gateway transport seam (WS/Noise dial vs HTTP egress)

The Muse gateway needs a raw `net.Conn` from `OutboundDialer.WebSocketDial`
(`internal/gateway/connector.go:265`, the call; the interface is at
`internal/gateway/connector.go:31-35`) plus an `*http.Client` for the auth
chain. The egress proxy offers HTTP forwarding and opaque CONNECT tunnels
— it does not offer a "dial me a pre-TLS conn" primitive, and the only
host callback is `host.log` (`internal/pluginhost/host.go:911-916`): no
`host.dial` callback exists. Three options, none implemented:

- (a) CONNECT-through-egress: the plugin's WS/TLS runs inside the opaque
  CONNECT tunnel. Consequence, stated plainly: core cookie scoping does
  not apply inside TLS (§1.3). The cookie-delivery channel problem
  (safety observation O-1) is conditional: IF the WS upgrade required
  a `Cookie` header, the plugin would have to set it itself inside
  TLS, because the proxy injects nothing into CONNECT
  (`internal/pluginhost/egress.go:343-360`) — and NO channel for
  delivering the session cookie to the plugin is named anywhere in
  ABI v1 or in this plan's §§1–3. The current upgrade sets no
  `Cookie` header (see the CONNECT scope note below), so this
  conditional does not block (a) on its own; it blocks (a) only if
  PR-3's measurement shows a header is required. No cookie value
  may cross in `RegisterRequest` OR in any `provider.call` payload
  (hard rule, §1.3 and §3.3). PR-3 must therefore either confirm no
  WS `Cookie` header is required, or name a delivery channel that
  satisfies that rule, or rule (a) out: (a) is an open question with
  a STOP gate, not a viable default. The PR-3 stop wording is
  disambiguated as follows: "observable plugin-side" means the cookie
  value appears in any host-visible surface — `host.log` output,
  envelope error text, echoed material, any `provider.call` payload,
  or `RegisterRequest` — and that outcome is STOP. "Held inside TLS"
  means cookie bytes exist only inside the TLS stream established
  through the tunnel and never appear in any host-visible surface —
  but the delivery channel by which they got there must still be named
  and must not itself be a host-visible surface. If no such channel
  exists, (a) is ruled out and PR-3 selects (b) or STOPs.
- (b) New `host.dial` callback (ABI schema 2): core dials through the
  outbound and hands the conn to the plugin. Cleanest enforcement-wise,
  largest ABI change; requires schema-version handling beyond v1.
- (c) Plugin links the core's outbound dialer as a Go dependency (c-shared
  library importing `internal/outbound`): rejected — it would hand the
  plugin the dialer itself, violating the handoff rule (§1.3), and
  entangle two Go runtimes' network stacks.

`DECISION`: PR-3 (spike/measurement, §4) must measure (a) live before (b)
is designed, under the O-1 channel rule above. No extraction PR may
assume (a) works. Fingerprint measurement (REQUIRED for (a)): the
observable is the captured ClientHello — ALPN list order, cipher-suite
order, TLS version, and extension order — captured at an observation
point PR-3 defines (proxy-side for the tunnel case; an equivalent
capture point for the baseline, since baseline traffic does not pass
the egress proxy) for (i)
the current direct-dial baseline (the outbound `Dialer` path,
`internal/gateway/connector.go:250-295`, with the uTLS `chrome`
default from `GatewayTLSOptions`,
`internal/outbound/tls.go:15-43`) vs (ii) the plugin's TLS through the
CONNECT tunnel, compared field-by-field; pass requires identity with
the baseline, where the baseline is the CURRENT castctl WS handshake
(including its existing ALPN pin to `["http/1.1"]`, stated in the comment
at `internal/gateway/connector.go:231` and applied in code at
`internal/gateway/connector.go:265`, which already differs from a
real Chrome hello `["h2", "http/1.1"]`), not a real Chrome hello. The
observation must not leak secrets (proxy-side counting/capture of the
unencrypted ClientHello only; no cookie, token, or key material in any
recorded output). uTLS mechanism for (a): the plugin must link a uTLS
stack with the profile's fingerprint preset — the same sing-box/common
uTLS the core uses, with the effective TLS options supplied through
the `gateway.open` TLS-options channel defined in §3.5 (the named
core accessor returning the secret-free serialised subset of
`GatewayTLSOptions`, `internal/outbound/tls.go:15-43`; never via
`RegisterRequest` fragment, which is config-authored, and never as
a bare fingerprint name alone) — or PR-3 records explicitly that (a)
changes the fingerprint as a behaviour change. Linking a different
TLS stack (e.g. stdlib `crypto/tls`) changes the fingerprint by
construction and is a recorded behaviour change, not a pass. (a) must
NOT be selectable on handshake success alone: without the ClientHello
comparison above, (a) is unselected. Cookie rotation (§3.3: the
core-side connector re-reads the cookies file on every connect,
`internal/gateway/connector.go:149`, and the plugin-side connector
re-runs its auth chain through the egress proxy on every
`gateway.open`, §2.5 D-AUTHCHAIN, never reading a file; the keeper
rewrites the file under lock (`LockCookiesFile` at
`internal/keeper/tick.go:366,428`, `WriteCookiesFileLocked` at
`internal/profile/cookielock.go:132`)) is a further gap under (a):
a rotated cookie requires core to rebuild or re-scope the proxy
(the proxy holds the cookie string passed to `NewEgressProxy`,
`internal/pluginhost/egress.go:89`) or re-register the plugin — no
code handles this today, and PR-3 must record the chosen mechanism
(proxy rebuild on re-register is the recommended default;
re-registration must not drop a warm connection silently — see S7).
CONNECT scope note: the proxy-injection mechanism in §2.5 covers
the HTTPS auth chain through `serveForward` only. It does not
extend to CONNECT: `serveConnect` is opaque and injects nothing
(`internal/pluginhost/egress.go:343-360`). The current WS upgrade
sets only `User-Agent` and `Origin`, no `Cookie` header
(`internal/gateway/connector.go:285-289`), with authentication
carried as the hatch token in the WS URL
(`internal/gateway/connector.go:189`) — so option (a) needs no WS
cookie-delivery channel for the current handshake, and none is
invented here. If PR-3's measurement shows the peer requires a
`Cookie` header on the upgrade, (a) is ruled out unless a channel
satisfying the §3.6 hard rule (no cookie value in
`RegisterRequest` or any `provider.call` payload) is named; the
STOP wording below applies to any such channel.

### 3.7 S7 — Shared-connection / lease seam

`conn.Muse` is a shared warm connection with heartbeat, transparent
reconnect, and `Leaser` semantics (`internal/conn/conn.go:30-148`,
`internal/conn/gateway.go:344-352`). A per-call `provider.call` model has
no shared-connection concept. `DECISION D-STATE`: the plugin owns the warm
connection, stateful across `provider.call`s; core's `conn.Muse` keeps
owning sharing/heartbeat/reconnect *over the adapter* (§3.5), and the
host lifecycle maps onto plugin connection lifecycle as follows:
`plugin.reconfigure` (same path) must not drop the warm connection;
`plugin.quiesce` + replace (different path) closes it; detach closes it.
`Host.Close` waiting on in-flight native calls is a known limit (U7,
`docs/plugins.md:578-615`); whether it hangs a Muse plugin mid-turn, and
whether the shutdown-join work (PR #38) composes with plugin shutdown, is
`[NEEDS-MEASUREMENT]` (§5, M-9). The wiring PR must add a hang-plugin
test (a plugin that blocks in `provider.call` past `Host.Close`) before
extraction; extraction must not land on an unmeasured shutdown path. Lease,
generation-bump, and close-ordering semantics are specified in §3.5 and
decided in §3.1; this section's lifecycle mapping assumes them: an
adapter `Close()` that fails to drop the raw warm connection, a
lease view whose `Close` is not a no-op, or a missing generation
bump, breaks this mapping and fails PR-2 review. Teardown
ownership when both close signals fire is stated in §3.5: adapter
`Close()` owns connection teardown, `plugin.shutdown` owns plugin
shutdown, both idempotent, neither assuming the other has not run.

### 3.8 S8 — Keeper parametrisation

Cut points (all Muse literals, §1.4): `FilteredDomains`
(`internal/keeper/jar.go:77`), `ExportURLs`
(`internal/keeper/export_cdp.go:77`), `exportHosts`
(`internal/keeper/export_cdp.go:159`), `screencastHosts`
(`internal/keeper/screencast.go:151`), `SessionCheckURL`/`AuthCheckURL`
(`internal/keeper/tick.go:27-28`), `DefaultLoginContract`
(`internal/keeper/contract.go:75`), launch URL
(`internal/keeper/launch.go:190`). `DECISION D-KEEPER`: introduce a
core-owned `ProviderSession` descriptor — type in a new file
`internal/keeper/provider.go`, created by PR-4 (if PR-4 chooses another
file, every criterion naming this file follows the type's file) —
carrying: check URLs, cookie domains, export URLs/hosts, screencast
hosts, login contract, launch URL, wake URL, session-cookie names
(ordered; the first is the driving-cookie name), the provider home
URL (for user-facing messages, below), and the export
fallback behaviour (§3.8 mapping table below). The descriptor is
consumed by the keeper through its existing interfaces
(`Checker`/`Exporter`/`ReloginDriver`, §1.4). Descriptor source
channel (DECIDED, PR-6): the descriptor is built from a new field
on the plugin's `Registration` response — field `ProviderSession`,
JSON key `provider_session,omitempty`, on `Registration`
(`internal/pluginabi/pluginabi.go:142-160`), a JSON object carrying
exactly the descriptor fields listed above (check URLs, cookie
domains, export URLs/hosts, screencast hosts, login contract,
launch URL, wake URL, session-cookie names, provider home URL,
export fallback). Precedent: `Registration` already carries
provider-declared data in `CookieHosts`
(`pluginabi.go:147-154`, documented "schema 1, additive").
Schema-version decision: ADDITIVE at schema 1 — no `SchemaVersion`
bump (the ceiling enforced by `ValidateRegistration`,
`pluginabi.go:216-218`, stays at 1); the field is `omitempty`, and
a registration used as the keeper-descriptor source that omits it
fails descriptor build closed, with no Muse-valued fallback
substituted. The field is on the `Registration` RESPONSE (plugin →
core); it does not change `RegisterRequest` (§1.3: exactly
fragment/schema/tag/type/identity/egress,
`pluginabi.go:190-199`), and it is not the verbatim `ConfigJSON`
fragment — the values are provider-declared, not config-authored.
Data path: the plugin's `register`/`reconfigure` returns a
`Registration` carrying `provider_session` → core validates the
registration through the existing schema gate
(`ValidateRegistration`) → core builds the `ProviderSession`
descriptor from the field at load, applying the §3.8 validation
at descriptor build → the keeper consumes the descriptor through
`Checker`/`Exporter`/`ReloginDriver`. PR-4 must not add this
field: PR-4 builds the descriptor from core-held Muse values, and
PR-6 adds the field and switches the source. Fetched-URL seam
(REQUIRED): the descriptor's check URLs are NOT the constants at
`internal/keeper/tick.go:27-28` — those constants are used only as
`toUpdates` labels (`internal/keeper/tick.go:69,76`), while the
URLs actually fetched are hardcoded inside the helpers:
`https://muse.ai/api/session` at
`internal/gateway/authcookies.go:59` and
`https://muse.ai/api/auth/check` at `:106`. Moving the constants
behind `ProviderSession` without changing the helpers would change
nothing fetched. PR-4 must therefore change the helper seam by signature change
only, and only on the descriptor-scoped paths: the keeper cheap
chain (`GatewayChecker`, `internal/keeper/tick.go:51-54`) and
`wireWake` (`internal/commands/keeper.go:419,423,439`). On those
paths only, every helper that fetches a descriptor URL gains a URL
parameter, and no URL-defaulting form remains on those paths. The
URL-parameterised helpers are `FetchSessionInfoAt` and
`FetchAccessTokenAt` (the plain fetchers at
`internal/gateway/auth.go:119,128`, each taking the fetch URL as a
parameter alongside the existing arguments),
`FetchSessionInfoWithCookiesAt` / `FetchAccessTokenWithCookiesAt`
(the `*WithCookies` variants at
`internal/gateway/authcookies.go:99,128`, core-only like their
predecessors), and URL parameters on the raw helpers
`fetchSessionInfoRaw` / `fetchAccessTokenRaw`
(`internal/gateway/authcookies.go:58,105`). `FetchHatchToken`
(`internal/gateway/auth.go:137`, fetching
`https://muse.ai/api/hatch/token` at `:145`) is not in the
descriptor-scoped list: its URL is not a descriptor field, no
`FetchHatchTokenAt` variant is required, and its URL source stays
the connector's own retained source (out of scope, below).
OUT OF SCOPE for PR-1..PR-6 — the following call sites keep
their own URL sources, unchanged by PR-4, and are reserved for a
later step if needed; this plan promises nothing about them: the
`NewConnector` auth chain (`internal/gateway/connector.go:172,178,
182`, calling the plain fetchers with no descriptor in scope —
`connectorConfig` at `connector.go:39-56` carries no
session/auth/hatch URL field, and the gateway cannot consume the
keeper descriptor: `internal/keeper/tick.go:19` imports
`internal/gateway` while no `internal/gateway` file imports
`internal/keeper`); `statusVMID`
(`internal/commands/read.go:119`); the profile-test HTTPS phase
(`internal/commands/profilecmd.go:826`); `deliver.Wake` /
`WakeDeps` (`internal/deliver/wake.go:71-78`, defaults at `:98,102`;
sole caller `internal/commands/deliver.go:244` sets only `WakeVM`),
whose old-signature wake helper and `WakeFunc` type
(`internal/deliver/wake.go:40`) are unchanged by PR-4; the hatch
URL (`internal/gateway/auth.go:145`); and the screencast message
literal (`internal/keeper/screencast.go:192`), which is display
text, not a fetched URL — its keeper-path message rebuild from
`ProviderHomeURL` is the table row below, not a fetch seam. The
old no-URL signatures remain, unchanged, for these call sites;
the D-AUTHCHAIN sync rule (§2.5) governs the duplicated chain's
wire behaviour and does not extend the descriptor seam to them.
`GatewayChecker`
(`internal/keeper/tick.go:51-54`) gains the descriptor's check URLs
as fields (or takes the descriptor), passes them to the helpers,
and builds `toUpdates` labels from the same descriptor fields, so
the label and the fetched URL can never diverge: on
descriptor-scoped paths, after PR-4 there is ONE source for each
fetched check URL (the descriptor field), not three (constant,
helper literal, label). The same scoped rule applies to the
plugin copy's descriptor-scoped paths: its helpers there take URL
parameters and its production URLs are its own provider data,
tested against the same fixture corpus (§2.5). Wake seam: `WakeVM` takes no URL parameter today —
`wakeURL` is a package variable
(`internal/gateway/wake.go:20`, `WakeVM` at `:52`) and `wireWake`
calls `gateway.WakeVM` directly
(`internal/commands/keeper.go:439`). PR-4 replaces `WakeVM` with
the URL-parameterised form `WakeVMWithURL` as the wake entry
point on the keeper path; `wireWake` must pass the descriptor's
`WakeURL` to it. The `WakeFunc` injection type
(`internal/deliver/wake.go:40`) is unchanged by PR-4: the deliver
path is out of scope (above), and the old `WakeVM` signature
remains available for `deliver.Wake`'s `WakeDeps.WakeVM`
injection. The `FetchSessionInfo`/
`FetchAccessToken` calls in the same `wireWake`
(`internal/commands/keeper.go:419,423`) must likewise pass the
descriptor's check URLs through `FetchSessionInfoAt` /
`FetchAccessTokenAt`. The `wakeURL` package variable is no longer
read on descriptor-scoped paths, but it is RETAINED, unchanged,
solely as the deliver path's out-of-scope source (read only by
the retained old `WakeVM` form at `internal/gateway/wake.go:62`);
PR-4 does not delete it. Tests that override it for keeper-path
tests (`internal/gateway/wake_test.go:23-29`) are updated to pass
an httptest URL through the URL parameter instead; the override
helper itself is retained with the variable for deliver-path
tests, as is the comment referencing it
(`internal/gateway/loop4_straddle_test.go:26`). Validation rule for
provider-supplied URLs (safety observation O-4): every URL the
descriptor carries (check, export, launch, wake) must be validated
when the descriptor is built — `https` scheme only, bare hostname, no
userinfo and no credential-bearing query — and rejected at load when
invalid, before the keeper fetches anything through it. PR-4 defines
this validation for the Muse values; PR-6 applies the same validation
to the values arriving through the `provider_session` field. The trusted first-party model does
not waive it: a malformed URL in config must fail closed at load, not
at first fetch. PR-4 must also define, in the same validation
(safety OBS-2): what counts as a credential-bearing query key; the
port rule (explicit ports allowed or rejected, and which); IP-literal
and localhost hosts (allowed or rejected); URL fragments (stripped
or rejected); redirect following by the keeper's HTTP client (follow
or fail closed, and to which hosts); and validation of the non-URL
descriptor fields (screencast/export hosts, cookie domains —
bare-hostname rule, no userinfo/query). An undefined item in any of
these is a PR-4 exit failure, not a follow-up. PR-4 performs a
behaviour-identical parametrisation: the Muse values move behind the
descriptor (still Muse values, now data, not code paths) and every keeper
test + e2e leg 10 passes unchanged. The descriptor's *source* switches to the `provider_session`
field of the plugin's `Registration` (channel defined above) only
in PR-6; PR-4 must not invent the field or any other registration
extension. Every remaining Muse literal in keeper logic
maps to a descriptor field as follows — no literal in this table may
remain in keeper logic files after PR-4:

| Site (verified at this HEAD) | Literal / behaviour | Descriptor field |
|---|---|---|
| `internal/keeper/jar.go:455-460` (`DrivingCookie`) | `hatch_sess` preferred as the driving-expiry cookie (`c.Name == "hatch_sess" && !c.Session()`) | `SessionCookieNames` (ordered list; first entry is the driving name). The preference becomes "first listed name present with a non-session expiry", with the Muse names as data. |
| `internal/keeper/tick.go:108`, `:485` | Synthesised `StoredCookie` entries hardcode `Domain: "muse.ai"` | `CookieDomains` (the synthesised domain comes from the descriptor). |
| `internal/keeper/tick.go:921`, `internal/keeper/login.go:367`, `internal/keeper/relogin_chromedp.go:559` | `hatch_sess` presence gates (`c.Name == "hatch_sess" && c.Value != ""`) | `SessionCookieNames` (presence = any listed name present and non-empty). Error/message text naming the cookie (e.g. `internal/keeper/login.go:320`, "no usable hatch_sess") must be built from the descriptor names, not literals. |
| `internal/keeper/export_cdp.go:209-218` (`resolveExportTargets`) | Fallback behaviour: first page target of any URL when no Muse page is open | `ExportFallback` behaviour datum (enum: first-page-target), alongside the `ExportURLs`/`exportHosts` data. The fallback is provider data, not keeper logic. |
| Wake leg: `internal/commands/keeper.go:390-439` (`wireWake`), `internal/gateway/wake.go:52` (`WakeVM`), wake URL at `internal/gateway/wake.go:20` | `https://muse.ai/api/hatch/vm/wake` | `WakeURL`. `WakeVM` itself STAYS in core (session HTTP helper, §2.2); only its URL becomes descriptor data. The `GatewayProbe` in the same function is served by the §3.5 adapter after extraction, not by a second gateway implementation. |
| `internal/keeper/relogin_chromedp.go:37`, `:546` (browser-level `Storage.getCookies` poll) | Browser-level cookie harvest (the K-LIVE-2-family residual: the poll itself is provider-neutral mechanics) | No new field: the poll stays in core mechanics. Its Muse-specific parts are only the presence gate (mapped above) and the contract selectors/keywords (already descriptor data). PR-4 must state this mapping explicitly; the poll must not be left unmentioned as "keeper mechanics" while its gate literals remain. |
| `internal/keeper/screencast.go:192` (`ResolveScreencastTarget` error message) | URL literal `https://muse.ai/` inside the "no Muse page is open" message | `ProviderHomeURL` descriptor field. The message is rebuilt from the descriptor field (`"open " + ProviderHomeURL + " there first"` shape, PR-4 fixes the exact wording); no URL literal remains in the message construction. PR-4 exit (iii)'s keeper-logic grep and exit (iv)'s whole-tree grep (below) cover this literal: it is in the removed-by-design group of the exit (iv) accounting. |

Login-contract fixture and the `//go:embed`: the fixture is embedded
at `internal/keeper/contract.go:33-35` (`//go:embed
testdata/login-contract.v1.json`). Moving the fixture file in PR-6
requires changing the embed or duplicating the file — `DECISION`
(deferred to PR-6's design section, both options stated here): either
(i) the embed moves with the plugin and core receives the contract
bytes through the `provider_session` field defined above — the
schema-version decision for that channel is the additive-at-schema-1
decision stated above, and option (i) is an ABI/schema change
outside PR-2's `provider.call`-only scope
(§1.3: `RegisterRequest` carries exactly fragment/schema/tag/type/
identity/egress, `internal/pluginabi/pluginabi.go:190-199`), so it
must not be read as covered by PR-2's schema work; or (ii) the
fixture is duplicated (the core copy stays the matcher input, the
plugin copy is the provider-owned source) with a test asserting
byte-equality. Option (ii) is the default unless PR-6 records the
schema-version decision for (i). PR-4 does not move the fixture.
Whichever option PR-6 picks, the matcher
(`internal/keeper/contract.go:194-207`, `MatchContract` at `:194`,
`validateContract` starting at `:218`) stays in core. The keeper's cheap chain (the `GatewayChecker`'s outbound HTTP client,
`internal/keeper/tick.go:51-59`) is already separate from the
gateway connection and stays so; the keeper's gateway probe (`TickDeps.
GatewayProbe`, `internal/keeper/tick.go:201-209`) is served by the §3.5
adapter after extraction, not by a second gateway implementation. The
`DefaultProxyAllowedHosts` default (`internal/profile/keeper.go:283`)
stays as a documented core default for v1 (its mechanism,
`EffectiveProxyAllowedHosts`, is generic); moving it to provider defaults
is deferred with UNDECIDED-5.

### 3.9 S9 — Command-dispatch gap (deferred, recorded)

`command.register` / `command.execute`
(`internal/pluginabi/pluginabi.go:62-72`) have no dispatch path (§1.2).
Per D-COMMANDS/UNDECIDED-1, no dispatch seam is added in extraction v1.
The gap is recorded here so no later PR mistakes "no dispatch" for "no
gap": if Muse CLI commands are ever to be served by a
`command_provider` plugin, the plan for that PR must define how
registered commands enter `commandTable`
(`internal/commands/commands.go:751-788`), including help/flags and
exit-code mapping. Until then, `docs/plugins.md` presents both
capabilities without choosing, and this plan chooses `Provider` only.

### 3.10 S10 — Web UI plugins endpoint

Cut point: `handleGetPlugins` (`internal/webui/plugins.go:33-39`) + the
frontend Plugins page. `DECISION`: PR-5 replaces the placeholder with a
versioned contract: `available` reflects `SupportPlugins()`
(`internal/pluginhost/support.go:11-15`) and a real loaded-plugin list
from the runtime `Host` (tag, type, schema, capabilities, loaded/skipped
state — never fragment contents, never secrets, consistent with
`internal/profile/redact.go:117-202`). The endpoint's own comment states
the follow-up "must NOT reuse this shape for real data without versioning
the contract" (`internal/webui/plugins.go:10-31`) — PR-5 versions it.
"Enable/disable" has no meaning under presence-means-active
(`internal/profile/plugins.go:12-49`); the endpoint lists and reports,
it does not toggle. The endpoint forwards exactly the enumerated
fields and no others: `Host.Loaded` also returns the filesystem `Path`
(`internal/pluginhost/host.go:243-262`), which the endpoint must NOT
forward. The chats surface is unaffected by PR-5 (UNDECIDED-4).

### 3.11 S11 — No-plugin flavour

Cut points: stub loader (`internal/pluginhost/loader_stub.go:10-25`),
release job `build-linux-no-plugin`
(`.github/workflows/release.yaml:357-363`, `CGO_ENABLED=0` build at
`:457-458`). `DECISION D-NOPLUGIN` (proposal, Boss decision required
before PR-6): after extraction, the `_no-plugin` static binary fails
closed with a clear error for every Muse command (no dual implementation,
no bundled plugin). Rationale: a core fallback would duplicate the entire
gateway stack and defeat the extraction; bundling a `.so` with a static
binary contradicts the flavour's purpose (musl/older systems,
`README.md:358-359`). Alternative (bundle the plugin `.so` as a separate
release asset) is recorded and rejected for v1 only — it may be revisited
if the fail-closed behaviour breaks a real deployment, which is
`[NEEDS-MEASUREMENT]` (§5, M-7). Until D-NOPLUGIN is decided, no
extraction PR lands. The no-plugin binary's behaviour *before* extraction
is unchanged (Muse in core).

### 3.12 S12 — BD-C1 config-block gap

Cut point: the BD-C1 audit table (`docs/plugins.md:247-285`). `DECISION
D-HOSTBLOCK` (proposal, new config surface, approval required): when
runtime wiring lands (PR-1), host-level values move into a new optional
top-level `plugin_host` block (sing-box style, all fields optional with
documented defaults equal to today's library defaults): `dir` (discovery
root, §3.2), shadow-dir root, egress bind/timeouts, render cap,
check-output caps, `host.log` level allowlist. If the block is rejected,
PR-1 must explicitly defer it with the BD-C1 citation and keep library
defaults — and must say so in the PR body. No other host setting may be
added without a block field. This plan does not invent the block's field
names beyond `dir`; PR-1's design section fixes them before code.

## 4. Sequential PR plan

Order is dependency order. No PR may claim a gate it cannot measure; each
PR's exit criteria are checked by the means stated, on cue where live
behaviour is claimed (the sandbox intercepts raw outbound TCP, so
live-gateway claims need the cue environment — see §5, M-5). Every PR is
its own branch + PR into `main`, docs updated in the same PR (repo hard
rule 5), CI green before merge. Rollback for every PR is revert of that
single PR; no PR depends on an unmerged predecessor's internals.

### Gate D-ROADMAP — before PR-1 (not a PR)

D-ROADMAP (§0) must be decided by Boss before PR-1 lands: either the
E2E baseline is recorded on `main` first (M-5 closed), or Boss approves
the reorder and `AGENTS.md:20-25` is amended. PR-1's entry criteria
require the decision record; "the roadmap was read as permitting
wiring-first" is not a decision record.

### PR-1 — Runtime wiring only (no Muse code moves)

- Goal (one, measurable): a non-Muse plugin (the echo example,
  `examples/plugin/echo/main.go`, or a `plugintest` fixture) loads through
  the real runtime path — `Desired` resolved from `config.json`,
  `ApplyConfig` called from `Runtime` construction, egress proxy +
  stripped identity built per profile — while every Muse command behaves
  exactly as before in the absent-`plugins`-block case. With a block
  present-but-broken, behaviour changes by design to fail-closed
  (§3.2d); the goal is qualified to the absent-block case.
- Entry: this plan merged; D-ROADMAP decided (§0 gate above);
  D-DISCOVERY + D-HOSTBLOCK decided (block name
  and `dir` semantics approved, or BD-C1 deferral recorded);
  D-MULTIENTRY decided (§3.2e, single-entry-only fail-closed).
- Work: S1 (§3.1), S2 (§3.2), S3 (§3.3), S4 (§3.4) wiring code only;
  `Runtime` host lifetime; `plugin check` untouched; no `rt.Muse` call
  site touched; no gateway file touched.
- Exit: (i) unit + integration tests cover load, same-path reconfigure,
  different-path replace + rollback, detach, skip/fuse behaviour through
  the runtime wiring (mirroring `host_test.go`/`host_hardening_test.go`
  contracts, but through the new call site — today only `plugin check` +
  tests call `ApplyConfig`, §1.2); (ii) `castctl plugin check` output
  unchanged; (iii) full e2e (§6) passes unchanged on cue at that HEAD;
  (iv) absent `plugins` block → byte-identical behaviour to today;
  present-but-unresolvable entry → exit 2 naming the entry (§3.2d);
  (v) `Host.Close` runs after `muse.Close()` (the §3.1 ordering test,
  including the hang-plugin case), the §3.4 accessor test passes (raw
  bytes never enter a `Desired`/`RegisterRequest`), and the multi-entry
  and zero-file-discovery cases fail closed with exit 2 (§3.2e).
- Stop/rollback: any Muse-command regression → revert PR-1. A wiring
  failure that only affects plugin-present runs stops at PR-1; it must
  not be "fixed" by touching Muse code.

### PR-2 — `provider.call` operation schema + adapter (no live Muse traffic)

- Goal: the §3.5 schema is specified, and a core-owned `conn.Gateway`
  adapter over `Host.Call` passes all 14 `Gateway` operations against a
  fake plugin in tests.
- Entry: PR-1 merged. D-SCHEMA + D-BOUNDARY-1 approved as the schema's
  basis.
- Work: S5 (§3.5): schema section added to `docs/plugins-spec.md`;
  adapter implementation; error/exit-code mapping; successful-result
  redaction responsibility assigned to the adapter; fake-plugin contract
  tests via `internal/plugintest`.
- Exit: (i) schema doc merged and reviewed against the 14-method
  interface + lease semantics; (ii) adapter tests green for every
  operation including stream open/cancel, subscribe poll/halt (or the
  decided blocking-call model with its recorded behaviour change),
  the `Leaser` marker + `SharedConn` no-op-close behaviour and
  adapter `Close()` teardown (§3.5 lease paragraph), generation bump, the
  ConnectionDown/ConnectionError distinction, route total/list from
  the snapshot, framing/validation typed-error reconstruction,
  `GatewayError`/`TimeoutError` reconstruction, and
  `AuthError` surfacing; (iii) no production Muse path uses the adapter
  yet (it is unreachable from any command — verified by grep, as in
  §1.2); (iv) the D-BOUNDARY-1 stop condition is answered in writing
  against the COMPLETED schema (§3.5: subscribe callbacks,
  halt/cancel ordering, Lease, generation bump, ConnectionDown
  distinction, route count/list, framing-error taxonomy,
  `GatewayError`/`TimeoutError` reconstruction, `gateway.open`):
  either the schema expresses all of them,
  or extraction stops here; (v) D-LAYOUT is ratified in PR-2's design
  section (in-repo plugin tree, §2.5, or a recorded change with the
  PR-3 re-run rule triggered), the §2.5 shared-helper split is
  confirmed file-by-file, and the D-AUTHCHAIN duplication mechanism +
  sync rule are specified with the PR-3 live auth-chain criterion
  stated; (vi) the `routes.json` single-source-of-truth path (§2.5)
  is fixed.
- Stop/rollback: schema review finds an inexpressible operation
  (including any §3.5 REQUIRED item) →
  stop, revisit D-BOUNDARY-1; do not proceed to PR-3's prototype on an
  unproven schema. Rollback is revert of PR-2.

### PR-3 — Transport spike / measurement (prototype branch, decision record)

- Goal: settle §3.6 empirically. This PR (or prototype branch + decision
  doc — the form is the author's choice, the measurements are not
  optional) records: (a) a c-shared Go plugin linking the full gateway
  stack loads and runs in-process without runtime conflicts (two Go
  runtimes, signal handlers, `os.Exit` behaviour); (b) WS/Noise over
  CONNECT-through-egress works live (handshake, ALPN pin, plugin-side
  header setting inside TLS under the §3.6 channel rule — the proxy
  injects nothing through a CONNECT tunnel, so no "proxy injection"
  is measured here — and no secret in any plugin-visible surface);
  (c) cookie rotation mechanism (§3.6) works without dropping the warm
  connection silently; (d) shutdown behaviour (§3.7) does not hang.
- Entry: PR-2 merged, with D-LAYOUT ratified in PR-2's design section;
  if the ratified layout differs from the layout PR-3 first ran in,
  PR-3 re-runs its load proof in the final layout before its decision
  record is written. Phone/Droidspaces load of the echo plugin is
  `[NEEDS-MEASUREMENT]` (§5, M-1) — PR-3 must not claim it; the spike
  runs on cue + Linux amd64/arm64 only, and the phone leg is recorded as
  still open.
- Exit: a decision record MERGED as a preserved artifact (a decision
  doc merged into `docs/research/` by its own PR — a prototype branch
  that can vanish does not satisfy this criterion) naming option (a)
  or (b) from §3.6 with the recorded measurements, or a STOP record:
  extraction cannot proceed on the measured evidence. The record must
  contain: the §3.6 fingerprint observable with its baseline
  comparison (ClientHello field-by-field vs the direct-dial baseline;
  (a) is not selectable on handshake success alone), the uTLS
  mechanism for (a) or the recorded fingerprint behaviour change, the
  O-1 cookie-delivery channel named or (a) ruled out (with the
  §3.6 CONNECT scope note: no WS `Cookie` header is set today, so
  the channel question is conditional on PR-3's measurement), the
  disambiguated STOP wording applied, the cookie-rotation mechanism,
  and the live auth-chain criterion (a plugin-built gateway completes
  the auth chain live, or the boundary moves per D-AUTHCHAIN). No
  production code from the spike merges without a separate review; the
  spike's only merged artifact, if any, is the decision record + any
  reusable test harness.
- Stop/rollback: prototype cannot load/run, CONNECT breaks the WS
  handshake, or cookie material is observable plugin-side (see §3.6
  for the definition of "observable plugin-side") → STOP
  extraction. Do not work around a failed spike by widening the handoff
  (no raw keys, no cookie values in `RegisterRequest`, ever; a cookie
  path or raw outbound hash reaching the plugin by any channel →
  STOP — see §2.5 D-AUTHCHAIN and §3.5 `gateway.open`).

### PR-4 — Keeper parametrisation (behaviour-identical)

- Goal: keeper provider literals move behind the `ProviderSession`
  descriptor (§3.8) with zero behaviour change.
- Entry: PR-1 merged (PR-2/PR-3 may run in parallel only if they touch no
  keeper file; PR-4's exit does not depend on them). D-KEEPER approved.
- Work: S8 (§3.8): descriptor type + keeper wiring through existing
  interfaces; Muse values as data; `DefaultLoginContract` matcher
  unchanged; web UI import name scan + `auth import` rule untouched
  (UNDECIDED-5 deferred).
- Exit: (i) all keeper tests green, including chromedp-gated tests under
  the 5-tag build; (ii) e2e leg 10 (§6) verdicts identical to the
  pre-PR-4 baseline recorded on cue; (iii) the exact checks
  `grep -rn 'https://' internal/keeper/ --include='*.go'
  --exclude='*_test.go'` and `grep -rn 'muse\.ai\|hatch_sess'
  internal/keeper/ --include='*.go' --exclude='*_test.go' | grep
  -vE ':[0-9]+:[[:space:]]*//'` return hits only in
  `internal/keeper/provider.go` (the `ProviderSession` type's
  file, §3.8 — the descriptor itself is the single place; every
  site in the §3.8 mapping table is covered, including the wake
  URL, the export fallback datum, the presence gates, and the
  screencast message URL; full-line `//` comment mentions are not
  literals and are excluded by the second check's filter);
  (iv) the exact check `grep -rn 'https://' internal/
  --include='*.go' --exclude='*_test.go'` returns exactly the
  retained-exception list below plus any hits in the new
  `internal/keeper/provider.go` itself (which holds the
  descriptor's Muse URL values) — every other `https://` hit in
  production code is removed by the design (the removed group),
  and no hit outside the removed group, the retained list, and
  `provider.go` may remain; hits in `*_test.go` files are fixture
  and expected-value data, not production URL sources, and are
  excluded by the `--exclude` flag. Removed by the design (must
  be absent): `internal/keeper/tick.go:27,28` (label constants;
  labels come from the descriptor, §3.8),
  `internal/keeper/screencast.go:192` (message literal, display
  text only; rebuilt from `ProviderHomeURL`, §3.8 table),
  `internal/keeper/launch.go:190` (launch URL; descriptor
  `LaunchURL`), `internal/keeper/export_cdp.go:77`
  (`ExportURLs`; descriptor field),
  `internal/gateway/authcookies.go:59,106` (fetched check URLs;
  descriptor fields). Retained exceptions, each named with its
  reason: request header literals, not fetched URLs —
  `internal/gateway/auth.go:36,37`,
  `internal/gateway/connector.go:287`; out-of-scope fetch URLs,
  retained unchanged — `internal/gateway/auth.go:145` (hatch
  URL; the connector's own source),
  `internal/gateway/subscription.go:38,163` (subscription
  helpers), `internal/gateway/invite.go:31,64,112` (invite
  helpers); not a URL source — `internal/gateway/media.go:55`
  (URL-shape predicate); display text and guidance —
  `internal/shared/usage.go:274`,
  `internal/deliver/authexport.go:13,16,17`,
  `internal/commands/help.go:436`,
  `internal/commands/authobserve.go:52`; comments and doc
  examples — `internal/update/update.go:72,75`,
  `internal/telegram/bot.go:171`,
  `internal/redact/redact.go:102,108`,
  `internal/profile/envproxy.go:53`,
  `internal/gateway/gatewaytest/server.go:262`,
  `internal/deliver/wake.go:28`,
  `internal/commands/profilecmd.go:817,1059`; unrelated
  subsystems, out of scope — `internal/update/update.go:362,369`
  (GitHub API roots), `internal/commands/profilecmd.go:1061`
  (IP check), `internal/commands/keeper.go:570` (Telegram API),
  `internal/commands/authobserve.go:103` (observe-login default);
  fixture and example metadata —
  `internal/plugintest/fake.go:29`,
  `internal/plugintest/testdata/fakeplugin/main.go:198`;
  deliver-path retained default — `internal/gateway/wake.go:20`
  (see the `wakeURL` check below). The `wakeURL` check
  `grep -rn 'wakeURL' internal/ --include='*.go'` returns hits
  only at the retained set `internal/gateway/wake.go:16,20,28,62`,
  `internal/gateway/wake_test.go:23,27,28,29,34`, and
  `internal/gateway/loop4_straddle_test.go:26` (the deliver
  path's retained source; the keeper path no longer reads the
  variable). Inspection of the `wireWake` call sites
  (`internal/commands/keeper.go:419,423,439`) shows only
  URL-parameterised calls on descriptor-scoped paths — every
  fetched URL on those paths arrives as a parameter from the
  descriptor (§3.8 fetched-URL seam).
- Stop/rollback: any keeper verdict change → revert PR-4. This PR must
  not change keeper behaviour to "prepare" for extraction.

### PR-5 — Web UI plugins endpoint (real list, versioned contract)

- Goal: `GET /plugins` lists real loaded plugins (§3.10).
- Entry: PR-1 merged (needs the runtime `Host` to list from).
- Work: S10 (§3.10): versioned endpoint contract, `available` from
  `SupportPlugins()`, stale comment in `internal/webui/plugins.go`
  corrected, frontend Plugins page wired to the versioned contract.
- Exit: (i) endpoint returns the loaded list (tag/type/schema/
  capabilities/state, no fragments, no secrets, no `Path` — exactly the
  enumerated fields, §3.10) in a wiring test with a
  loaded echo plugin; (ii) no-plugin build still returns
  `available: false`; (iii) e2e leg 11 (§6) verdicts unchanged (leg 11
  does not exercise `/plugins` today — the PR adds one scripted check
  for the endpoint shape, without editing any other leg's assertions).
- Stop/rollback: endpoint leaks fragment contents or secrets in any test
  output → revert PR-5.

### PR-6 — Extraction: gateway transport + proto move into `castctl-muse`

- Goal: the Muse wire stack runs as a plugin; every Muse command works
  through the §3.5 adapter with the plugin loaded, and fails closed
  without it.
- Entry: PR-1–PR-5 merged; D-NOPLUGIN decided (§3.11); PR-3 decision
  record MERGED as a preserved artifact (§4, PR-3) naming transport
  option (a) or (b) with measurements, produced in the final D-LAYOUT
  layout; phone load `[NEEDS-MEASUREMENT]` (M-1) is recorded as open
  and is NOT claimed as passed.
- Work: move §2.1 components into the plugin tree fixed by D-LAYOUT
  (§2.5, ratified in PR-2 — the in-repo plugin tree under the same
  module; PR-6 does not re-open the location decision); session-HTTP
  split per D-AUTHCHAIN (§2.5); keeper descriptor source switches
  to the `provider_session` field of the plugin's `Registration`
  (§3.8 channel), and the core-held Muse descriptor values are
  removed with no fallback; login-contract fixture moves with the
  provider per the §3.8 embed decision; `routes.json` source of truth
  moves to the plugin tree (§2.5); `Runtime` connector becomes
  plugin-backed when the Muse plugin is loaded. The plugin is a
  separate build artifact, never committed as a `.so`.
- Exit: (i) e2e legs 1, 2 (live branch), and 4 (§6) pass on cue with the
  plugin loaded through the runtime path, asserting the same JSON fields
  and exit codes as the pre-extraction baseline recorded at PR-1;
  (ii) plugin-absent runs of `profile test`, `send`, `wait`, `watch`,
  `approvals` fail closed with the decided error (§3.11), tested;
  (iii) leg 12 secret scan (§6) extended to plugin host-log /
  provider-call output with counts-only reporting, bare-secret residual
  statement kept; (iv) `plugin check` still passes for the extracted
  plugin; (v) docs (`docs/architecture.md` Core + plugins section,
  `docs/plugins.md` status, `README.md` loader sentences) updated in the
  same PR to state the wired state — the stale sentences flagged in §1.4
  must not survive PR-6; (vi) the plugin is loaded through the runtime
  path in the PR-3 layout (identical layout — PR-3 evidence transfers
  only in the ratified layout, §2.5); (vii) the §3.5 schema semantics
  are exercised live, not only by legs 1/2/4 field parity: subscribe
  halt/progress (early stop takes live effect), generation bump
  (stale-frame filtering after a reconnect), and the
  ConnectionDown-before-open vs after-open distinction are each
  observed on cue with the plugin loaded. The keeper CDP re-export
  leg (§6.2 item 5) is owned by PR-6: it is either added or explicitly
  deferred with a named owner and measurement — it must not be claimed
  as covered while still SKIP.
- Stop/rollback: any leg 1/2/4 parity failure, any secret-scan hit, or
  any shutdown hang → revert PR-6; the pre-extraction core (PR-1–PR-5
  state) is the rollback target and must keep working with Muse in core
  until PR-6 re-lands. PR-6 must not land in the same merge window as
  any other behaviour change. PR-6 must not land on PR-3 evidence
  produced in a different layout.

### PR-7 — No-plugin + release parity + E2E/coverage completion

- Goal: the release matrix, the no-plugin flavour, and e2e coverage are
  complete for the extracted state (§6.2).
- Entry: PR-6 merged and e2e parity recorded.
- Work: no-plugin binary behaviour per D-NOPLUGIN, tested with at least
  one `--binary` e2e run against the no-plugin build; release-matrix
  parity (both release jobs, amd64 + arm64, keep building; state what
  the no-plugin archive contains/omits regarding plugins and whether a
  plugin `.so` ships as a separate release asset — today no such asset
  exists and the checksums job expects exactly 4 archives,
  `.github/workflows/release.yaml:504-547`); CI matrix decision (§5,
  M-6/M-11); `docs/e2e.md` re-verified against `scripts/e2e.sh` at the
  landing HEAD (§6.2 item 9).
- Exit: (i) full e2e pass on cue at the landing HEAD with the verdict
  table recorded (including the new plugin-present, plugin-absent, and
  egress-proxy legs in §6.2); (ii) CI check list read from live GitHub
  state and recorded (§5, M-6) — the plan's file-derived count (§5) is
  replaced by the observed list; (iii) `docs/e2e.md` base updated to the
  landing HEAD; (iv) M-1/M-2/M-3 are closed by measurement or recorded
  as open with a named owner (Boss, for device/host access) and a Boss
  decision that extraction may land without them (§5, Ownership) —
  they must not be left unowned.
- Stop/rollback: full-e2e failure or a release-job failure → revert
  PR-7 only if PR-7 caused it; if the failure is in PR-6's extraction,
  revert PR-6 per its own stop condition, not PR-7.

### Explicitly not in this sequence

- `command.execute` dispatch (UNDECIDED-1): separate design + PR, after
  PR-7 at the earliest.
- A second provider (Facebook/TikTok/YouTube): no code, no schema work
  in this sequence. The extraction is proven by one provider; second-
  provider generality is not claimed.
- ABI v2 / `host.dial` (option (b), §3.6): only if PR-3 measures option
  (a) as unworkable. Designing it speculatively in PR-2 is forbidden by
  this plan.
- Native login / `auth login` completion: blocked on a human-entered code
  (§5, M-8); it is not a dependency of any PR above, and no PR above may
  claim it.

## 5. Risks and unverified items

Every item below is tagged `[NEEDS-MEASUREMENT]` with the exact
measurement that would settle it. None is guessed in this plan, and no PR
in §4 may claim any of them as passed without that measurement.

- **M-1 — Phone (Droidspaces) plugin load.** `docs/plugins.md:531-563`
  records `castctl plugin check` inside Droidspaces as the merge gate
  with result `[NEEDS-MEASUREMENT]`, and `docs/plugins-spec.md:117-128`
  states the Droidspaces glibc version "is recorded only from the
  on-device check, never assumed". Measurement: run the check inside
  Droidspaces on the phone against a real plugin `.so` and record the
  five stage lines + exit code, plus `ldd --version` output. A qemu load
  is build proof only and does not settle this.
  `[NEEDS-MEASUREMENT]`
- **M-2 — Windows and macOS loads.** `docs/plugins.md:565-577`: Windows
  loader "compiles, never ran", macOS loader "never ran"; CI is
  Linux-only. Measurement: run the real-loader contract tests /
  `plugin check` on each host. `[NEEDS-MEASUREMENT]`
- **M-3 — Droidspaces glibc version vs the compat gate.** Same
  measurement as M-1 (gate error output or `ldd --version` on device);
  the gate refuses when the plugin's highest required `GLIBC_` exceeds
  the running libc (`internal/pluginhost/compat.go:708-735`).
  `[NEEDS-MEASUREMENT]`
- **M-4 — Live egress-proxy end-to-end.** The proxy "proves the mechanism
  with a fake/local upstream in tests; it does not prove a live profile
  outbound path" (`docs/plugins.md`, "Secrets and egress" — see §1.3
  citations for the mechanism). The test-only proof is the fake
  upstream in `internal/pluginhost/egress_test.go:54,94`
  (`recordingRoundTripper`) plus zero production callers of
  `NewEgressProxy` (§1.2). No production wiring exists to measure
  against yet. Measurement (belongs to PR-1/PR-3): proxy-side counting
  probe on cue through a real outbound (direct + WireGuard), cookie
  injection for a declared host observed proxy-side, CONNECT behaviour
  observed, never by echoing plugin-built requests. How to observe
  without leaking secrets is itself unproven — the probe design is part
  of PR-1's work, not assumed here. `[NEEDS-MEASUREMENT]`
- **M-5 — E2E pass at this HEAD on cue.** No e2e run was performed for
  this plan (docs-only phase). Measurement: run `scripts/e2e.sh` on cue
  with the 5-tag build (`scripts/e2e.sh:52`) and authorised
  `--live-send`/`--live-keeper`, recording the verdict table. Headline
  counts are environment-dependent. Until then, the pre-extraction
  baseline that PR-1/PR-6 compare against does not exist.
  `[NEEDS-MEASUREMENT]`
- **M-6 — Live CI check list / branch protection.** The task brief for
  this plan said "7 checks". The workflow files imply **8 checks total**:
  2 from `.github/workflows/test.yaml` (matrix `untagged` + `with_utls`,
  `.github/workflows/test.yaml:30-35`) and 6 from
  `.github/workflows/release.yaml` (`prepare release`,
  `build-linux-glibc` amd64+arm64, `build-linux-no-plugin` amd64+arm64,
  `publish checksums`; jobs at `.github/workflows/release.yaml:86-89`,
  `:180-187`, `:357-363`, `:504-513`), of which **6 run and 2 are
  skipped on a PR** (`prepare` and `checksums` are gated off by their
  `if:` predicates). Neither workflow has a `paths:` filter, so a
  docs-only PR triggers all of them, and neither invokes
  `scripts/e2e.sh`. The "7 checks" figure is not corroborated by any
  file at this HEAD. Do NOT assert 7 in any PR body. Measurement: read
  the live check runs + branch-protection required-checks for a recent
  PR at `github.com/thoitiettxl-cyber/castctl`; repo settings are not in
  the clone. `[NEEDS-MEASUREMENT]`
- **M-7 — No-plugin binary behaviour after extraction.** No code or doc
  decides it (§3.11); D-NOPLUGIN is a Boss decision, not a probe.
  Measurement/decision: the decision itself, plus a `--binary` e2e run
  against the no-plugin build (PR-7). `[NEEDS-MEASUREMENT]`
- **M-8 — Screencast / `auth login` leg.** Blocked on a human-entered
  code; no e2e coverage exists (§6). Measurement: a live screencast
  session with a fresh code, observing only the documented outcomes
  (validation via cheap chain, export + locked write), after the
  keeper-parametrisation PR. No PR above claims it.
  `[NEEDS-MEASUREMENT]`
- **M-9 — Full-stack c-shared plugin viability + shutdown composition.**
  The echo example proves only a trivial plugin loads. Whether a plugin
  carrying the full gateway stack (Noise + protobuf + WebSocket + 258
  routes) loads and runs in-process without runtime conflicts, and
  whether `Host.Close` waiting on in-flight native calls hangs a Muse
  plugin mid-turn, are unmeasured. Measurement: PR-3 spike (§4) +
  hang-plugin test (§3.7). `[NEEDS-MEASUREMENT]`
- **M-10 — `docs/e2e.md` currency.** The doc's stated base is
  `2a3c1fa` (`docs/e2e.md:4`), older than the HEAD in §0; whether its
  leg claims match `scripts/e2e.sh` line-for-line at this HEAD was not
  verified for this plan. Measurement: line-by-line diff of doc claims
  vs the script before any PR quotes leg numbers (PR-7 re-verifies).
  `[NEEDS-MEASUREMENT]`
- **M-11 — Test baseline / flake rate.** No test suite was run for this
  plan. Pass/fail/flake rates at this HEAD (including `with_chromedp`
  mock-loop tests and `with_utls` race legs, which CI does not run —
  `.github/workflows/test.yaml:30-35` runs untagged + `with_utls` only)
  are unknown. Measurement: run the canonical command
  (`docs/development.md:10`) and the 5-tag e2e build, recording results,
  before PR-1 claims a regression baseline. `[NEEDS-MEASUREMENT]`
- **M-12 — Cookie rotation through the egress proxy.** See §3.6. No code
  handles proxy rebuild/re-scope on rotation today. Measurement: PR-3
  spike observation (rotation event → proxy state → warm-connection
  continuity). `[NEEDS-MEASUREMENT]`

### Ownership of the unmeasured legs

M-1/M-2/M-3 (phone/Windows/macOS loads) are owned by PR-7, with Boss as
the owner of the device/host access the measurements need; PR-7's exit
criterion (iv) requires them closed by measurement or recorded as open
with a Boss decision that extraction may land without them. The keeper
CDP re-export leg is owned by PR-6 (§6.2 item 5). M-8 (screencast /
`auth login`) is blocked on a human-entered code and owned by no PR in
§4. No unmeasured leg is left without a named PR or owner.

### Other risks (code-grounded, not measurements)

- **Shadow TOCTOU (U1).** Between shadow-copy verification and `dlopen`
  the shadow file could be swapped by another process with write access
  to the shadow directory; there is no fd pin
  (`docs/plugins.md:578-615`). Mitigation is the 0700 per-process shadow
  dir (`internal/pluginhost/shadow.go:55-94`); the residual is accepted
  and must stay documented, not silently widened by wiring (e.g. no
  world-writable plugin directory).
- **Runtime bypass (U2).** A plugin can `dlopen` another library at
  runtime, bypassing compat/checksum gates for that library
  (`docs/plugins.md:578-615`). Trusted-model limit; the wiring PR must
  not present the gates as a sandbox.
- **Fuse semantics vs warm connections.** A fused plugin (host-adapter
  panic or call timeout, fuse state at
  `internal/pluginhost/host.go:550-594`, panic/timeout fuse recordings
  at `:820-860`) fails
  fast for that image until a different-path load; a Muse plugin fused
  mid-turn drops the warm connection. PR-2's schema must define what a
  fused-plugin error looks like to `wait`/`send` callers (typed error,
  exit code), not leave it as a generic envelope error.
- **Per-plugin failure is warn-and-skip** (`internal/pluginhost/host.go:369-534`).
  That is correct for multi-plugin convergence and wrong for a
  first-load failure of the only provider (§3.2d). The wiring PR must
  keep the two cases distinct.
- **Second-provider illusion.** No second provider exists in the tree.
  Every "generic" seam in this plan is generic-shaped with a single
  consumer until a second provider lands. The plan's language must keep
  saying so.
- **CI gaps.** CI runs neither `with_chromedp` nor
  `with_quic`/`with_wireguard`/`with_gvisor` tests (§5, M-6/M-11). Any
  extraction PR moving keeper/screencast-adjacent code must state
  whether CI gains a leg or the gap stays e2e-only; silence is not an
  option in the PR body.

## 6. E2E impact

`scripts/e2e.sh` (1993 lines) is the only end-to-end net. It builds with
`BUILD_TAGS='with_utls,with_quic,with_wireguard,with_gvisor,with_chromedp'`
(`scripts/e2e.sh:52`), isolates every run in a `mktemp -d` 0700 dir, never
modifies the supplied config, never copies/reads cookies, and exits
non-zero on any FAIL (`scripts/e2e.sh:12-41`, `:143-230`). A sandbox SKIP
(TLS-handshake plaintext error) never counts as PASS
(`scripts/e2e.sh:231-240`). The word `plugin` occurs 0 times in the
script: no leg loads a plugin, invokes `plugin check`, or exercises auth/
screencast/chat/fs/web UI chats. Leg boundaries below are the `# ----
leg N` headers verified at this HEAD; `docs/e2e.md`'s leg table must be
re-verified per M-10 before being quoted.

| Leg (script lines) | What it proves today | At risk from extraction? | New coverage the extraction PRs must add |
|---|---|---|---|
| Build (`scripts/e2e.sh:896-936`) | Binary builds from the checkout with all 5 tags; `--version` runs | Shape changes | Binary must still build with the full tag set AND with the plugin present/absent; `--binary` path means a release (no-chromedp) binary is also a valid target with different keeper behaviour. |
| 1 — profile test (`scripts/e2e.sh:959-1013`) | Only leg exercising the live Muse gateway handshake end to end: DNS phase, `GET https://muse.ai/api/session`, egress IP, Noise handshake then close (`internal/commands/profilecmd.go:787-887`) | **Highest.** Gateway moves | Re-run with the Muse plugin loaded through the runtime path (not `plugin check`), asserting identical JSON fields (`dns.ok`/`https.ok`/`gateway.ok`, `dns.source` enum) and exit codes. Until this exists, extraction loses the only live-gateway net. |
| 2 — send/wait (`scripts/e2e.sh:1014-1096`) | Offline conflict-toggle check (exit 2); live branch: `send` + `wait --after-seq` JSON (`delivered`, `outcome` in `done\|needs_input\|needs_approval`) through the in-core connector (`internal/commands/runtime.go:357`) | **Highest** (live branch) | Plugin-present live parity, same fields/exit codes. Offline check unaffected (parser-only). |
| 3 — approvals (`scripts/e2e.sh:1097-1184`) | Offline status/env/persist checks (config-level); live listing shape-only, never decides | Partial (live listing uses the gateway) | Live listing parity through the adapter; deciding stays manual/`[NEEDS-MEASUREMENT]` — extraction must not claim to close it. |
| 4 — watch (`scripts/e2e.sh:1185-1240`) | Live branch streams gateway events; offline branch is a SKIP by design | **Yes** | Plugin-present live parity (row shape, ≥1 `event`+`seq` row). |
| 5 — DNS (`scripts/e2e.sh:1241-1303`) | `config migrate` dry-run byte-identical; DNS source/server re-read from leg 1; empty-`dns` and dual-`dns` parse errors | Indirect (inherits leg 1 via re-read + `profile test` construction) | None new, beyond leg 1 parity. |
| 6 — outbounds/WG, shape only (`scripts/e2e.sh:1304-1377`) | Config shape/parse; WireGuard liveness reuses leg 1 `gateway.ok`; no standalone WG liveness command | Indirect (via leg 1) | None new, beyond leg 1 parity. |
| 7 — logging (`scripts/e2e.sh:1378-1461`) | Failing `wait` path (offline, no cookies): exit 2, log-file 0600, typed `cookies_missing` JSON | **Yes — behaviour.** Failing path runs through `wait` | Failing path, exit 2, and log gating must hold with the plugin absent AND present. The plan must define both; the extraction PR must test both. |
| 8 — Telegram (`scripts/e2e.sh:1462-1510`) | `telegram status` + SIGINT `telegram run` exit 130; no turn driven; real-message delivery explicitly not claimed | No, as scripted | None. Live-turn risk is pre-existing `[NEEDS-MEASUREMENT]`; extraction must not claim to close it. |
| 9 — update (`scripts/e2e.sh:1511-1542`) | Dry-run/refusal only; binary hash unchanged | No | None. |
| 10 — keeper (`scripts/e2e.sh:1543-1618`) | `keeper status`/`check` state-file checks; `keeper check` dry/SKIP unless `--live-keeper`; CDP re-export + `keeper run` single-flight are explicit SKIPs | **Yes — tick internals.** Tick uses gateway checker + CDP exporter + re-login driver (`internal/commands/keeper.go:345-375`) | Keeper CDP re-export → plugin session + `check` cheap-chain outcome, with the cookies-originals immutability invariant preserved (`scripts/e2e.sh:866-881`). Currently SKIP/`[NEEDS-MEASUREMENT]` — PR-6 owns it (§6.2 item 5):
   PR-6 must either add it or explicitly defer it with a named owner
   and measurement; it must not be claimed as covered. |
| 11 — web UI (`scripts/e2e.sh:1619-1893`) | Status/config/settings/logs over HTTP; auth, loopback bind, redaction, log-gate enum | Indirect (scripted checks are core HTTP; chat endpoints drive `deliver`/`wait` but are never exercised) | PR-5's one new scripted check for the `/plugins` endpoint shape (§4, PR-5). Chat-endpoint coverage remains zero — recorded, not claimed. |
| 12 — secret scan (`scripts/e2e.sh:1894-1961`) | Counts-only scan of captured outputs; held values 0, label patterns 0; bare secrets explicitly unprovable (`scripts/e2e.sh:43-44`) | **Yes — scope.** Plugin-origin output is not produced by any current leg | Extend or explicitly bound Scope A to plugin host-log / provider-call output, keeping counts-only reporting and the bare-secret residual statement (PR-6 exit criterion). |
| Tail (`scripts/e2e.sh:1962-1993`) | Unknown-key exit 2; supplied config byte-identical; cookies originals re-verified; summary counts | Indirect | Immutability invariants must hold with plugins configured (temp-copy `plugins` entries + plugin binaries must not mutate the supplied config or cookie originals). |

### 6.1 Zero coverage today (gaps, not regressions — extraction must not hide them)

- Plugin loading: 0 legs (see above).
- Auth/screencast: no `auth import`/`login`/`observe`/`status` invocation
  in the script; screencast has no leg.
- `chat`, `read`, `fs`, web UI chat endpoints: no invocation.
- `keeper run`: no invocation; no CDP re-export against a running browser.
- Egress-proxy + cookie-injection integration: unit coverage exists
  (`internal/pluginhost/egress_test.go`) but no production wiring exists
  to cover (§1.2); observation method is M-4.

### 6.2 Coverage each extraction PR must add (so no coverage is lost)

1. **Plugin-present e2e parity** (PR-6): legs 1, 2 (live), 4 re-run with
   the plugin loaded through the runtime path, same fields/exit codes.
2. **Runtime `ApplyConfig` wiring coverage** (PR-1): load, reconfigure,
   replace + rollback, detach, skip/fuse through the new call site.
3. **Per-profile egress proxy through a real outbound** (PR-1/PR-3):
   plugin traffic through the core-owned proxy, ephemeral loopback-only
   credentials, cookie injection scoped to declared hosts, no raw
   WireGuard key or secret in any plugin-built surface — observed
   proxy-side (M-4), never by plugin-side echo.
4. **No-plugin / plugin-absent fail-closed behaviour** (PR-6/PR-7):
   defined, tested behaviour for every Muse command when no plugin is
   configured, when the `.so` is missing/corrupt, and on the `_no-plugin`
   static build (stub loader, `internal/pluginhost/loader_stub.go:21-25`);
   at least one `--binary` e2e run against the no-plugin build, or a
   recorded reason why not.
5. **Cookie/session handoff coverage** (PR-6/PR-7): see leg 10 row above.
6. **CI matrix decision** (PR-7): per extraction PR, add a matrix leg
   (which tags, which runners — loader tests need cgo + Linux/Darwin/
   FreeBSD, no-plugin needs `CGO_ENABLED=0`) or record the deliberate
   gap and keep e2e as the only net. Resolve the check-count discrepancy
   (M-6) against live GitHub state before quoting a check count.
7. **Release-matrix parity** (PR-7): both release jobs (glibc +
   no-plugin, amd64 + arm64) keep building; state what the no-plugin
   archive contains/omits and whether a plugin `.so` ships as a separate
   asset (none exists today).
8. **Secret-scan scope for plugin output** (PR-6): see leg 12 row above.
9. **Docs parity** (PR-7): `docs/e2e.md` re-verified against
   `scripts/e2e.sh` at the landing HEAD; leg numbers never quoted
   without re-checking (M-10).

`scripts/e2e.sh` itself is not edited by this plan, and no PR in §4
edits it except PR-5's single added endpoint-shape check and PR-6/PR-7's
added legs, each in its own PR with the leg table in this section updated
in the same PR.

## 7. Review checklist for Phase 3

- [ ] Every `file:line` in §§1–2 and §6 re-opened at the HEAD in §0 and
      found to say what is claimed (spot-check at minimum: `ApplyConfig`
      definition + sole caller, runtime seam, egress constructor,
      identity constructors, discovery entry, architecture boundary
      sentences).
- [ ] No claim in §§1–2 relies on a Phase 1 research file without
      re-verification; corrected secondary line numbers used (notably
      `internal/commands/runtime.go:101/112/344-368`,
      `internal/commands/commands.go:751/766/788`,
      `internal/profile/config.go:61/380-384`,
      `internal/pluginhost/egress.go:129/141/316-321`).
- [ ] Every `DECISION`/`UNDECIDED` row has an owner (Boss decision where
      it is config surface or no-plugin behaviour) and a PR that settles
      it; no silent defaults remain. Owners: D-ROADMAP — Boss, before
      PR-1; D-LAYOUT — PR-2 author (ratification), Boss if the layout
      changes from §2.5; D-MULTIENTRY — PR-1 author, before PR-1;
      D-AUTHCHAIN — PR-2/PR-3 authors; D-NOPLUGIN — Boss, before PR-6;
      M-1/M-2/M-3 — PR-7/Boss (§5, Ownership); CDP leg — PR-6.
- [ ] Revision-2 corrections re-opened at the HEAD in §0: `doc.go`
      boundary quote `13-20`; `redact` secret-key set `44-86`;
      exit-code comment `pluginabi.go:87-90`; waiter field reads
      `91-116`/`414`/`671`; fuse state `550-594` + triggers `820-860`;
      e2e leg 12 `1894-1961`, tail `1962-1993`; web UI handlers
      `380-594`; egress never-imports `22-42`; `proto.go:32-39`;
      `FragmentJSON` `77-85`; `ValidateRegistration` ends `258`;
      `dispatchHostCall` starts `911`; `KeeperEntry.Profile` field
      `298`; NOT FOR PLUGIN USE warning `identity.go:80-85`;
      PR-7 cross-reference M-6/M-11 (not M-8).
- [ ] Revision-3 corrections re-opened at the HEAD in §0: wake URL
      `wake.go:20`; `cmdRaw` `Total()` `read.go:1022-1027`; ALPN pin
      `connector.go:231` (comment) / `:265` (code) and `WebSocketDial`
      call `:265`; `egress_test.go` first use `:54`; matcher
      `contract.go:194-207`; `classifyError`
      `commands.go:268-337` with `GatewayError` `:301-304` and
      `TimeoutError` `:313-316`; `GatewayError` producers
      `summary.go:213`, `subscription.go:316,350`,
      `authcookies.go:76,81,91`; `TimeoutError` producers
      `gateway.go:201,220`, `calls.go:165`; `Leaser` marker
      `conn.go:543,581`, raw-slot close `conn.go:634-650`,
      `SharedConn.Lease`/`Close` `shared.go:127-131`; helper usages
      in the §2.5 per-helper table; discovery ID derivation
      `discovery.go:47-56,75-110,191-243`; fetched URLs
      `authcookies.go:59,106` vs label constants `tick.go:27-28`;
      screencast message URL `screencast.go:192`; `TLS` options
      `outbound/tls.go:15-43`; no `FetchHatchTokenWithCookies`
      exists; `hatchHeaders` `auth.go:29-43`, `doHatch`
      `auth.go:50-66`, non-retention `connector.go:130`.
- [ ] Every `[NEEDS-MEASUREMENT]` item names its measurement; no PR exit
      criterion claims one as passed.
- [ ] The trusted-plugin limit (§1.3) and the CONNECT opacity limit
      (§3.6) appear in the PR bodies of PR-1/PR-3/PR-6, not only here.
- [ ] No Go code, no `scripts/e2e.sh` edit, no merge, and no secret value
      in this plan's own diff.
