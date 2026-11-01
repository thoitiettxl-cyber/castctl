# Plugins

Plugins extend castctl with new content sources and publishers.
Each platform is a plugin: castctl-muse first, then
castctl-facebook, castctl-tiktok, and castctl-youtube. This
document describes the plugin framework as implemented. The
condensed implementable spec is `docs/plugins-spec.md`; the
design rationale draft is `~/workspace/plans/castctl-plugins.md`
(not in this repo).

Status of this PR: the framework only. No Muse code was moved
into a plugin, and `ApplyConfig` is not wired into the runtime:
plugins load only through `castctl plugin check` and tests.
Wiring plugins into profile runtimes is a later PR.

## Trust model

Plugins are trusted and in-process, with no sandbox, exactly
like CLIProxyAPI (BQ1, closed). Only first-party CLIs are
plugins. A plugin runs in the castctl process with the same
privileges: a malicious or buggy plugin can crash the process
or read process memory. Do not load third-party plugins.

Plain limit on isolation: a panic, crash, `os.Exit`, or memory
corruption in native plugin code cannot be prevented by
`recover` or timeouts. Only panics in the host adapter and
plugin-returned errors are isolated (the plugin is fused and
the core survives). See "Fuse" below. There is no sandbox
promise of any kind.

## Layout

Two packages, a justified consolidation of CLIProxyAPI's
three-part shape (`pluginhost` + `pluginapi` + `pluginabi`):

- `internal/pluginabi` — the contract: C ABI constants, the
  JSON envelope, registration, capabilities, identity, egress.
  No host logic, no Muse types.
- `internal/pluginhost` — the host: loader, lifecycle,
  discovery, shadow copy, glibc compat, checksums, egress
  proxy. It imports `pluginabi` only.
- `internal/plugintest` — contract-test fakes and the
  c-shared fixture builder (tests only).
- `examples/plugin/echo` — the minimal Go c-shared example.

There is no `internal/pluginapi` package: it would duplicate
`pluginabi` with no second consumer. There is no public `sdk/`
tree: castctl is a binary, not a library. The core imports no
Muse wire types, no `internal/gateway`, and no
`internal/proto` in plugin code; provider traffic is an opaque
JSON envelope.

## C ABI

A plugin is a dynamic library (`.so` / `.dylib` / `.dll`)
exporting one entry symbol:

```
castctl_plugin_init
```

The entry fills a plugin function table (call, free_buffer,
shutdown) and receives a host function table (host context,
call, free_buffer). The tables mirror CLIProxyAPI's
`cliproxy_host_api` / `cliproxy_plugin_api`, renamed into the
`castctl` namespace. The plugin is loaded with
`RTLD_NOW | RTLD_LOCAL` on unix, `LoadLibrary` on Windows.

Constants (`internal/pluginabi`):

| Name | Value |
|---|---|
| ABI version (`ABIVersion`) | `1`, exact match required |
| Entry symbol (`EntrySymbol`) | `castctl_plugin_init` |
| Schema version (`SchemaVersion`) | `1` (ceiling) |

Schema rules: a missing `schema_version` in a registration is
treated as `1`; a higher version is rejected with a clear
error, never a crash. ABI mismatch (the C table's
`abi_version`) is likewise a refusal, never a load.

All host/plugin calls exchange one JSON envelope:

```json
{"ok": true, "result": {...}}
{"ok": false, "error": {"code": "…", "message": "…"}}
```

Lifecycle methods: `plugin.register`, `plugin.reconfigure`,
`plugin.quiesce`. Provider method: `provider.call`. There is
no `plugin.shutdown` envelope method: shutdown is loader-level
(the C table's shutdown function, called when the client is
detached). Command methods are `command.*` (see Capabilities).

## Lifecycle (`pluginhost.Host.ApplyConfig`)

`ApplyConfig` takes the desired plugin set and converges to
it, one plugin at a time, in order:

1. Duplicate tags in one desired set: the first wins, later
   ones are skipped.
2. A plugin absent from the desired set is detached
   (shutdown, never unloaded — see below).
3. Same binary path: `plugin.reconfigure` with the new
   fragment. On failure the old fragment is re-registered
   (rollback); if rollback also fails the plugin is fused
   and detached.
4. Different binary path: the old plugin is quiesced first
   (a quiesce failure is logged, never fatal), then the new
   image loads. On new-image failure the old image is
   re-registered (rollback); rollback failure fuses and
   detaches.
5. A fresh load shadow-copies, compat-checks, dlopens,
   inits, and registers. Any failure detaches the client
   and records a skip.
6. Per-plugin failures are warn-and-skip: they are recorded
   in `ApplyReport.Skipped` with the tag and a short reason,
   and never fail the whole call or abort other plugins.

Fuse: a host-adapter panic or a call timeout fuses the
plugin, per PATH. A fused plugin stays loaded but is skipped
by later `ApplyConfig` calls for the same path; loading a
different path replaces it and clears the fuse. A fused
plugin's remaining calls fail fast with the stored fuse
reason, without invoking the plugin again. `Host.Call`
checks the fuse first. The fuse reason names the method
and the panic type only — never a panic value, never a
secret.

Never unload: a loaded image is never `dlclose`d /
`FreeLibrary`d, including when initialization fails, because
`dlopen` may already have started the plugin runtime, and a
Go c-shared runtime cannot be removed from the host process
safely. Detach is logical only (shutdown function + drop the
client). Shadow copies keep the source artifact replaceable
while the image stays mapped.

Timeouts: a hung call returns on the caller's context
deadline; the call is abandoned, not killed (the plugin
thread is not terminated), and the plugin is fused.

## Discovery

Plugins are discovered from a root directory. Selection is
by VERSION, mirroring upstream `comparePluginVersions` /
`pluginFilePreferred` (`platform.go:218` / `:204`): numeric
dot-separated segments, a missing segment counting as 0,
non-numeric segments falling back to lexical order; a
versioned file beats a versionless one; on an exact version
tie the `<GOOS>/<GOARCH>` platform directory wins. A
downgrade is never silent: dropping an older file into the
root cannot beat a newer platform file. File names are
`<id>-v<version>.<ext>` (`.so`, `.dylib`, `.dll`); a bare
`<id>.<ext>` is versionless. Names that do not parse —
including a `-v` suffix with a malformed version
(`echo-vv1.0.so`) — are skipped, never given a silent odd
id. Symlink entries are skipped at discovery. IDs match
`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$` (the upstream rule,
`platform.go:17`). The shadow copy name is
`castctl-plugin-<id>-<sha256[:32]>.so` under a per-process
directory (`castctl-pluginhost/pid-<pid>/`, 0700): the same
content maps to the same path, different content to a
different path. The name is predictable from content, as
upstream (`shadow.go:154`) — not random, not a memfd.

Image sharing: two Hosts loading the same tag+path share
one shadow path, so `dlopen` caches one image (logical
instances, BQ2(A)); different tags get different shadow
paths and are isolated. This is by design, not a bug.

Hardening castctl adds (not upstream, never cite upstream
for it): every component of the plugin path is Lstat-checked
(a symlinked directory component refuses the load, on unix);
the source file is opened with `O_NOFOLLOW` and must be a
regular file — symlinks and directories are refused, so a
swapped symlink cannot redirect a load. On unix the file
must additionally have exactly one hard link (`Nlink==1`);
on Windows/macOS there is no equivalent check and only the
symlink+regular-file refusal applies. Pre-existing shadow
directories are hardened to 0700 with an ownership check.
On graceful host shutdown the process's own shadow
directory is removed (best-effort), and constructing a host
sweeps stale `pid-<pid>` shadow directories whose pid is
not alive. Crash-killed processes leave stale directories
until the next sweep; `/tmp` size remains a deployment
consideration.

## Config

The top-level `plugins` key is an ARRAY of entries, in the
sing-box outbounds/endpoints style (type/tag inline, no
wrapper object):

```json
{
  "plugins": [
    {"tag": "muse", "type": "muse", "model": "opus"}
  ]
}
```

Rules:

- Each entry requires `tag` (unique) and `type`. There is
  NO `enabled` field at any level: presence in the array
  means active; remove the entry to disable. An `enabled`
  key inside an entry is plugin-opaque data, never a core
  toggle.
- Core parses `tag`/`type` strictly (both required, both
  matching the plugin-ID rule). There is NO unknown-key
  rejection for the rest of the entry: every other key
  becomes part of the fragment. The REMAINING object is
  handed to the plugin verbatim as its config fragment, in
  original key order, and raw-preserved on save.
- Display and redaction show `tag`/`type` only; the fragment
  is shown as `<redacted>` wholesale under the `fragment`
  key (`internal/profile/redact.go`). Plugin fragments never
  appear in logs, errors, or the web UI. (A PUT round-trip
  of displayed content fail-closes loudly through the web
  UI's sentinel merge instead of writing the marker into
  a fragment.)
- Plugin tags live in their own namespace: they do NOT
  participate in `validateTagGraph`'s outbound/endpoint tag
  namespace. Fragment contents are the plugin's business.

## Capabilities

A registration declares capabilities; at least one is
required, and name/version/author are required:

- `provider` — the plugin answers `provider.call` with an
  opaque JSON envelope. The core never interprets provider
  payloads.
- `command_provider` — the plugin registers commands via
  the contract (`commands` in the registration). Commands
  are registered through the contract only; there is no
  `init()`-based registration.

## Reverse callbacks: `host.log` only

The only reverse callback a plugin may call is `host.log`
(`{level, message}`), delivered to the host log function
with the message truncated to 4096 characters and control
characters stripped, and the level restricted to an
allowlist (`info`, `warn`, `error`, `debug`; anything else
becomes `info`) so a level cannot forge a log line.
Every other `host.*` method is rejected with
`unsupported_host_callback`. In particular `host.auth.*`
is rejected absolutely: plugins never read, list, or save
credentials through the host. Upstream's auth callbacks
(`auth_callbacks.go`, which reads credential files) were
deliberately NOT ported.

## Secrets and egress

A plugin never receives: a `*Manager`, a `SingleConfig` /
`Profile`, a cookie path, environment passthrough, a raw
WireGuard key, a token, real proxy credentials, or a
self-built `http.Client`. What it receives at register time:

- Identity: `{outbound_tag, outbound_hash}` where the hash
  is computed over the secret-stripped outbound object
  (`redact.Value`, sorted-key canonical JSON, SHA-256). A
  password change does not change the hash; a type change
  does.
- Egress: `{proxy_url, username, password}` for the
  per-session loopback proxy (below).
- Config fragment: the verbatim remainder of its config
  entry, handed VERBATIM by core (never scrubbed on
  handoff) and displayed REDACTED wholesale — the fragment
  is the plugin's own configuration, and core adds no
  secrets to it.

Egress (BQ5, hybrid): each plugin session gets a loopback
HTTP proxy (`127.0.0.1:0`) owned by core, with ephemeral
random Basic credentials that exist only for that proxy's
lifetime (lifetime = instance lifetime; no rotation in v1;
`Host.Close` closes adopted proxies and revokes the
credentials). The proxy requires those credentials (407
otherwise), forwards absolute-form requests through the
caller-supplied upstream transport (in real wiring, derived
from the profile's outbound — `pluginhost` never imports
`internal/outbound`), strips hop-by-hop headers (including
`Connection`-listed tokens), strips `Set-Cookie` from
responses so upstream session cookies never reach the
plugin, and injects the session `Cookie` header inside core
ONLY for hosts the plugin declares in its registration
`cookie_hosts` — no declaration means NO injection
(fail-closed) — overwriting anything the plugin sent for a
declared host, and removing the plugin's `Cookie` header
for undeclared hosts. CONNECT tunneling works only when
the caller supplies a dial function; without one it
returns 502. A CONNECT tunnel is OPAQUE: core neither
injects nor inspects anything inside TLS, so cookie
scoping does not apply there — a trusted-model limit.
Proxy use by plugins is by CONTRACT and code review for
first-party plugins, NOT an enforcement boundary: an
in-process native plugin can still `net.Dial`, read the
environment, or read process memory. The enforceable
guarantees are only the handed surface, redaction on
output, and per-plugin isolation. Plugin-chosen text
reaching output is redacted and capped at 4096 characters
(the single plugin-text limit, matching the `host.log`
cap). The proxy proves the mechanism with a fake/local
upstream in tests; it does not prove a live profile
outbound path.

Errors travel as envelopes plus the existing classifier; a
plugin never picks an exit code, and no raw server body
appears on any output.

## glibc compatibility

Build floor: glibc 2.17. Bundled runtime (KernelSU module):
glibc 2.44. Both are documented because they answer
different questions: 2.17 is what a plugin may require at
most to load everywhere castctl runs; 2.44 is what the
module ships today.

Before `dlopen`, the loader parses the plugin ELF
`.gnu.version_r` (`debug/elf`, no new dependency) for the
highest required `GLIBC_` version and compares it against
the running libc via `gnu_get_libc_version` (cgo/linux).
A higher requirement is refused with a clear error naming
the required and running versions — never a crash, never a
silent pass. Running-version strings with distro suffixes
(e.g. Debian's `2.44-0`) parse by leading digits. On non-glibc targets (darwin, Windows) and on
no-cgo builds the check is fail-closed for ELF files with
requirements present: the file is refused rather than
loaded unchecked. Non-ELF files skip the check (the format
gate is the loader itself).

Android: there is no `GOOS=android` loader file. The
module runs the `GOOS=linux` / `GOARCH=arm64` glibc build
under the bundled glibc loader
(`/lib/ld-linux-aarch64.so.1`), so the unix loader
(`cgo && linux/darwin/freebsd`) IS the Android path. A
`GOOS=android` binary falls back to the stub loader and
refuses loads clearly. The phone load is the merge gate
(see "On-device check").

Builds: the default build is dynamically linked
(`CGO_ENABLED=1`) and loads plugins. Each architecture also
ships a `_no-plugin` static build (`CGO_ENABLED=0`) whose
loader refuses loads with a clear error. The Windows loader
exists (stdlib `syscall` only, same never-unload rule) but
has not run on a Windows host: [NEEDS-MEASUREMENT]. The
macOS loader is the unix loader; it has not run on macOS:
[NEEDS-MEASUREMENT].

## Checksums manifest (local dir only)

There is no plugin store, download, registry, or signing
(BQ4). For local-directory plugins only, a `checksums.txt`
manifest (SHA-256, `checksums.txt` format) may accompany the
binaries; when a manifest path is supplied by the caller,
the SHADOW-COPY bytes about to be `dlopen`ed are verified
against it BEFORE load (the verify-before-use pattern from
upstream's plugin store, without the store), through one
`O_NOFOLLOW` open with a regular-file re-check. A mismatch,
a missing entry, a duplicate or traversing manifest name,
or a symlinked manifest/plugin path refuses the load.
Manifest generation and distribution are the operator's
job. There is no production caller wiring a manifest path
in this PR: verification happens only where the caller
supplies `Desired.ManifestPath`. A residual window remains
between shadow verification and `dlopen` (no fd pin); see
"Known limits".

## Writing a plugin

1. Implement `castctl_plugin_init` + the JSON envelope
   (see `examples/plugin/echo/main.go`). Return schema `1`,
   metadata, and at least one capability.
2. Answer `plugin.register` / `plugin.reconfigure` with
   the registration, `plugin.quiesce` with an empty OK
   envelope, and `provider.call` with the provider result.
3. Use only `host.log` for reverse calls. Never expect
   cookies, tokens, keys, or paths in the register
   request; use the egress proxy for all network traffic.
4. Keep the plugin side stateless across reconfigure:
   reconfigure replaces the fragment in place.
5. Name the artifact `<id>-v<version>.so` and place it in
   `<root>/<GOOS>/<GOARCH>/`.

The echo example builds with:

```sh
go build -buildmode=c-shared -o echo.so ./examples/plugin/echo
```

Cross-compiling for the module (linux/arm64, glibc 2.17)
uses the pinned Gate 0 toolchain (zig 0.17.0 + pinned
glibc 2.44 sysroot) — see "Cross-compiling the echo
example" below. Verify any build with
`castctl plugin check <path>` before placing it on a
device.

## Cross-compiling the echo example

The arm64 build reuses the Gate 0 setup
(`~/workspace/tmp/gate0-retry/`: zig 0.17.0, tarball
sha256 `1cbe9df9f27e6b78d14ccbca43b6703a404ef79ef1c463de901d7f088d4e2026`;
qemu-aarch64-static 7.2.22, `.deb` sha256
`c3e3ba2bd87f8c5b9a5da5ef21b5a3b82d7c63b89dd448d9ddaa4eabc5b6e402`;
glibc sysroot `.deb` sha256
`5392d254e84c436e96783bcb6ffffe429d6b24c7ad00490f23f06f66c4769fb6`
= `module/sources.lock` `LOCK_GLIBC_SHA256`). The exact
commands and the qemu load log are recorded in the PR
report; the load itself is proven under qemu with the
bundled-loader invocation, and on the phone with
`plugin-check` (merge gate). Do not re-download the
toolchain without sha verification.

## On-device check

`castctl plugin check <path>` loads one plugin binary
through the real loader and runs one provider call. It
loads no config, starts no services, writes no config or
cookies, and logs no secrets. Output on success:

```
dlopen: ok
init: ok
register: ok schema=1 name=echo version=0.1.0 capabilities=provider
provider.call: ok {"payload":"echo:ping"}
shutdown: ok
```

On failure it prints one `FAIL` line naming the tag and a
short reason, and exits 2. On the device, the wrapper is
`castctl-ctl plugin-check <file>` (lifecycle-locked,
root-gated; the file must already be in the reserved
plugin dir, must not be a symlink, and the core binary
runs under the bundled glibc loader):

```sh
# on the phone, as root (KernelSU module installed):
cp echo-v0.1.0.so /data/local/castctl/plugins/linux/arm64/
castctl-ctl plugin-check echo-v0.1.0.so
```

Expected output is the five lines above (name/version
per the plugin). Phone result: [NEEDS-MEASUREMENT] — it is
the merge gate for this PR.

## Per-platform load proof

| Platform | Load proven? |
|---|---|
| Linux amd64 (host) | Yes — real-loader contract tests + `plugin check` dry run |
| Linux arm64 under qemu (bundled loader) | See PR report (qemu load log + exit code) |
| Windows | [NEEDS-MEASUREMENT] — loader compiles, never ran |
| macOS | [NEEDS-MEASUREMENT] — unix loader, never ran |
| Phone (KernelSU module) | [NEEDS-MEASUREMENT] — merge gate |

CI runs Linux-only jobs; no Windows/macOS/Android CI job
exists, and none is claimed.

## Known limits

- TOCTOU window (U1): between shadow-copy verification and
  `dlopen` the shadow file could be swapped by another
  process with write access to the shadow directory. The
  verification + symlinked-component checks narrow the
  window; there is no fd pin. Treat the shadow directory
  as host-private (`0700`, per-process).
- Runtime bypass (U2): a plugin can `dlopen` another
  library at runtime, bypassing the compat/checksum gates
  for that library. The gates cover only the direct `.so`
  at load time. Trusted-model limit.
- Callback-id guessing (U3): a plugin guessing another
  plugin's host-callback id gets only that plugin's
  `host.log` lines misattributed in logs. No secret or
  control surface is reachable through `host.log`.
- Native access (U6): a native plugin can read the
  environment, files, and process memory. Trusted-model
  limit; see "Trust model".
- Hung native calls (U7): `Host.Close` waits for
  in-flight native calls to return; a hung plugin call
  blocks shutdown until it returns.
- Envelope size (U8): there is no cap on the size of a
  plugin's envelope response; only RENDERED plugin text is
  capped at 4096 characters. A >2 GiB response length is
  refused rather than truncated in the C call path.
- Lazy binding (U9): loading uses `RTLD_NOW`, so missing
  symbols fail at load; a plugin that resolves symbols
  lazily at runtime is outside the gate.
- `$ORIGIN` sidecars / transitive deps (R13/R14): a
  plugin whose `DT_NEEDED` dependency is resolved via
  `$ORIGIN` fails through the shadow copy (no sidecar is
  copied); absolute-rpath dependencies load bypassing the
  gates. Dependencies must be self-contained or
  absolute-rpath with this limitation understood. The
  compat gate covers only the direct `.so`: a dependency
  requiring a newer glibc is refused cleanly by `dlopen`
  (`RTLD_NOW` backstop), not by the gate.
- Windows/macOS/phone: [NEEDS-MEASUREMENT] (U4/U5) — the
  Windows loader compiles but has not run; the macOS
  loader is the unix loader, unrun; the phone load is the
  merge gate.

## What was NOT copied, and why

- `host.auth.*` callbacks: upstream reads credential files
  through them; castctl rejects them absolutely. No
  credential surface exists for plugins.
- Lstat/hardlink rejection in the shadow copy: absent
  upstream (verified by grep at the pin); implemented by
  castctl (hardlink check unix-only). Never cite upstream
  for it.
- Upstream `validPlugin` also requires a non-empty
  `GitHubRepository` (`host.go:1241`); castctl deliberately
  does NOT require it. Do not cite upstream for castctl's
  metadata gate without stating this deviation.
- `min_version` / `allow_downgrade` plugin config: absent
  upstream; not implemented.
- Random shadow names / memfd: absent upstream; shadow
  names stay content-derived.
- Load-time signature checks: absent upstream; only the
  opt-in local `checksums.txt` verification exists.
- Upstream `PluginsConfig` (enabled/dir/store-sources/
  store-auth/auth-revision/configs map): deliberately not
  ported. Castctl's `plugins` array follows the sing-box
  inline shape instead; see "Config".
- Sandbox promises: none, in either codebase.

## References

Upstream: `github.com/router-for-me/CLIProxyAPI`, commit
`250d598175db61a4e99ac38b9164ed04745754e5` (ABIVersion 1,
SchemaVersion 10 upstream; castctl schema starts at 1).
Files mirrored (renamed namespace, castctl schema 1):

- `internal/pluginhost/loader_unix.go` — C preamble,
  `dlopen` RTLD_NOW|RTLD_LOCAL (:44), entry lookup (:130),
  ABI exact check (:166-168), never-unload close
  (:225-237).
- `internal/pluginhost/loader_windows.go` — table shape,
  never-unload comment (:204).
- `internal/pluginhost/loader_unsupported.go` — stub
  refusal wording.
- `internal/pluginhost/abi.go` — host/client/loader
  interface shape.
- `internal/pluginhost/host.go` — `ApplyConfig` (:213),
  quiesce, rollback.
- `internal/pluginhost/platform.go` — candidate dirs
  (:308), discovery (:292), extension (:99), ID rule
  (:17), version comparison (:218), file preference
  (:204).
- `internal/pluginhost/shadow.go` — shadow copy (:33),
  sha256 naming (:154), per-process dir (:126-138).
- `internal/pluginhost/client_guard.go` — guarded call,
  recover, abandon-on-timeout (:80-115).
- `internal/pluginhost/rpc_schema.go` — lifecycle
  request/response shape.
- `internal/pluginhost/rpc_client.go` — schema ceiling +
  missing→1 (:111-118).
- `sdk/pluginabi/types.go` — ABIVersion (:7),
  SchemaVersion (:36), `host.log` (:140).
- `sdk/pluginapi/types.go` — Capabilities (:74).
- `internal/config/config_types.go` — upstream
  `PluginsConfig` (:28-52), deliberately not ported.
- `internal/pluginstore/install.go` +
  `internal/pluginstore/checksum.go` — verify-before-use
  (`VerifyChecksum`, checksum.go:34); no store/download.
- `examples/plugin/simple/go/main.go` — c-shared example
  shape, extern declarations.

Sing-box v1.14.4 (module cache): `option/outbound.go` and
`option/endpoint.go` (`_Outbound` / `_Endpoint`: Type/Tag
inline, no `enabled` field) and
`docs/configuration/outbound/index.md`
(`{"outbounds": [{"type": "", "tag": ""}]}`); top-level
arrays at `docs/configuration/index.md`.

Full provenance record: `docs/provenance.md` §2.
