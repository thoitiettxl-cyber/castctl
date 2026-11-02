# Architecture

## Overview

castctl is a general content-pipeline control tool: content sources (first:
Muse) feed publishers (later: Facebook, TikTok, YouTube, via official APIs
first). One Go binary (CGO_ENABLED=1, GLIBC 2.17 baseline). All network traffic of a profile goes through
that profile's outbound (sing-box). The web UI is a single-file React app
embedded in the binary; see "Web UI" below.

Core + plugins: see "Core + plugins" below. The earlier layout
(`internal/source/muse`, `internal/publish/<platform>`) is superseded;
it is not the layout. Binary: `castctl`. Env vars: `CASTCTL_CONFIG`,
`CASTCTL_PROFILE`.

Migration done: the `go/` tree moved to the castctl
root keeping only `go/` history, the Go module became
`github.com/thoitiettxl-cyber/castctl`, and the binary is `castctl`.
Deleting `go/` from muse-cli with a README pointer is a separate PR.

## Core + plugins

castctl is core + plugins. The plugin framework is
implemented (`internal/pluginabi` + `internal/pluginhost`,
mirroring CLIProxyAPI's loader approach, ABI/contract style,
and plugins directory layout, adapted for the per-profile
proxy/cookies handoff to plugins — never raw WireGuard
keys). The framework is not yet wired into the runtime:
`ApplyConfig` is called only by `castctl plugin check` and
tests, no Muse code has moved into a plugin, and wiring is
a later PR. Plugins MUST send all network traffic through
the per-profile egress proxy that core provides, and never
dial directly, since without a sandbox they could otherwise
bypass the profile's outbound.

Config is the sing-box inline shape, NOT upstream's toggles:
a top-level `plugins` array of `{tag, type, ...fields}`
entries, with no `enabled` field at any level (presence =
active). Upstream's `PluginsConfig` (`enabled`, `dir`,
`store-sources`, `store-auth`, `auth-revision`, per-instance
`configs` map) was deliberately not ported: no store,
download, registry, or signing exists (BQ4). The plugin
design draft is rationale only: the implementable spec is
`docs/plugins-spec.md` (under 20 KB, mirroring CLIProxyAPI),
and the full contract is `docs/plugins.md`.

Core is profiles, per-profile outbound (sing-box), the cookie/session
store and keeper, config, the web UI, and Telegram. Screencast login
stays in core. Each platform is a plugin: castctl-muse first, then
castctl-facebook, castctl-tiktok, and castctl-youtube.

Plugins are trusted and in-process, with no sandbox, exactly like
CLIProxyAPI, and only first-party CLIs (BQ1, closed). BQ2 (logical
instances) is settled as (A); BQ3 (dlopen-init residual) is
accepted and documented; BQ5 is the core per-session loopback
proxy with ephemeral credentials. A native plugin panic/crash
cannot be isolated by the host — only host-adapter panics and
plugin-returned errors are (fuse). The red-team findings B1, B2,
and B4–B10 are kept; B3 stays dropped (per the accepted
plugins design). The earlier "BQ2–B5 parked" line is
superseded by the implemented framework.

The upstream sources for the plugin model, what was mirrored,
and what was deliberately not taken are recorded in
docs/provenance.md §2.

Castctl stays one config.json whose schema grows by adding top-level modular blocks, sing-box style (log, dns, outbounds, profiles, later telegram/keeper), each block optional with sing-box-like defaults, and blocks reference each other by tag (profile -> outbound tag, dns server -> detour tag) rather than duplicating settings; there are no hidden hardcoded paths or rigid defaults, and every new feature is a new block or field, not a separate file.

## Platforms

castctl is a general tool, not VM-only. Supported run targets: Linux only — linux/amd64 and linux/arm64 (Debian/server Linux host). No VM assumptions: no hard-coded paths,
no launcher, no agent-browser, no sandbox.

This supersedes the earlier five-target plan: release targets are
Linux only (above). The default build is dynamically linked
(`CGO_ENABLED=1`) on a GLIBC 2.17 baseline (manylinux2014); each
architecture also ships a `_no-plugin` static build
(`CGO_ENABLED=0`) whose loader refuses loads. The plugin loader
is implemented in-tree (unix + Windows loaders, stub for
no-cgo); Linux amd64 loads are proven by contract tests and
Linux arm64 loads under qemu (build proof only), while
Windows and macOS loads are unproven
([NEEDS-MEASUREMENT] — see docs/plugins.md). The phone
runs the normal linux/arm64 glibc build inside
Droidspaces (a Linux container); there are no separate
Android, Windows, or macOS release builds. Release builds are produced by
`.github/workflows/release.yaml`, adapted from CLIProxyAPI's
release.yaml (see docs/provenance.md §2).

Config location: `--config`, then `CASTCTL_CONFIG`, then `XDG_CONFIG_HOME`, via `os.UserConfigDir` semantics. Directory fallback: when the `castctl` home does not exist but the pre-migration `muse-cli` home does, the old home is used with a one-line warning; nothing is moved or deleted (see README.md).

Screencast login: the browser dependency is optional and detected at
runtime (system Chromium or a configured path); with no browser, fall back
to `auth import` with a clear message. The web UI is loopback-only: a
phone or other device reaches it through an SSH tunnel forwarding the
loopback port, never through a non-loopback bind (see docs/security.md).
Tests
must not depend on the developer VM's environment (hermetic: temp dirs,
fakes, no live hosts).

## Self-update (`castctl update`)

`castctl update` replaces the running binary from the latest
stable GitHub release. It is user-invoked only: no daemon, no
scheduled check, no config file read or written, no credentials.
Release downloads are public URLs, not profile traffic, so the
command loads no profile and uses its own stdlib HTTP client
(`internal/update`), never a profile outbound and never
`http.DefaultClient`. The command refuses on any platform other
than Linux: no release assets exist for Windows, macOS, or
Android, and that behaviour is [UNVERIFIED] by construction
(no assets, never executed there).

Behaviour, in order:

1. The running build must be stamped (release `-X` flags set
   `Commit` and `BuildDate`). An unstamped dev build refuses in
   every mode, including `--dry-run` and explicit `--version`,
   with "cannot determine running version"; the stale `Version`
   default is never guessed from.
2. The latest stable release is selected from the unauthenticated
   GitHub API (`releases/latest`, castctl User-Agent). Drafts and
   prereleases abort; an invalid `tag_name` aborts. On an API 403
   (rate limit) there is one fallback, scoped to `/latest`: follow
   the public `github.com/.../releases/latest` redirect to learn
   the tag, then construct asset URLs only from the proven release
   matrix pattern and verify checksums as usual. The fallback is
   draft-blind by necessity (the redirect probe carries no draft
   data, so a draft tag learned this way cannot be refused as a
   draft); only the prerelease guard applies to a fallback tag.
   An explicit-version API 403 falls back without a redirect probe
   (the tag is already known) and constructs URLs from the matrix
   pattern only. Semver comparison is a hand-written stdlib
   parser (no `x/mod/semver` dependency). Equal version is an
   exit-0 no-op with zero writes; a downgrade refuses unless
   `--allow-downgrade` is given; a pre-release target refuses
   unless `--allow-prerelease` is given. `--version TAG` names a
   specific release instead of the latest, under the same
   verification; an explicit-mode `tag_name` mismatch is ignored
   (the install is bound by the requested tag, the exact asset
   name, and the checksums). The host allowlist applies to
   redirects only: the initial asset and checksums URLs come from
   the release JSON's `browser_download_url`, are not
   host-restricted, and are bound by the checksums verification.
   A redirect target carrying userinfo refuses before it is
   followed, so no Authorization header derived from a redirect
   URL is ever sent; a download URL carrying userinfo in the
   release JSON is refused during asset selection, before any
   request.
3. Asset selection is exact-equality against the release matrix
   for the selected tag: `castctl_<VERSION>_linux_<arch>.tar.gz`
   or `..._no-plugin.tar.gz`, matching `runtime.GOOS`,
   `runtime.GOARCH`, and the build flavour. The flavour is read
   from the build info `CGO_ENABLED` setting (`1` = glibc,
   `0` = no-plugin), verified by probe against the release build
   flags; an unknown flavour refuses rather than guessing. Flavour
   is a selection heuristic, not authentication: a hand-stamped
   build with mismatched `CGO_ENABLED` selects the wrong flavour,
   passes the exec check, and silently flips flavour (the asset
   installed is a genuine verified release asset either way); on
   a glibc-less host the wrong flavour would fail to exec and
   fail closed [UNVERIFIED]. No match is fail-closed, nothing
   written.
4. Verification happens BEFORE any replace: `checksums.txt` is
   held in memory (64 KiB cap, never written to disk) and only
   the asset is downloaded to a temp file in the target's
   directory (0600); the asset sha256 is verified against the
   checksums entry for the exact asset filename (missing or
   conflicting entries refuse; identical duplicate entries are
   idempotent), and only the regular file named exactly
   `castctl` is extracted. Only link/device typeflags refuse
   anywhere in the archive; other non-`castctl` regular members
   (including traversal or absolute names) are skipped unread
   and never used as paths; an archive with no exact `castctl`
   member refuses (a PAX-renamed `castctl` refuses by this path,
   since the effective name after PAX overrides is validated);
   trailing data after the tar end-blocks refuses only when it
   contains a non-zero byte; all-zero padding (GNU tar record
   padding to the 10240-byte boundary) is accepted. The
   extracted binary is validated with ELF/arch sanity
   (`debug/elf`) and an exec
   check: the checksummed candidate binary is executed,
   unsandboxed, with argv `--version`, clean minimal env,
   closed stdin, 10s timeout, capped stdout, and the output
   must be exactly one line, `castctl <version>`, parsed and
   compared equal to the target version (an optional
   parenthetical after the version is shape-only). Every failure
   before the rename leaves the old binary intact and partials
   are deleted; a directory-sync failure after a successful
   rename returns an error with the new binary in place
   (durability unproven). A child process detached by the
   candidate binary would survive the timeout kill; that
   residual is carried (see the PR record).
5. Replace is one rename in the target's directory, after
   preserving the target's Perm() (0777 rwx) bits (setuid/
   setgid/sticky bits of the old binary are dropped), fsyncing
   the temp file, and fsyncing the directory after the rename.
   The target is resolved once through symlinks, including a
   target resolving out of the directory. An advisory flock on
   a lock file in the target directory (`.castctl-update.lock`,
   created 0600, never deleted, persists by design; only temp files are
   removed) is held across download and replace; a held lock
   fails fast with "another update in progress". A tolerated
   directory-sync error (filesystems without directory fsync)
   succeeds silently. `--dry-run` reports what would be
   downloaded, verified, and replaced with zero writes: it takes
   no lock and skips the exec check, the chmod, and the re-hash
   (the report says the exec check is skipped).

No-signature limitation (stated, not hidden): releases carry no
signatures. The checksums prove only that the downloaded bytes
match what the release published, over HTTPS GitHub; they prove
nothing about who published the release. The exec check runs
bytes already checksum-verified against the release.

Exit codes: 0 = success, already-latest no-op, or dry-run
report; 2 = usage and policy refusals (no download, no replace;
release metadata may have been fetched first); 1 = operational
failures. Error output carries status, host, path, class, and
body length only, never response bodies, query strings, or
secrets.

Live-proof checklist (for the operator's own box, before
relying on `update`): run `castctl update --dry-run` against the
live release and confirm the report names the expected tag,
asset, and target path with zero writes; then run a real
`castctl update` on a COPY of the binary (not the live one) and
confirm the replaced copy prints the target version and the
original bytes are gone only in the copy; confirm a second
concurrent `update` fails fast with the lock message; confirm
an unstamped local build refuses. Redacted evidence only (tag,
asset name, exit codes, version strings) — never binary bytes,
tokens, or response bodies. Falsifiers: a dry-run that writes,
a replace without a checksum match, or an update that proceeds
from an unstamped build each invalidate the command.

## Profile isolation (hard invariant)

Profiles must never interfere with each other through the sing-box
stack. This is a HARD invariant: a violation is a bug, and enforcement
is by test, not by convention. It applied in the `go/` tree in
muse-cli, on `feat/go-port`, pre-migration, and applies in castctl
now that the migration has landed, to every command,
the Telegram bot, the web UI, the session keeper, and the screencast
login flow.

1. **One outbound stack per profile.** Either one sing-box box instance
   per profile, or unique tags per profile, namespaced as
   `<profile>/<tag>`. Never share MUTABLE state between profiles:
   registries, outbound/endpoint managers, routers, DNS clients, and
   dialers are built per profile. Shared data across profiles must be
   immutable configuration only, proven read-only by test. Two profiles
   built concurrently must have independent lifecycles (start/stop of
   one never affects the other).

2. **Local inbounds are per profile and per session, with auth.** A
   local inbound created for the login browser (or any other local
   consumer) binds `127.0.0.1` on an OS-assigned port (`:0`), belongs to
   exactly one profile and one session, requires authentication with a
   random username/password generated for that session, and is closed
   when the session ends. Never a fixed port, never `0.0.0.0`, never
   shared across profiles or sessions, never without auth — so another
   profile or process cannot use it.

3. **Per-profile network state, no cross-profile routing.** The DNS
   cache/client, connection pools, TLS session cache, and cookie jar are
   all per profile. Profile A's traffic must NEVER leave through profile
   B's outbound. Required test: run two profiles concurrently through
   DIFFERENT outbounds backed by fake servers, and assert each egress
   hit only the right upstream (each fake records arrivals; profile A's
   requests appear only at fake A, B's only at fake B), with DNS and
   cookie-jar activity staying inside the owning profile. The TLS session
   cache is OFF by default; if it is ever enabled, it is per profile —
   a global cache must not exist.

4. **No shared WireGuard private key across profiles.** Two profiles
   may not share a WireGuard endpoint config with the same private key
   at the same time — including via a shared endpoint tag referenced by
   both profiles. Validate at config load: the load FAILS with exit 2
   and a clear error naming both profiles. Never print the key in the
   error, a log, or a fixture. Different keys, or a key used by a single
   profile, load normally.

5. **No environment proxy, no system proxy, ever.** No
   `ProxyFromEnvironment`, no reads of `HTTP_PROXY` / `HTTPS_PROXY` /
   `ALL_PROXY` / `NO_PROXY` anywhere in product code, no OS/system-proxy
   detection, and sing-box `SetSystemProxy` is `false` everywhere. A
   test must prove dialling is unaffected by hostile proxy environment
   variables. The only proxy a profile uses is the explicit `http`
   outbound in its own configuration, if any; `direct` stays truly
   direct.

Related invariants (already decided, restated here because this
section is the single reference): every network call of a profile
goes through that profile's one outbound dialer (fail closed, no
system-resolver fallback); cookies live in separate `0600` files, never
inline in `config.json`; secrets are never printed, logged, or
committed (see `docs/security.md`).

**Session keeper and screencast login — documented routing
exception.** The keeper's cheap-chain checks go through the
profile's own outbound like any other profile traffic. The CDP
re-export is different: it reads cookies from the user's
already-running browser over a loopback CDP connection. The
browser's own traffic does NOT go through the profile outbound
(the browser is user-owned and pre-existing; castctl only reads
its cookies locally, never navigates it or dispatches input).
This is a deliberate, narrow exception to "every network call
goes through the outbound": the CDP reads are local loopback
reads of an already-authenticated session, not profile egress.
The screencast launch fallback has the opposite rule: a
castctl-launched browser must only ever egress through a
fail-closed per-profile inbound, and until that plumbing exists
the launch fails closed instead of spawning. The keeper's
`session-state.json` is the first runtime state file in the
tree: observed state (expiry dates, outcomes, warn markers),
not configuration — it lives next to `config.json`, never
inside it, because a sticky stopped state must survive config
rewrites and must never be edited as config. Separation also
keeps tick-churn out of a token-bearing file: `config.json`
carries secrets (the telegram token, cookie paths), and
rewriting it on every tick would churn a secret-bearing file
for observed state; state that changes every tick lives
beside it instead.

## Web UI

Source: `webui/` — a fork of the router-for-me/Cli-Proxy-API-Management-Center
frontend at `64b4f5aed19b8f791eb21eb9e785ea379ea05b44` (MIT; see
`webui/NOTICE` and the in-app About page). Kept: React + TypeScript + Vite
build, `vite-plugin-singlefile` output, theme/layout (including the mobile
off-canvas sidebar), shared UI components, i18next mechanism, CodeMirror
integration, diff-before-save pattern. Replaced: all pages, the API client
(fetch wrapper against castctl's own `/api/v1`), the auth store
(sessionStorage token), locale strings (English + Vietnamese), branding.

The committed `webui/dist/index.html` is the PRODUCTION build (mocks off).
The mock API layer (`webui/dev-mocks/`, `VITE_USE_MOCKS=true`) is dev-only
and never bundled. The screencast Login page is behind a build-time flag
(`VITE_ENABLE_SCREENCAST_LOGIN`, default off); the committed dist is
built with the flag on so the page is observable, and the page queries
the server for availability first. Build/serve/mock
instructions: docs/development.md. Native-login bundle research (PARKED):
docs/research/native-login-bundle-analysis.md.

The Go server (`internal/webui`, `castctl webui serve`, go-chi/chi)
serves the embedded dist and `/api/v1`. It is loopback-only and
token-authed: the optional top-level `webui` block configures it
(absent = no server), every API route requires a Bearer token, and
the listen address is validated loopback-only at parse time and
again for flag overrides. Config saves validate the full config
before writing and reuse the guarded atomic 0600 write path;
cookie set/replace reuses the locked cookies writer and the keeper
reset. Live logs tail the configured log *file* only, through the
same SafeString boundary as the log pipeline, and report disabled
when the log gate is off. The screencast relay embeds
`internal/keeper` only: frames and input flow through the keeper
Transport, chromedp stays behind `with_chromedp`, and without the
tag the page and the API say unavailable. Profile/outbound test
endpoints are CLI-only in this build (501 `unavailable`); the
phased test runner was not extracted.

Secrets in config are write-only under the [secrets write-only contract](../webui/SECRETS-CONTRACT.md),
which the Go server MUST implement server-side (see docs/security.md).

The web UI fork's upstream commit, the measured file diff, and what
was kept, adapted, or removed are recorded in docs/provenance.md §3.
