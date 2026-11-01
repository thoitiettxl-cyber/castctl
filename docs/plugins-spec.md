# Plugin spec (castctl)

Condensed implementable spec, mirroring CLIProxyAPI's plugin
model. Rationale lives in `~/workspace/plans/castctl-plugins.md`
(design draft, not in this repo); this spec is normative for
the framework. Upstream pin:
`github.com/router-for-me/CLIProxyAPI`
`250d598175db61a4e99ac38b9164ed04745754e5`.

## 1. Scope

Trusted, in-process, first-party-only plugins. No sandbox, no
store, no download, no registry, no signing, no runtime
wiring in this PR (`ApplyConfig` is called by
`plugin check` and tests only). One config file; plugins
are a top-level `plugins` array (sing-box inline shape).

## 2. Native ABI

- Library: `.so` (linux), `.dylib` (darwin), `.dll`
  (windows). Entry symbol: `castctl_plugin_init`.
- Host table: `{abi_version:u32, host_ctx, call, free_buffer}`.
  Plugin table: `{abi_version:u32, call, free_buffer,
  shutdown}`. Function-pointer types mirror upstream
  `loader_unix.go` (renamed namespace).
- Load flags: `RTLD_NOW | RTLD_LOCAL` (unix);
  `LoadLibrary` (windows). Init return != 0 refuses the
  load. ABI must equal `1` exactly. Tables with a nil
  `call`/`free_buffer` are refused.
- Never unload: no `dlclose`/`FreeLibrary`, including on
  init failure. Detach calls the shutdown function and
  drops the client only.
- `CGO_ENABLED=0` builds and `GOOS=android` builds use
  the stub loader and refuse loads with a clear error.
  The phone runs the normal `GOOS=linux/arm64` glibc
  build inside Droidspaces; the unix loader is the
  phone path.

## 3. JSON envelope

Every call carries one envelope:

```json
{"ok":true,"result":{...}}
{"ok":false,"error":{"code":"…","message":"…"}}
```

Methods: `plugin.register`, `plugin.reconfigure`,
`plugin.quiesce`, `provider.call`, `command.*`.
`plugin.shutdown` does not exist as an envelope method.

Registration (`plugin.register` /
`plugin.reconfigure` request):

```json
{"config_json":{...},"schema_version":1,"tag":"…","type":"…",
 "identity":{"outbound_tag":"…","outbound_hash":"…"},
 "egress":{"proxy_url":"…","username":"…","password":"…"}}
```

Registration response:

```json
{"schema_version":1,
 "metadata":{"name":"…","version":"…","author":"…"},
 "capabilities":{"provider":true,"command_provider":false},
 "commands":[{"name":"…","usage":"…"}]}
```

Rules: `schema_version` missing → `1`; higher than the
ceiling (`1`) → reject with `not supported`, never load.
Metadata name/version/author are required. At least one
capability is required. `commands` only with
`command_provider`; commands register via the contract,
never via `init()`. `command.execute` is registration-only
in this PR: no dispatch path exists.

## 4. Lifecycle

`Host.ApplyConfig(desired[])` converges serially:

- Same path → `plugin.reconfigure(new fragment)`; on
  failure, re-register the old fragment (rollback);
  rollback failure → fuse + detach.
- Different path → `plugin.quiesce` old (failure logged,
  never fatal), load new; on failure, re-register old
  (rollback); rollback failure → fuse + detach.
- Absent from desired → detach (shutdown, no unload).
- Duplicate tags → first wins, rest skipped.
- Any per-plugin failure → skip with tag + short reason;
  other plugins continue; the call itself succeeds.

Fuse: host-adapter panic or call timeout fuses the plugin
(reason: method + panic type only). Fused + same path →
skip. Different path replaces and clears the fuse.
Timeout: the call returns on context deadline; the plugin
thread is abandoned, not killed.

## 5. Discovery and shadow copy

- Root: `<root>/<GOOS>/<GOARCH>/` first, then `<root>/`.
- Names: `<id>-v<version>.<ext>` or `<id>.<ext>`.
  Invalid names skipped. ID:
  `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`.
- Shadow: copy to
  `<tmp>/castctl-pluginhost/pid-<pid>/castctl-plugin-<id>-<sha256[:32]>.<ext>`
  (0700 dir). Same content → same path. Source opened
  with `O_NOFOLLOW` on unix (plain open + Lstat refusal
  on Windows/other), must be a regular file (symlinks /
  directories refused — castctl hardening, not upstream).
- The shadow copy is removed when any load gate fails:
  checksum, compat, `dlopen`, missing entry symbol, init
  failure, or ABI mismatch. A successfully loaded image's
  shadow file stays until host shutdown removes the
  directory; the image stays mapped regardless.

## 6. glibc compatibility

Before `dlopen`, parse `.gnu.version_r` (`debug/elf`) for
the highest `GLIBC_` requirement; compare with the running
libc (`gnu_get_libc_version`, cgo/linux). Higher → refuse
with required vs running versions. Non-glibc / no-cgo
builds: refuse ELF files with requirements present
(fail-closed); non-ELF files skip the check. Build floor
2.17. Droidspaces provides its own glibc on the phone;
its version is recorded only from the on-device check,
never assumed.

## 7. Config

```json
{"plugins":[{"tag":"muse","type":"muse","model":"opus"}]}
```

- `tag` required + unique, `type` required. No `enabled`
  at any level; presence = active. `enabled` inside an
  entry is plugin-opaque.
- Core validates `tag`/`type` strictly (both matching the
  plugin-ID rule). There is no unknown-key rejection for
  the remainder: every other key becomes the verbatim
  fragment (original order, raw-preserved on save).
  Plugin tags do not participate in the tag-graph
  namespace.
- Display/redaction: `tag`/`type` + fragment `<redacted>`.

## 8. Egress and secrets

- Plugins receive ONLY: identity, egress, fragment.
  Never: managers, `SingleConfig`/`Profile`, cookie
  paths, env, WireGuard keys, tokens, real proxy creds,
  self-built `http.Client`.
- Identity hash: SHA-256 over the secret-stripped outbound
  (`redact.Value`, sorted-key canonical JSON).
- Egress: per-session loopback proxy (`127.0.0.1:0`),
  ephemeral random Basic creds (instance lifetime, no
  rotation in v1, revoked on host Close), 407 without
  them, absolute-form forwarding through the
  caller-supplied upstream transport, hop-by-hop
  stripping, `Set-Cookie` stripped from responses,
  `Cookie` injected inside core ONLY for hosts declared
  in the registration `cookie_hosts` (no declaration =
  no injection; overwrites plugin-sent values for
  declared hosts, removes them for others). CONNECT
  only with a caller-supplied dial function, else 502;
  a CONNECT tunnel is opaque (no injection/inspection
  inside TLS). Proxy use is by contract + code review,
  not an enforcement boundary: a native plugin can
  still dial directly. Plugin text on output is redacted
  and capped at 4096 characters.
- Errors: envelope + existing classifier; plugin never
  picks an exit code; no raw server bodies on output.

## 9. Reverse callbacks

Only `host.log` (`{level,message}`; truncated to 4096,
control chars stripped, level allowlisted). All other
`host.*` methods → `unsupported_host_callback`.
`host.auth.*` rejected absolutely. Upstream auth
callbacks were not ported.

## 10. Checksums

Opt-in local-dir verification only: `checksums.txt`
(SHA-256) verified against the SHADOW bytes before load
when a manifest path is supplied by the caller;
mismatch/missing entry refuses. No store, download,
registry, signing, or version gating
(`min_version`/`allow_downgrade` absent upstream and here).
Residual verify-to-dlopen window (no fd pin): see
`docs/plugins.md` "Known limits".

## 11. Isolation limit

Native plugin panic/crash/`os.Exit`/memory corruption
cannot be prevented by `recover`/timeouts. Only
host-adapter panics and plugin-returned errors are
isolated (fuse). Documented, never tested-as-covered.

## 12. On-device check

`castctl plugin check <path>`: no config, no services,
no writes, no secrets. Prints one line per stage
(`dlopen/init/register/provider.call/shutdown`, plus any
`host.log` lines; command-only plugins print the
provider.call stage as skipped); exit 0/2. On the phone,
run the normal linux/arm64 castctl binary inside
Droidspaces (a Linux container) against a plugin in a
normal filesystem layout — no module loader, no
`castctl-ctl` wrapper. Phone result is the merge gate:
[NEEDS-MEASUREMENT].

## 13. References

CLIProxyAPI @250d5981: `loader_unix.go`,
`loader_windows.go`, `loader_unsupported.go`, `abi.go`,
`host.go`, `platform.go`, `shadow.go`,
`client_guard.go`, `rpc_schema.go`, `rpc_client.go`,
`sdk/pluginabi/types.go`, `sdk/pluginapi/types.go`,
`internal/config/config_types.go` (not ported),
`internal/pluginstore/checksum.go` (verify idea only),
`examples/plugin/simple/go/main.go`. Sing-box v1.14.4:
`option/outbound.go`, `option/endpoint.go`,
`docs/configuration/outbound/index.md`. Detail and
per-file lines: `docs/plugins.md` References,
`docs/provenance.md` §2.
