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
  Android runs the `GOOS=linux/arm64` glibc build under
  the bundled loader; the unix loader is the Android path.

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
never via `init()`.

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
  with `O_NOFOLLOW`, must be a regular file (symlinks /
  directories refused — castctl hardening, not upstream).
- The shadow copy is removed only when `dlopen` fails.

## 6. glibc compatibility

Before `dlopen`, parse `.gnu.version_r` (`debug/elf`) for
the highest `GLIBC_` requirement; compare with the running
libc (`gnu_get_libc_version`, cgo/linux). Higher → refuse
with required vs running versions. Non-glibc / no-cgo
builds: refuse ELF files with requirements present
(fail-closed); non-ELF files skip the check. Build floor
2.17; module bundled runtime 2.44.

## 7. Config

```json
{"plugins":[{"tag":"muse","type":"muse","model":"opus"}]}
```

- `tag` required + unique, `type` required. No `enabled`
  at any level; presence = active. `enabled` inside an
  entry is plugin-opaque.
- Core validates the envelope (`tag`/`type`) under the
  strict unknown-key rules; the remainder is the verbatim
  fragment (original order, raw-preserved on save).
- Display/redaction: `tag`/`type` + fragment `<redacted>`.

## 8. Egress and secrets

- Plugins receive ONLY: identity, egress, fragment.
  Never: managers, `SingleConfig`/`Profile`, cookie
  paths, env, WireGuard keys, tokens, real proxy creds,
  self-built `http.Client`.
- Identity hash: SHA-256 over the secret-stripped outbound
  (`redact.Value`, sorted-key canonical JSON).
- Egress: per-session loopback proxy (`127.0.0.1:0`),
  ephemeral random Basic creds, 407 without them,
  absolute-form forwarding through the caller-supplied
  upstream transport, hop-by-hop stripping, `Cookie`
  injected inside core (overwrites plugin-sent values).
  CONNECT only with a caller-supplied dial function, else
  502. No direct dial path exists for plugins.
- Errors: envelope + existing classifier; plugin never
  picks an exit code; no raw server bodies on output.

## 9. Reverse callbacks

Only `host.log` (`{level,message}`; truncated, control
chars stripped). All other `host.*` methods →
`unsupported_host_callback`. `host.auth.*` rejected
absolutely. Upstream auth callbacks were not ported.

## 10. Checksums

Opt-in local-dir verification only: `checksums.txt`
(SHA-256) verified before load when a manifest path is
supplied; mismatch/missing entry refuses. No store,
download, registry, signing, or version gating
(`min_version`/`allow_downgrade` absent upstream and here).

## 11. Isolation limit

Native plugin panic/crash/`os.Exit`/memory corruption
cannot be prevented by `recover`/timeouts. Only
host-adapter panics and plugin-returned errors are
isolated (fuse). Documented, never tested-as-covered.

## 12. On-device check

`castctl plugin check <path>`: no config, no services,
no writes, no secrets. Prints `dlopen/init/register/
provider.call/shutdown` lines; exit 0/2. Device wrapper:
`castctl-ctl plugin-check <file>` (file in
`$DATA_DIR/plugins/linux/arm64/`, no symlinks, bundled
loader). Phone result is the merge gate:
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
