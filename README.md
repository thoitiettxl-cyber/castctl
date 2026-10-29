# muse-cli Go port

Go port of the Python `muse-cli` (module `github.com/thoitiettxl-cyber/muse-cli/go`).
All commands below run from this directory (`go/`).

## Build and vet

```sh
go build ./...
go vet ./...
```

## Tests

Canonical test command (with all feature tags, race detection on):

```sh
go test -race -tags with_utls,with_quic,with_wireguard,with_gvisor ./...
```

## Build tags

| Tag | Effect |
| --- | --- |
| `with_utls` | Enables uTLS (Chrome fingerprint) for gateway TLS. Required: without it, the untagged build fails 4 TLS subtests **by design** (see below). |
| `with_quic` | Enables QUIC transports (Hysteria/Hysteria2/TUIC/naive HTTP/3). |
| `with_wireguard` | Enables WireGuard endpoints. |
| `with_gvisor` | **Required** for WireGuard endpoints. Without it, `transport/wireguard/device_stack_stub.go` (`//go:build !with_gvisor`, sing-box v1.14.4) returns `tun.ErrGVisorNotIncluded` from both stack-device constructors. |

### Untagged build: 4 TLS subtests fail by design

Running `go test ./internal/outbound/` without `with_utls` fails exactly
these 4 subtests of `TestBuildTLSConfig` (verified 2026-10-29 in the PR2
worktree): `default_chrome_server_name_and_alpn_passthrough`,
`server_name_falls_back_to_server_address`,
`reality_options_pass_through_untouched`, and
`handshake_against_fake_tls_server`. They build a uTLS config, which the
stub TLS implementation rejects. This is expected, not a regression: run
the canonical tagged command above.

## Binary sizes (PR1 measurements)

Measured in PR1, not re-measured in PR2:
`CGO_ENABLED=0`, `-trimpath`, `-ldflags '-s -w -buildid='`.

| Tag set | Size (bytes) |
| --- | --- |
| `with_utls` | 34,574,460 |
| `with_utls,with_quic,with_wireguard` (+quic+wireguard) | 38,985,852 |
| `with_utls,with_quic,with_wireguard,with_gvisor` (+gvisor) | 43,053,180 |

## Bootstrap DNS lookup

`outbound.BootstrapLookup` (`internal/outbound/bootstrap.go`) is the
sole exception where a DNS server's own hostname is resolved via the
system resolver (`net.DefaultResolver`, 5 s timeout). It resolves the
hostname once, before that server can be used; the DNS package
substitutes the first IPv4 address (else the first address) for the
hostname and preserves the original hostname as the TLS ServerName
when TLS options exist with an empty ServerName. The lookup is
debug-logged with the hostname and the address count only — never the
resolved values.

Fail-closed boundary: bootstrap applies only to the DNS server's own
hostname. Every other lookup goes through the configured DNS server
and the outbound/detour that server is configured with; DNS failure
is an error, and there is no system-resolver fallback for any other
host. A bootstrap failure is a construction error, never a silent
fallback.

Recommendation: configure DNS servers by IP address to avoid the
bootstrap lookup entirely. An IP-address server needs no bootstrap
lookup at all, so the system resolver is never consulted.

## Real WireGuard conf test

`TestParseRealWireGuardConfRuntime`
(`internal/outbound/wireguard_conf_test.go`) reads a real wg-quick
conf at runtime only, asserts shape only, and never logs key
material. Its path comes from the `MUSE_CLI_WG_CONF_PATH` environment
variable when set, defaulting to
`~/.config/muse-cli/secrets/wg-proton-usca420.conf` when unset or
empty. If the file is missing or unreadable (including a bad
`MUSE_CLI_WG_CONF_PATH` value), the test skips with a visible reason
naming the resolved path — it never fails the suite on a machine
without the conf.

## Licence headers

Every `.go` file under `go/` carries the SPDX header
`SPDX-License-Identifier: GPL-3.0-or-later` at the top (after any
build tags). The generated `*.pb.go` files get the same header from
`internal/proto/generate/generate.sh` on every regeneration; see
`internal/proto/generate/README.md`. A test (`go/spdx_test.go`)
fails the suite if any `.go` file lacks the header.

## CLI surface

`cmd/muse-cli` currently exposes only `--version` / `--help` and a
read-only config load. PR2 adds the gateway library (`internal/gateway`
and related packages); it adds no new CLI commands.
