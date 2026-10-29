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

## CLI surface

`cmd/muse-cli` currently exposes only `--version` / `--help` and a
read-only config load. PR2 adds the gateway library (`internal/gateway`
and related packages); it adds no new CLI commands.
