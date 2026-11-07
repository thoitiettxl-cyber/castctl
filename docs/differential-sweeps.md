# Differential sweeps — Go binary vs Rust binary

The parity harness in `rust/parity/` compares a *fixed* case list
(`cases.json`, `m7b_cases/`, …) byte-for-byte. The sweeps below do the
opposite: they generate many small fixtures and argv combinations and
compare the two binaries live. They exist because every parity bug found
after the port was announced came from a surface no fixed case covered —
config validation, live output streaming, a Web UI route.

All sweeps run offline against scratch fixtures under `/tmp`, never the
live profile, and print `TOTAL=`/`DIFFS=` so a run can be pasted into a
report. Exit code is always 0; a non-zero `DIFFS` is the finding.

| Script | Surface | Cases | Where |
|---|---|---|---|
| `sweep_go_vs_rs.py` | config validation at load (block types, unknown keys, tag graph, profile identity) | 102 | added by M7f |
| `sweep_layouts.py` | single/legacy layouts × `profile list/show`, `auth status/list`, `telegram status`, `keeper status`, `config migrate --dry-run`, `auto-approve status`, `plugin list` | 110 | this doc |
| `sweep_args.py` | flag/argument parsing edges (missing values, bad enums, extra positionals, conflicting toggles) across every command | 75 | this doc |
| `sweep_migrate.py` | `config migrate --write`: resulting file tree compared byte-for-byte | 10 layouts | this doc |
| `sweep_location.py` | config/profile location resolution (`--config`, `--profile`, XDG set/unset/relative, legacy flat file) | 18 | this doc |
| `sweep_webui_routes.py` | every Web UI route × {Bearer, no token}, plus malformed methods/paths | 88 requests | this doc |
| `sweep_profile_writes.py` | `profile add/rm/name/set-outbound/set-fingerprint/set-tls-engine`, `auto-approve`, `config migrate --write`: resulting file tree + mode compared | 16 | this doc |
| `sweep_redaction.py` | a secret in an error position (wireguard `private_key`, shadowsocks/trojan/hysteria2 `password`, vless `uuid`, telegram `token`, `credentials`): stderr must match Go's `[redacted]` | 10 | this doc |

Run them with the Rust binary as the single argument:

```sh
cargo build --release -p castctl-rs
python3 rust/parity/sweep_layouts.py rust/target/release/castctl-rs
```

Volatile values are normalised inside each script (per-side fixture
paths, generated `node_id`, timestamps, versions, sizes); everything else
is compared byte-for-byte.

## Recorded runs

| Date | Head | `sweep_layouts` | `sweep_args` | `sweep_migrate` | `sweep_location` | `sweep_webui_routes` | `sweep_go_vs_rs` |
|---|---|---|---|---|---|---|---|
| 2026-11-07 | `76518cb` | 110/0 | 75/0 | 10/0 | 18/0 | 88/0 | 102/**7** |
| 2026-11-07 | `8807310` (M7f PR head) | 110/0 | 75/0 | 10/0 | 18/0 | 88/0 | 118/0 |
| 2026-11-07 | `8807310` — the two later sweeps | `sweep_profile_writes` 16/0 | `sweep_redaction` 10/0 | | | | |
| 2026-11-07 | `7d072a1` (Rust binary built from that head) | 110/0 | 75/0 | 10/0 | 18/0 | 88/0 | 118/**0** |

Format: cases/diffs. `sweep_redaction` did not exist at `76518cb`; it was written after the M7f
review found that the Rust CLI printed error lines raw while Go passes
every line through `SafeString` (`private_key: 5` → `private_key:
[redacted]`). At `76518cb` it reproduces **6 diffs** — five outbounds Go
refuses and Rust accepted, plus the redaction difference itself; at
`8807310` it is 10/0.

The seven `sweep_go_vs_rs` diffs at `76518cb` were
real: the Rust build accepted five kinds of config that Go refuses
(`dns` not an object, unknown `dns` key, duplicate outbound tag, outbound
without `type`, profile identity in a single config) and then ran — one
case dialled the live account. They are fixed by the M7f change that
moves Go's full validation tail into `parse_single_config`; the sweep is
the acceptance test for it (`DIFFS=0` at the M7f head).

Two surfaces are deliberately **not** swept, with reasons:

- **Go's sing-box runtime log lines.** With a `log` block enabled, Go
  emits `outbound connection to host:port` lines produced by sing-box
  internals. A Rust build without sing-box cannot produce those events;
  the typed-log gate (M7a) is compared instead.
- **Generated identifiers and stamps.** `session-start` UUIDs and the
  `--version` build stamp differ by design (each binary reports its own
  source), so the sweeps that hit them normalise them out.
