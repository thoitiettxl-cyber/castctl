# castctl — Rust port

Rust implementation of `castctl`, ported crate-by-crate from the Go tree at
the repository root. The Go binary keeps working and is the behavioural
ground truth during (and after) the port.

- Porting notes, decisions, deviations and unverified items: **`PORTING.md`**
  (large; it records *why* each crate looks the way it does, with Go
  `file:line` references).
- Licence: **GPL-3.0-only** (`LICENSE`, `NOTICE`), unlike the Go tree's
  GPL-3.0-or-later — the Rust artifact links `honk-outbound`
  (GPL-3.0-only), so two artifacts carry two licences. See
  `docs/provenance.md` §13.
- Provenance of every third-party dependency: `../docs/provenance.md`.

## Requirements

| What | Why |
|---|---|
| Rust **1.99.1** | pinned by `rust-toolchain.toml` (honk pulls `aya 0.16`, which requires rustc ≥ 1.98); rustup installs it on demand |
| `cmake` | builds BoringSSL for `boring-sys` |
| `libclang-dev` | `bindgen` needs `libclang` for `boring-sys` |
| Go ≥ 1.27.3 (`GOTOOLCHAIN=auto`) | only for the parity harnesses (`parity/`) and the plugin live tests, which build the reference Go binary / `examples/plugin/echo` |
| `python3` | perf driver and the one-command rerun |

`ninja` is optional (BoringSSL's build falls back to `make`).

## Build, test, lint

```sh
cd rust
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

Release binary (what ships):

```sh
cargo build --release -p castctl-rs      # -> target/release/castctl-rs
```

The plugin live tests re-execute the same binary as the plugin worker, and
build `examples/plugin/echo` through `go`, so run them with
`GOTOOLCHAIN=auto`:

```sh
GOTOOLCHAIN=auto PATH=/usr/local/go/bin:$PATH cargo test -p castctl-pluginhost --test loader_live
```

## Differential sweeps (Go vs Rust)

`parity/sweep_*.py` generate fixtures and argv combinations and compare
the two binaries live, for surfaces a fixed case list cannot cover:
config validation at load, layouts, argument parsing, `config migrate`
write output, config/profile location resolution and the whole Web UI
route table. Each script prints `TOTAL=`/`DIFFS=`; run one with the Rust
binary as the only argument:

```sh
python3 parity/sweep_layouts.py target/release/castctl-rs
```

Recorded runs, case counts and the two deliberately unswept surfaces
(Go's sing-box runtime log lines, generated identifiers/stamps) are in
[`docs/differential-sweeps.md`](../docs/differential-sweeps.md).

## Parity harness (Go vs Rust)

`parity/` compares the Rust CLI against the Go binary byte-for-byte:

```sh
sh parity/gen_golden.sh          # regenerate goldens from the Go binary
sh parity/run_m7b_cases.sh       # compare Rust against the goldens
sh parity/run_wait_cases.sh      # wait state-machine cases
sh parity/run_send_wait_cases.sh # send --wait cases
sh parity/run_watch_cases.sh     # watch cases
```

Each script prints a pass/fail table; the goldens are regenerated from the
Go binary, never hand-edited.

## Performance harness

`perf/` measures the Go binary against the Rust shell and the full Rust
stack (size, startup, RSS, pure-logic), one command:

```sh
sh perf/run.sh               # writes perf/data/summary.json + prints a table
```

Baseline numbers and methodology notes: `perf/README.md`.

## Layout

One crate per Go package group, named after it (`castctl-cli`, `-config`,
`-gateway`, `-transport`, `-telegram`, `-keeper`, `-webui`, `-update`,
`-pluginhost`, `-wait`, `-fsclient`, `-deliver`, `-dns`, `-logging`,
`-approvals`, plus small shared crates). `castctl-rs` is the binary.
