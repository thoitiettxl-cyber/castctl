# Parity harness (M2)

Byte-for-byte comparison of the Rust binary against the Go binary
over the 59 offline argv cases in `cases.json` (the single source
of truth for the case list).

## Regenerate (on cue, one command)

```sh
sh rust/parity/gen_golden.sh
```

`GO_BIN` defaults to `/usr/local/bin/castctl`. The generator
overwrites the whole `golden/` dir and fails on timeout, signal
death, or a case-count mismatch. Never hand-edit golden files.
The generator asserts `GO_BIN --version` is exactly
`castctl 0.9.0 (1396697 2026-11-04T21:38:36Z)` before generating
(F9(a)); regeneration writes `golden/manifest.json` in the same
command (F9(b)).

Each case runs with an isolated HOME/XDG, a minimal environment
(`HOME`, `XDG_CONFIG_HOME`, `LC_ALL=C`, `TZ=UTC`, `PATH`),
stdin `/dev/null`, a 10s timeout, cwd = a fresh fixture work dir,
and the case's fixture config (default `fixtures/config.json`,
NO `log` block; case 55 uses `fixtures/bad-config.json`, cases
56–59 use the four `decoder-*.json` fixtures)
installed at `$XDG_CONFIG_HOME/castctl/config.json`.
`CASTCTL_CONFIG`/`CASTCTL_PROFILE` are unset (the environment is
cleared first).

## Cases (59)

46 × `<command> --help` in `commandOrder`, plus 13: `--version`,
`--help`, `bogus`, `redeem` (missing positional), `goal` (missing
positional), `seen` (missing positional), `--log-level xyz`,
`--config /nonexistent`, `status` with a bad-JSON config
(F5: exercises the config-parse gate before the stub), and 4 ×
`status` with a decoder-message fixture (cases 56–59: truncated
array, bad exponent, bad string escape, incomplete `\u` escape).

## Normalisations (comparison only, applied to both sides)

- N1: fixture-root paths → `<FIXTURE>`
- N2 (corrected, D-M2-7): an optional ` (<commit> <date>)` stamp
  suffix is stripped from the `--version` line on BOTH sides; the
  bare `castctl <version>` is compared exactly
- N3: HOME → `<HOME>`
- N4: XDG_CONFIG_HOME → `<XDG>`

No other normalisation. The Rust test (`castctl-rs/tests/
parity.rs`) asserts the golden count equals the argv-list length,
verifies `golden/manifest.json` before loading goldens (per-case
sha256 over the canonical stdout/stderr/exit-code form, plus the
pinned `generated_by` version), checks the golden schema/id/argv/
fixture, asserts the Rust `--version` output (unstripped) is
exactly `castctl 0.9.0`, asserts no leftover temp paths or stamps
in the normalised outputs, and reports the first differing byte
on mismatch.

## `schema2.json` provenance (M7f)

`rust/parity/schema2.json` is a reflection dump of the sing-box
v1.14.4 option registry (version per the repo `go.mod`:
`github.com/sagernet/sing-box v1.14.4`). It feeds
`rust/parity/gen_singbox_tables.py`, which generates
`rust/castctl-config/src/singbox_tables.rs` (the strict
validator's field tables). To regenerate the tables: run the
generator, then `cargo fmt` (the generator output is not
formatted on its own), and check in the diff.

The exact command/tool and the sing-box checkout/commit used
to dump the schema are **[NEEDS-MEASUREMENT]**: the writer's
scratch notes (`~/workspace/tmp/castctl-rust-m7f-notes/
singbox/`) hold only copied Go sources, no dumper program or
provenance note. What IS known: the tables are reproducible
via generator + `cargo fmt` and were verified byte-identical
by two reviewers, and the red-team spot-verified the schema
against sing-box 1.14.4.

## Not covered

The 34 subcommand `--help` cases (D-M2-6), any network behaviour,
`config migrate` execution, and legacy-flat-config refusal (the
stub path only parses via `LoadSingleConfig`; see PORTING.md
§M2.5). The `config-telegram.json` fixture (F2, shape-only fake
token) is reserved for future cases.

Limitation (H6): the no-write assertion covers the fixture
config bytes and the empty work dir only; writes elsewhere under
`$HOME`/`$XDG_CONFIG_HOME` are not snapshotted.
