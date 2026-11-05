# Parity harness (M2)

Byte-for-byte comparison of the Rust binary against the Go binary
over the 54 offline argv cases in `cases.json` (the single source
of truth for the case list).

## Regenerate (on cue, one command)

```sh
sh rust/parity/gen_golden.sh
```

`GO_BIN` defaults to `/usr/local/bin/castctl`. The generator
overwrites the whole `golden/` dir and fails on timeout, signal
death, or a case-count mismatch. Never hand-edit golden files.

Each case runs with an isolated HOME/XDG, a minimal environment
(`HOME`, `XDG_CONFIG_HOME`, `LC_ALL=C`, `TZ=UTC`, `PATH`),
stdin `/dev/null`, a 10s timeout, cwd = a fresh fixture work dir,
and the F1 fixture config (`fixtures/config.json`, NO `log`
block) installed at `$XDG_CONFIG_HOME/castctl/config.json`.
`CASTCTL_CONFIG`/`CASTCTL_PROFILE` are unset (the environment is
cleared first).

## Cases (54)

46 × `<command> --help` in `commandOrder`, plus 8: `--version`,
`--help`, `bogus`, `redeem` (missing positional), `goal` (missing
positional), `seen` (missing positional), `--log-level xyz`,
`--config /nonexistent`.

## Normalisations (comparison only, applied to both sides)

- N1: fixture-root paths → `<FIXTURE>`
- N2 (corrected, D-M2-7): an optional ` (<commit> <date>)` stamp
  suffix is stripped from the `--version` line on BOTH sides; the
  bare `castctl <version>` is compared exactly
- N3: HOME → `<HOME>`
- N4: XDG_CONFIG_HOME → `<XDG>`

No other normalisation. The Rust test (`castctl-rs/tests/
parity.rs`) asserts the golden count equals the argv-list length,
checks the golden schema/id/argv, asserts no leftover temp paths
or stamps in the normalised outputs, and reports the first
differing byte on mismatch.

## Not covered

The 34 subcommand `--help` cases (D-M2-6), any network behaviour,
`config migrate` execution, and any case that reads a config file
body: none of the 54 cases reaches config content, so the fixture
config is present only to keep the environment realistic. The
`config-telegram.json` fixture (F2, shape-only fake token) is
reserved for future cases.
