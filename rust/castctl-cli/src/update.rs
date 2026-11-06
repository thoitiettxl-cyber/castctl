// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! `update` command wiring (M7b PR-3): `update.go:72`.
//!
//! Go has NO `--check` flag — the flags are only
//! `--dry-run` / `--version` / `--allow-downgrade` /
//! `--allow-prerelease` (`update.go:72`, `updateHelpText`).
//! Boss's "update --check" IS Go's `--dry-run` mode
//! (D-M7b-PR3-7): no `--check` flag is invented; the PR body
//! states the mapping.
//!
//! Safety is Go's fail-before-rename (`replace.go:88-229`):
//! every failure before the rename leaves the old binary
//! intact; there is NO rollback-restore step in Go — the one
//! post-rename failure (directory fsync) returns an error
//! WITH the new binary in place. The mid-way failure test is
//! therefore valid only for pre-rename errors
//! (D-M7b-PR3-10, recorded in `rust/PORTING.md` §M7b.13).
//!
//! Stamps come from `build.rs` (`CASTCTL_BUILD_COMMIT` /
//! `CASTCTL_BUILD_DATE`, git-derived, empty without git
//! metadata): the crate refuses an unstamped build exactly
//! like Go's. The flavour comes from the host libc:
//! `cfg!(target_env = "gnu")` means the glibc asset can run
//! here (`CGO_ENABLED=1`), anything else the no-plugin asset
//! (`CGO_ENABLED=0`). KNOWN LIMITATION (PORTING §M7b.13):
//! `update` installs the published release asset, which
//! today is the Go build — the release workflow
//! (`.github/workflows/release.yaml`) is Go-only; no Rust
//! release asset exists.

use std::cell::RefCell;
use std::io::Write;
use std::rc::Rc;

use castctl_update::{Deps, Options};

use crate::run::{Ctx, FlowErr, VERSION, msg};

/// A `Write` sink sharing a buffer with its owner, so the
/// crate's report can be flushed into `ctx.out.stdout` only
/// after `run()` returns. The crate prints only on success
/// paths (no-op line, dry-run report after verification,
/// install success line); every error path returns before
/// printing, so the buffer is empty on error and nothing is
/// lost by flushing late.
struct SharedWriter(Rc<RefCell<Vec<u8>>>);

impl Write for SharedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The build flavour (Go `debug.ReadBuildInfo`
/// `CGO_ENABLED`): `"1"` on glibc targets — the glibc
/// release asset runs here — `"0"` elsewhere (musl and
/// other targets take the no-plugin asset).
fn cgo_enabled_flavour() -> &'static str {
    if cfg!(target_env = "gnu") { "1" } else { "0" }
}

/// Build the crate `Options` from CLI state. Stamps and the
/// stdout sink are explicit inputs so tests can drive the
/// refusal paths without a stamped binary or network.
pub(crate) fn build_update_options(
    dry_run: bool,
    target_version: &str,
    allow_downgrade: bool,
    allow_prerelease: bool,
    commit: &str,
    build_date: &str,
    stdout: Option<Box<dyn Write>>,
) -> Options {
    Options {
        deps: Deps {
            cgo_settings: Some(vec![(
                "CGO_ENABLED".to_string(),
                cgo_enabled_flavour().to_string(),
            )]),
            ..Default::default()
        },
        current_version: VERSION.to_string(),
        commit: commit.to_string(),
        build_date: build_date.to_string(),
        target_version: target_version.to_string(),
        dry_run,
        allow_downgrade,
        allow_prerelease,
        stdout,
    }
}

/// `cmdUpdate` (`update.go:72`): parse + positionals are
/// done by the caller in `run.rs`; this runs the update and
/// maps the crate error to Go's `errCode(ue.Code(), ue)`
/// (`update.go:72`, `Error.Code()`: 2 usage/policy, 1
/// fetch/verify/replace). No config is loaded (release
/// downloads are public URLs).
pub(crate) fn run_update(
    ctx: &mut Ctx<'_>,
    dry_run: bool,
    target_version: &str,
    allow_downgrade: bool,
    allow_prerelease: bool,
) -> Result<(), FlowErr> {
    let buf = Rc::new(RefCell::new(Vec::new()));
    let opts = build_update_options(
        dry_run,
        target_version,
        allow_downgrade,
        allow_prerelease,
        env!("CASTCTL_BUILD_COMMIT"),
        env!("CASTCTL_BUILD_DATE"),
        Some(Box::new(SharedWriter(Rc::clone(&buf)))),
    );
    let (_res, outcome) = castctl_update::run(opts);
    ctx.out
        .stdout
        .push_str(&String::from_utf8_lossy(&buf.borrow()));
    match outcome {
        Ok(()) => Ok(()),
        Err(e) => Err(msg(e.code(), e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flavour_is_glibc_on_gnu() {
        // The cue/sandbox hosts are glibc: the flavour the
        // CLI reports must be the glibc asset.
        if cfg!(target_env = "gnu") {
            assert_eq!(cgo_enabled_flavour(), "1");
        } else {
            assert_eq!(cgo_enabled_flavour(), "0");
        }
    }

    #[test]
    fn options_carry_stamps_and_flags() {
        let opts = build_update_options(true, "v0.9.0", true, false, "abc", "2026-11-06", None);
        assert_eq!(opts.current_version, "0.9.0");
        assert_eq!(opts.commit, "abc");
        assert_eq!(opts.build_date, "2026-11-06");
        assert!(opts.dry_run);
        assert_eq!(opts.target_version, "v0.9.0");
        assert!(opts.allow_downgrade);
        assert!(!opts.allow_prerelease);
        assert_eq!(
            opts.deps.cgo_settings,
            Some(vec![(
                "CGO_ENABLED".to_string(),
                cgo_enabled_flavour().to_string()
            )])
        );
    }

    #[test]
    fn unstamped_options_refuse_before_network() {
        // Mirrors the crate's `dev_build_refuses_before_network`
        // at the CLI seam: empty stamps refuse with exit 2
        // before any fetch, even with a fetcher that would panic.
        let opts = build_update_options(false, "", false, false, "", "", None);
        let (_res, outcome) = castctl_update::run(opts);
        let err = outcome.unwrap_err();
        assert_eq!(err.code(), 2);
        assert!(
            err.to_string().contains("cannot determine running version"),
            "{err}"
        );
    }

    #[test]
    fn invalid_explicit_version_is_usage_not_network() {
        // `--version bogus` fails at version parse, before any
        // fetch: exit 2, no network. (The CLI-level test
        // `test_update_invalid_version` pins the same through
        // `run()`.)
        let mut opts =
            build_update_options(false, "bogus", false, false, "abc", "2026-11-06", None);
        // Point the target at the test binary so target
        // resolution succeeds; the parse fails first.
        opts.deps.executable = Some(std::env::current_exe().unwrap().display().to_string());
        let (_res, outcome) = castctl_update::run(opts);
        let err = outcome.unwrap_err();
        assert_eq!(err.code(), 2);
        assert!(err.to_string().contains("invalid --version value"), "{err}");
    }
}
