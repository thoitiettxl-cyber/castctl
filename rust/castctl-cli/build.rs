// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Build stamps for `castctl update` (M7b PR-3).
//!
//! Go stamps the release binary with `-X` flags (`main.commit`,
//! `main.buildDate`); an unstamped build refuses every `update`
//! mode with "cannot determine running version"
//! (`internal/update/update.go:120`). There is no Rust
//! release-stamping step, so the stamp comes from git instead:
//! `HEAD` and its commit date (`%cI`). A checkout without git
//! metadata (or a `git` failure) yields EMPTY stamps, and
//! `castctl-update::run()` then refuses exactly like Go's
//! unstamped build — fail-closed, never a fabricated stamp.
//!
//! No `cargo:rerun-if-changed` lines are emitted on purpose:
//! with none, Cargo re-runs this script whenever any file in
//! the package changes, so the stamp follows the source it was
//! built from instead of going stale across commits.
//!
//! DEVIATION (recorded in `rust/PORTING.md` §M7b.13): a dev
//! build from a git checkout IS stamped, where Go's dev builds
//! are unstamped and refuse. Without a stamp the wired
//! `update` command would be dead code in every dev build;
//! git-derived stamps are the honest equivalent — the binary
//! reports its own source commit.

use std::process::Command;

/// Run `git <args>` and return its trimmed stdout, or `None`
/// on any failure (missing binary, non-git directory,
/// non-zero exit, non-UTF-8 output, empty output).
fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    let s = s.trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

fn main() {
    let commit = git(&["rev-parse", "HEAD"]).unwrap_or_default();
    let date = git(&["log", "-1", "--format=%cI"]).unwrap_or_default();
    println!("cargo:rustc-env=CASTCTL_BUILD_COMMIT={commit}");
    println!("cargo:rustc-env=CASTCTL_BUILD_DATE={date}");
}
