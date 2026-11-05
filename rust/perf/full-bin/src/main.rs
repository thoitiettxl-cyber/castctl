// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! `castctl-full` (M-perf-1): same CLI behaviour as `castctl-rs`
//! (`castctl_cli::run`), but linked against the full ported stack
//! (CLI + config + transport/honk + gateway) so items 1–3 measure an
//! apples-to-apples Rust binary against the Go full binary.
//!
//! `main` is `castctl-rs/src/main.rs` verbatim plus one env-guarded
//! retention call (`keep::keep_linked`, see `keep.rs`): the call never
//! runs on the measured path (PERF_KEEP_LINKED unset), it only keeps
//! the transport+gateway code linked under LTO.

#[cfg(feature = "keep-linked")]
mod keep;

use std::io::Write;

fn main() {
    // argv[1..], lossy-converted: Go receives UTF-8 argv from the
    // OS on Unix; non-UTF8 bytes are a documented approximation
    // (PORTING.md).
    let args: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    // Retention (keep-linked feature only): construct the
    // transport+gateway roots so LTO keeps their code in the binary.
    // Guarded by env so the measured --version path does no extra work.
    #[cfg(feature = "keep-linked")]
    if std::env::var("PERF_KEEP_LINKED").is_ok() {
        keep::keep_linked();
    }
    let outcome = castctl_cli::run(&args, None);
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    let _ = stdout.write_all(outcome.stdout.as_bytes());
    let _ = stdout.flush();
    let stderr = std::io::stderr();
    let mut stderr = stderr.lock();
    let _ = stderr.write_all(outcome.stderr.as_bytes());
    let _ = stderr.flush();
    std::process::exit(outcome.code);
}
