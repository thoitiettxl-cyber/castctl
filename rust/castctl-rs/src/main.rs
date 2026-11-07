// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! `castctl` Rust port binary (M2): wires only the offline CLI
//! surface from `castctl-cli`. `main` mirrors `cmd/castctl/main.go`
//! (`os.Exit(commands.Run(...))`); signal handling (exit 130 on
//! SIGINT) is NOT ported in M2 and is recorded in PORTING.md.
//!
//! Scope (Boss decision 2026-11-07, `rust/AGENT-CLI-SCOPE.md`):
//! this binary is the agent-facing CLI only. The plugin host was
//! dropped together with `webui` and the telegram bot, so no
//! `__plugin-worker` mode is dispatched here.

use std::io::Write;

fn main() {
    let os_args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    // argv[1..], lossy-converted: Go receives UTF-8 argv from the
    // OS on Unix; non-UTF8 bytes are a documented approximation
    // (PORTING.md).
    let args: Vec<String> = os_args
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let outcome = castctl_cli::run(&args, None);
    // A streaming command already wrote its lines through
    // `write_live`; replaying the buffered copy would duplicate them.
    if !castctl_cli::live_output_written() {
        let stdout = std::io::stdout();
        let mut stdout = stdout.lock();
        let _ = stdout.write_all(outcome.stdout.as_bytes());
        let _ = stdout.write_all(&outcome.stdout_bytes);
        let _ = stdout.flush();
        let stderr = std::io::stderr();
        let mut stderr = stderr.lock();
        let _ = stderr.write_all(outcome.stderr.as_bytes());
        let _ = stderr.flush();
    }
    std::process::exit(outcome.code);
}
