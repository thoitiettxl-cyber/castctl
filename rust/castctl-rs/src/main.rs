// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! `castctl` Rust port binary (M2): wires only the offline CLI
//! surface from `castctl-cli`. `main` mirrors `cmd/castctl/main.go`
//! (`os.Exit(commands.Run(...))`); signal handling (exit 130 on
//! SIGINT) is NOT ported in M2 and is recorded in PORTING.md.
//!
//! Hidden subcommand `__plugin-worker` (M6c-b): the plugin
//! worker mode. It is dispatched here, before the CLI
//! runs, so it never appears in help output and the CLI
//! parser never sees it. It takes exactly one argument,
//! the handshake token (see `castctl_pluginhost::worker`).

use std::io::Write;

fn main() {
    // Hidden worker mode first: the parent loader
    // re-execs this binary with `__plugin-worker
    // <token>`; the worker speaks framed protocol v2 on
    // stdin/stdout and exits with the worker's code.
    let os_args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    if os_args
        .first()
        .is_some_and(|a| a.to_string_lossy() == "__plugin-worker")
    {
        std::process::exit(castctl_pluginhost::worker::run_worker(&os_args));
    }
    // argv[1..], lossy-converted: Go receives UTF-8 argv from the
    // OS on Unix; non-UTF8 bytes are a documented approximation
    // (PORTING.md).
    let args: Vec<String> = os_args
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let outcome = castctl_cli::run(&args, None);
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    let _ = stdout.write_all(outcome.stdout.as_bytes());
    let _ = stdout.write_all(&outcome.stdout_bytes);
    let _ = stdout.flush();
    let stderr = std::io::stderr();
    let mut stderr = stderr.lock();
    let _ = stderr.write_all(outcome.stderr.as_bytes());
    let _ = stderr.flush();
    std::process::exit(outcome.code);
}
