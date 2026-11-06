// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Standalone plugin worker binary (M6c-b): the same
//! worker mode the castctl binary runs under the hidden
//! `__plugin-worker` subcommand, as its own binary.
//! Tests use it via `CARGO_BIN_EXE_castctl-plugin-worker`
//! (the loader resolves it with
//! `CASTCTL_PLUGIN_WORKER_BIN` or the sibling lookup in
//! `loader::resolve_worker_bin`). Takes exactly one
//! argument, the handshake token (see
//! `castctl_pluginhost::worker::run_worker`).
//!
//! Test-only mode (fix loop 1, B7):
//! `__pdeath-test-parent <plugin.so>` loads the plugin
//! and starts a `provider.call` on a thread, then
//! parks forever. The live test SIGKILLs this process
//! mid-call and asserts the worker (its child) dies
//! with it via `PR_SET_PDEATHSIG` — it never runs a
//! plugin check itself.

fn main() {
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    if args
        .first()
        .is_some_and(|a| a.to_string_lossy() == "__pdeath-test-parent")
    {
        std::process::exit(pdeath_test_parent(&args[1..]));
    }
    std::process::exit(castctl_pluginhost::worker::run_worker(&args));
}

fn pdeath_test_parent(args: &[std::ffi::OsString]) -> i32 {
    use castctl_pluginhost::host::{Desired, Host, Options};
    use castctl_pluginhost::loader::WorkerLoader;
    use castctl_pluginhost::pluginabi::METHOD_PROVIDER_CALL;

    if args.len() != 1 {
        eprintln!("castctl-plugin-worker: __pdeath-test-parent takes exactly one plugin path");
        return 2;
    }
    let path = args[0].to_string_lossy().into_owned();
    let exe = std::env::current_exe()
        .unwrap_or_else(|_| std::path::PathBuf::from("castctl-plugin-worker"));
    let loader = WorkerLoader::with_worker_bin(exe);
    let host = Host::new(Options {
        loader: Some(Box::new(loader)),
        log: None,
    });
    let mut desired = Desired::new("hung", "check", &path);
    desired.fragment = b"{}".to_vec();
    let report = host.apply_config(vec![desired]);
    if !report.skipped.is_empty() {
        eprintln!("pdeath parent: load skipped: {:?}", report.skipped);
        return 2;
    }
    let host = std::sync::Arc::new(host);
    let caller = std::sync::Arc::clone(&host);
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        let _ = caller.call("hung", METHOD_PROVIDER_CALL, b"{\"input\":\"ping\"}", None);
        let _ = tx.send(());
    });
    // Park forever: the test SIGKILLs this process
    // while the call is hung. If the call ever
    // returns, the plugin was not hung — exit 3 so
    // the test fails loudly instead of hanging.
    loop {
        match rx.recv_timeout(std::time::Duration::from_secs(3600)) {
            Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return 3,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
        }
    }
}
