// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Plugin loader — real `.so` loading (M6c-b).
//!
//! Go source: `internal/pluginhost/loader_unix.go`,
//! `loader_windows.go`, `loader_stub.go`,
//! `loader_other.go`, and
//! `internal/pluginhost/callbacks_unix.go:208,223,244`.
//!
//! The Go loader is `dlopen` + a C ABI
//! (`loader_unix.go:168`, NOT `plugin.Open` — grep 0
//! hits): `RTLD_NOW|RTLD_LOCAL`, `dlsym` for
//! `castctl_plugin_init`, an ABI-version exact check, a
//! function-table completeness check (`call` /
//! `free_buffer` non-nil), and it NEVER unloads
//! (`dlclose` / `FreeLibrary` are never called).
//!
//! How the Rust port does it (M6c-b, Option A —
//! subprocess helper-worker; the old "loader STOPPED /
//! safe pure-Rust port is impossible" claim is deleted:
//! it was a safety choice, not an impossibility — Go
//! itself dlopens with `unsafe`+cgo):
//!
//!   - The pre-load gates run in the PARENT, in Go's
//!     order (shadow copy -> manifest checksum on the
//!     shadow bytes -> glibc compat gate), using the
//!     already-ported `shadow` / `checksum` / `compat`
//!     modules. Only a gated shadow path is ever
//!     dlopened.
//!   - The `dlopen` itself runs in a WORKER process
//!     (see `worker.rs`): the same binary re-executed
//!     under the hidden `__plugin-worker` subcommand
//!     (or the dedicated `castctl-plugin-worker`
//!     binary), speaking framed protocol v2 over a Unix
//!     socketpair. The `unsafe` FFI lives ONLY in the
//!     `ffi` module and ONLY inside the worker, so a
//!     plugin segfault kills the worker — never the
//!     host — and is reported as `PluginCrashed`.
//!   - This is deliberately stronger than Go, whose
//!     signal guard covers only the `host.log`
//!     method-name scan and whose host dies on any other
//!     plugin fault (`docs/plugins.md`, trusted
//!     in-process model). The price is a new framed
//!     protocol (v2) and one IPC round-trip per plugin
//!     call, plus worker supervision; the in-process
//!     `sigsetjmp` guard (Option B) was rejected because
//!     `longjmp` skips Rust destructors (locks never
//!     release), a fault inside `malloc` leaves the
//!     allocator locked, faults on plugin threads have
//!     no guard, and heap corruption survives the jump.
//!     `signal-hook` cannot implement the guard (it
//!     forbids SIGSEGV); `hw-exception` 0.1.0 was
//!     examined and not adopted (stale, single release,
//!     same soundness holes).
//!
//! What this module provides:
//!
//!   - `WorkerLoader`: the `Loader` impl. It is the
//!     default loader for `Host::new` (see `host.rs`).
//!   - `open_plugin` / `check_plugin`: the free-function
//!     seam (`plugin check` uses `Host` directly for its
//!     stage lines; `check_plugin` is the same check
//!     without the printing).
//!   - `LOADER_UNAVAILABLE_MESSAGE`: still the message
//!     for the platforms without a worker (non-unix) and
//!     for an explicit `StoppedLoader`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::checksum::verify_shadow_file_checksum;
use crate::compat::check_plugin_compat;
use crate::discovery::{PluginFile, validate_plugin_id};
use crate::error::PluginHostError;
use crate::host::{Client, Desired, Host, Loader, Options};
use crate::pluginabi::METHOD_PROVIDER_CALL;
use crate::shadow::{remove_shadow_file, shadow_copy};

/// The message load attempts on platforms without a
/// worker fail with. Kept for the `StoppedLoader` /
/// non-unix path and pinned by `error.rs`. (Fix loop 1,
/// tech N4: the old text claimed the Go binary was
/// the plugin host — there is no Go-binary delegation
/// anywhere in this branch; the real loader is the
/// worker in `worker.rs`.)
pub const LOADER_UNAVAILABLE_MESSAGE: &str =
    "plugin loading is not supported on this platform (no worker loader)";

/// Resolve the worker binary: `CASTCTL_PLUGIN_WORKER_BIN`
/// when set, else the dedicated `castctl-plugin-worker`
/// next to the current executable (the cargo-test
/// layout: the test binary lives in `target/debug/deps/`,
/// the worker binary in `target/debug/`), else the
/// current executable itself (production: the castctl
/// binary re-execs under `__plugin-worker`).
///
/// The env override is a TEST-ONLY hook (fix loop 1,
/// safety N6): it is validated (must exist, be a file,
/// and have an executable bit) and an invalid value
/// falls through to the sibling/`current_exe`
/// resolution instead of executing an arbitrary binary.
/// It is never a trust decision — whoever can set the
/// process environment can already run code as the
/// user — but a leaked test variable or a typo must
/// not silently re-point the worker.
#[must_use]
pub fn resolve_worker_bin() -> PathBuf {
    if let Ok(p) = std::env::var("CASTCTL_PLUGIN_WORKER_BIN")
        && !p.is_empty()
    {
        let cand = PathBuf::from(p);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(&cand)
                && meta.is_file()
                && meta.permissions().mode() & 0o111 != 0
            {
                return cand;
            }
        }
        #[cfg(not(unix))]
        {
            if cand.exists() {
                return cand;
            }
        }
        // Invalid override: fall through to the
        // sibling / current-exe resolution below.
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let cand = dir.join("castctl-plugin-worker");
            if cand.exists() {
                return cand;
            }
            if let Some(parent) = dir.parent() {
                let cand = parent.join("castctl-plugin-worker");
                if cand.exists() {
                    return cand;
                }
            }
        }
        return exe;
    }
    PathBuf::from("castctl-plugin-worker")
}

/// The real loader: pre-load gates in the parent, then
/// a subprocess worker per loaded plugin (see
/// `worker.rs`). `plugin check` is spawn-per-check: the
/// worker lives from `Host::apply_config` to
/// `Host::close`.
pub struct WorkerLoader {
    worker_bin: PathBuf,
}

impl WorkerLoader {
    /// Build a loader resolving the worker binary with
    /// `resolve_worker_bin()`.
    #[must_use]
    pub fn new() -> WorkerLoader {
        WorkerLoader {
            worker_bin: resolve_worker_bin(),
        }
    }

    /// Build a loader with an explicit worker binary
    /// (tests use the `castctl-plugin-worker` binary
    /// cargo builds for the package).
    #[must_use]
    pub fn with_worker_bin(path: PathBuf) -> WorkerLoader {
        WorkerLoader { worker_bin: path }
    }
}

impl Default for WorkerLoader {
    fn default() -> Self {
        WorkerLoader::new()
    }
}

impl Loader for WorkerLoader {
    fn open(&self, file: &PluginFile, host: &Host) -> Result<Arc<dyn Client>, PluginHostError> {
        self.open_inner(file, host)
    }
}

#[cfg(unix)]
impl WorkerLoader {
    /// Pre-load gates (Go §2.1 order) + worker spawn.
    /// The shadow file is removed on every failure
    /// after the copy; on success the spawned client
    /// owns it and removes it on shutdown.
    fn open_inner(
        &self,
        file: &PluginFile,
        host: &Host,
    ) -> Result<Arc<dyn Client>, PluginHostError> {
        let shadow = shadow_copy(file)?;
        if !file.manifest_path.as_os_str().is_empty() {
            let entry = file
                .path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if let Err(e) = verify_shadow_file_checksum(&shadow, &file.manifest_path, &entry) {
                let _ = remove_shadow_file(&shadow);
                return Err(e);
            }
        }
        if let Err(e) = check_plugin_compat(&shadow) {
            let _ = remove_shadow_file(&shadow);
            return Err(e);
        }
        let display = file.path.to_string_lossy().into_owned();
        let dispatcher = host.host_callback_dispatcher();
        match crate::worker::spawn_worker(&self.worker_bin, &shadow, &display, dispatcher) {
            Ok(client) => Ok(Arc::new(client)),
            Err(e) => {
                let _ = remove_shadow_file(&shadow);
                Err(e)
            }
        }
    }
}

#[cfg(not(unix))]
impl WorkerLoader {
    /// Non-unix: no worker loader exists.
    fn open_inner(
        &self,
        _file: &PluginFile,
        _host: &Host,
    ) -> Result<Arc<dyn Client>, PluginHostError> {
        Err(PluginHostError::LoaderUnavailable)
    }
}

/// Attempt to load a plugin: runs the real loader
/// (pre-load gates + worker) and returns the client.
/// The id is derived from the file stem when it is a
/// valid plugin id, else `"plugin"`.
pub fn open_plugin(path: &Path, host: &Host) -> Result<Arc<dyn Client>, PluginHostError> {
    let id = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .filter(|s| validate_plugin_id(s))
        .unwrap_or_else(|| "plugin".to_string());
    let file = PluginFile {
        id,
        path: path.to_path_buf(),
        version: String::new(),
        manifest_path: PathBuf::new(),
    };
    WorkerLoader::new().open(&file, host)
}

/// The `plugin check` path without the stage printing:
/// load + register + one `provider.call` ping (when the
/// plugin is a provider). Returns `Ok` only when every
/// stage passes — including a clean `shutdown` (fix
/// loop 1, B4: a worker crash inside `shutdown` fails
/// the check). The CLI (`cmd_plugin`) does the same
/// stages through `Host` directly so it can print them.
///
/// NOTE (fix loop 1, red N4 / tech N9): `open_plugin`
/// and `check_plugin` have no production callers yet —
/// the CLI drives `Host` directly. They are the
/// tested public seam for embedders and for a future
/// CLI wiring, not dead code to delete. The provider
/// call here takes no `Host` deadline (same as the
/// CLI): the 30s worker transact is the bound, so a
/// `check_plugin` timeout can never abandon a transact
/// that then blocks `Host::close` (safety N5).
pub fn check_plugin(path: &Path) -> Result<(), PluginHostError> {
    let host = Host::new(Options::default());
    let mut desired = Desired::new("check", "check", &path.to_string_lossy());
    desired.fragment = b"{}".to_vec();
    let report = host.apply_config(vec![desired]);
    if let Some(skipped) = report.skipped.first() {
        host.close();
        return Err(PluginHostError::failed(skipped.reason.clone()));
    }
    let Some(loaded) = host.loaded("check") else {
        host.close();
        return Err(PluginHostError::failed(
            "plugin check: loaded but not reported",
        ));
    };
    if loaded.capabilities.provider {
        let result = host.call("check", METHOD_PROVIDER_CALL, b"{\"input\":\"ping\"}", None);
        host.close();
        // A shutdown crash fails the check even when
        // the provider call passed (fix loop 1, B4).
        if let Some((_, e)) = host.shutdown_errors().into_iter().next() {
            return Err(e);
        }
        result.map(|_| ())
    } else {
        host.close();
        if let Some((_, e)) = host.shutdown_errors().into_iter().next() {
            return Err(e);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loader_unavailable_message_pinned() {
        // The variant and its message still exist for
        // the non-unix / StoppedLoader path; the message
        // is pinned equal in `error.rs`.
        assert_eq!(
            PluginHostError::LoaderUnavailable.to_string(),
            LOADER_UNAVAILABLE_MESSAGE
        );
    }

    #[test]
    #[cfg(unix)]
    fn open_missing_file_fails_without_worker() {
        // `shadow_copy` creates the own pid dir before
        // failing on the missing file: take the shared
        // shadow-dir lock (see `SHADOW_DIR_TEST_LOCK`).
        let _guard = crate::shadow::SHADOW_DIR_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // The pre-load gates run before any worker is
        // spawned: a missing file fails at the shadow
        // copy, never at a worker.
        let host = Host::new(Options::default());
        // (`unwrap_err` needs `Debug` on the `Ok` type;
        // `Arc<dyn Client>` has none — match instead.)
        let err = match open_plugin(Path::new("/tmp/definitely-not-a-plugin.so"), &host) {
            Ok(_) => panic!("missing file must not load"),
            Err(e) => e,
        };
        assert!(
            !matches!(err, PluginHostError::LoaderUnavailable),
            "missing file must fail at the shadow gate, got {err}"
        );
    }
}
