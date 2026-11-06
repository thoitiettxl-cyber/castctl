// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! `dlopen` + `dlsym` + `init` + ABI/completeness
//! checks. Runs ONLY inside the worker process.
//!
//! Go source: `internal/pluginhost/loader_unix.go`
//! (`dynamicLibraryLoader.Open` `:142-234`). Order is
//! load-bearing and is reproduced exactly: `dlopen`
//! (`RTLD_NOW|RTLD_LOCAL`) -> `dlsym`
//! (`castctl_plugin_init`) -> allocate host table +
//! host ctx (malloc, leaked deliberately like Go) ->
//! call init -> init rc check -> ABI exact check ->
//! completeness check. The pre-load gates (shadow copy,
//! manifest checksum on shadow bytes, glibc compat gate)
//! run in the PARENT before the worker is spawned (see
//! `loader.rs`); this module only ever opens the shadow
//! path it is given.
//!
//! From a successful `dlopen` on, the image is NEVER
//! unloaded: `LoadedPlugin` holds the `Library` in a
//! `ManuallyDrop`, so `Drop` never runs for it and
//! `dlclose` is structurally impossible. Any error after
//! `dlopen` therefore drops the struct and forgets the
//! image — the leak is the rule, not a bug.

use std::ffi::c_uint;
use std::path::Path;

use crate::error::PluginHostError;
#[cfg(unix)]
use crate::pluginabi::{ABI_VERSION, ENTRY_SYMBOL};
#[cfg(unix)]
use crate::text::scrub_shadow_path;

#[cfg(unix)]
use super::hostcall::{CALLBACK_ID, castctl_host_call, castctl_host_free};
#[cfg(unix)]
use super::types::{HostApi, PluginApi, PluginCallFn, PluginFreeFn, PluginShutdownFn};

/// One loaded plugin image inside the worker. The
/// `Library` is wrapped in `ManuallyDrop` and is never
/// closed: `Drop` never runs for it, so `dlclose` is
/// structurally impossible — any error after `dlopen`
/// drops the struct and the image stays mapped, exactly
/// like Go's failure paths. These fn pointers stay valid
/// exactly because the `Library` is never closed.
/// `call`/`free_buffer` are `Some` after a successful
/// `open`; `shutdown` may be `None` (Go checks before
/// calling).
#[cfg(unix)]
pub struct LoadedPlugin {
    lib: std::mem::ManuallyDrop<libloading::os::unix::Library>,
    pub(crate) call: Option<PluginCallFn>,
    pub(crate) free_buffer: Option<PluginFreeFn>,
    pub(crate) shutdown: Option<PluginShutdownFn>,
    closed: bool,
}

#[cfg(unix)]
impl LoadedPlugin {
    /// Whether `shutdown` already ran (or the client was
    /// closed after a failed load).
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Mark closed and invoke the plugin's `shutdown`
    /// when present. Runs outside any lock (Go `close()`
    /// invokes shutdown outside `mu`). A crash inside
    /// plugin shutdown kills the worker — the designed
    /// outcome; the parent reports EOF on shutdown as
    /// a crash (fix loop 1, B4), never as success.
    pub fn shutdown(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        if let Some(shutdown) = self.shutdown.take() {
            unsafe {
                shutdown();
            }
        }
    }
}

/// The `dlerror` text for a libloading failure:
/// prefer the underlying `dlerror` string (`source()`),
/// fall back to the error's own display. The shadow
/// path is scrubbed to the display path, and a leading
/// `<displayPath>: ` prefix is stripped so the path
/// prints once, not twice (Go `:169-178`).
#[cfg(unix)]
fn dlerror_text(err: &libloading::Error, shadow_path: &str, display_path: &str) -> String {
    use std::error::Error as _;
    let raw = err
        .source()
        .map(|s| s.to_string())
        .unwrap_or_else(|| err.to_string());
    let scrubbed = scrub_shadow_path(&raw, shadow_path, display_path);
    let prefix = format!("{display_path}: ");
    scrubbed
        .strip_prefix(&prefix)
        .map(str::to_string)
        .unwrap_or(scrubbed)
}

/// Invoke the plugin's `shutdown` when init already
/// filled it, on a failed open (Go
/// `closeAfterOpenFailure`). A crash inside it kills
/// the worker — the designed outcome; the parent then
/// reports the crash instead of the init error.
#[cfg(unix)]
fn shutdown_if_filled(plugin_api: &PluginApi) {
    if let Some(shutdown) = plugin_api.shutdown {
        unsafe {
            shutdown();
        }
    }
}

/// Load the plugin at the shadow `path` (already
/// shadow-copied, checksummed, and compat-gated by the
/// parent). `display_path` is the operator-supplied
/// source path used in error strings.
#[cfg(unix)]
pub fn open(path: &Path, display_path: &str) -> Result<LoadedPlugin, PluginHostError> {
    let shadow_path = path.to_string_lossy().into_owned();
    // SAFETY (ffi boundary): init routines in the `.so`
    // run arbitrary code; the file was shadow-copied,
    // checksummed, and glibc-gated by the caller.
    // Flags are RTLD_NOW|RTLD_LOCAL (Go parity): the
    // cross-platform `Library::new` is RTLD_LAZY and is
    // NOT used — lazy binding would let a broken plugin
    // pass `plugin check` and die on first call.
    let lib = unsafe {
        libloading::os::unix::Library::open(
            Some(path.as_os_str()),
            libloading::os::unix::RTLD_NOW | libloading::os::unix::RTLD_LOCAL,
        )
    }
    .map_err(|e| {
        PluginHostError::failed(format!(
            "dlopen {display_path}: {}",
            dlerror_text(&e, &shadow_path, display_path)
        ))
    })?;
    // From here on the image must never be unloaded: the
    // struct below owns the `Library` inside
    // `ManuallyDrop`, so every error return below leaks
    // the image exactly like Go's failure paths do.
    let mut plugin = LoadedPlugin {
        lib: std::mem::ManuallyDrop::new(lib),
        call: None,
        free_buffer: None,
        shutdown: None,
        closed: false,
    };
    // SAFETY: the symbol name is a `c"..."` literal and
    // the type must match the C ABI exactly
    // (`loader_unix.go:42`); a wrong type is UB.
    let init = unsafe {
        plugin
            .lib
            .get::<super::types::PluginInitFn>(c"castctl_plugin_init")
    }
    .map_err(|e| {
        PluginHostError::failed(format!(
            "missing {ENTRY_SYMBOL}: {}",
            dlerror_text(&e, &shadow_path, display_path)
        ))
    })?;
    // Copy the fn pointer out of the borrowed `Symbol`;
    // the address stays valid exactly because the
    // `Library` is never closed. `into_raw` is NOT used:
    // it would drop the lifetime guarantee for nothing.
    // (`init` is not `Drop`: its borrow ends here by
    // NLL, no explicit drop needed.)
    let init_fn: super::types::PluginInitFn = *init;

    // Host table + host ctx: C-malloc'd, leaked
    // deliberately (Go `:197-205`): the resident plugin
    // runtime may still pass `host_ctx` back into
    // `castctlHostCall` after close.
    let host_api = unsafe { libc::malloc(std::mem::size_of::<HostApi>()) as *mut HostApi };
    if host_api.is_null() {
        return Err(PluginHostError::failed("allocate host api"));
    }
    let host_ctx = unsafe { libc::malloc(std::mem::size_of::<u64>()) as *mut u64 };
    if host_ctx.is_null() {
        return Err(PluginHostError::failed("allocate host context"));
    }
    unsafe {
        *host_ctx = CALLBACK_ID;
        (*host_api).abi_version = ABI_VERSION as c_uint;
        (*host_api).host_ctx = host_ctx as *mut std::ffi::c_void;
        (*host_api).call = Some(castctl_host_call);
        (*host_api).free_buffer = Some(castctl_host_free);
    }
    let mut plugin_api = PluginApi {
        abi_version: 0,
        call: None,
        free_buffer: None,
        shutdown: None,
    };
    // SAFETY: `init_fn` came from `dlsym` of the entry
    // symbol; `host_api` is a valid, fully initialised
    // `HostApi` and `plugin_api` is a valid out-param.
    let rc = unsafe { init_fn(host_api as *const HostApi, &mut plugin_api) };
    if rc != 0 {
        // Go `closeAfterOpenFailure`: an init that
        // already filled `shutdown` gets it invoked
        // (fix loop 1, G7 / tech N2). The worker exits
        // right after, so only a `shutdown` with
        // external side effects is observably different
        // — but it is a Go-parity gap closed here, not
        // recorded as a deviation.
        shutdown_if_filled(&plugin_api);
        return Err(PluginHostError::failed(format!(
            "{ENTRY_SYMBOL} returned {rc}"
        )));
    }
    if plugin_api.abi_version != ABI_VERSION {
        shutdown_if_filled(&plugin_api);
        return Err(PluginHostError::failed(format!(
            "plugin ABI version {} is not supported",
            plugin_api.abi_version
        )));
    }
    if plugin_api.call.is_none() || plugin_api.free_buffer.is_none() {
        shutdown_if_filled(&plugin_api);
        return Err(PluginHostError::failed(
            "plugin function table is incomplete",
        ));
    }
    plugin.call = plugin_api.call;
    plugin.free_buffer = plugin_api.free_buffer;
    plugin.shutdown = plugin_api.shutdown;
    Ok(plugin)
}

/// Non-unix stub: the worker loader is unavailable, so
/// there is nothing to load. (The crate already requires
/// unix via its `nix` dependency; this stub keeps the
/// module graph coherent.)
#[cfg(not(unix))]
pub struct LoadedPlugin {
    closed: bool,
}

#[cfg(not(unix))]
impl LoadedPlugin {
    /// Whether `shutdown` already ran.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Mark closed; no plugin is ever loaded here.
    pub fn shutdown(&mut self) {
        self.closed = true;
    }

    /// Never succeeds on non-unix.
    pub fn call(&self, _method: &str, _request: &[u8]) -> Result<Vec<u8>, PluginHostError> {
        Err(PluginHostError::LoaderUnavailable)
    }
}

#[cfg(not(unix))]
pub fn open(_path: &Path, _display_path: &str) -> Result<LoadedPlugin, PluginHostError> {
    Err(PluginHostError::LoaderUnavailable)
}
