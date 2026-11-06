// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! The `extern "C"` host callbacks the plugin calls
//! back into: `castctlHostCall` (`host.log` only) and
//! `castctlHostFree`.
//!
//! Go source: `internal/pluginhost/callbacks_unix.go`
//! (`castctlHostCall` `:244-284`, `castctlHostFree`
//! `:287-291`, `boundedCStringLen` `:223-241`).
//!
//! The method name is a bare `*char` with no length, so
//! it is read with a bounded scan of at most 256 bytes
//! for a NUL (`maxHostMethodLen`). There is deliberately
//! NO signal guard around the scan in v1 (see
//! `loader.rs` / PORTING §M6c-b): this code runs inside
//! the worker process, so an unreadable method pointer
//! faults the worker and the parent reports
//! `PluginCrashed` — the designed outcome. Go's guard
//! (B-narrow) is deferred, not adopted.
//!
//! The callback never panics: the body runs inside
//! `catch_unwind` and returns 1 on panic (a panic
//! across FFI is UB). It never takes a lock that is also
//! taken on the call path: the dispatcher is installed
//! once at worker startup, and the round-trip lock lives
//! in the worker module, taken only inside the
//! dispatcher itself.

use std::ffi::{c_char, c_int, c_void};
use std::sync::Mutex;

use crate::host::HostCallbackDispatcher;

use super::types::CastctlBuffer;

/// Maximum host-method name length, in bytes.
/// Source: `maxHostMethodLen = 256` (`text.go`).
pub const MAX_HOST_METHOD_LEN: usize = 256;

/// The one callback-registry id. The worker loads one
/// plugin, so there is exactly one registered host
/// (`id == 1`; Go ids start at 1, 0 is never valid).
pub const CALLBACK_ID: u64 = 1;

/// A host-callback dispatcher: `method` + request bytes
/// in, response envelope bytes out (`None` = delivery
/// failed, the callback returns 1). The worker installs
/// a dispatcher that round-trips the frame to the
/// parent; the parent's dispatcher calls
/// `Host::dispatch_host_call`. The type lives in
/// `host.rs` so both sides share one definition.
/// The installed dispatcher, if any. Set once at worker
/// startup, before any plugin is loaded.
static HOST_DISPATCH: Mutex<Option<HostCallbackDispatcher>> = Mutex::new(None);

/// Install the host-callback dispatcher. Called once at
/// worker startup; a second call replaces the previous
/// dispatcher (the worker installs exactly once).
pub fn install_host_dispatcher(dispatcher: HostCallbackDispatcher) {
    *HOST_DISPATCH.lock().unwrap_or_else(|e| e.into_inner()) = Some(dispatcher);
}

fn dispatcher() -> Option<HostCallbackDispatcher> {
    HOST_DISPATCH
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

/// The reverse entry point, wired as `host_api.call`.
/// Return contract (Go `castctlHostCall`): 0 = callback
/// delivered (even when the reply is an error envelope —
/// that is payload, not failure), 1 = delivery failed
/// (bad ctx/method/length/alloc). Never panics.
///
/// # Safety
/// The caller (plugin code, via the host table) must
/// pass pointers that are valid for the ABI:
/// `host_ctx` is the malloc'd `u64` id from `load.rs`
/// (or null, which fails closed); `method` is a
/// NUL-terminated C string (or null); `request` points
/// to `request_len` readable bytes (or is null with
/// length 0); `response` is a writable `CastctlBuffer`
/// (or null). An unreadable `method` pointer faults
/// the worker by design (no signal guard in v1).
pub unsafe extern "C" fn castctl_host_call(
    host_ctx: *mut c_void,
    method: *const c_char,
    request: *const u8,
    request_len: usize,
    response: *mut CastctlBuffer,
) -> c_int {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        host_call_inner(host_ctx, method, request, request_len, response)
    }))
    .unwrap_or(1)
}

fn host_call_inner(
    host_ctx: *mut c_void,
    method: *const c_char,
    request: *const u8,
    request_len: usize,
    response: *mut CastctlBuffer,
) -> c_int {
    // Zero the out-param first (Go `:245-248`).
    if !response.is_null() {
        unsafe {
            *response = CastctlBuffer {
                ptr: std::ptr::null_mut(),
                len: 0,
            };
        }
    }
    if host_ctx.is_null() || method.is_null() {
        return 1;
    }
    // The cookie must hold the one registered id.
    let id = unsafe { *(host_ctx as *const u64) };
    if id != CALLBACK_ID {
        return 1;
    }
    // Bounded scan for the NUL terminator (max 256
    // bytes). No NUL in range -> refuse (return 1). An
    // unreadable pointer faults the worker: the designed
    // v1 outcome, not a host crash.
    let mut len = 0usize;
    let mut found = false;
    while len < MAX_HOST_METHOD_LEN {
        let byte = unsafe { *method.add(len) } as u8;
        if byte == 0 {
            found = true;
            break;
        }
        len += 1;
    }
    if !found {
        return 1;
    }
    let method_bytes = unsafe { std::slice::from_raw_parts(method as *const u8, len) };
    let method_str = String::from_utf8_lossy(method_bytes);
    // Request: the plugin retains ownership; the host
    // only copies. A length past i32::MAX is refused
    // rather than truncated (Go `:262-272`).
    let req: Vec<u8> = if request.is_null() || request_len == 0 {
        Vec::new()
    } else {
        if request_len > i32::MAX as usize {
            return 1;
        }
        unsafe { std::slice::from_raw_parts(request, request_len) }.to_vec()
    };
    let Some(dispatch) = dispatcher() else {
        return 1;
    };
    let Some(resp) = dispatch(&method_str, &req) else {
        return 1;
    };
    if resp.is_empty() || response.is_null() {
        return 0;
    }
    // Host-malloc'd response: the plugin must free it via
    // `castctl_host_free`. Alloc failure -> 1.
    let ptr = unsafe { libc::malloc(resp.len()) as *mut u8 };
    if ptr.is_null() {
        return 1;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(resp.as_ptr(), ptr, resp.len());
        (*response).ptr = ptr as *mut c_void;
        (*response).len = resp.len();
    }
    0
}

/// The host `free_buffer`: frees a host-allocated
/// response buffer. The length is ignored (it exists
/// only so the signature matches
/// `castctl_host_free_fn`). Go: `callbacks_unix.go:287`.
///
/// # Safety
/// `ptr` must be null or a pointer previously returned
/// in a `CastctlBuffer` by `castctl_host_call`
/// (`libc::malloc`, freed at most once).
pub unsafe extern "C" fn castctl_host_free(ptr: *mut c_void, _len: usize) {
    if !ptr.is_null() {
        unsafe {
            libc::free(ptr);
        }
    }
}
