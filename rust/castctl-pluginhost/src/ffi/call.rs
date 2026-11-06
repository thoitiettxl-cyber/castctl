// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Host -> plugin `Call`: C copies of method/request,
//! the `MaxInt32` oversize rule, unconditional
//! plugin-`free_buffer` after the copy, and the
//! rc/envelope rule.
//!
//! Go source: `internal/pluginhost/loader_unix.go`
//! (`dynamicLibraryClient.Call` `:236-294`).
//!
//! Ownership (the one-line version): the side that
//! allocated a `castctl_buffer`'s bytes never frees
//! them; the side that received them frees them exactly
//! once, through the allocator's own `free_buffer`,
//! immediately after copying — and the receiver must
//! never use the pointer after freeing. Concretely:
//! request/method copies are host-malloc'd and freed
//! with `libc::free` after the call; the plugin's
//! response bytes are freed via the plugin's own
//! `free_buffer`, on EVERY path where `ptr != null`
//! (including the oversize path and `rc != 0`).

use std::ffi::{CString, c_void};

use crate::error::PluginHostError;
use crate::host::is_error_envelope;
use crate::text::plugin_call_error;

use super::load::LoadedPlugin;
use super::types::{CastctlBuffer, PluginFreeFn};

/// Unix only: the real call wrapper. (On non-unix the
/// stub `call` in `load.rs` reports `LoaderUnavailable`.)
#[cfg(unix)]
impl LoadedPlugin {
    /// One envelope call. `method`/`request` are copied
    /// into C memory; the plugin must not free them and
    /// must not retain the pointers after return.
    pub fn call(&self, method: &str, request: &[u8]) -> Result<Vec<u8>, PluginHostError> {
        if self.is_closed() {
            return Err(PluginHostError::failed("plugin client is closed"));
        }
        let Some(call) = self.call else {
            return Err(PluginHostError::failed("plugin client is closed"));
        };
        let Some(free_buffer) = self.free_buffer else {
            return Err(PluginHostError::failed("plugin client is closed"));
        };
        // `C.CString(method)`: an interior NUL is a host
        // bug, but it is still an error, never a panic
        // and never a silent truncation (Go truncates;
        // the Rust port fails closed here — recorded in
        // PORTING.md §M6c-b).
        let c_method = CString::new(method)
            .map_err(|_| PluginHostError::failed("plugin method contains a NUL byte"))?;
        // `C.CBytes(request)`: a malloc'd copy, freed by
        // the host after the call. Empty request -> NULL
        // pointer with length 0.
        let req_ptr: *const u8 = if request.is_empty() {
            std::ptr::null()
        } else {
            let ptr = unsafe { libc::malloc(request.len()) as *mut u8 };
            if ptr.is_null() {
                return Err(PluginHostError::failed("allocate request buffer"));
            }
            unsafe {
                std::ptr::copy_nonoverlapping(request.as_ptr(), ptr, request.len());
            }
            ptr as *const u8
        };
        // The response out-param starts zeroed
        // (`ptr = nil, len = 0`); the plugin writes
        // `ptr`/`len` only when it has bytes.
        let mut response = CastctlBuffer {
            ptr: std::ptr::null_mut(),
            len: 0,
        };
        // SAFETY: `call` is a non-null fn pointer from
        // the plugin table; `c_method` is NUL-terminated,
        // `req_ptr` is a malloc'd copy (or null with
        // length 0), `response` is a valid out-param.
        let rc = unsafe {
            call(
                c_method.as_ptr(),
                req_ptr,
                request.len(),
                &mut response as *mut CastctlBuffer,
            )
        };
        if !req_ptr.is_null() {
            unsafe {
                libc::free(req_ptr as *mut c_void);
            }
        }
        // Copy first, then free — always, when
        // `ptr != null` (including `len == 0`, `rc != 0`,
        // and the oversize path below). The length AND
        // the pointer are snapshotted ONCE into locals
        // (fix loop 1, red N7, for `len`; fix loop 2,
        // safety R2-N4, for `ptr`): re-reading either
        // on every use lets a plugin thread retaining
        // the out-param pointer mutate it between the
        // check and the copy.
        let resp_ptr = response.ptr;
        let resp_len = response.len;
        let out: Vec<u8> = if resp_ptr.is_null() || resp_len == 0 {
            Vec::new()
        } else if resp_len > i32::MAX as usize {
            free_response(free_buffer, resp_ptr, resp_len);
            return Err(PluginHostError::failed(format!(
                "plugin call {method} returned an oversize response"
            )));
        } else {
            let bytes = unsafe { std::slice::from_raw_parts(resp_ptr as *const u8, resp_len) };
            bytes.to_vec()
        };
        if !resp_ptr.is_null() {
            free_response(free_buffer, resp_ptr, resp_len);
        }
        if rc == 0 {
            return Ok(out);
        }
        // `rc != 0` with an error envelope is NOT a
        // transport failure: the envelope bytes are handed
        // up so `parseEnvelope` can surface the plugin's
        // own code/message.
        if is_error_envelope(&out) {
            return Ok(out);
        }
        Err(plugin_call_error(method, rc, &out))
    }
}

/// Free a plugin-allocated response through the
/// plugin's own `free_buffer`, with the exact
/// `(ptr, len)` the plugin reported. Never
/// `libc::free`: the plugin's allocator is the
/// plugin's private choice.
#[cfg(unix)]
fn free_response(free_buffer: PluginFreeFn, ptr: *mut c_void, len: usize) {
    unsafe {
        free_buffer(ptr, len);
    }
}
