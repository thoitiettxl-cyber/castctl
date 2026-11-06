// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! C ABI types for the plugin loader. Field order and
//! widths match the cgo preamble of Go
//! `internal/pluginhost/loader_unix.go:11-42` exactly; do
//! not re-derive them from memory.
//!
//! Layout (64-bit LP64, `repr(C)`):
//! - `CastctlBuffer`: 16 bytes (pointer + `size_t`).
//! - `HostApi` / `PluginApi`: 32 bytes (`u32` + 4 pad +
//!   three 8-byte pointers).
//! - A `None` fn pointer is a null pointer (the nullable
//!   fn-pointer idiom); `shutdown == None` is allowed by
//!   Go and is not completeness-checked.

use std::ffi::{c_char, c_int, c_uint, c_void};

/// The only heap buffer that crosses the ABI, in both
/// directions. A NULL `ptr` means "no bytes", regardless
/// of `len`. Source: `loader_unix.go:11-14`.
#[repr(C)]
pub struct CastctlBuffer {
    /// Pointer to the bytes (may be null).
    pub ptr: *mut c_void,
    /// Byte length (untrusted until checked).
    pub len: usize,
}

/// The host table the host passes to `init`.
/// Source: `loader_unix.go:19-29`.
#[repr(C)]
pub struct HostApi {
    /// Host ABI version, always 1.
    pub abi_version: c_uint,
    /// Opaque cookie: a malloc'd `uintptr_t` holding a
    /// callback-registry id (1 in this port; the worker
    /// loads one plugin). Never dereferenced as a struct.
    pub host_ctx: *mut c_void,
    /// Plugin -> host reverse call.
    pub call: Option<HostCallFn>,
    /// Plugin frees a host-allocated response buffer.
    pub free_buffer: Option<HostFreeFn>,
}

/// The plugin table the plugin fills in `init`.
/// Source: `loader_unix.go:31-40`.
#[repr(C)]
pub struct PluginApi {
    /// Plugin ABI version; must equal 1 exactly.
    pub abi_version: c_uint,
    /// Host -> plugin call; must be non-null.
    pub call: Option<PluginCallFn>,
    /// Host frees a plugin-allocated response buffer;
    /// must be non-null.
    pub free_buffer: Option<PluginFreeFn>,
    /// May be null; `close` skips a null shutdown.
    pub shutdown: Option<PluginShutdownFn>,
}

/// `int (*)(void*, const char*, const uint8_t*, size_t,
/// castctl_buffer*)` — plugin -> host reverse call.
pub type HostCallFn =
    unsafe extern "C" fn(*mut c_void, *const c_char, *const u8, usize, *mut CastctlBuffer) -> c_int;

/// `void (*)(void*, size_t)` — free a host-allocated
/// buffer (length ignored, kept for ABI shape).
pub type HostFreeFn = unsafe extern "C" fn(*mut c_void, usize);

/// `int (*)(const castctl_host_api*,
/// castctl_plugin_api*)` — the single entry symbol.
pub type PluginInitFn = unsafe extern "C" fn(*const HostApi, *mut PluginApi) -> c_int;

/// `int (*)(const char*, const uint8_t*, size_t,
/// castctl_buffer*)` — host -> plugin call.
pub type PluginCallFn =
    unsafe extern "C" fn(*const c_char, *const u8, usize, *mut CastctlBuffer) -> c_int;

/// `void (*)(void*, size_t)` — free a plugin-allocated
/// buffer (length ignored by echo, kept for ABI shape).
pub type PluginFreeFn = unsafe extern "C" fn(*mut c_void, usize);

/// `void (*)(void)` — plugin shutdown; may be null.
pub type PluginShutdownFn = unsafe extern "C" fn();
