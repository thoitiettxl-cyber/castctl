// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Plugin loader — STOPPED SUB-SCOPE (not a port).
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
//! (`dlclose` / `FreeLibrary` are never called). The
//! init call is guarded by a SIGSEGV/SIGBUS signal
//! handler around a bare `*char` method
//! (`callbacks_unix.go:208,223,244`).
//!
//! A safe pure-Rust port is impossible: it would need
//! `unsafe` FFI (`dlopen`/`dlsym`, raw function
//! pointers, a bare `*char` method) plus a signal guard
//! no safe Rust equivalent exists for, and this task
//! forbids `unsafe` outside libraries. No `libloading`
//! dependency is added, no dlopen loader is written,
//! and nothing here pretends to port the loader.
//!
//! What this module DOES provide:
//!
//!   - a typed `LoaderUnavailable` error (see
//!     `PluginHostError::LoaderUnavailable`), returned
//!     by every load attempt, with the message pinned
//!     below;
//!   - the full limit + proposal (Options A/B/C from
//!     the Phase 1 pluginhost-ABI report §7), recorded
//!     here and in PORTING.md (M6c section) so a later
//!     decision can pick one up without re-deriving it.
//!
//! Option A (RECOMMENDED): keep the Go binary as the
//! plugin host; the Rust host delegates `plugin check`
//! (and any future load) to it. The Rust `Host`
//! lifecycle logic (fuse/rollback/quiesce/guarded call)
//! stays valid: only the `Loader` trait implementation
//! lives in Go.
//!
//! Option B: a subprocess protocol v2 — the plugin
//! runs in a child process speaking a framed protocol
//! over stdio/a socket. Safer (a crashing plugin cannot
//! take the host down) but a new wire protocol, new
//! versioning, and new failure modes; out of scope for
//! M6c.
//!
//! Option C: a small C shim (or `libloading` in a
//! dedicated unsafe crate) that owns the dlopen/dlsym
//! surface and the signal guard, exposing a narrow safe
//! API to Rust. Keeps in-process loading but re-adds
//! exactly the unsafe surface the port was meant to
//! remove; needs its own audit round.
//!
//! Until one of these is decided, `check_plugin`
//! (the `plugin check` path) reports the limit instead
//! of loading.

use crate::error::PluginHostError;

/// The message every load attempt fails with.
/// Source: coordinator decision in the M6c task brief
/// (Option A wording).
pub const LOADER_UNAVAILABLE_MESSAGE: &str = "plugin loading requires the Go binary (Option A: keep the Go binary as plugin host, Rust delegates plugin check)";

/// Attempt to load a plugin: always refuses with
/// `LoaderUnavailable`. The signature mirrors Go's
/// `Loader.Open(file, host)` shape (file path in,
/// client out) so a future Option A/B/C implementation
/// can fill this seam without changing callers.
pub fn open_plugin(_path: &std::path::Path) -> Result<(), PluginHostError> {
    Err(PluginHostError::LoaderUnavailable)
}

/// The `plugin check` path: reports the limit instead
/// of loading. Callers surface this as a skip reason,
/// never as a successful load.
pub fn check_plugin(_path: &std::path::Path) -> Result<(), PluginHostError> {
    open_plugin(_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loader_unavailable_message_pinned() {
        let err = open_plugin(std::path::Path::new("/tmp/echo.so")).unwrap_err();
        assert_eq!(err.to_string(), LOADER_UNAVAILABLE_MESSAGE);
        assert!(matches!(err, PluginHostError::LoaderUnavailable));
        assert!(check_plugin(std::path::Path::new("/tmp/echo.so")).is_err());
    }
}
