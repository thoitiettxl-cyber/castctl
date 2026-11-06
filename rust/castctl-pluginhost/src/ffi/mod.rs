// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! FFI boundary — the ONLY module in this crate where
//! `unsafe` is allowed.
//!
//! Why `unsafe` is mandatory here: loading a `.so`
//! requires `dlopen`/`dlsym` (libloading), calling
//! function pointers obtained from another binary, and
//! reading/writing raw C buffers. There is no safe-Rust
//! equivalent: a function pointer of the wrong type is UB
//! (libloading docs), and a bare `*char` method name has
//! no length. The Boss decision is that Go does the same
//! with `unsafe`+cgo, so confinement — not elimination —
//! is the rule. This module runs ONLY inside the plugin
//! worker process (see `worker.rs`): a fault in plugin
//! code kills the worker, never the host.
//!
//! Safety boundary (every function in this module must
//! uphold all of these):
//!   1. Null-check EVERY pointer before any call or
//!      dereference — fn pointers from the plugin table,
//!      `response.ptr`, `host_ctx`, `method`, `request`.
//!      A null where a value is required is an error,
//!      never a dereference.
//!   2. Plugin-allocated buffers are freed ONLY via the
//!      plugin's own `free_buffer` fn pointer, never
//!      `libc::free`. Host-allocated buffers handed to the
//!      plugin are freed with `libc::free` after the call
//!      returns. Allocator identity is paired per buffer;
//!      mixing allocators is a heap-corruption bug, not a
//!      leak.
//!   3. No reference into plugin memory is kept after the
//!      plugin returns. Copy bytes out (bounded: null
//!      check, then `len <= i32::MAX`, then copy), call
//!      `free_buffer`, and only then hand owned `Vec<u8>`
//!      up. The `&[u8]` view must not outlive the copy.
//!   4. Lengths are numbers, not promises: a
//!      plugin-reported `len` is checked
//!      (`len <= i32::MAX`, matching Go's `C.GoBytes`
//!      limit) BEFORE any read. A lying `len` past
//!      `i32::MAX` is refused before any read; a
//!      smaller lying `len` faults the *worker*
//!      (contained by the process boundary — the copy
//!      reads adjacent worker heap, which usually
//!      segfaults and is reported as `PluginCrashed`,
//!      or yields garbage the host refuses as an
//!      invalid envelope) and is NEVER accepted as a
//!      truncated read. (Fix loop 1, safety N2: the
//!      old wording claimed a lying `len` yields an
//!      error, which is false in this range.)
//!   5. The loaded image is NEVER unloaded
//!      (`dlclose`/`Library::close` are never called; the
//!      `Library` sits in a `ManuallyDrop`).
//!      A Go c-shared runtime cannot be removed safely
//!      (Go `loader_unix.go` `close()`).
//!   6. The `extern "C"` host callback never panics: its
//!      body is wrapped in `catch_unwind` and returns 1 on
//!      panic (a panic across FFI is UB). It allocates only
//!      ordinary Rust memory; it never takes a lock that
//!      is also taken on the call path (deadlock across the
//!      plugin boundary).
//!   7. No `unwrap()`/`expect()` on external input anywhere
//!      in this module (or in the crate). Every failure is
//!      a `Result<_, PluginHostError>`.
//!   8. Only this module may name `libloading`/`libc`
//!      items for a function call. Constants (e.g. the
//!      pre-existing `libc::O_NOFOLLOW` in `paths.rs`,
//!      `libc::STDIN_FILENO` in `worker.rs`) are not
//!      calls and are excluded. If another module needs
//!      an FFI fact, add a safe wrapper here and call
//!      that. (Fix loop 1, safety N7: the old wording
//!      claimed no module outside `ffi` names `libc`
//!      at all, which `paths.rs` already falsified.)

#![allow(unsafe_code)]

pub mod call;
#[cfg(unix)]
pub mod fd;
#[cfg(unix)]
pub mod hostcall;
pub mod load;
#[cfg(unix)]
pub mod pdeath;
pub mod types;

#[cfg(unix)]
pub use fd::{poll_readable, poll_writable, read_fd};
pub use load::{LoadedPlugin, open};
#[cfg(unix)]
pub use pdeath::set_parent_death_signal;
