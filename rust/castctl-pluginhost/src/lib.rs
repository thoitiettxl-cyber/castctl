// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

#![deny(unsafe_code)]

//! Plugin host: pure layers ported from Go, plus the
//! real `.so` loader (M6c-b).
//!
//! Go sources: `internal/pluginhost/*` + `internal/pluginabi/pluginabi.go`
//! (all at `dev-rust` `25a124e`). No Go code was changed.
//!
//! Crate map (modules land one at a time; see PORTING.md §M6c):
//!
//! | Module | Go source | Contents |
//! |---|---|---|
//! | `pluginabi` | `pluginabi.go` | ABI types, `ValidateRegistration`, envelope JSON |
//! | `discovery` | `discovery.go` | Plugin file discovery + version compare |
//! | `shadow` | `shadow.go` | Content-addressed shadow copy under `pid-<pid>/` |
//! | `checksum` | `checksum.go` | Manifest format (differs from update) + verify |
//! | `compat` | `compat.go` | Hand-rolled verneed walk + strtab bound scanner |
//! | `paths` | `paths.go` | `refuseSymlinkedComponents` |
//! | `text` | `text.go` | Cap-before-redact, control/C1/CSI stripping |
//! | `identity` | `identity.go` | JSON-value redactor + stripped outbound hash |
//! | `host` | `host.go` | ApplyConfig / fuse / rollback / guarded call |
//! | `egress` | `egress.go` | Loopback egress proxy (tokio/hyper) |
//! | `loader` | `loader_unix.go` | Real loader: worker + `ffi` (M6c-b) |
//! | `worker` | — (new) | Subprocess worker + framed protocol v2 |
//! | `ffi` | `loader_unix.go` + `callbacks_unix.go` | dlopen/dlsym + C ABI (ONLY `unsafe` module) |
//!
//! The dlopen loader IS ported (M6c-b): Go loads plugins
//! with `dlopen` + a C ABI (`loader_unix.go:168`) and
//! guards the init call with a SIGSEGV/SIGBUS signal
//! handler around a bare `*char` method
//! (`callbacks_unix.go:208,223,244`). The Rust port
//! confines the `unsafe` FFI to the single `ffi` module
//! (see its header comment for the safety boundary) and
//! runs it ONLY inside a subprocess worker, so a plugin
//! crash kills the worker — never the host — and is
//! reported as `PluginCrashed`. This is deliberately
//! stronger than Go, whose guard covers only the
//! `host.log` method-name scan and whose host dies on
//! any other plugin fault. See `loader.rs` and
//! PORTING.md §M6c-b.

pub mod checksum;
pub mod compat;
pub mod discovery;
pub mod egress;
pub mod error;
pub mod ffi;
pub mod host;
pub mod identity;
pub mod loader;
pub mod paths;
pub mod pluginabi;
pub mod shadow;
pub mod support;
pub mod text;
pub mod worker;
