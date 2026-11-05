// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Plugin host: pure layers ported from Go, loader STOPPED.
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
//! | `loader` | `loader_unix.go` | STOPPED: `LoaderUnavailable`, Options A/B/C |
//!
//! The dlopen loader is NOT ported: Go loads plugins with
//! `dlopen` + a C ABI (`loader_unix.go:168`) and guards the
//! init call with a SIGSEGV/SIGBUS signal handler around a
//! bare `*char` method (`callbacks_unix.go:208,223,244`).
//! There is no safe pure-Rust equivalent, and this task
//! forbids `unsafe` outside libraries. See `loader.rs`.
