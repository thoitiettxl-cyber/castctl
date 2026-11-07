// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Single-file config parse/validate/render and profile
//! resolution, ported from castctl's Go `internal/profile` (M2).
//!
//! Scope (D-M2-1): the config/profile surface that is computable
//! without sing-box's option registry. Sing-box option validation
//! (tag graph, DNS, WireGuard) is deferred and recorded in
//! PORTING.md; the deferred blocks are stored raw and rendered
//! verbatim.
//!
//! No `unwrap()`/`expect()` on external input. One `unsafe` call:
//! `libc::flock` in `toggle.rs` (the inter-process config lock, which
//! has no safe std equivalent). Every public item cites its Go source
//! at base `dev-rust` `85a8d5e`.

pub mod blocks;
pub mod config;
pub mod configlocation;
pub mod dnsvalidate;
pub mod errors;
pub mod fingerprint;
pub mod gopath;
pub mod gostr;
pub mod jsonvalue;
pub mod keeper;
pub mod log;
pub mod migrate;
pub mod oserr;
pub mod profile;
pub mod profile_ops;
pub mod redact;
pub mod singbox;
pub mod singbox_tables;
pub mod taggraph;
pub mod telegram;
pub mod toggle;
pub mod webui;

pub use blocks::LoginCredential;
pub use errors::{ConfigError, config_error};
pub use profile::{ResolvedSetting, resolve_auto_allow_once, resolve_auto_approve};
pub use toggle::{
    ConfigLock, ConfigState, generate_node_id, load_config_state, lock_config_dir,
    refuse_unmigrated, set_auto_allow_once, set_auto_approve, update_single_config,
    write_single_config_locked,
};
