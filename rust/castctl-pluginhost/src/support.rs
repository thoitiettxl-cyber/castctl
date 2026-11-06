// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Plugin support value: whether this binary can load
//! dynamic-library plugins.
//!
//! Go source: `internal/pluginhost/support.go`
//! (`SupportValue` / `SupportPlugins`).
//!
//! Go reports `"1"` on cgo unix/windows builds and
//! `"0"` on stub builds. The Rust binary loads plugins
//! through the real worker loader on unix (see
//! `loader.rs`: libloading inside a subprocess worker),
//! so it reports `"1"` there — the same value Go's cgo
//! loader reports. On non-unix platforms the worker
//! loader is unavailable and the value stays `"0"`,
//! like Go's stub loader. (M6c-b: this used to be a
//! [DEVIATION] reporting `"0"` everywhere because the
//! loader was STOPPED; the deviation is closed on unix
//! by the real loader, see PORTING.md §M6c-b.)

/// `"1"` on unix (the worker loader is real),
/// `"0"` elsewhere. See the module docs.
#[must_use]
pub const fn support_value() -> &'static str {
    if cfg!(unix) { "1" } else { "0" }
}

/// Whether plugins are supported by this binary: true
/// on unix (the worker loader is real), false elsewhere.
#[must_use]
pub const fn support_plugins() -> bool {
    cfg!(unix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn support_matches_loader_capability() {
        if cfg!(unix) {
            assert_eq!(support_value(), "1");
            assert!(support_plugins());
        } else {
            assert_eq!(support_value(), "0");
            assert!(!support_plugins());
        }
    }
}
