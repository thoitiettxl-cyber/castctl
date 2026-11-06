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
//! `"0"` on stub builds. The Rust binary CANNOT dlopen
//! (see `loader.rs`: the loader sub-scope is STOPPED),
//! so it always reports `"0"` — the same value Go's
//! stub loader reports on platforms without dynamic
//! loading. This is a [DEVIATION] from the Go cgo value
//! `"1"`, recorded in PORTING.md (M6c section) with the
//! reason: the value describes the LOADER capability,
//! and this binary has none.

/// `"0"`: this binary cannot load dynamic-library
/// plugins. See the module docs for the reason.
#[must_use]
pub const fn support_value() -> &'static str {
    "0"
}

/// Whether plugins are supported by this binary:
/// always false while the loader is STOPPED.
#[must_use]
pub const fn support_plugins() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn support_is_zero_without_loader() {
        assert_eq!(support_value(), "0");
        assert!(!support_plugins());
    }
}
