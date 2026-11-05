// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! `auth list` (M7a): port of Go
//! `internal/deliver/authlist.go`.

use castctl_config::config::load_profile;
use castctl_config::profile::discover_profile_names;
use serde::Serialize;

use crate::DeliverError;

/// One row of the `auth list` output (Go `ProfileRow`).
/// Field order is the Python dict order: name, active,
/// dir, exists, cookies, cookies_file, auto_approve.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProfileRow {
    /// Profile name.
    pub name: String,
    /// Whether this is the active profile.
    pub active: bool,
    /// Profile directory.
    pub dir: String,
    /// Whether the profile directory exists.
    pub exists: bool,
    /// Whether the cookies file exists and is non-empty.
    pub cookies: bool,
    /// Resolved cookies file path.
    pub cookies_file: String,
    /// Normalised `auto_approve` (`"always"` or `"off"`).
    pub auto_approve: String,
}

/// The `--json` form of `auth list`: `{"active": ...,
/// "profiles": [...]}` (Go `AuthList`). Field order is the
/// Python dict order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthList {
    /// The active profile name.
    pub active: String,
    /// One row per profile.
    pub profiles: Vec<ProfileRow>,
}

/// List every profile, offline: no network, no writes
/// (Go `ListProfiles`). `"default"` first, then the
/// sorted valid profile directories, then the active
/// profile appended at the end when it is not already
/// listed (for example an active profile whose directory
/// does not exist yet).
///
/// `LoadProfile` is called with no environment lookup, so
/// no environment fill applies. A `LoadProfile` error
/// (for example an unparseable single config file) is
/// returned with context; one corrupt profile fails the
/// whole list.
///
/// `base_dir` is the config base directory (the directory
/// holding `config.json` and `profiles/`); `active` is the
/// active profile name.
pub fn list_profiles(base_dir: &str, active: &str) -> Result<AuthList, DeliverError> {
    let mut names = discover_profile_names(base_dir).map_err(|e| {
        DeliverError::wrap("deliver: list profiles", Box::new(e))
    })?;
    if !names.iter().any(|n| n == active) {
        names.push(active.to_string());
    }
    let mut rows = Vec::with_capacity(names.len());
    for name in &names {
        let p = load_profile(base_dir, name, None).map_err(|e| {
            DeliverError::wrap(format!("deliver: load profile {name:?}"), Box::new(e))
        })?;
        rows.push(ProfileRow {
            name: name.clone(),
            active: name == active,
            dir: p.dir,
            exists: p.exists,
            cookies: has_cookies(&p.cookies_file),
            cookies_file: p.cookies_file,
            auto_approve: auto_approve_value(&p.auto_approve),
        });
    }
    Ok(AuthList {
        active: active.to_string(),
        profiles: rows,
    })
}

/// Whether the cookies file exists and is non-empty (Go
/// `hasCookies`). Any error (missing file, unreadable
/// file) means no cookies.
fn has_cookies(cookies_file: &str) -> bool {
    match std::fs::metadata(cookies_file) {
        Ok(meta) => meta.len() > 0,
        Err(_) => false,
    }
}

/// Render the stored auto-approve value the way Python
/// does (Go `autoApproveValue`):
/// `str(cfg.get("auto_approve") or "off").lower()`.
fn auto_approve_value(v: &str) -> String {
    let v = v.trim().to_lowercase();
    if v.is_empty() {
        "off".to_string()
    } else {
        v
    }
}

/// Render the text form of `auth list` (Go
/// `FormatAuthList`): one line per row, `"* name  state
/// dir"`, the name column padded to the widest name, the
/// state column padded to width 11, `"*"` for the active
/// profile and `" "` otherwise. State is `"cookies"` when
/// the profile has a non-empty cookies file, `"no
/// cookies"` when its directory exists without one, and
/// `"not created"` otherwise. Each line ends with a
/// newline. An empty list renders empty.
pub fn format_auth_list(list: &AuthList) -> String {
    let width = list
        .profiles
        .iter()
        .map(|r| r.name.chars().count())
        .max()
        .unwrap_or(0);
    let mut out = String::new();
    for r in &list.profiles {
        let mark = if r.active { "*" } else { " " };
        let state = if r.cookies {
            "cookies"
        } else if r.exists {
            "no cookies"
        } else {
            "not created"
        };
        out.push_str(&format!(
            "{mark} {name:<width$}  {state:<11}  {dir}\n",
            name = r.name,
            dir = r.dir,
        ));
    }
    out
}

