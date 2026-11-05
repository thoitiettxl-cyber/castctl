// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! `auth export` guidance (M7a): port of Go
//! `internal/deliver/authexport.go`.

use std::error::Error;
use std::fmt;

/// The manual guidance `auth_export` returns (Go
/// `ExportGuidance`). It tells the user how to establish
/// a login by hand, portably: no platform tool is named,
/// because no automatic extraction exists in this build.
pub const EXPORT_GUIDANCE: &str = "cookie export is not available in this build: no automatic cookie extraction is implemented yet.\n\nLog in at https://muse.ai/ in your browser, leave the tab open, and run \"castctl auth export\" again after a cookie source exists.\n\nCopy the login by hand instead:\n  1. In your browser, open https://muse.ai/ and log in.\n  2. Open the browser developer tools and read the cookies for https://muse.ai/.\n  3. Write one line to the active profile's cookies.txt file:\n       hatch_sess=VALUE; other_name=other_value\n     hatch_sess is required. Separate cookies with \"; \".\n  4. Set the file mode to 600.\n  5. Run \"castctl status\" to check the login.\n\nNo file was written or changed.";

/// The typed error `auth_export` always returns (Go
/// `ExportError`). It carries the manual guidance in
/// `guidance` so the commands layer can print it to stderr
/// and exit 1, matching Python's exit code for the
/// missing-extraction-tool path. `exit_code` reports 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportError {
    /// The manual guidance text.
    pub guidance: String,
}

impl ExportError {
    /// The process exit code for this error: 1, Python's
    /// exact exit code for the missing-tool path.
    pub fn exit_code(&self) -> i32 {
        1
    }
}

impl fmt::Display for ExportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.guidance)
    }
}

impl Error for ExportError {}

/// Guidance-only, by coordinator decision (Go
/// `AuthExport`). It never invokes any browser subprocess,
/// never reads any browser cookie store, and never writes
/// any file — there is no write path in this function at
/// all, so the never-clobber invariant (never replace a
/// working login with an empty or logged-out cookie set)
/// holds structurally: the existing cookies file is always
/// left unchanged.
///
/// It always returns an `ExportError` carrying
/// `EXPORT_GUIDANCE`. Callers print the guidance to stderr
/// and exit 1.
pub fn auth_export() -> Result<(), ExportError> {
    Err(ExportError {
        guidance: EXPORT_GUIDANCE.to_string(),
    })
}
