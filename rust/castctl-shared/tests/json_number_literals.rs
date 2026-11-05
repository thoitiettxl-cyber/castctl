// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Fixture test: gateway numbers keep their literal spelling
//! through the bridge, exactly as Go emits them.
//!
//! Go side (measured, `go-output-research.md` §2 — verbatim
//! copy of `decodeJSONValue` + `writeJSON` + `StatusSummary`,
//! Go 1.27.3, input fragment
//! `{"bookmark_display_crop":{"size":<fixture>}}` in `identity`):
//!
//! | fixture (server sends) | Go emits (`"size": ...`) |
//! | 1.0                    | 1.0                    |
//! | 0.0                    | 0.0                    |
//! | 1e3                    | 1e3 (NOT 1000)         |
//! | 1.5                    | 1.5                    |
//! | 9007199254740993       | 9007199254740993       |
//! | 1.50                   | 1.50                   |
//! | 1E3                    | 1E3                    |
//! | 18446744073709551615   | 18446744073709551615   |
//!
//! `-0` is deliberately NOT in this table: Go emits `-0`,
//! but serde_json normalizes it to integer `0` at parse
//! time (see `rust/PORTING.md` §M4c.10), so no bridge
//! special-case can preserve it — the minus is gone before
//! `from_serde` runs. Pinned as a known limitation in
//! `bridge::tests::from_serde_neg_zero_collapses_to_int_zero_known_limitation`.
//!
//! Full Go output for `1.0` (len 133, measured):
//! ```json
//! {
//!   "vm_id": "vm-test",
//!   "sessions": 1,
//!   "unread": 0,
//!   "identity": {
//!     "bookmark_display_crop": {
//!       "size": 1.0
//!     }
//!   }
//! }
//! ```
//!
//! The Rust side below runs the same shape through the real
//! path (`from_serde` → `summarize_status` →
//! `status_summary_to_json`, compact form — the CLI indenter
//! scans tokens without re-parsing, so a literal that
//! survives the compact form survives the indented form too;
//! the live gate proves the indented form byte-for-byte).
//! Expected strings are hand-written literals, never
//! recomputed by the code under test. `1e3` is the
//! discriminator: any `f64` path emits `1000`.

use castctl_shared::{from_serde, status_summary_to_json, summarize_status};
use serde_json::Value as SerdeValue;

fn render_size(fixture: &str) -> String {
    let identity: SerdeValue = serde_json::from_str(&format!(
        r#"{{"bookmark_display_crop":{{"size":{fixture}}}}}"#
    ))
    .unwrap();
    let sessions: SerdeValue = serde_json::from_str(r#"{"sessions":[{}]}"#).unwrap();
    let unread: SerdeValue = serde_json::from_str("0").unwrap();
    let summary = summarize_status(
        "vm-test",
        &from_serde(&sessions),
        from_serde(&unread),
        from_serde(&identity),
    );
    status_summary_to_json(&summary)
}

#[test]
fn status_numbers_keep_go_literal_spelling() {
    // Each expected string is the compact form of the Go
    // output above, with only the `size` literal varying.
    let cases: &[(&str, &str)] = &[
        (
            "1.0",
            r#"{"vm_id":"vm-test","sessions":1,"unread":0,"identity":{"bookmark_display_crop":{"size":1.0}}}"#,
        ),
        (
            "0.0",
            r#"{"vm_id":"vm-test","sessions":1,"unread":0,"identity":{"bookmark_display_crop":{"size":0.0}}}"#,
        ),
        (
            "1e3",
            r#"{"vm_id":"vm-test","sessions":1,"unread":0,"identity":{"bookmark_display_crop":{"size":1e3}}}"#,
        ),
        (
            "1.5",
            r#"{"vm_id":"vm-test","sessions":1,"unread":0,"identity":{"bookmark_display_crop":{"size":1.5}}}"#,
        ),
        (
            "9007199254740993",
            r#"{"vm_id":"vm-test","sessions":1,"unread":0,"identity":{"bookmark_display_crop":{"size":9007199254740993}}}"#,
        ),
        (
            "1.50",
            r#"{"vm_id":"vm-test","sessions":1,"unread":0,"identity":{"bookmark_display_crop":{"size":1.50}}}"#,
        ),
        (
            "1E3",
            r#"{"vm_id":"vm-test","sessions":1,"unread":0,"identity":{"bookmark_display_crop":{"size":1E3}}}"#,
        ),
        (
            "18446744073709551615",
            r#"{"vm_id":"vm-test","sessions":1,"unread":0,"identity":{"bookmark_display_crop":{"size":18446744073709551615}}}"#,
        ),
    ];
    for (fixture, want) in cases {
        assert_eq!(render_size(fixture), *want, "fixture {fixture}");
    }
}
