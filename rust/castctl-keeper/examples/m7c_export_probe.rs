// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! M7c item 5 (fix loop 1) probe: call the real `CdpExporter::export()`
//! directly against a browser URL and print exactly what it returns.
//!
//! Why a separate probe: the keeper tick's `stop_entry` hardcodes
//! `exported: 0` in its `TickResult` (`tick.rs`), so the tick line
//! cannot tell whether the export ran or what it returned on the
//! stop path. This probe measures the exporter itself.
//!
//! Env:
//! - `M7C_EXPORT_BROWSER` (default `http://127.0.0.1:9301`): own
//!   Chrome CDP URL — never the shared 9226.
//!
//! Exit 0 iff at least one cookie is returned; the count and the
//! (name, domain, path, expires) of each cookie are printed either
//! way. Values are NEVER printed (a seeded test cookie's value is
//! fake, but the habit stands).

use castctl_keeper::new_cdp_exporter;

#[tokio::main]
async fn main() {
    let browser =
        std::env::var("M7C_EXPORT_BROWSER").unwrap_or_else(|_| "http://127.0.0.1:9301".to_string());
    println!("M7C-EXPORT-PROBE browser={browser}");
    let exporter = new_cdp_exporter(&browser);
    match exporter.export().await {
        Ok(cookies) => {
            println!("M7C-EXPORT-PROBE exported={}", cookies.len());
            for c in &cookies {
                println!(
                    "M7C-EXPORT-PROBE cookie name={} domain={} path={} expires={}",
                    c.name, c.domain, c.path, c.expires
                );
            }
            if cookies.is_empty() {
                eprintln!("M7C-EXPORT-PROBE FAIL: empty export");
                std::process::exit(1);
            }
            println!("M7C-EXPORT-PROBE OK");
        }
        Err(e) => {
            eprintln!("M7C-EXPORT-PROBE FAIL: {e}");
            std::process::exit(1);
        }
    }
}
