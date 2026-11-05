// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Read-only CDP probe against a running Chrome with remote
//! debugging enabled (the cue Chrome on 127.0.0.1:9226).
//!
//! Steps, all read-only: GET `/json/version`, GET
//! `/json/list`, WS connect to the browser target,
//! `Browser.getVersion`, attach to the first page target
//! (`flatten: true`), `Target.getTargetInfo` on that
//! session, detach. Nothing is navigated, opened, closed,
//! or evaluated; no cookie, token, or page content is
//! printed.
//!
//! Run on cue:
//! `CDP_HTTP_BASE=http://127.0.0.1:9226 cargo run -p castctl-keeper --example cdp_probe`

use castctl_keeper::cdp::{CdpClient, browser_version_info, discover_websocket_url, list_targets};
use serde_json::Value;

#[tokio::main]
async fn main() {
    let base =
        std::env::var("CDP_HTTP_BASE").unwrap_or_else(|_| "http://127.0.0.1:9226".to_string());
    if let Err(e) = run(&base).await {
        eprintln!("PROBE FAILED: {e}");
        std::process::exit(1);
    }
}

async fn run(base: &str) -> Result<(), Box<dyn std::error::Error>> {
    let ver = browser_version_info(base).await?;
    println!(
        "version: browser={} protocol={}",
        ver.browser, ver.protocol_version
    );
    let targets = list_targets(base).await?;
    println!("targets: count={}", targets.len());
    for t in &targets {
        println!(
            "  target: type={} title={:?} url={}",
            t.target_type, t.title, t.url
        );
    }
    let ws_url = discover_websocket_url(base).await?;
    println!("ws: connected to browser target");
    let client = CdpClient::connect(&ws_url).await?;
    let version = client.version().await?;
    println!(
        "Browser.getVersion: product={} protocol={}",
        version
            .get("product")
            .and_then(Value::as_str)
            .unwrap_or("?"),
        version
            .get("protocolVersion")
            .and_then(Value::as_str)
            .unwrap_or("?"),
    );
    let page = targets
        .iter()
        .find(|t| t.target_type == "page")
        .ok_or("no page target to attach to")?;
    let session = client.attach(&page.id).await?;
    println!(
        "attached: target={} session={}",
        page.id,
        session.session_id()
    );
    let info = session
        .call("Target.getTargetInfo", Value::Object(Default::default()))
        .await?;
    println!(
        "Target.getTargetInfo: type={} url={}",
        info.get("targetInfo")
            .and_then(|i| i.get("type"))
            .and_then(Value::as_str)
            .unwrap_or("?"),
        info.get("targetInfo")
            .and_then(|i| i.get("url"))
            .and_then(Value::as_str)
            .unwrap_or("?"),
    );
    session.detach().await?;
    println!("detached");
    println!("PROBE OK");
    Ok(())
}
