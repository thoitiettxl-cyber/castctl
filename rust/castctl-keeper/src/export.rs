// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! CDP re-export — port of `internal/keeper/export_cdp.go`
//! (with_chromedp) and `export_stub.go` (`!with_chromedp`).
//!
//! Read-only: attach to an already-running Chrome over
//! DevTools, read the live session cookies, detach. No
//! navigation, no input, no target creation/activation/
//! closure, no Emulation.
//!
//! Discipline (K-LIVE-2 fix): the PRIMARY read is
//! target-level — `Network.getCookies` on each open Muse
//! page target, merged and deduplicated. The FALLBACK is
//! the browser-level read: `Storage.getCookies`, then
//! `Network.getCookies` with explicit URLs. The
//! browser-level Storage read is NOT trusted on its own:
//! against Chrome 155 headless it succeeds with zero
//! cookies while the browser holds a live session, so an
//! empty read at any level is a FAILED read, never a
//! result — the exporter falls through to the next level.
//! Only when every level yields empty with success does
//! `export` return an empty result, and the tick's
//! validation gate decides (an export with no usable
//! filtered set still stops the entry).
//!
//! Attaching to a target runs the chromedp bootstrap — the
//! SAME bootstrap as the screencast attach path: it enables
//! Runtime, Log, Network, Inspector, Page, DOM, and CSS on
//! the target, sets `Target.setDiscoverTargets` and
//! `Target.setAutoAttach`, enables
//! `Page.setLifecycleEventsEnabled`, and evaluates the
//! constant `"self"`.

use std::collections::HashMap;

use async_trait::async_trait;
use serde_json::Value;

use crate::cdp::{CdpClient, CdpError, TargetInfo, discover_websocket_url, list_targets};
use crate::error::KeeperError;
use crate::jar::ExportedCookie;

/// The explicit `Network.getCookies` URL list: the Muse
/// origins only (`export_cdp.go`). An empty URL list would
/// mean "page + subframes", which is NOT all cookies, so
/// the list is explicit wherever `Network.getCookies` is
/// used (target-level primary and browser-level fallback
/// alike), except the harvest's L3 unscoped read, which
/// deliberately carries no list.
pub const EXPORT_URLS: &[&str] = &["https://muse.ai/", "https://auth.muse.ai/"];

/// The page hosts a cookie export may attach to: the Muse
/// app and its auth subdomain only — the same set the
/// screencast target resolver uses.
pub const EXPORT_HOSTS: &[&str] = &["muse.ai", "auth.muse.ai", "www.muse.ai"];

/// Whether this build can re-export cookies from a browser
/// over CDP (Go `CDPAvailable`).
pub const CDP_AVAILABLE: bool = crate::cdp::CDP_AVAILABLE;

/// The exporter seam (`export_cdp.go`): attach to the
/// browser, read the live session cookies, return them
/// UNFILTERED — the tick applies the domain filter and the
/// `hatch_sess` gate before any write.
#[async_trait]
pub trait Exporter: Send + Sync {
    /// Read the live session cookies from the browser.
    async fn export(&self) -> Result<Vec<ExportedCookie>, KeeperError>;
}

/// Build an exporter for a browser URL (the keeper
/// entry's `browser` value: an `http://` loopback debug
/// URL or a `ws://` WebSocket URL). With the `chromedp`
/// feature off, every call refuses with
/// [`KeeperError::ReexportUnavailable`] (Go stub).
pub fn new_cdp_exporter(browser_url: &str) -> Box<dyn Exporter> {
    Box::new(CdpExporter {
        browser_url: browser_url.to_string(),
    })
}

/// The CDP exporter.
pub struct CdpExporter {
    browser_url: String,
}

impl CdpExporter {
    /// The browser URL this exporter attaches to.
    pub fn browser_url(&self) -> &str {
        &self.browser_url
    }

    /// Resolve the WebSocket URL for the browser: a `ws://`
    /// / `wss://` value is used as-is; an `http://` value
    /// goes through `/json/version` discovery.
    async fn ws_url(&self) -> Result<String, KeeperError> {
        if self.browser_url.starts_with("ws://") || self.browser_url.starts_with("wss://") {
            return Ok(self.browser_url.clone());
        }
        discover_websocket_url(&self.browser_url)
            .await
            .map_err(KeeperError::from)
    }

    /// Resolve the export targets: every open Muse page
    /// target, or the first page target of any URL when no
    /// Muse page is open.
    async fn resolve_export_targets(&self) -> Result<Vec<String>, KeeperError> {
        let base = crate::screencast::http_base_from_browser_url(&self.browser_url)?;
        let targets = list_targets(&base).await.map_err(KeeperError::from)?;
        let mut muse_pages: Vec<String> = Vec::new();
        let mut first_page: Option<String> = None;
        for t in &targets {
            if t.target_type != "page" {
                continue;
            }
            if first_page.is_none() {
                first_page = Some(t.id.clone());
            }
            if let Some(host) = host_of_url(&t.url) {
                if EXPORT_HOSTS.contains(&host.as_str()) {
                    muse_pages.push(t.id.clone());
                }
            }
        }
        if !muse_pages.is_empty() {
            return Ok(muse_pages);
        }
        match first_page {
            Some(id) => Ok(vec![id]),
            None => Err(KeeperError::Other("no page target is open".to_string())),
        }
    }

    /// Level 1: target-level read. Any failure — no page
    /// target at all, an attach error, an empty read —
    /// falls through to the browser-level read below.
    async fn export_from_targets(
        &self,
        client: &CdpClient,
    ) -> Result<Vec<ExportedCookie>, KeeperError> {
        let ids = self.resolve_export_targets().await?;
        let mut seen: HashMap<String, bool> = HashMap::new();
        let mut merged: Vec<ExportedCookie> = Vec::new();
        let mut errs: Vec<String> = Vec::new();
        for id in ids {
            match self.export_from_target(client, &id).await {
                Ok(cookies) => {
                    for c in cookies {
                        let key = format!("{}\0{}\0{}", c.name, c.domain, c.path);
                        if seen.contains_key(&key) {
                            continue;
                        }
                        seen.insert(key, true);
                        merged.push(c);
                    }
                }
                Err(e) => errs.push(e.to_string()),
            }
        }
        if !merged.is_empty() {
            return Ok(merged);
        }
        if errs.is_empty() {
            return Err(KeeperError::Other(
                "cdp read returned no cookies".to_string(),
            ));
        }
        Err(KeeperError::Other(format!(
            "target cookie read failed: {}",
            errs.join("; ")
        )))
    }

    /// One target-level read: attach, bootstrap, then
    /// `Network.getCookies` with the explicit URL list,
    /// then detach.
    async fn export_from_target(
        &self,
        client: &CdpClient,
        target_id: &str,
    ) -> Result<Vec<ExportedCookie>, KeeperError> {
        let session = client.attach(target_id).await.map_err(KeeperError::from)?;
        let res = async {
            session.bootstrap().await.map_err(KeeperError::from)?;
            let out = session
                .call(
                    "Network.getCookies",
                    serde_json::json!({"urls": EXPORT_URLS}),
                )
                .await
                .map_err(KeeperError::from)?;
            parse_network_cookies(&out)
        }
        .await;
        let _ = session.detach().await;
        res
    }
}

#[async_trait]
impl Exporter for CdpExporter {
    async fn export(&self) -> Result<Vec<ExportedCookie>, KeeperError> {
        if !CDP_AVAILABLE {
            return Err(KeeperError::ReexportUnavailable);
        }
        let ws_url = self.ws_url().await?;
        let client = CdpClient::connect(&ws_url)
            .await
            .map_err(KeeperError::from)?;
        // Level 1: target-level read.
        match self.export_from_targets(&client).await {
            Ok(cookies) => return Ok(cookies),
            Err(target_err) => {
                // Level 2: browser-level Storage.getCookies.
                let mut storage_err = String::new();
                let mut storage_empty = false;
                match client
                    .call("Storage.getCookies", Value::Object(Default::default()))
                    .await
                {
                    Ok(out) => match parse_network_cookies(&out) {
                        Ok(cookies) if !cookies.is_empty() => return Ok(cookies),
                        Ok(_) => storage_empty = true,
                        Err(e) => storage_err = e.to_string(),
                    },
                    Err(e) => storage_err = e.to_string(),
                }
                if storage_empty {
                    storage_err = "cdp read returned no cookies".to_string();
                }
                // Level 3: browser-level Network.getCookies
                // with explicit URLs. Its result stands even
                // when empty, but ONLY when it succeeds.
                match client
                    .call(
                        "Network.getCookies",
                        serde_json::json!({"urls": EXPORT_URLS}),
                    )
                    .await
                {
                    Ok(out) => parse_network_cookies(&out),
                    Err(network_err) => Err(KeeperError::Other(format!(
                        "cdp cookie read failed: target: {target_err}; storage: {storage_err}; network: {network_err}"
                    ))),
                }
            }
        }
    }
}

/// Parse a `Network.getCookies` / `Storage.getCookies`
/// result (`{"cookies": [...]}`) into exported cookies.
pub fn parse_network_cookies(result: &Value) -> Result<Vec<ExportedCookie>, KeeperError> {
    let arr = result
        .get("cookies")
        .and_then(|c| c.as_array())
        .ok_or_else(|| KeeperError::Other("getCookies result has no cookies array".to_string()))?;
    let mut out = Vec::with_capacity(arr.len());
    for c in arr {
        let name = c
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let value = c
            .get("value")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let domain = c
            .get("domain")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let path = c
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let expires = c.get("expires").and_then(|v| v.as_f64()).unwrap_or(-1.0);
        let http_only = c.get("httpOnly").and_then(|v| v.as_bool()).unwrap_or(false);
        let secure = c.get("secure").and_then(|v| v.as_bool()).unwrap_or(false);
        let session = c.get("session").and_then(|v| v.as_bool()).unwrap_or(false);
        out.push(ExportedCookie {
            name,
            value,
            domain,
            path,
            expires,
            http_only,
            secure,
            session,
        });
    }
    Ok(out)
}

/// The host part of a URL, lowercased, or `None` when the
/// URL does not parse.
fn host_of_url(raw: &str) -> Option<String> {
    url::Url::parse(raw)
        .ok()?
        .host_str()
        .map(|h| h.to_lowercase())
}

/// The target list, for callers that need it (kept public
/// for the screencast resolver's shared shape).
pub type ExportTargetList = Vec<TargetInfo>;

/// A [`CdpError`] as a [`KeeperError`] (kept for callers
/// that map errors explicitly).
pub fn cdp_error_to_keeper(e: CdpError) -> KeeperError {
    KeeperError::from(e)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_network_cookies_shape() {
        let raw = r#"{"cookies":[{"name":"hatch_sess","value":"v","domain":".muse.ai","path":"/","expires":1800000000,"httpOnly":true,"secure":true,"session":false,"sameSite":"Lax"}]}"#;
        let v: Value = serde_json::from_str(raw).unwrap();
        let out = parse_network_cookies(&v).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "hatch_sess");
        assert_eq!(out[0].domain, ".muse.ai");
        assert!(!out[0].session);
        assert_eq!(out[0].expires, 1_800_000_000.0);
    }

    #[test]
    fn export_urls_are_muse_origins_only() {
        assert_eq!(EXPORT_URLS, ["https://muse.ai/", "https://auth.muse.ai/"]);
        assert_eq!(EXPORT_HOSTS, ["muse.ai", "auth.muse.ai", "www.muse.ai"]);
    }

    #[test]
    fn host_of_url_lowercases() {
        assert_eq!(
            host_of_url("https://WWW.Muse.AI/x"),
            Some("www.muse.ai".to_string())
        );
        assert_eq!(host_of_url("not a url"), None);
    }
}
