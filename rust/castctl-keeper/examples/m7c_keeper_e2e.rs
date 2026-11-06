// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! M7c item 5 driver: run the Rust keeper for one entry
//! (`no.0`) for a bounded wall-clock window against a
//! SCRATCH copy of the live config + cookies — never the
//! live `/root/.config/castctl` tree.
//!
//! `castctl-rs keeper run` is still a stub at dev-rust
//! `e7a97d7` (`castctl-cli/src/run.rs:1057`), so this
//! driver hand-builds `TickDeps` (the M6a pattern from
//! `tests/tick_table.rs`) and calls `run_entry` directly.
//! Library-level evidence, labelled as such in the M7c
//! report, never claimed as CLI parity.
//!
//! Env:
//! - `M7C_KEEPER_BASE` (required): scratch dir holding
//!   `config.json` (copy, keeper entry added test-only)
//!   + `profiles/no.0/cookies.txt` (copy). The driver
//!     never opens the live config dir for writing.
//! - `M7C_KEEPER_SECONDS` (default 60): wall-clock run.
//! - `M7C_KEEPER_INTERVAL_SECS` (default 30): TEST-ONLY
//!   tick interval (production default is 24h).
//! - `M7C_KEEPER_BROWSER` (default
//!   `http://127.0.0.1:9301`): own Chrome CDP URL — never
//!   the shared 9226.
//!
//! The checker dials direct (`DirectDialer`). For profile `no.0`
//! this IS the profile-outbound path, not a bypass: the live
//! config gives `no.0` no outbound, and Go synthesises a direct
//! outbound for such profiles ("The synthesised direct tag
//! (direct profiles' default, ...)", `internal/commands/runtime.go:264`).
//! A profile WITH a non-direct outbound would need its honk /
//! WireGuard dialer here instead — record that limit, do not
//! generalise this driver beyond `no.0`. No notifier, no
//! credentials, no relogin: on auth failure the tick must STOP
//! and alert, never attempt a login.
//!
//! Exit 0 iff `ticks >= 2` and no panic; the caller
//! scores outcome/stage/cookies_seen/wrote_cookies and
//! the sha256 before/after separately (see the M7c
//! evidence report).

use std::sync::Arc;
use std::time::Duration;

use castctl_keeper::{
    CancelFlag, GatewayChecker, RealClock, TickDeps, acquire_single_flight, new_cdp_exporter,
    run_entry,
};
use castctl_transport::{Dialer, DirectDialer, HttpClient};

#[tokio::main]
async fn main() {
    let base = std::env::var("M7C_KEEPER_BASE").expect("M7C_KEEPER_BASE is required");
    let seconds: u64 = std::env::var("M7C_KEEPER_SECONDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60);
    let interval_secs: u64 = std::env::var("M7C_KEEPER_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30);
    let browser =
        std::env::var("M7C_KEEPER_BROWSER").unwrap_or_else(|_| "http://127.0.0.1:9301".to_string());
    println!(
        "M7C-KEEPER base={base} seconds={seconds} interval={interval_secs}s browser={browser} dialer=direct notifier=none credentials=none"
    );
    let clock = Arc::new(RealClock) as Arc<dyn castctl_keeper::Clock>;
    let profile_dir = format!("{base}/profiles/no.0");
    // Single-flight FIRST (mirrors Go cmdKeeperRun):
    // hold the owner file, then prove a second acquire
    // refuses naming the live PID.
    let flight = acquire_single_flight(&profile_dir, "no.0", Arc::clone(&clock))
        .await
        .expect("first acquire_single_flight");
    match acquire_single_flight(&profile_dir, "no.0", Arc::clone(&clock)).await {
        Ok(_) => {
            eprintln!("M7C-KEEPER FAIL: second acquire unexpectedly succeeded");
            std::process::exit(1);
        }
        Err(e) => println!("M7C-KEEPER second-acquire refused as expected: {e}"),
    }
    let client = Arc::new(HttpClient::new(
        Arc::new(DirectDialer::new()) as Arc<dyn Dialer>
    ));
    let checker = Arc::new(GatewayChecker::new(client, Arc::clone(&clock)));
    let exporter: Option<Arc<dyn castctl_keeper::Exporter>> =
        Some(Arc::from(new_cdp_exporter(&browser)));
    let deps = TickDeps {
        clock: Arc::clone(&clock),
        tag: "no.0".to_string(),
        interval: Duration::from_secs(interval_secs),
        retry_backoff: vec![
            Duration::from_secs(5 * 60),
            Duration::from_secs(15 * 60),
            Duration::from_secs(45 * 60),
        ],
        wake_on_gateway_failure: false,
        wake_attempts: 0,
        credentials_configured: false,
        base_dir: base.clone(),
        profile_name: "no.0".to_string(),
        checker,
        exporter,
        notifier: None,
        gateway_probe: None,
        wake: None,
        relogin: None,
        credential_provider: None,
        jitter: Some(Arc::new(|| 0.5)),
        lock_timeout: Duration::from_secs(5),
        before_state_save: None,
    };
    let on_tick: Arc<dyn Fn(&castctl_keeper::TickResult) + Send + Sync> = Arc::new(
        |r: &castctl_keeper::TickResult| {
            println!(
                "keeper: no.0 (no.0): {} cookies_seen={} wrote={} next_delay={:?} stage={} stopped={} recovered={} exported={} dropped={} cdp_dropped={} state_corrupt={}",
                r.outcome,
                r.cookies_seen,
                r.wrote_cookies,
                r.next_delay,
                r.stage,
                r.stopped,
                r.recovered,
                r.exported,
                r.dropped,
                r.cdp_dropped,
                r.state_corrupt,
            );
            if let Some(e) = &r.error {
                println!("keeper: tick error: {e}");
            }
        },
    );
    let cancel = CancelFlag::new();
    let cancel2 = cancel.clone();
    let run = tokio::spawn(async move { run_entry(deps, cancel2, Some(on_tick)).await });
    tokio::time::sleep(Duration::from_secs(seconds)).await;
    cancel.cancel();
    let result = run.await.expect("run_entry task panicked");
    println!(
        "M7C-KEEPER result ticks={} stopped={} last={:?}",
        result.ticks, result.stopped, result.last
    );
    flight.release();
    if result.ticks >= 2 {
        println!("M7C-KEEPER OK ticks>=2");
    } else {
        eprintln!("M7C-KEEPER FAIL ticks={} < 2", result.ticks);
        std::process::exit(1);
    }
}
