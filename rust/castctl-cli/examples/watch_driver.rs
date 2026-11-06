// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Rust side of the M7b PR-2 watch Tier A parity gate:
//! run the Rust `watch` implementation (the PRODUCTION
//! code under test, via `castctl_cli::watch::run_driver_watch`)
//! against a scripted gateway_server (`serve-wait` mode),
//! printing the CLI row shape + exit code, so the gate
//! can diff it byte-for-byte against the Go watch_driver
//! run with the same script and argv.
//!
//! The connection mirrors the real CLI: a `SharedConn` over
//! a fake connector that dials the scripted server with the
//! canned fake token (HT-FAKE, as the Go driver does).
//!
//! Rows are already exact bytes (one compact JSON row per
//! record line); the example prints the production stdout
//! as-is, with no JSON round-trip.
//!
//! Usage:
//!   cargo run -p castctl-cli --example watch_driver -- \
//!     --addr 127.0.0.1:PORT [--timeout SECONDS] [--n N]
//!     [--all] [--thread ID]
//!
//! All credentials here are fake.

use std::future::Future;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::pin::Pin;
use std::sync::Arc;

use castctl_cli::parser::ArgParser;
use castctl_cli::runtime::Runtime;
use castctl_cli::table::command_spec;
use castctl_cli::watch::run_driver_watch;
use castctl_config::profile::Profile;
use castctl_gateway::dial::dial_gateway;
use castctl_gateway::shared::{Connector, SharedConn};
use castctl_transport::{Dialer, DirectDialer, HttpClient, RouteTable, TransportError};

/// Fake connector: dial the scripted server once per
/// `connect()` with the canned fake token, exactly as the
/// M4a `parity_client` example does and as the Go driver
/// does with its canned auth (`gatewaytest.CannedAuth`:
/// VMID "vm-test", AccessToken "AT-FAKE", HatchToken
/// "HT-FAKE"). No real credentials are ever involved.
struct FakeConnector {
    url: String,
    routes: Arc<RouteTable>,
}

impl Connector for FakeConnector {
    fn connect(
        &self,
    ) -> Pin<
        Box<dyn Future<Output = Result<Arc<castctl_gateway::Gateway>, TransportError>> + Send + '_>,
    > {
        let url = self.url.clone();
        let routes = Arc::clone(&self.routes);
        Box::pin(async move { dial_gateway(&url, routes).await })
    }
}

struct Args {
    addr: String,
    rest: Vec<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        addr: String::new(),
        rest: Vec::new(),
    };
    let mut it = std::env::args().skip(1).peekable();
    let mut seen_dashdash = false;
    while let Some(a) = it.next() {
        if seen_dashdash {
            args.rest.push(a);
            continue;
        }
        match a.as_str() {
            "--addr" => {
                args.addr = it.next().ok_or("--addr needs a value")?;
            }
            "--" => seen_dashdash = true,
            other => args.rest.push(other.to_string()),
        }
    }
    if args.addr.is_empty() {
        return Err("--addr is required".to_string());
    }
    Ok(args)
}

#[tokio::main]
async fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("watch_driver: {e}");
            std::process::exit(2);
        }
    };

    let spec = match command_spec("watch") {
        Some(s) => s,
        None => {
            eprintln!("watch_driver: no watch spec");
            std::process::exit(1);
        }
    };

    let routes = match RouteTable::default_routes() {
        Ok(r) => Arc::new(r),
        Err(e) => {
            eprintln!("watch_driver: routes: {e}");
            std::process::exit(1);
        }
    };
    // The canned hatch token (HT-FAKE) from CannedAuth,
    // interpolated as a format argument (it needs no
    // URL-quoting) — the same fixture token the Go driver
    // sends (see D6). The URL is never logged.
    let url = format!(
        "ws://{}/v1/noise?vm_id=vm-test&auth_token={}",
        args.addr, "HT-FAKE"
    );
    let shared = Arc::new(SharedConn::new(Arc::new(FakeConnector { url, routes })));
    if let Err(e) = shared.live().await {
        eprintln!("watch_driver: connect: {e}");
        std::process::exit(1);
    }

    // Fake cookies file, mode 0600 set explicitly (the
    // content is the same fake cookie the Go driver writes).
    let cookies_path =
        std::env::temp_dir().join(format!("watch-driver-cookies-{}.txt", std::process::id()));
    if let Err(e) = (|| -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&cookies_path)?;
        f.write_all(b"hatch_sess=FAKE; datr=FAKE")?;
        Ok(())
    })() {
        eprintln!("watch_driver: cookies: {e}");
        std::process::exit(1);
    }
    let profile = Profile {
        name: "no1".to_string(),
        node_id: "watch-driver".to_string(),
        cookies_file: cookies_path.to_string_lossy().to_string(),
        ..Default::default()
    };

    let dialer: Arc<dyn Dialer> = Arc::new(DirectDialer::new());
    let http = HttpClient::new(Arc::clone(&dialer));
    let rt = Runtime::new(profile, dialer, http, Arc::clone(&shared));

    let parser = ArgParser {
        defs: spec.defs.clone(),
        help_text: spec.help_text,
    };
    let mut help_out = String::new();
    let parsed = match parser.parse(&args.rest, &mut help_out) {
        Ok(outcome) => {
            if outcome.help_shown {
                print!("{help_out}");
                let _ = std::fs::remove_file(&cookies_path);
                std::process::exit(0);
            }
            outcome.parsed
        }
        Err(e) => {
            eprintln!("watch_driver: parse: {}", e.0);
            let _ = std::fs::remove_file(&cookies_path);
            std::process::exit(2);
        }
    };

    let (stdout, stderr, code) = run_driver_watch(&rt, &parsed).await;
    // Rows are already exact bytes (one JSON row per line);
    // print them as-is — no JSON round-trip.
    let _ = std::io::stdout().write_all(&stdout);
    eprint!("{stderr}");
    let _ = std::fs::remove_file(&cookies_path);
    std::process::exit(code);
}
