// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Rust side of the M7b Phase A parity gate
//! (`rust/parity/run_m7b_cases.sh`): run the Rust Phase A
//! command implementations (the PRODUCTION code under test,
//! via `castctl_cli::network::run_driver_command`) against a
//! scripted gateway_server (`serve-m7b` mode) and a fake
//! muse.ai HTTP server (`rust/parity/m7b_http_server.py`),
//! printing the CLI result shape + exit code, so the gate
//! can diff it byte-for-byte against the Go m7b_driver run
//! with the same script and argv.
//!
//! The connection mirrors the real CLI: a `SharedConn` over
//! a fake connector that dials the scripted server with the
//! canned fake token (HT-FAKE, as the Go driver does), and
//! `DirectDialer` pointed at the fake HTTP server via the
//! driver's `http_base` override (production never sees a
//! gateway host flag/env/config — D-M7b-2).
//!
//! Usage:
//!   cargo run -p castctl-cli --example m7b_driver -- \
//!     --addr 127.0.0.1:GWPORT --http-addr 127.0.0.1:HTTPPORT \
//!     [--download-dir DIR] <command> [args...]
//!
//! `--download-dir` is a driver-only default for the CLI's
//! `-o/--output` when the case argv does not set it (the Go
//! driver takes the same flag). All credentials here are fake.

use std::future::Future;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::pin::Pin;
use std::sync::Arc;

use castctl_cli::fs::run_driver_fs;
use castctl_cli::help_texts::FS_HELP_TEXT;
use castctl_cli::network::run_driver_command;
use castctl_cli::parser::ArgParser;
use castctl_cli::runtime::Runtime;
use castctl_cli::table::{command_spec, fs_defs};
use castctl_config::gostr::go_quote;
use castctl_config::profile::Profile;
use castctl_gateway::dial::dial_gateway;
use castctl_gateway::shared::{Connector, SharedConn};
use castctl_transport::{DirectDialer, HttpClient, RouteTable, TransportError};

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
    http_addr: String,
    download_dir: String,
    rest: Vec<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        addr: String::new(),
        http_addr: String::new(),
        download_dir: String::new(),
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
            "--http-addr" => {
                args.http_addr = it.next().ok_or("--http-addr needs a value")?;
            }
            "--download-dir" => {
                args.download_dir = it.next().ok_or("--download-dir needs a value")?;
            }
            "--" => seen_dashdash = true,
            other => args.rest.push(other.to_string()),
        }
    }
    if args.addr.is_empty() {
        return Err("--addr is required".to_string());
    }
    if args.http_addr.is_empty() {
        return Err("--http-addr is required".to_string());
    }
    if args.rest.is_empty() {
        return Err("a command is required".to_string());
    }
    Ok(args)
}

#[tokio::main]
async fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("m7b_driver: {e}");
            std::process::exit(2);
        }
    };
    let cmd = args.rest[0].clone();
    let cmd_args: Vec<String> = args.rest[1..].to_vec();

    let spec = match command_spec(&cmd) {
        Some(s) => s,
        None => {
            eprintln!("m7b_driver: unknown command {cmd}");
            std::process::exit(2);
        }
    };

    let routes = match RouteTable::default_routes() {
        Ok(r) => Arc::new(r),
        Err(e) => {
            eprintln!("m7b_driver: routes: {e}");
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
        eprintln!("m7b_driver: connect: {e}");
        std::process::exit(1);
    }

    // Fake cookies file, mode 0600 set explicitly (the
    // content is the same fake cookie the Go driver writes).
    let cookies_path = std::env::temp_dir().join(format!(
        "m7b-driver-cookies-{}-{}.txt",
        std::process::id(),
        cmd.replace('/', "_")
    ));
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
        eprintln!("m7b_driver: cookies: {e}");
        std::process::exit(1);
    }
    let profile = Profile {
        name: "no1".to_string(),
        cookies_file: cookies_path.to_string_lossy().to_string(),
        ..Default::default()
    };

    let http = HttpClient::new(Arc::new(DirectDialer::new()));
    let mut rt = Runtime::new(profile, http, Arc::clone(&shared));
    rt.http_base = format!("http://{}", args.http_addr);

    let parser = ArgParser {
        defs: spec.defs.clone(),
        help_text: spec.help_text,
    };
    let mut help_out = String::new();
    // `fs` has its own per-subcommand parser (`cmd_fs` in
    // `run.rs`): the subcommand name selects the flag defs,
    // and `fs write` reads stdin before connecting.
    if cmd == "fs" {
        if cmd_args.is_empty() {
            eprint!("castctl: the following arguments are required: subcommand\n{FS_HELP_TEXT}");
            let _ = std::fs::remove_file(&cookies_path);
            std::process::exit(2);
        }
        if cmd_args[0] == "--help" || cmd_args[0] == "-h" {
            print!("{FS_HELP_TEXT}");
            let _ = std::fs::remove_file(&cookies_path);
            std::process::exit(0);
        }
        let sub = cmd_args[0].clone();
        if !castctl_cli::table::FS_SUBCOMMANDS.contains(&sub.as_str()) {
            eprintln!(
                "castctl: argument subcommand: invalid choice: {} (choose from {})",
                go_quote(&sub),
                castctl_cli::table::FS_SUBCOMMANDS.join(", ")
            );
            let _ = std::fs::remove_file(&cookies_path);
            std::process::exit(2);
        }
        let (defs, help_text) = fs_defs(&sub);
        let sub_parser = ArgParser { defs, help_text };
        let mut sub_help_out = String::new();
        let sub_parsed = match sub_parser.parse(&cmd_args[1..], &mut sub_help_out) {
            Ok(outcome) => {
                if outcome.help_shown {
                    print!("{sub_help_out}");
                    let _ = std::fs::remove_file(&cookies_path);
                    std::process::exit(0);
                }
                outcome.parsed
            }
            Err(e) => {
                eprintln!("m7b_driver: parse: {}", e.0);
                std::process::exit(2);
            }
        };
        let stdin_data = if sub == "write" {
            let mut data = Vec::new();
            use std::io::Read;
            if let Err(e) = std::io::stdin().read_to_end(&mut data) {
                eprintln!("m7b_driver: stdin: {e}");
                std::process::exit(1);
            }
            Some(data)
        } else {
            None
        };
        // Driver-only `fs get` default: the harness passes a
        // fresh --download-dir per side; the CLI's -o/--output
        // wins when the case argv sets it (same rule as the Go
        // driver, and as `download` above).
        let mut sub_parsed = sub_parsed;
        if sub == "get" && !args.download_dir.is_empty() && !sub_parsed.str_is_set("output") {
            sub_parsed
                .strs
                .push(("output".to_string(), args.download_dir.clone()));
            sub_parsed.str_set.push("output".to_string());
        }
        let (stdout, stderr, code) = run_driver_fs(&rt, &sub, &sub_parsed, stdin_data).await;
        let _ = std::io::stdout().write_all(&stdout);
        eprint!("{stderr}");
        let _ = std::fs::remove_file(&cookies_path);
        std::process::exit(code);
    }
    let mut parsed = match parser.parse(&cmd_args, &mut help_out) {
        Ok(outcome) => {
            if outcome.help_shown {
                print!("{help_out}");
                std::process::exit(0);
            }
            outcome.parsed
        }
        Err(e) => {
            eprintln!("m7b_driver: parse: {}", e.0);
            std::process::exit(2);
        }
    };
    // Driver-only download default: the harness passes a
    // fresh --download-dir per side; the CLI's -o/--output
    // wins when the case argv sets it (same rule as the Go
    // driver).
    if cmd == "download" && !args.download_dir.is_empty() && !parsed.str_is_set("output") {
        parsed
            .strs
            .push(("output".to_string(), args.download_dir.clone()));
        parsed.str_set.push("output".to_string());
    }

    let (stdout, stderr, code) = run_driver_command(&spec, &rt, &parsed).await;
    let _ = std::io::stdout().write_all(&stdout);
    eprint!("{stderr}");
    let _ = std::fs::remove_file(&cookies_path);
    std::process::exit(code);
}
