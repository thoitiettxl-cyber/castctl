// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

// M-perf-0 pure-logic timing harness (stdlib only).
// Modes: parse-min | parse-large | decode-large | md-to-html | split-text
//        | render-chain | socks5-get
// Each mode runs an adaptive loop (>= ~200ms total), prints one JSON line:
// {"mode":..,"iters":K,"total_ms":..,"ns_per_iter":..,"output_len":..}
// socks5-get reads PERF_SOCKS5_ADDR / PERF_HTTP_ADDR / PERF_SOCKS5_RUNS
// (default 20) and reports ms/request stats instead.
use std::hint::black_box;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Instant;

fn stats_ms(vals: &[f64]) -> (f64, f64, f64) {
    let mut v = vals.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let med = v[v.len() / 2];
    (med, v[0], v[v.len() - 1])
}

fn timed<F: FnMut() -> usize>(label: &str, mut f: F) {
    // Adaptive K: double until total >= 200ms (or K hits 1<<20).
    let mut k: u64 = 1;
    let mut total;
    let mut out_len = 0usize;
    loop {
        let start = Instant::now();
        for _ in 0..k {
            out_len = black_box(f());
        }
        total = start.elapsed();
        if total.as_millis() >= 200 || k >= (1 << 20) {
            break;
        }
        k *= 2;
    }
    let ns = total.as_nanos() as f64 / k as f64;
    let total_ms = total.as_secs_f64() * 1000.0;
    println!(
        "{{\"mode\":\"{label}\",\"iters\":{k},\"total_ms\":{total_ms:.3},\"ns_per_iter\":{ns:.1},\"output_len\":{out_len}}}"
    );
}

fn socks5_get() {
    // Both addresses are REQUIRED env vars: there is no safe default.
    // A stale default (127.0.0.1:18080) once pointed at another session's
    // server; a manual run without env must fail loudly, not probe a
    // foreign loopback service.
    let proxy = std::env::var("PERF_SOCKS5_ADDR").unwrap_or_else(|_| {
        eprintln!("PERF_SOCKS5_ADDR is required (e.g. 127.0.0.1:<ephemeral>)");
        std::process::exit(2);
    });
    let http_addr = std::env::var("PERF_HTTP_ADDR").unwrap_or_else(|_| {
        eprintln!("PERF_HTTP_ADDR is required (e.g. 127.0.0.1:<ephemeral>)");
        std::process::exit(2);
    });
    let runs: usize = std::env::var("PERF_SOCKS5_RUNS")
        .unwrap_or("20".into())
        .parse()
        .unwrap_or(20);
    let mut per_req: Vec<f64> = Vec::new();
    let mut ok = 0usize;
    for _ in 0..runs {
        let start = Instant::now();
        match one_request(&proxy, &http_addr) {
            Ok(n) => {
                ok += 1;
                black_box(n);
                per_req.push(start.elapsed().as_secs_f64() * 1000.0);
            }
            Err(e) => {
                eprintln!("socks5-get request failed: {e}");
                break;
            }
        }
    }
    if per_req.is_empty() {
        println!("{{\"mode\":\"socks5-get\",\"runs\":{runs},\"ok\":0,\"error\":\"all requests failed\"}}");
        std::process::exit(1);
    }
    let (med, min, max) = stats_ms(&per_req);
    println!(
        "{{\"mode\":\"socks5-get\",\"runs\":{runs},\"ok\":{ok},\"ms_per_request\":{{\"median\":{med:.3},\"min\":{min:.3},\"max\":{max:.3}}}}}"
    );
}

fn one_request(proxy: &str, http_addr: &str) -> std::io::Result<usize> {
    let mut s = TcpStream::connect(proxy)?;
    s.write_all(&[5, 1, 0])?; // greeting, no-auth
    let mut buf = [0u8; 2];
    s.read_exact(&mut buf)?;
    if buf != [5, 0] {
        return Err(std::io::Error::other("no-auth rejected"));
    }
    let mut req = vec![5, 1, 0, 1];
    let (host, port) = http_addr.rsplit_once(':').unwrap();
    let ip: std::net::Ipv4Addr = host.parse().map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "http addr must be IPv4")
    })?;
    req.extend_from_slice(&ip.octets());
    req.extend_from_slice(&port.parse::<u16>().unwrap().to_be_bytes());
    s.write_all(&req)?;
    let mut hdr = [0u8; 10];
    s.read_exact(&mut hdr)?;
    if hdr[1] != 0 {
        return Err(std::io::Error::other("CONNECT failed"));
    }
    s.write_all(b"GET /body-1024.bin HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")?;
    let mut body = Vec::new();
    s.read_to_end(&mut body)?;
    let text = String::from_utf8_lossy(&body);
    let n = text.split("\r\n\r\n").nth(1).map_or(0, |b| b.len());
    if n != 1024 {
        return Err(std::io::Error::other(format!("body len {n}, want 1024")));
    }
    Ok(n)
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "help".into());
    let cfg_min = include_str!("../../fixtures/config-min.json");
    let cfg_large = include_str!("../../fixtures/config-large.json");
    let msg = include_str!("../../fixtures/message-long.md");
    match mode.as_str() {
        "parse-min" => timed("parse-min", || {
            castctl_config::config::parse_single_config(cfg_min.as_bytes(), "/cfg")
                .unwrap()
                .profiles
                .len()
        }),
        "parse-large" => timed("parse-large", || {
            castctl_config::config::parse_single_config(cfg_large.as_bytes(), "/cfg")
                .unwrap()
                .profiles
                .len()
        }),
        "decode-large" => timed("decode-large", || {
            castctl_config::jsonvalue::decode_ordered_object(cfg_large.as_bytes())
                .unwrap()
                .keys()
                .len()
        }),
        "md-to-html" => timed("md-to-html", || castctl_tg_text::md_to_html(msg).len()),
        "split-text" => timed("split-text", || castctl_tg_text::split_text(msg).len()),
        "render-chain" => timed("render-chain", || {
            let html = castctl_tg_text::md_to_html(msg);
            castctl_tg_text::split_text(&html).len() + html.len()
        }),
        "socks5-get" => socks5_get(),
        _ => {
            eprintln!("usage: perf-bench <parse-min|parse-large|decode-large|md-to-html|split-text|render-chain|socks5-get>");
            std::process::exit(2);
        }
    }
}
