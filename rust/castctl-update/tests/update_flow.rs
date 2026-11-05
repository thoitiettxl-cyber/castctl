// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! End-to-end update flow against a local fake release server.
//!
//! Go sources: `internal/update/fake_test.go` (harness) +
//! `update_test.go` / `edge_test.go` (flow tests). The fake
//! server is a plain `std::net::TcpListener` (no HTTP server
//! crate in the lock); the fake binary is a small Rust
//! helper compiled at test time with `rustc` (decision (a):
//! the Rust harness is self-contained — no `go build`
//! testdata — and the helper is a real ELF64 printing
//! `castctl <version>`).
//!
//! Every test uses its own server (own loopback port) and
//! its own tempdir target, so tests run in parallel.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use castctl_update::http::fetch_bytes;
use castctl_update::lock::acquire_update_lock;
use castctl_update::replace::{open_for_sync, run_exec_check};
use castctl_update::{Deps, Options, parse_version, run};

// ---------------------------------------------------------------- fake server

/// What the fake server serves, and what it observed.
#[derive(Default)]
struct ServerState {
    /// Release JSON fields for `/latest` and `/tags/*`.
    tag: String,
    draft: bool,
    prerelease: bool,
    /// Status for the `/latest` endpoint (200 or 403).
    latest_status: u16,
    /// Status for the `/tags/*` endpoint.
    tags_status: u16,
    /// Asset bytes served at `/download/<asset-name>`.
    asset_bytes: Vec<u8>,
    /// Status for the asset download (200 or 404).
    asset_status: u16,
    /// checksums.txt bytes served at `/download/checksums.txt`.
    checksums_bytes: Vec<u8>,
    /// Status for the checksums download (200 or 404).
    checksums_status: u16,
    /// Serve checksums with `Transfer-Encoding: chunked`.
    checksums_chunked: bool,
    /// If set, `/latest` answers 302 with this Location.
    redirect_location: Option<String>,
    /// If set, the web `/releases/latest` probe answers 302
    /// with this Location (the fallback path).
    fallback_location: Option<String>,
    /// Request counts by exact path.
    counts: HashMap<String, usize>,
    /// Requests that carried an `Authorization` header.
    auth_seen: usize,
}

struct FakeServer {
    addr: SocketAddr,
    state: Arc<Mutex<ServerState>>,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl FakeServer {
    fn start(state: ServerState) -> FakeServer {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(state));
        let stop = Arc::new(AtomicBool::new(false));
        listener.set_nonblocking(true).unwrap();
        let s2 = state.clone();
        let stop2 = stop.clone();
        let handle = std::thread::spawn(move || {
            while !stop2.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        handle_conn(stream, s2.clone());
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        FakeServer {
            addr,
            state,
            stop,
            handle: Some(handle),
        }
    }

    fn base(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn count(&self, path: &str) -> usize {
        *self.state.lock().unwrap().counts.get(path).unwrap_or(&0)
    }

    fn auth_seen(&self) -> usize {
        self.state.lock().unwrap().auth_seen
    }
}

impl Drop for FakeServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn handle_conn(mut stream: TcpStream, state: Arc<Mutex<ServerState>>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buf = [0u8; 8192];
    let mut req = Vec::new();
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                req.extend_from_slice(&buf[..n]);
                if req.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                if req.len() > 65536 {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let text = String::from_utf8_lossy(&req);
    let mut lines = text.lines();
    let first = lines.next().unwrap_or("");
    let path = first
        .split_whitespace()
        .nth(1)
        .unwrap_or("")
        .to_string();
    let has_auth = text
        .lines()
        .any(|l| l.to_ascii_lowercase().starts_with("authorization:"));
    // Chunked checksums need a different responder; handle
    // that path before the shared lock scope.
    let chunked = {
        let s = state.lock().unwrap();
        path.ends_with("/checksums.txt") && s.checksums_chunked
    };
    if chunked {
        let (status, body) = {
            let s = state.lock().unwrap();
            (s.checksums_status, s.checksums_bytes.clone())
        };
        respond_chunked(stream, status, &body);
        return;
    }
    let (status, body, extra_headers): (u16, Vec<u8>, String) = {
        let mut s = state.lock().unwrap();
        if has_auth {
            s.auth_seen += 1;
        }
        *s.counts.entry(path.clone()).or_insert(0) += 1;
        if path == "/repos/thoitiettxl-cyber/castctl/releases/latest" {
            if let Some(loc) = &s.redirect_location {
                (302, Vec::new(), format!("Location: {loc}\r\n"))
            } else if s.latest_status != 200 {
                (s.latest_status, Vec::new(), String::new())
            } else {
                (200, release_json(&s, &stream), String::new())
            }
        } else if path.starts_with("/repos/thoitiettxl-cyber/castctl/releases/tags/") {
            if s.tags_status != 200 {
                (s.tags_status, Vec::new(), String::new())
            } else {
                (200, release_json(&s, &stream), String::new())
            }
        } else if path == "/thoitiettxl-cyber/castctl/releases/latest" {
            if let Some(loc) = &s.fallback_location {
                (302, Vec::new(), format!("Location: {loc}\r\n"))
            } else {
                (404, Vec::new(), String::new())
            }
        } else if path.ends_with("/castctl_0.6.4_linux_amd64.tar.gz") {
            // `ends_with`: the fallback mode constructs
            // download URLs with the full repo path
            // (`/.../releases/download/<tag>/<asset>`, the
            // tag sits between `download/` and the name).
            (s.asset_status, s.asset_bytes.clone(), String::new())
        } else if path.ends_with("/checksums.txt") {
            (
                s.checksums_status,
                s.checksums_bytes.clone(),
                String::new(),
            )
        } else {
            (404, Vec::new(), String::new())
        }
    };
    let reason = match status {
        200 => "OK",
        302 => "Found",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "Error",
    };
    let _ = stream.write_all(
        format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\n{extra_headers}Connection: close\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    );
    let _ = stream.write_all(&body);
    let _ = stream.flush();
}

fn respond_chunked(mut stream: TcpStream, status: u16, body: &[u8]) {
    let reason = if status == 200 { "OK" } else { "Not Found" };
    let _ = stream.write_all(
        format!(
            "HTTP/1.1 {status} {reason}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    );
    let _ = stream.write_all(format!("{:x}\r\n", body.len()).as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.write_all(b"\r\n0\r\n\r\n");
    let _ = stream.flush();
}

/// Release JSON with asset URLs pointing at this server.
/// Sizes are the true served sizes: `downloadAsset`
/// refuses when `Content-Length` disagrees with the
/// release metadata.
fn release_json(s: &ServerState, stream: &TcpStream) -> Vec<u8> {
    let base = format!("http://{}", stream.local_addr().unwrap());
    let asset_size = s.asset_bytes.len();
    let sums_size = s.checksums_bytes.len();
    format!(
        r#"{{"tag_name":"{}","draft":{},"prerelease":{},"assets":[{{"name":"castctl_0.6.4_linux_amd64.tar.gz","browser_download_url":"{base}/download/castctl_0.6.4_linux_amd64.tar.gz","size":{asset_size},"state":"uploaded"}},{{"name":"checksums.txt","browser_download_url":"{base}/download/checksums.txt","size":{sums_size},"state":"uploaded"}}]}}"#,
        s.tag, s.draft, s.prerelease
    )
    .into_bytes()
}

// ---------------------------------------------------------------- helpers

/// Shared stdout capture: `run()` writes its report here.
#[derive(Clone)]
struct SharedVec(Arc<Mutex<Vec<u8>>>);

impl Write for SharedVec {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A fake binary: prints `castctl <version>` on `--version`.
/// `mode`: "ok" | "hang" | "flood" | "exit1".
fn fake_binary_source(version: &str, mode: &str) -> String {
    match mode {
        "hang" => {
            "fn main() { loop { std::thread::sleep(std::time::Duration::from_secs(3600)); } }"
                .to_string()
        }
        "flood" => format!(
            "fn main() {{ for _ in 0..200000 {{ print!(\"x\"); }} println!(); println!(\"castctl {version}\"); }}"
        ),
        "exit1" => "fn main() { std::process::exit(1); }".to_string(),
        _ => format!(
            "fn main() {{ let a: Vec<String> = std::env::args().collect(); if a.get(1).map(|s| s.as_str()) == Some(\"--version\") {{ println!(\"castctl {version}\"); }} }}"
        ),
    }
}

/// Compile the fake binary into `dir`, return its path.
fn build_fake_binary(dir: &Path, version: &str, mode: &str) -> PathBuf {
    let src_path = dir.join(format!("fake-{version}-{mode}.rs"));
    let out_path = dir.join(format!("fake-{version}-{mode}"));
    std::fs::write(&src_path, fake_binary_source(version, mode)).unwrap();
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let output = std::process::Command::new(&rustc)
        .arg("--crate-name")
        .arg("fake_binary")
        .arg("-O")
        .arg("-o")
        .arg(&out_path)
        .arg(&src_path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "rustc {rustc} failed for {version}/{mode}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&out_path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    out_path
}

/// Build a `.tar.gz` asset whose `castctl` member is the
/// given binary's bytes.
fn build_asset(binary_bytes: &[u8]) -> Vec<u8> {
    let mut tar_bytes = Vec::new();
    {
        let mut b = tar::Builder::new(&mut tar_bytes);
        let mut h = tar::Header::new_gnu();
        h.set_path("castctl").unwrap();
        h.set_size(binary_bytes.len() as u64);
        h.set_entry_type(tar::EntryType::Regular);
        h.set_mode(0o755);
        h.set_cksum();
        b.append(&h, binary_bytes).unwrap();
        b.finish().unwrap();
    }
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(&tar_bytes).unwrap();
    enc.finish().unwrap()
}

/// `checksums.txt` for one asset.
fn checksums_txt(asset_name: &str, digest: &[u8; 32]) -> Vec<u8> {
    format!("{}  {asset_name}\n", hex::encode(digest)).into_bytes()
}

fn sha256_of(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).into()
}

/// A tempdir target: `castctl` = the fake binary for
/// `version`, mode 0755. Returns (tempdir, target path).
fn make_target(dir: &Path, version: &str) -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir_in(dir).unwrap();
    // Build the fake binary in the WORK dir, not the target
    // dir: the target dir must contain only `castctl` (plus
    // the lock file after a run) for the litter assertions.
    let bin = build_fake_binary(dir, version, "ok");
    let target = tmp.path().join("castctl");
    std::fs::copy(&bin, &target).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    (tmp, target)
}

fn base_opts(target: &Path, server: &FakeServer) -> (Options, SharedVec) {
    let out = SharedVec(Arc::new(Mutex::new(Vec::new())));
    let opts = Options {
        deps: Deps {
            executable: Some(target.display().to_string()),
            cgo_settings: Some(vec![("CGO_ENABLED".to_string(), "1".to_string())]),
            api_base: server.base(),
            github_base: server.base(),
            ..Deps::default()
        },
        current_version: "0.6.3".to_string(),
        commit: "0807125".to_string(),
        build_date: "2026-10-30T17:31:50Z".to_string(),
        target_version: String::new(),
        dry_run: false,
        allow_downgrade: false,
        allow_prerelease: false,
        stdout: Some(Box::new(out.clone())),
    };
    (opts, out)
}

fn stdout_text(out: &SharedVec) -> String {
    let bytes = out.0.lock().unwrap().clone();
    String::from_utf8_lossy(&bytes).to_string()
}

fn dir_snapshot(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut v = Vec::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let e = e.unwrap();
        let name = e.file_name().to_string_lossy().to_string();
        let bytes = std::fs::read(e.path()).unwrap_or_default();
        v.push((name, bytes));
    }
    v.sort();
    v
}

/// A standard 0.6.4 release server: asset = fake 0.6.4
/// binary, checksums match. Returns (server, new bytes).
fn standard_server(work: &Path) -> (FakeServer, Vec<u8>) {
    let new_bin = build_fake_binary(work, "0.6.4", "ok");
    let new_bytes = std::fs::read(&new_bin).unwrap();
    let asset = build_asset(&new_bytes);
    let digest = sha256_of(&asset);
    let server = FakeServer::start(ServerState {
        tag: "v0.6.4".to_string(),
        asset_bytes: asset,
        checksums_bytes: checksums_txt("castctl_0.6.4_linux_amd64.tar.gz", &digest),
        latest_status: 200,
        tags_status: 200,
        asset_status: 200,
        checksums_status: 200,
        ..ServerState::default()
    });
    (server, new_bytes)
}

// ---------------------------------------------------------------- tests

#[test]
fn install_newer_version_end_to_end() {
    let work = tempfile::tempdir().unwrap();
    let (server, new_bytes) = standard_server(work.path());
    let (_tmp, target) = make_target(work.path(), "0.6.3");
    let dir = target.parent().unwrap().to_path_buf();
    let (opts, out) = base_opts(&target, &server);
    let (res, err) = run(opts);
    assert!(err.is_ok(), "install failed: {:?}", err.err());
    assert!(res.replaced);
    assert_eq!(res.target.to_string(), "0.6.4");
    assert_eq!(std::fs::read(&target).unwrap(), new_bytes);
    // Mode preserved (0755), no temp litter beyond the lock.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }
    let names: Vec<String> = dir_snapshot(&dir)
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    assert_eq!(names, vec![".castctl-update.lock", "castctl"]);
    assert!(stdout_text(&out).contains("castctl updated: 0.6.3 -> 0.6.4"));
    // No credentials ever sent.
    assert_eq!(server.auth_seen(), 0);
}

#[test]
fn checksum_mismatch_refuses_target_intact() {
    let work = tempfile::tempdir().unwrap();
    let (server, _new) = standard_server(work.path());
    // Corrupt the checksums entry after the server started.
    {
        let mut s = server.state.lock().unwrap();
        s.checksums_bytes =
            checksums_txt("castctl_0.6.4_linux_amd64.tar.gz", &[0u8; 32]);
    }
    let (_tmp, target) = make_target(work.path(), "0.6.3");
    let old_bytes = std::fs::read(&target).unwrap();
    let (opts, _out) = base_opts(&target, &server);
    let (res, err) = run(opts);
    let err = err.expect_err("mismatch must refuse");
    assert_eq!(err.code(), 1);
    assert_eq!(
        err.to_string(),
        "update: the downloaded asset does not match the checksums file"
    );
    assert!(!res.replaced);
    assert_eq!(std::fs::read(&target).unwrap(), old_bytes);
}

#[test]
fn dry_run_writes_nothing() {
    let work = tempfile::tempdir().unwrap();
    let (server, _new) = standard_server(work.path());
    let (_tmp, target) = make_target(work.path(), "0.6.3");
    let dir = target.parent().unwrap().to_path_buf();
    let before = dir_snapshot(&dir);
    let (mut opts, out) = base_opts(&target, &server);
    opts.dry_run = true;
    let (res, err) = run(opts);
    assert!(err.is_ok(), "dry-run failed: {:?}", err.err());
    assert!(!res.replaced);
    assert!(res.dry_run);
    assert_eq!(dir_snapshot(&dir), before, "dry-run must not write");
    let lines: Vec<String> = stdout_text(&out).lines().map(|l| l.to_string()).collect();
    assert_eq!(lines.len(), 5);
    assert!(lines[0].starts_with("dry-run: would update 0.6.3 -> 0.6.4"));
    assert!(lines[1].starts_with("dry-run: asset castctl_0.6.4_linux_amd64.tar.gz ("));
    assert_eq!(
        lines[2],
        "dry-run: checksums verified (sha256 against checksums.txt)"
    );
    assert!(lines[3].contains("(permissions 0755 preserved)"));
    assert_eq!(
        lines[4],
        "dry-run: exec check skipped in dry-run; it runs before replace in a real update"
    );
}

#[test]
fn dev_build_refuses_with_zero_requests() {
    let work = tempfile::tempdir().unwrap();
    let (server, _new) = standard_server(work.path());
    let (_tmp, target) = make_target(work.path(), "0.6.3");
    let (mut opts, _out) = base_opts(&target, &server);
    opts.commit = String::new();
    opts.build_date = String::new();
    let (_res, err) = run(opts);
    assert_eq!(err.expect_err("dev must refuse").code(), 2);
    assert_eq!(
        server.count("/repos/thoitiettxl-cyber/castctl/releases/latest"),
        0
    );
    assert_eq!(server.count("/download/checksums.txt"), 0);
}

#[test]
fn already_latest_noop_zero_downloads() {
    let work = tempfile::tempdir().unwrap();
    let (server, _new) = standard_server(work.path());
    {
        let mut s = server.state.lock().unwrap();
        s.tag = "v0.6.3".to_string();
    }
    let (_tmp, target) = make_target(work.path(), "0.6.3");
    let (opts, out) = base_opts(&target, &server);
    let (res, err) = run(opts);
    assert!(err.is_ok(), "no-op failed: {:?}", err.err());
    assert!(!res.replaced);
    assert_eq!(
        server.count("/download/castctl_0.6.4_linux_amd64.tar.gz"),
        0
    );
    assert_eq!(server.count("/download/checksums.txt"), 0);
    assert!(stdout_text(&out).contains("castctl is up to date: 0.6.3"));
}

#[test]
fn downgrade_and_prerelease_refuse() {
    // Downgrade: release 0.6.2 < current 0.6.3.
    let work = tempfile::tempdir().unwrap();
    let (server, _new) = standard_server(work.path());
    {
        let mut s = server.state.lock().unwrap();
        s.tag = "v0.6.2".to_string();
    }
    let (_tmp, target) = make_target(work.path(), "0.6.3");
    let (opts, _out) = base_opts(&target, &server);
    let (_res, err) = run(opts);
    let err = err.expect_err("downgrade must refuse");
    assert_eq!(err.code(), 2);
    assert!(err.to_string().contains("refusing downgrade"));
    // Prerelease: release 0.6.4-rc.1.
    let work = tempfile::tempdir().unwrap();
    let (server, _new) = standard_server(work.path());
    {
        let mut s = server.state.lock().unwrap();
        s.tag = "v0.6.4-rc.1".to_string();
        s.prerelease = true;
    }
    let (_tmp, target) = make_target(work.path(), "0.6.3");
    let (opts, _out) = base_opts(&target, &server);
    let (_res, err) = run(opts);
    assert_eq!(err.expect_err("prerelease must refuse").code(), 2);
}

#[test]
fn redirect_outside_allowlist_refuses_before_dial() {
    let work = tempfile::tempdir().unwrap();
    // Second server on a different hostname (localhost vs
    // 127.0.0.1): same machine, different host string, so
    // the redirect policy must refuse before dialing it.
    let other = FakeServer::start(ServerState::default());
    let other_port = other.addr.port();
    let (server, _new) = standard_server(work.path());
    {
        let mut s = server.state.lock().unwrap();
        s.redirect_location = Some(format!("http://localhost:{other_port}/x"));
    }
    let (_tmp, target) = make_target(work.path(), "0.6.3");
    let (opts, _out) = base_opts(&target, &server);
    let (_res, err) = run(opts);
    assert_eq!(err.expect_err("foreign redirect must refuse").code(), 1);
    assert_eq!(other.count("/x"), 0, "must refuse before dial");
    assert_eq!(server.auth_seen(), 0);
}

#[test]
fn redirect_userinfo_refuses() {
    let work = tempfile::tempdir().unwrap();
    let other = FakeServer::start(ServerState::default());
    let other_port = other.addr.port();
    let (server, _new) = standard_server(work.path());
    {
        let mut s = server.state.lock().unwrap();
        s.redirect_location =
            Some(format!("http://user:pass@localhost:{other_port}/x"));
    }
    let (_tmp, target) = make_target(work.path(), "0.6.3");
    let (opts, _out) = base_opts(&target, &server);
    let (_res, err) = run(opts);
    assert!(err.is_err(), "userinfo redirect must refuse");
    assert_eq!(other.count("/x"), 0, "must refuse before dial");
}

#[test]
fn rate_limit_fallback_installs() {
    let work = tempfile::tempdir().unwrap();
    let (server, new_bytes) = standard_server(work.path());
    {
        let mut s = server.state.lock().unwrap();
        s.latest_status = 403;
        // The fallback probe follows the public-web
        // redirect once; the Location host must be the
        // base host (here: the fake server itself).
        let base = server.base();
        s.fallback_location = Some(format!(
            "{base}/thoitiettxl-cyber/castctl/releases/tag/v0.6.4"
        ));
    }
    let (_tmp, target) = make_target(work.path(), "0.6.3");
    let (opts, _out) = base_opts(&target, &server);
    let (res, err) = run(opts);
    assert!(err.is_ok(), "fallback install failed: {:?}", err.err());
    assert!(res.replaced);
    assert_eq!(std::fs::read(&target).unwrap(), new_bytes);
}

#[test]
fn lock_held_fails_fast_zero_downloads() {
    let work = tempfile::tempdir().unwrap();
    let (server, _new) = standard_server(work.path());
    let (_tmp, target) = make_target(work.path(), "0.6.3");
    let dir = target.parent().unwrap();
    let _held = acquire_update_lock(dir).unwrap();
    let (opts, _out) = base_opts(&target, &server);
    let (_res, err) = run(opts);
    let err = err.expect_err("held lock must refuse");
    assert_eq!(err.code(), 1);
    assert!(err.to_string().contains("another update is already in progress"));
    assert_eq!(server.count("/download/checksums.txt"), 0);
}

#[test]
fn rename_failure_leaves_old_intact() {
    let work = tempfile::tempdir().unwrap();
    let (server, _new) = standard_server(work.path());
    let (_tmp, target) = make_target(work.path(), "0.6.3");
    let dir = target.parent().unwrap().to_path_buf();
    let old_bytes = std::fs::read(&target).unwrap();
    let (mut opts, _out) = base_opts(&target, &server);
    opts.deps.rename_fn = Some(|_, _| {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "injected rename failure",
        ))
    });
    let (res, err) = run(opts);
    let err = err.expect_err("rename failure must surface");
    assert_eq!(err.code(), 1);
    assert!(err.to_string().contains("cannot replace the running binary"));
    assert!(!res.replaced);
    assert_eq!(std::fs::read(&target).unwrap(), old_bytes);
    let names: Vec<String> = dir_snapshot(&dir)
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    assert_eq!(names, vec![".castctl-update.lock", "castctl"]);
}

#[test]
fn dir_sync_failure_reports_replaced() {
    let work = tempfile::tempdir().unwrap();
    let (server, new_bytes) = standard_server(work.path());
    let (_tmp, target) = make_target(work.path(), "0.6.3");
    let (mut opts, _out) = base_opts(&target, &server);
    opts.deps.sync_dir_fn = Some(|_| {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "injected dir-sync failure",
        ))
    });
    let (res, err) = run(opts);
    let err = err.expect_err("dir-sync failure must surface");
    assert_eq!(err.code(), 1);
    assert_eq!(
        err.to_string(),
        "update: directory sync failed after replace; the new binary is in place but its durability is not guaranteed"
    );
    assert!(res.replaced);
    assert_eq!(std::fs::read(&target).unwrap(), new_bytes);
}

#[test]
fn dir_sync_enotsup_succeeds_silently() {
    let work = tempfile::tempdir().unwrap();
    let (server, new_bytes) = standard_server(work.path());
    let (_tmp, target) = make_target(work.path(), "0.6.3");
    let (mut opts, _out) = base_opts(&target, &server);
    // ENOTSUP is errno 95 on Linux.
    opts.deps.sync_dir_fn =
        Some(|_| Err(std::io::Error::from_raw_os_error(95)));
    let (res, err) = run(opts);
    assert!(err.is_ok(), "ENOTSUP dir-sync must succeed: {:?}", err.err());
    assert!(res.replaced);
    assert_eq!(std::fs::read(&target).unwrap(), new_bytes);
}

#[test]
fn symlink_target_preserved() {
    let work = tempfile::tempdir().unwrap();
    let (server, new_bytes) = standard_server(work.path());
    let real_dir = tempfile::tempdir_in(work.path()).unwrap();
    let (_tmp, real_target) = make_target(real_dir.path(), "0.6.3");
    let link_dir = tempfile::tempdir_in(work.path()).unwrap();
    let link = link_dir.path().join("castctl");
    std::os::unix::fs::symlink(&real_target, &link).unwrap();
    let (opts, _out) = base_opts(&link, &server);
    let (res, err) = run(opts);
    assert!(err.is_ok(), "symlink install failed: {:?}", err.err());
    assert!(res.replaced);
    assert!(std::fs::symlink_metadata(&link)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(std::fs::read_link(&link).unwrap(), real_target);
    assert_eq!(std::fs::read(&real_target).unwrap(), new_bytes);
}

#[test]
fn hardlink_keeps_old_inode() {
    let work = tempfile::tempdir().unwrap();
    let (server, new_bytes) = standard_server(work.path());
    let (_tmp, target) = make_target(work.path(), "0.6.3");
    let old_bytes = std::fs::read(&target).unwrap();
    let sibling = target.parent().unwrap().join("castctl-old");
    std::fs::hard_link(&target, &sibling).unwrap();
    let (opts, _out) = base_opts(&target, &server);
    let (res, err) = run(opts);
    assert!(err.is_ok(), "install failed: {:?}", err.err());
    assert!(res.replaced);
    assert_eq!(std::fs::read(&target).unwrap(), new_bytes);
    // The other link still holds the old bytes.
    assert_eq!(std::fs::read(&sibling).unwrap(), old_bytes);
}

#[test]
fn exec_check_fake_versions() {
    let work = tempfile::tempdir().unwrap();
    let want = parse_version("0.6.4").unwrap();
    let good = build_fake_binary(work.path(), "0.6.4", "ok");
    assert!(run_exec_check(&good, &want, Duration::from_secs(10)).is_ok());
    let stale = build_fake_binary(work.path(), "0.6.3", "ok");
    assert!(run_exec_check(&stale, &want, Duration::from_secs(10)).is_err());
    let hang = build_fake_binary(work.path(), "0.6.4", "hang");
    let err = run_exec_check(&hang, &want, Duration::from_millis(200))
        .expect_err("hang must time out");
    // Exact Go message (`replace.go:349`).
    assert_eq!(
        err.to_string(),
        "update: the downloaded binary did not answer --version in time"
    );
    let flood = build_fake_binary(work.path(), "0.6.4", "flood");
    assert!(run_exec_check(&flood, &want, Duration::from_secs(10)).is_err());
    let exit1 = build_fake_binary(work.path(), "0.6.4", "exit1");
    assert!(run_exec_check(&exit1, &want, Duration::from_secs(10)).is_err());
}

#[test]
fn asset_and_checksums_404_refuse() {
    let work = tempfile::tempdir().unwrap();
    let (server, _new) = standard_server(work.path());
    {
        let mut s = server.state.lock().unwrap();
        s.asset_status = 404;
    }
    let (_tmp, target) = make_target(work.path(), "0.6.3");
    let (opts, _out) = base_opts(&target, &server);
    let (_res, err) = run(opts);
    assert_eq!(err.expect_err("asset 404 must refuse").code(), 1);
    let work = tempfile::tempdir().unwrap();
    let (server, _new) = standard_server(work.path());
    {
        let mut s = server.state.lock().unwrap();
        s.checksums_status = 404;
    }
    let (_tmp, target) = make_target(work.path(), "0.6.3");
    let (opts, _out) = base_opts(&target, &server);
    let (_res, err) = run(opts);
    let err = err.expect_err("checksums 404 must refuse");
    assert_eq!(err.code(), 1);
    assert_eq!(err.to_string(), "update: the release has no checksums file");
}

#[test]
fn fetch_bytes_chunked_body() {
    let work = tempfile::tempdir().unwrap();
    let (server, _new) = standard_server(work.path());
    {
        let mut s = server.state.lock().unwrap();
        s.checksums_chunked = true;
    }
    let mut fetcher = castctl_update::http::StdFetcher;
    let body = fetch_bytes(
        &mut fetcher,
        &format!("{}/download/checksums.txt", server.base()),
        "castctl/0.6.3",
        64 * 1024,
        Duration::from_secs(10),
    )
    .unwrap();
    let want = {
        let s = server.state.lock().unwrap();
        s.checksums_bytes.clone()
    };
    assert_eq!(body, want);
}

#[test]
fn open_for_sync_after_real_exec_200_rounds() {
    // Q7: the ETXTBSY window on this filesystem. 200
    // exec → open rounds must all succeed: the 200ms
    // retry budget covers the observed kernel window.
    let work = tempfile::tempdir().unwrap();
    let bin = build_fake_binary(work.path(), "0.6.4", "ok");
    let want = parse_version("0.6.4").unwrap();
    for _ in 0..200 {
        run_exec_check(&bin, &want, Duration::from_secs(10)).unwrap();
        let f = open_for_sync(&bin).unwrap();
        drop(f);
    }
}

#[test]
fn read_only_dir_refuses_skips_as_root() {
    // Mirrors Go's `TestReadOnlyDirRefuses` skip:
    // root can write through 0555, so the test is vacuous.
    if euid() == 0 {
        return;
    }
    let work = tempfile::tempdir().unwrap();
    let (server, _new) = standard_server(work.path());
    let (_tmp, target) = make_target(work.path(), "0.6.3");
    let dir = target.parent().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o555)).unwrap();
    }
    let (opts, _out) = base_opts(&target, &server);
    let (_res, err) = run(opts);
    assert!(err.is_err(), "read-only dir must refuse");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

/// Effective UID without a `libc` dev-dependency: parse
/// `/proc/self/status`.
fn euid() -> u32 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest
                .split_whitespace()
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
        }
    }
    0
}

#[test]
fn concurrent_runs_no_torn_state() {
    let work = tempfile::tempdir().unwrap();
    let (server, new_bytes) = standard_server(work.path());
    let (_tmp, target) = make_target(work.path(), "0.6.3");
    let base = server.base();
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let target_a = target.clone();
    let target_b = target.clone();
    let base_a = base.clone();
    let base_b = base.clone();
    let b1 = barrier.clone();
    let b2 = barrier.clone();
    let run_one = move |target: PathBuf, base: String, b: Arc<std::sync::Barrier>| {
        let opts = Options {
            deps: Deps {
                executable: Some(target.display().to_string()),
                cgo_settings: Some(vec![("CGO_ENABLED".to_string(), "1".to_string())]),
                api_base: base.clone(),
                github_base: base,
                ..Deps::default()
            },
            current_version: "0.6.3".to_string(),
            commit: "0807125".to_string(),
            build_date: "2026-10-30T17:31:50Z".to_string(),
            target_version: String::new(),
            dry_run: false,
            allow_downgrade: false,
            allow_prerelease: false,
            stdout: None,
        };
        b.wait();
        run(opts)
    };
    let h1 = std::thread::spawn(move || run_one(target_a, base_a, b1));
    let h2 = std::thread::spawn(move || run_one(target_b, base_b, b2));
    let (r1, e1) = h1.join().unwrap();
    let (r2, e2) = h2.join().unwrap();
    // The in-process mutex serialises the runs (like Go's
    // `updateMu`), so both may succeed — the second
    // re-installs over the first. The invariant is: no
    // error, no torn target, final bytes are the new binary.
    assert!(e1.is_ok(), "run 1 failed: {e1:?}");
    assert!(e2.is_ok(), "run 2 failed: {e2:?}");
    let replaced_count = [r1.replaced, r2.replaced].into_iter().filter(|b| *b).count();
    assert!(replaced_count >= 1, "at least one run must replace");
    let final_bytes = std::fs::read(&target).unwrap();
    assert_eq!(final_bytes, new_bytes, "torn target");
}

#[test]
fn explicit_version_installs() {
    let work = tempfile::tempdir().unwrap();
    let (server, new_bytes) = standard_server(work.path());
    let (_tmp, target) = make_target(work.path(), "0.6.3");
    let (mut opts, _out) = base_opts(&target, &server);
    opts.target_version = "0.6.4".to_string();
    let (res, err) = run(opts);
    assert!(err.is_ok(), "explicit install failed: {:?}", err.err());
    assert!(res.replaced);
    assert_eq!(std::fs::read(&target).unwrap(), new_bytes);
    // Explicit mode uses the /tags/ endpoint.
    assert_eq!(
        server.count("/repos/thoitiettxl-cyber/castctl/releases/tags/v0.6.4"),
        1
    );
}
