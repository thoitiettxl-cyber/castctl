// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Golden parity test (M2): runs the built `castctl-rs` binary
//! over the 59 argv cases in `rust/parity/cases.json` and compares
//! stdout/stderr/exit code byte-for-byte with the golden files in
//! `rust/parity/golden/` (generated on cue by
//! `rust/parity/gen_golden.sh` from the Go binary), after the
//! documented normalisations only.
//!
//! Normalisations (R3, as corrected by D-M2-7): N1 fixture-root
//! paths -> `<FIXTURE>`, N2 stamp suffix stripped from the
//! `--version` line on BOTH sides, N3 HOME -> `<HOME>`, N4
//! XDG_CONFIG_HOME -> `<XDG>`. No other normalisation.
//!
//! The test asserts the golden count equals the argv-list length,
//! so a case added to one side without the other fails loudly.
//! Harness integrity (F9): before loading goldens, the test
//! verifies `golden/manifest.json` (per-case sha256 over the
//! canonical stdout/stderr/exit-code form, written by the
//! generator in the same command), asserts every golden's
//! `generated_by` equals the exact golden-binary version string,
//! and asserts the Rust `--version` output is exactly
//! `castctl 0.9.0` after the N2 stamp strip.

use castctl_config::jsonvalue::{JsonValue, decode_ordered_json};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// The exact golden-binary version the harness is pinned to
/// (F9(a)/(c)): the generator asserts `GO_BIN --version` prints
/// this; the manifest and every golden record carry it; the Rust
/// `--version` output must be the bare `castctl 0.9.0`.
const EXPECTED_GO_VERSION: &str = "castctl 0.9.0 (1396697 2026-11-04T21:38:36Z)";
const EXPECTED_RUST_VERSION_LINE: &str = "castctl 0.9.0\n";

const TIMEOUT: Duration = Duration::from_secs(10);

/// Minimal SHA-256 (F9(b) manifest verification; the workspace
/// has no hashing dependency and adding one for a test-only
/// check is disproportionate). Pinned by the known-answer test
/// below.
fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[4 * i],
                chunk[4 * i + 1],
                chunk[4 * i + 2],
                chunk[4 * i + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = String::with_capacity(64);
    for word in h {
        out.push_str(&format!("{word:08x}"));
    }
    out
}

/// The canonical digest (F9(b)): sha256 over stdout bytes, a NUL
/// byte, stderr bytes, a NUL byte, and the exit code in decimal.
/// Must match `canonical_digest` in `gen_golden.py` exactly.
fn canonical_digest(stdout: &str, stderr: &str, exit_code: i64) -> String {
    let mut data = Vec::new();
    data.extend_from_slice(stdout.as_bytes());
    data.push(0);
    data.extend_from_slice(stderr.as_bytes());
    data.push(0);
    data.extend_from_slice(exit_code.to_string().as_bytes());
    sha256_hex(&data)
}

#[test]
fn sha256_known_answer() {
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn parity_dir() -> PathBuf {
    manifest_dir().join("..").join("parity")
}

/// The built binary under test (P-14: confirm the exact
/// `CARGO_BIN_EXE_*` variable name on cue; both spellings and a
/// target-dir fallback are tried).
fn binary_path() -> PathBuf {
    if let Some(p) = option_env!("CARGO_BIN_EXE_castctl-rs") {
        return PathBuf::from(p);
    }
    if let Some(p) = option_env!("CARGO_BIN_EXE_castctl_rs") {
        return PathBuf::from(p);
    }
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_castctl-rs") {
        return PathBuf::from(p);
    }
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_castctl_rs") {
        return PathBuf::from(p);
    }
    manifest_dir()
        .join("..")
        .join("target")
        .join("debug")
        .join("castctl-rs")
}

fn json_str(v: &JsonValue, key: &str) -> String {
    match v {
        JsonValue::Object(obj) => match obj.get(key) {
            Some(JsonValue::Str(s)) => s.clone(),
            Some(other) => panic!("field {key} is not a string: {other:?}"),
            None => panic!("missing field {key}"),
        },
        _ => panic!("expected object"),
    }
}

fn json_int(v: &JsonValue, key: &str) -> i64 {
    match v {
        JsonValue::Object(obj) => match obj.get(key) {
            Some(JsonValue::Number(n)) => n
                .parse::<i64>()
                .unwrap_or_else(|_| panic!("field {key} is not an integer literal: {n}")),
            Some(other) => panic!("field {key} is not a number: {other:?}"),
            None => panic!("missing field {key}"),
        },
        _ => panic!("expected object"),
    }
}

fn json_argv(v: &JsonValue) -> Vec<String> {
    match v {
        JsonValue::Object(obj) => match obj.get("argv") {
            Some(JsonValue::Array(items)) => items
                .iter()
                .map(|item| match item {
                    JsonValue::Str(s) => s.clone(),
                    other => panic!("argv element is not a string: {other:?}"),
                })
                .collect(),
            _ => panic!("missing argv array"),
        },
        _ => panic!("expected object"),
    }
}

struct Case {
    id: String,
    argv: Vec<String>,
    /// Fixture file name under `parity/fixtures/` (default
    /// `config.json`); installed as `config.json` for the run.
    fixture: String,
}

fn json_opt_str(v: &JsonValue, key: &str) -> Option<String> {
    match v {
        JsonValue::Object(obj) => match obj.get(key) {
            Some(JsonValue::Str(s)) => Some(s.clone()),
            _ => None,
        },
        _ => None,
    }
}

fn load_cases() -> Vec<Case> {
    let text = std::fs::read_to_string(parity_dir().join("cases.json"))
        .expect("parity/cases.json must exist");
    let value = decode_ordered_json(text.as_bytes()).expect("cases.json must parse");
    let JsonValue::Array(items) = value else {
        panic!("cases.json must be an array");
    };
    items
        .iter()
        .map(|item| Case {
            id: json_str(item, "id"),
            argv: json_argv(item),
            fixture: json_opt_str(item, "fixture").unwrap_or_else(|| "config.json".to_string()),
        })
        .collect()
}

struct Golden {
    argv: Vec<String>,
    generated_by: String,
    fixture: String,
    home: String,
    xdg: String,
    cwd: String,
    stdout: String,
    stderr: String,
    exit_code: i64,
}

fn load_golden(id: &str) -> Golden {
    let path = parity_dir().join("golden").join(format!("{id}.json"));
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("missing golden file: {}", path.display()));
    let value = decode_ordered_json(text.as_bytes())
        .unwrap_or_else(|e| panic!("golden {id} must parse: {}", e.message));
    assert_eq!(
        json_int(&value, "schema_version"),
        1,
        "golden {id}: schema_version"
    );
    assert_eq!(json_str(&value, "id"), id, "golden {id}: id field");
    let env = match &value {
        JsonValue::Object(obj) => obj.get("env").cloned().expect("golden env"),
        _ => panic!("expected object"),
    };
    Golden {
        argv: json_argv(&value),
        generated_by: json_str(&value, "generated_by"),
        fixture: json_opt_str(&value, "fixture").unwrap_or_else(|| "config.json".to_string()),
        home: json_str(&env, "HOME"),
        xdg: json_str(&env, "XDG_CONFIG_HOME"),
        cwd: json_str(&value, "cwd"),
        stdout: json_str(&value, "stdout"),
        stderr: json_str(&value, "stderr"),
        exit_code: json_int(&value, "exit_code"),
    }
}

/// Verify `golden/manifest.json` (F9(b)) BEFORE loading goldens:
/// schema, `generated_by`, exact case set, and the per-case
/// canonical digest recomputed from each golden record. Any
/// hand edit to a golden file (or the manifest) fails here.
fn verify_manifest(cases: &[Case]) {
    let path = parity_dir().join("golden").join("manifest.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("missing manifest: {}", path.display()));
    let value = decode_ordered_json(text.as_bytes())
        .unwrap_or_else(|e| panic!("manifest must parse: {}", e.message));
    assert_eq!(
        json_int(&value, "schema_version"),
        1,
        "manifest: schema_version"
    );
    assert_eq!(
        json_str(&value, "generated_by"),
        EXPECTED_GO_VERSION,
        "manifest: generated_by"
    );
    let entries = match &value {
        JsonValue::Object(obj) => match obj.get("cases") {
            Some(JsonValue::Object(entries)) => entries,
            _ => panic!("manifest: missing cases object"),
        },
        _ => panic!("expected object"),
    };
    assert_eq!(
        entries.keys().len(),
        cases.len(),
        "manifest: case count must equal argv-list length"
    );
    for case in cases {
        let want = match entries.get(&case.id) {
            Some(JsonValue::Str(s)) => s.clone(),
            _ => panic!("manifest: missing entry for case {}", case.id),
        };
        let golden = load_golden(&case.id);
        assert_eq!(
            golden.generated_by, EXPECTED_GO_VERSION,
            "golden {}: generated_by must be the pinned Go version",
            case.id
        );
        let got = canonical_digest(&golden.stdout, &golden.stderr, golden.exit_code);
        assert_eq!(
            got, want,
            "golden {}: manifest digest mismatch (file edited after generation?)",
            case.id
        );
    }
}

/// N2 (corrected, D-M2-7): strip an optional ` (<commit> <date>)`
/// stamp suffix from a single-line `--version` payload, on either
/// side. Only applies when the whole output is one line starting
/// with `castctl `.
fn strip_version_stamp(text: &str) -> String {
    let mut lines: Vec<&str> = text.split('\n').collect();
    // A trailing newline leaves an empty last element; the payload
    // is a single line when there is one non-empty line.
    let body: Vec<&&str> = lines.iter().filter(|l| !l.is_empty()).collect();
    if body.len() != 1 {
        return text.to_string();
    }
    let line = body[0];
    if !line.starts_with("castctl ") {
        return text.to_string();
    }
    if let Some(idx) = line.find(" (")
        && line[idx + 2..].ends_with(')')
        && !line[idx + 2..].contains('(')
    {
        lines = vec![&line[..idx]];
        let mut out = lines.join("\n");
        if text.ends_with('\n') {
            out.push('\n');
        }
        return out;
    }
    text.to_string()
}

/// N1/N3/N4: replace run-specific paths with markers.
fn normalise(text: &str, home: &str, xdg: &str, cwd: &str) -> String {
    let mut out = text.to_string();
    if !cwd.is_empty() {
        out = out.replace(cwd, "<FIXTURE>");
    }
    if !home.is_empty() {
        out = out.replace(home, "<HOME>");
    }
    if !xdg.is_empty() {
        out = out.replace(xdg, "<XDG>");
    }
    out
}

fn first_diff(a: &str, b: &str) -> Option<(usize, String, String)> {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    let mut i = 0;
    while i < ab.len() && i < bb.len() {
        if ab[i] != bb[i] {
            let start = i.saturating_sub(40);
            let end_a = (i + 80).min(ab.len());
            let end_b = (i + 80).min(bb.len());
            return Some((
                i,
                String::from_utf8_lossy(&ab[start..end_a]).into_owned(),
                String::from_utf8_lossy(&bb[start..end_b]).into_owned(),
            ));
        }
        i += 1;
    }
    if ab.len() != bb.len() {
        let start = i.saturating_sub(40);
        return Some((
            i,
            String::from_utf8_lossy(&ab[start..]).into_owned(),
            String::from_utf8_lossy(&bb[start..]).into_owned(),
        ));
    }
    None
}

struct RunOutput {
    stdout: String,
    stderr: String,
    code: i32,
}

/// Run one argv with an isolated HOME/XDG, minimal env, stdin
/// /dev/null, cwd = fresh work dir, the case's fixture config
/// installed. Kills the child on timeout (10s) and reports it as
/// a failure.
fn run_case(bin: &Path, argv: &[String], fixture: &str, root: &Path) -> RunOutput {
    let home = root.join("home");
    let xdg = root.join("xdg");
    let work = root.join("work");
    let cfg_dir = xdg.join("castctl");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&cfg_dir).unwrap();
    std::fs::create_dir_all(&work).unwrap();
    let fixture = parity_dir().join("fixtures").join(fixture);
    let fixture_bytes = std::fs::read(&fixture).unwrap();
    std::fs::copy(&fixture, cfg_dir.join("config.json")).unwrap();

    let mut child = Command::new(bin)
        .args(argv)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .current_dir(&work)
        .env_clear()
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .env("PATH", "/usr/bin:/bin")
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {}: {e}", bin.display()));

    let mut stdout_pipe = child.stdout.take().expect("stdout piped");
    let mut stderr_pipe = child.stderr.take().expect("stderr piped");
    let (tx_out, rx_out) = mpsc::channel::<Vec<u8>>();
    let (tx_err, rx_err) = mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut buf);
        let _ = tx_out.send(buf);
    });
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut buf);
        let _ = tx_err.send(buf);
    });

    let deadline = std::time::Instant::now() + TIMEOUT;
    let status = loop {
        match child.try_wait().expect("try_wait") {
            Some(status) => break Some(status),
            None => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    };
    let status =
        status.unwrap_or_else(|| panic!("TIMEOUT after 10s: argv={argv:?} (child killed)"));
    let stdout = rx_out.recv().unwrap_or_default();
    let stderr = rx_err.recv().unwrap_or_default();
    // P-11: no case may write. The fixture config must be
    // byte-identical and the work dir must stay empty.
    let config_after = std::fs::read(cfg_dir.join("config.json")).unwrap_or_default();
    assert_eq!(
        config_after, fixture_bytes,
        "case wrote to the fixture config: argv={argv:?}"
    );
    let work_entries: Vec<_> = std::fs::read_dir(&work)
        .map(|rd| rd.map(|e| e.unwrap().file_name()).collect())
        .unwrap_or_default();
    assert!(
        work_entries.is_empty(),
        "case wrote to the work dir: argv={argv:?} entries={work_entries:?}"
    );
    RunOutput {
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
        code: status.code().unwrap_or(-1),
    }
}

/// F9(c): run the Rust binary with `--version` in an isolated
/// env and assert the output is exactly `castctl 0.9.0` after
/// the N2 stamp strip. The raw line carries ` (commit date)`
/// in a git-checkout build: PR #84 renders `--version` with
/// the git build stamp like Go, and `build.rs` derives that
/// stamp from git, so a dev build IS stamped (documented
/// deviation in `rust/castctl-cli/build.rs`). The strip is
/// the D-M2-7 rule, the same `strip_version_stamp` helper
/// the golden-cases loop uses; an unstamped build still
/// prints the bare line and passes unchanged.
fn assert_rust_version(bin: &Path) {
    let root = std::env::temp_dir().join(format!("castctl-parity-version-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let work = root.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let out = Command::new(bin)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .current_dir(&work)
        .env_clear()
        .env("HOME", root.join("home"))
        .env("XDG_CONFIG_HOME", root.join("xdg"))
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .env("PATH", "/usr/bin:/bin")
        .output()
        .expect("run --version");
    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(out.status.code(), Some(0), "--version exit code");
    assert_eq!(
        strip_version_stamp(&String::from_utf8_lossy(&out.stdout)),
        EXPECTED_RUST_VERSION_LINE,
        "--version stdout (stamp stripped per D-M2-7)"
    );
    assert!(
        out.stderr.is_empty(),
        "--version stderr must be empty: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn golden_parity() {
    let bin = binary_path();
    eprintln!("parity binary: {}", bin.display());
    assert!(
        bin.is_file(),
        "castctl-rs binary not found at {} (CARGO_BIN_EXE_castctl-rs?)",
        bin.display()
    );
    let cases = load_cases();
    assert_eq!(
        cases.len(),
        62,
        "argv-list length (D-M2-4 + F5 case + 4 decoder cases + 3 N7 wait-conflict cases 09a/09b/09c)"
    );
    verify_manifest(&cases);
    // F9(c): the Rust --version output is exactly
    // `castctl 0.9.0` after the N2 stamp strip, and the
    // golden --version case agrees after the same strip.
    assert_rust_version(&bin);
    let golden_dir = parity_dir().join("golden");
    let golden_files: Vec<String> = std::fs::read_dir(&golden_dir)
        .unwrap_or_else(|_| panic!("golden dir missing: {}", golden_dir.display()))
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".json") && n != "manifest.json")
        .collect();
    // The golden count must equal the argv-list length.
    assert_eq!(
        golden_files.len(),
        cases.len(),
        "golden count == argv-list length ({} files, {} cases)",
        golden_files.len(),
        cases.len()
    );

    let mut mismatches: Vec<String> = Vec::new();
    for case in &cases {
        let golden = load_golden(&case.id);
        assert_eq!(
            golden.argv, case.argv,
            "golden {} argv must match cases.json",
            case.id
        );
        assert_eq!(
            golden.fixture, case.fixture,
            "golden {} fixture must match cases.json",
            case.id
        );
        let root =
            std::env::temp_dir().join(format!("castctl-parity-{}-{}", std::process::id(), case.id));
        let _ = std::fs::remove_dir_all(&root);
        let run = run_case(&bin, &case.argv, &case.fixture, &root);
        let run_home = root.join("home").to_string_lossy().into_owned();
        let run_xdg = root.join("xdg").to_string_lossy().into_owned();
        let run_work = root.join("work").to_string_lossy().into_owned();
        let _ = std::fs::remove_dir_all(&root);

        // Normalise BOTH sides: golden paths from the golden
        // record, run paths from this run; the stamp on both.
        let golden_stdout = strip_version_stamp(&normalise(
            &golden.stdout,
            &golden.home,
            &golden.xdg,
            &golden.cwd,
        ));
        let golden_stderr = normalise(&golden.stderr, &golden.home, &golden.xdg, &golden.cwd);
        let run_stdout =
            strip_version_stamp(&normalise(&run.stdout, &run_home, &run_xdg, &run_work));
        let run_stderr = normalise(&run.stderr, &run_home, &run_xdg, &run_work);

        // No leftover generation/run paths or stamps in the
        // normalised outputs.
        for (label, text) in [
            ("golden stdout", &golden_stdout),
            ("golden stderr", &golden_stderr),
            ("run stdout", &run_stdout),
            ("run stderr", &run_stderr),
        ] {
            assert!(
                !text.contains("castctl-golden-") && !text.contains("castctl-parity-"),
                "case {}: leftover temp path in {label}: {text:?}",
                case.id
            );
        }

        if run.code as i64 != golden.exit_code {
            mismatches.push(format!(
                "{}: exit code run={} golden={}",
                case.id, run.code, golden.exit_code
            ));
            continue;
        }
        if let Some((at, a, b)) = first_diff(&run_stdout, &golden_stdout) {
            mismatches.push(format!(
                "{}: stdout differs at byte {at}:\n  run:    {a:?}\n  golden: {b:?}",
                case.id
            ));
        }
        if let Some((at, a, b)) = first_diff(&run_stderr, &golden_stderr) {
            mismatches.push(format!(
                "{}: stderr differs at byte {at}:\n  run:    {a:?}\n  golden: {b:?}",
                case.id
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} mismatch(es):\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}
