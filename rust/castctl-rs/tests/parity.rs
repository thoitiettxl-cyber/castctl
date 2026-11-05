//! Golden parity test (M2): runs the built `castctl-rs` binary
//! over the 54 argv cases in `rust/parity/cases.json` and compares
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

use castctl_config::jsonvalue::{JsonValue, decode_ordered_json};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(10);

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
        })
        .collect()
}

struct Golden {
    argv: Vec<String>,
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
        home: json_str(&env, "HOME"),
        xdg: json_str(&env, "XDG_CONFIG_HOME"),
        cwd: json_str(&value, "cwd"),
        stdout: json_str(&value, "stdout"),
        stderr: json_str(&value, "stderr"),
        exit_code: json_int(&value, "exit_code"),
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
    if let Some(idx) = line.find(" (") {
        if line[idx + 2..].ends_with(')') && !line[idx + 2..].contains('(') {
            lines = vec![&line[..idx]];
            let mut out = lines.join("\n");
            if text.ends_with('\n') {
                out.push('\n');
            }
            return out;
        }
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
/// /dev/null, cwd = fresh work dir, F1 fixture config installed.
/// Kills the child on timeout (10s) and reports it as a failure.
fn run_case(bin: &Path, argv: &[String], root: &Path) -> RunOutput {
    let home = root.join("home");
    let xdg = root.join("xdg");
    let work = root.join("work");
    let cfg_dir = xdg.join("castctl");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&cfg_dir).unwrap();
    std::fs::create_dir_all(&work).unwrap();
    let fixture = parity_dir().join("fixtures").join("config.json");
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
    assert_eq!(cases.len(), 54, "argv-list length (D-M2-4)");
    let golden_dir = parity_dir().join("golden");
    let golden_files: Vec<String> = std::fs::read_dir(&golden_dir)
        .unwrap_or_else(|_| panic!("golden dir missing: {}", golden_dir.display()))
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".json"))
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
        let root =
            std::env::temp_dir().join(format!("castctl-parity-{}-{}", std::process::id(), case.id));
        let _ = std::fs::remove_dir_all(&root);
        let run = run_case(&bin, &case.argv, &root);
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
