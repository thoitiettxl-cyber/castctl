// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Port of Go `internal/logging` tests:
//! `factory_test.go` (16 fns), `level_test.go` (5 fns),
//! `allowlist_test.go` `TestSafeErrForLevelTraceIsSummary`
//! (the other allowlist fn, `TestSafeStringListedVocabulary`,
//! is already ported in `castctl-log-redact` as
//! `test_safe_string_listed_vocabulary`), plus
//! `internal/profile/log_test.go` `TestResolveLogSettings`
//! (the resolution half of
//! `TestLogBlockEmptyObjectPresent` is folded into it).
//!
//! Adaptations (recorded in PORTING.md §M7a):
//! - `TestFactoryOutputStdout` asserts construction +
//!   emission without panic, not the captured bytes: Rust
//!   cannot swap the process stdout hermetically.
//! - `TestSummarizeErr`'s `ConnectionError`-wraps-`GatewayError`
//!   case is a wrapper error whose `source()` is the
//!   `Gateway` `TransportError` (Rust's `ConnectionError`
//!   variant carries no inner error).
//! - The Go tests use `t.Parallel()`; Rust runs test fns in
//!   parallel by default. Temp dirs are per-test unique.
//! - Fixture values are the Go literals (`LOGFIX-*`).

use std::error::Error;
use std::fmt;
use std::io::Write;
use std::sync::{Arc, Mutex};

use castctl_config::log::LogConfig;
use castctl_logging::{
    emit, new_factory, resolve_log_settings, safe_err_for_level, summarize_err, Level, Settings,
    SlogLevel, SlogValue,
};
use castctl_transport::{BodySummary, TransportError};

const FIX_VMID: &str = "LOGFIX-VMID-22d9f0";
const FIX_HATCH_TOKEN: &str = "LOGFIX-HT-2c6e88";
const FIX_COOKIE_VAL: &str = "LOGFIX-SESS-9d2e41";
const FIX_WG_PRIV: &str = "LOGFIX-WGPRIV-6e19d0";
const FIX_WG_PUB: &str = "LOGFIX-WGPUB-4b77c2";

/// A shared in-memory writer: the Rust equivalent of Go's
/// `bytes.Buffer` passed as the factory's stderr writer.
#[derive(Clone, Default)]
struct SharedBuf(Arc<Mutex<Vec<u8>>>);

impl SharedBuf {
    fn take(&self) -> String {
        let b = self.0.lock().unwrap().clone();
        String::from_utf8_lossy(&b).into_owned()
    }

    fn reset(&self) {
        self.0.lock().unwrap().clear();
    }

    fn len(&self) -> usize {
        self.0.lock().unwrap().len()
    }
}

impl Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn strip_ansi(s: &str) -> String {
    // Go's test regex: \x1b\[[0-9;]*m
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' && chars.peek() == Some(&'[') {
            chars.next();
            for c2 in chars.by_ref() {
                if c2 == 'm' {
                    break;
                }
                if !(c2.is_ascii_digit() || c2 == ';') {
                    out.push(c2);
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn factory(level: &str, buf: &SharedBuf) -> castctl_logging::Handle {
    new_factory(
        Settings {
            level: level.to_string(),
            ..Default::default()
        },
        Some(Box::new(buf.clone())),
    )
    .unwrap()
}

fn emit_all(h: &castctl_logging::Handle, tag: &str) {
    let logger = h.logger(tag);
    logger.trace("level-probe-trace");
    logger.debug("level-probe-debug");
    logger.info("level-probe-info");
    logger.warn("level-probe-warn");
    logger.error("level-probe-error");
    // Fatal/Panic are not emitted here: the real factory's
    // Fatal exits the process and Panic panics. Panic is
    // covered separately.
}

fn assert_contains(buf: &str, sub: &str) {
    assert!(
        buf.contains(sub),
        "output {buf:?}, want it to contain {sub:?}"
    );
}

fn assert_not_contains(buf: &str, sub: &str) {
    assert!(
        !buf.contains(sub),
        "output {buf:?}, want it NOT to contain {sub:?}"
    );
}

// ---- factory_test.go ----

#[test]
fn factory_level_filtering() {
    let cases: Vec<(&str, &str, Vec<&str>, Vec<&str>)> = vec![
        (
            "warn",
            "warn",
            vec!["level-probe-warn", "level-probe-error"],
            vec!["level-probe-debug", "level-probe-trace", "level-probe-info"],
        ),
        (
            "trace",
            "trace",
            vec![
                "level-probe-trace",
                "level-probe-debug",
                "level-probe-info",
                "level-probe-warn",
                "level-probe-error",
            ],
            vec![],
        ),
        (
            "error",
            "error",
            vec!["level-probe-error"],
            vec!["level-probe-warn", "level-probe-info", "level-probe-debug"],
        ),
        (
            "info",
            "info",
            vec!["level-probe-info", "level-probe-warn", "level-probe-error"],
            vec!["level-probe-debug", "level-probe-trace"],
        ),
        (
            "default empty means trace",
            "",
            vec![
                "level-probe-trace",
                "level-probe-debug",
                "level-probe-info",
                "level-probe-warn",
                "level-probe-error",
            ],
            vec![],
        ),
        (
            "warning alias",
            "warning",
            vec!["level-probe-warn", "level-probe-error"],
            vec!["level-probe-debug", "level-probe-trace"],
        ),
    ];
    for (name, level, want, drop) in cases {
        let buf = SharedBuf::default();
        let h = factory(level, &buf);
        emit_all(&h, "castctl");
        h.close();
        let got = strip_ansi(&buf.take());
        for w in want {
            assert_contains(&got, w);
        }
        for d in drop {
            assert_not_contains(&got, d);
        }
        let _ = name;
    }
}

#[test]
fn factory_invalid_level() {
    let buf = SharedBuf::default();
    assert!(
        new_factory(
            Settings {
                level: "verbose".to_string(),
                ..Default::default()
            },
            Some(Box::new(buf.clone())),
        )
        .is_err(),
        "NewFactory(level=verbose) = ok, want error"
    );
    assert!(
        new_factory(
            Settings {
                level: "TRACE".to_string(),
                ..Default::default()
            },
            Some(Box::new(buf.clone())),
        )
        .is_err(),
        "NewFactory(level=TRACE) = ok, want error (case-sensitive)"
    );
    // Disabled short-circuits level parsing: a disabled
    // factory with a bogus level constructs successfully and
    // emits nothing.
    let h = new_factory(
        Settings {
            disabled: true,
            level: "bogus".to_string(),
            ..Default::default()
        },
        Some(Box::new(buf.clone())),
    )
    .unwrap();
    emit_all(&h, "castctl");
    h.close();
    assert_eq!(buf.len(), 0, "disabled factory emitted {:?}", buf.take());
}

#[test]
fn factory_panic_level() {
    let buf = SharedBuf::default();
    let h = factory("panic", &buf);
    // Error is suppressed at panic level.
    h.logger("castctl").error("level-probe-error");
    assert_eq!(buf.len(), 0, "panic-level factory emitted {:?}", buf.take());
    // Panic panics with the formatted line; the panic value
    // must carry the marker.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        h.logger("castctl").panic("level-probe-panic");
    }));
    assert!(result.is_err(), "Panic did not panic");
    let payload = result.unwrap_err();
    let msg = payload
        .downcast_ref::<String>()
        .map(|s| s.as_str())
        .or_else(|| payload.downcast_ref::<&str>().copied())
        .unwrap_or("");
    assert!(
        msg.contains("level-probe-panic"),
        "panic value {msg:?}, want it to contain the marker"
    );
    h.close();
}

fn full_ts_prefix(line: &str) -> bool {
    // ^[+-]\d{4} \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} (TRACE|DEBUG|INFO|WARN|ERROR)
    // "+0700 2026-11-05 10:00:00 INFO ...": sign 0, zone 1..5,
    // space 5, date 6..16, space 16, time 17..25, space 25, level 26..
    let b = line.as_bytes();
    if b.len() < 27 || (b[0] != b'+' && b[0] != b'-') {
        return false;
    }
    let digits = |r: std::ops::Range<usize>| b[r].iter().all(|c| c.is_ascii_digit());
    digits(1..5)
        && b[5] == b' '
        && digits(6..10)
        && b[10] == b'-'
        && digits(11..13)
        && b[13] == b'-'
        && digits(14..16)
        && b[16] == b' '
        && digits(17..19)
        && b[19] == b':'
        && digits(20..22)
        && b[22] == b':'
        && digits(23..25)
        && b[25] == b' '
        && line[26..]
            .split(' ')
            .next()
            .is_some_and(|l| matches!(l, "TRACE" | "DEBUG" | "INFO" | "WARN" | "ERROR"))
}

fn rel_ts_prefix(line: &str) -> bool {
    // ^(TRACE|DEBUG|INFO|WARN|ERROR)\[\d{4,}\]
    let level = line.split('[').next().unwrap_or("");
    if !matches!(level, "TRACE" | "DEBUG" | "INFO" | "WARN" | "ERROR") {
        return false;
    }
    let rest = &line[level.len() + 1..];
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.len() >= 4 && rest[digits.len()..].starts_with("] ")
}

fn plain_prefix(line: &str) -> bool {
    // ^(TRACE|DEBUG|INFO|WARN|ERROR)
    let level = line.split(' ').next().unwrap_or("");
    matches!(level, "TRACE" | "DEBUG" | "INFO" | "WARN" | "ERROR")
}

fn single_line(buf: &str) -> String {
    let stripped = strip_ansi(buf);
    let lines: Vec<&str> = stripped.trim_end_matches('\n').split('\n').collect();
    assert_eq!(lines.len(), 1, "want exactly 1 line, got {lines:?}");
    lines[0].to_string()
}

#[test]
fn factory_timestamp_formats() {
    // Console, timestamp true: full timestamp prefix.
    let buf = SharedBuf::default();
    let h = new_factory(
        Settings {
            level: "info".to_string(),
            timestamp: true,
            ..Default::default()
        },
        Some(Box::new(buf.clone())),
    )
    .unwrap();
    h.logger("castctl").info("timestamp-probe");
    h.close();
    let line = single_line(&buf.take());
    assert!(
        full_ts_prefix(&line),
        "console timestamp=true line {line:?}, want full-timestamp prefix"
    );

    // Console, timestamp false: relative elapsed-seconds prefix
    // (sing-box semantics: false does NOT mean bare on console).
    let buf = SharedBuf::default();
    let h = new_factory(
        Settings {
            level: "info".to_string(),
            timestamp: false,
            ..Default::default()
        },
        Some(Box::new(buf.clone())),
    )
    .unwrap();
    h.logger("castctl").info("timestamp-probe");
    h.close();
    let line = single_line(&buf.take());
    assert!(
        rel_ts_prefix(&line),
        "console timestamp=false line {line:?}, want relative [SSSS] prefix"
    );

    // File, timestamp false: NO timestamp at all.
    let dir = temp_dir("ts-file");
    let path = dir.join("castctl.log");
    let buf = SharedBuf::default();
    let h = new_factory(
        Settings {
            level: "info".to_string(),
            output: path.to_str().unwrap().to_string(),
            timestamp: false,
            ..Default::default()
        },
        Some(Box::new(buf.clone())),
    )
    .unwrap();
    h.logger("castctl").info("timestamp-probe");
    h.close();
    let data = std::fs::read_to_string(&path).unwrap();
    let line = single_line(&data);
    assert!(
        plain_prefix(&line),
        "file timestamp=false line {line:?}, want bare level prefix"
    );

    // File, timestamp true: full timestamp prefix.
    let path2 = dir.join("castctl2.log");
    let h = new_factory(
        Settings {
            level: "info".to_string(),
            output: path2.to_str().unwrap().to_string(),
            timestamp: true,
            ..Default::default()
        },
        Some(Box::new(buf.clone())),
    )
    .unwrap();
    h.logger("castctl").info("timestamp-probe");
    h.close();
    let data = std::fs::read_to_string(&path2).unwrap();
    let line = single_line(&data);
    assert!(
        full_ts_prefix(&line),
        "file timestamp=true line {line:?}, want full-timestamp prefix"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir =
        std::env::temp_dir().join(format!("castctl-logging-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn factory_disabled() {
    // Stderr path: nothing emitted, at trace level
    // (suppression cannot be explained by level filtering).
    let buf = SharedBuf::default();
    let h = new_factory(
        Settings {
            disabled: true,
            level: "trace".to_string(),
            ..Default::default()
        },
        Some(Box::new(buf.clone())),
    )
    .unwrap();
    emit_all(&h, "castctl");
    h.close();
    assert_eq!(buf.len(), 0, "disabled factory emitted {:?}", buf.take());
    // File path: no file is created at all.
    let dir = temp_dir("disabled");
    let path = dir.join("castctl.log");
    let h = new_factory(
        Settings {
            disabled: true,
            level: "trace".to_string(),
            output: path.to_str().unwrap().to_string(),
            ..Default::default()
        },
        Some(Box::new(buf.clone())),
    )
    .unwrap();
    emit_all(&h, "castctl");
    h.close();
    assert!(
        !path.exists(),
        "disabled factory created log file, want no file"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn factory_file_mode() {
    let buf = SharedBuf::default();
    // Created file: mode 0600, non-empty.
    let dir = temp_dir("filemode");
    let path = dir.join("castctl.log");
    let h = new_factory(
        Settings {
            level: "info".to_string(),
            output: path.to_str().unwrap().to_string(),
            ..Default::default()
        },
        Some(Box::new(buf.clone())),
    )
    .unwrap();
    h.logger("castctl").info("file-mode-probe");
    h.close();
    use std::os::unix::fs::PermissionsExt;
    let info = std::fs::metadata(&path).unwrap();
    assert!(info.is_file(), "log path is not a regular file");
    assert_eq!(
        info.permissions().mode() & 0o777,
        0o600,
        "created log file mode = {:o}, want 0600",
        info.permissions().mode()
    );
    let data = std::fs::read_to_string(&path).unwrap();
    assert!(data.contains("file-mode-probe"), "log file {data:?}");

    // Pre-existing file: appended (never truncated) WITHOUT
    // any chmod.
    let path2 = dir.join("existing.log");
    std::fs::write(&path2, b"prior line\n").unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path2, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let before = std::fs::metadata(&path2).unwrap().permissions().mode() & 0o777;
    let h = new_factory(
        Settings {
            level: "info".to_string(),
            output: path2.to_str().unwrap().to_string(),
            ..Default::default()
        },
        Some(Box::new(buf.clone())),
    )
    .unwrap();
    h.logger("castctl").info("append-probe");
    h.close();
    let after = std::fs::metadata(&path2).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        after, before,
        "pre-existing log file mode changed (never chmod a foreign file)"
    );
    let data = std::fs::read_to_string(&path2).unwrap();
    assert!(
        data.contains("prior line\n") && data.contains("append-probe"),
        "log file {data:?}, want prior content preserved plus appended probe"
    );

    // Bad path (missing parent): fail-closed error, no fallback.
    let bad = dir.join("no-such-dir").join("castctl.log");
    assert!(
        new_factory(
            Settings {
                level: "info".to_string(),
                output: bad.to_str().unwrap().to_string(),
                ..Default::default()
            },
            Some(Box::new(buf.clone())),
        )
        .is_err(),
        "NewFactory with a missing-parent log path = ok, want error"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn factory_output_spelling() {
    // "" and "stderr" both mean the supplied stderr writer.
    for out in ["", "stderr"] {
        let buf = SharedBuf::default();
        let h = new_factory(
            Settings {
                level: "info".to_string(),
                output: out.to_string(),
                ..Default::default()
            },
            Some(Box::new(buf.clone())),
        )
        .unwrap();
        h.logger("castctl").info("stderr-probe");
        h.close();
        assert!(
            buf.take().contains("stderr-probe"),
            "output {out:?}: buffer empty, want the probe line"
        );
    }
    // A nil stderr writer falls back to the real stderr (no
    // panic, no crash); nothing is asserted about its bytes.
    let h = new_factory(
        Settings {
            level: "info".to_string(),
            ..Default::default()
        },
        None,
    )
    .unwrap();
    h.close();
}

#[test]
fn factory_level_accessor() {
    let buf = SharedBuf::default();
    let h = factory("warning", &buf);
    assert_eq!(h.level(), Level::WARN, "Level() for \"warning\"");
    h.close();
}

#[test]
fn emit_redacts() {
    let buf = SharedBuf::default();
    let h = factory("trace", &buf);
    emit(
        &h.logger("castctl"),
        Level::DEBUG,
        &format!(
            "event=ws_handshake status_token=error url=wss://gateway.example.invalid/v1/noise?vm_id={FIX_VMID}&auth_token={FIX_HATCH_TOKEN}"
        ),
    );
    h.close();
    let got = buf.take();
    for v in [FIX_VMID, FIX_HATCH_TOKEN] {
        assert!(
            !got.contains(v),
            "emitted output contains fixture value {v:?}: {got:?}"
        );
    }
    assert_contains(&got, "event=ws_handshake");
    assert_contains(&got, "auth_token=[redacted]");
}

#[test]
fn slog_bridge_filtering_and_redaction() {
    // At warn: slog Debug suppressed, Warn visible, through
    // the ONE resolved level.
    let buf = SharedBuf::default();
    let h = factory("warn", &buf);
    let sl = h.slog_logger("castctl");
    sl.debug("slog-debug-probe", &[]);
    sl.info("slog-info-probe", &[]);
    sl.warn("slog-warn-probe", &[("seconds", SlogValue::from(3))]);
    h.close();
    let got = strip_ansi(&buf.take());
    assert_not_contains(&got, "slog-debug-probe");
    assert_not_contains(&got, "slog-info-probe");
    assert_contains(&got, "slog-warn-probe");
    assert_contains(&got, "seconds=3");

    // At trace: slog Debug visible, and a fixture-bearing
    // error attr is stripped (vm_id case included) with the
    // marker surviving.
    let buf = SharedBuf::default();
    let h = factory("trace", &buf);
    let sl = h.slog_logger("castctl");
    sl.debug("slog-debug-probe", &[]);
    sl.warn(
        "gateway down",
        &[(
            "err",
            SlogValue::error(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "dial wss://gateway.example.invalid/v1/noise?vm_id={FIX_VMID}&auth_token={FIX_HATCH_TOKEN}"
                ),
            )),
        )],
    );
    sl.info(
        "retrying",
        &[
            ("what", SlogValue::from("fs.read")),
            (
                "err",
                SlogValue::error(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("down: hatch_sess={FIX_COOKIE_VAL}"),
                )),
            ),
        ],
    );
    h.close();
    let got = strip_ansi(&buf.take());
    assert_contains(&got, "slog-debug-probe");
    for v in [FIX_VMID, FIX_HATCH_TOKEN, FIX_COOKIE_VAL] {
        assert!(
            !got.contains(v),
            "slog output contains fixture value {v:?}: {got:?}"
        );
    }
    assert_contains(&got, "[redacted]");

    // slog levels map onto sing-box levels: a slog Error is
    // visible at error, suppressed at... (error is the
    // threshold; assert visibility, the warn case above
    // covers suppression of below-threshold lines).
    let buf = SharedBuf::default();
    let h = factory("error", &buf);
    let sl = h.slog_logger("castctl");
    sl.error(
        "slog-error-probe",
        &[(
            "err",
            SlogValue::error(std::io::Error::new(std::io::ErrorKind::Other, "boom")),
        )],
    );
    sl.warn("slog-warn-probe", &[]);
    h.close();
    let got = strip_ansi(&buf.take());
    assert_contains(&got, "slog-error-probe");
    assert_not_contains(&got, "slog-warn-probe");
}

#[test]
fn factory_concurrent_writes() {
    let buf = SharedBuf::default();
    let handle = new_factory(
        Settings {
            level: "trace".to_string(),
            output: "stderr".to_string(),
            ..Default::default()
        },
        Some(Box::new(buf.clone())),
    )
    .unwrap();
    let logger = handle.logger("conc");
    const THREADS: usize = 8;
    const PER_THREAD: usize = 25;
    let mut threads = Vec::new();
    for g in 0..THREADS {
        let logger = logger.clone();
        threads.push(std::thread::spawn(move || {
            for i in 0..PER_THREAD {
                emit(&logger, Level::INFO, &format!("event=conc g={g} i={i}"));
            }
        }));
    }
    for t in threads {
        t.join().unwrap();
    }
    handle.close();
    let text = buf.take();
    let lines: Vec<&str> = text.trim_end_matches('\n').split('\n').collect();
    assert_eq!(
        lines.len(),
        THREADS * PER_THREAD,
        "got {} lines, want {}:\n{text}",
        lines.len(),
        THREADS * PER_THREAD
    );
    for line in lines {
        assert_eq!(
            line.matches("event=conc").count(),
            1,
            "interleaved line: {line:?}"
        );
    }
}

#[test]
fn factory_refused_paths() {
    let buf = SharedBuf::default();
    let dir = temp_dir("refused");
    let config_path = dir.join("config.json");
    let cookie_path = dir.join("cookies.txt");
    let orig_config = "FIXTURE-CONFIG\n";
    let orig_cookie = "FIXTURE-COOKIE\n";
    std::fs::write(&config_path, orig_config).unwrap();
    std::fs::write(&cookie_path, orig_cookie).unwrap();
    let refused = vec![
        config_path.to_str().unwrap().to_string(),
        cookie_path.to_str().unwrap().to_string(),
    ];
    let settings = |out: &str| Settings {
        level: "trace".to_string(),
        output: out.to_string(),
        refused: refused.clone(),
        ..Default::default()
    };

    // Direct equality: refused before open.
    for out in [&config_path, &cookie_path] {
        assert!(
            new_factory(settings(out.to_str().unwrap()), Some(Box::new(buf.clone()))).is_err(),
            "NewFactory(Output={out:?}, refused) = ok, want error"
        );
    }
    for (p, want) in [(&config_path, orig_config), (&cookie_path, orig_cookie)] {
        let data = std::fs::read_to_string(p).unwrap();
        assert_eq!(data, want, "protected file {p:?} changed");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(p).unwrap().permissions().mode() & 0o777,
            0o600,
            "protected file {p:?} mode changed"
        );
    }

    // Symlinked alias of the config file: still refused.
    let alias = dir.join("alias.json");
    std::os::unix::fs::symlink(&config_path, &alias).unwrap();
    assert!(
        new_factory(
            settings(alias.to_str().unwrap()),
            Some(Box::new(buf.clone()))
        )
        .is_err(),
        "NewFactory(Output=symlink-to-config) = ok, want error"
    );
    assert_eq!(std::fs::read_to_string(&config_path).unwrap(), orig_config);

    // Symlink to an ORDINARY target: NOT refused; the line
    // lands in the target through the link.
    let target = dir.join("ordinary.log");
    std::fs::write(&target, b"prior\n").unwrap();
    let link = dir.join("link.log");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let h = new_factory(
        settings(link.to_str().unwrap()),
        Some(Box::new(buf.clone())),
    )
    .unwrap();
    h.logger("castctl").info("symlink-target-probe");
    h.close();
    let data = std::fs::read_to_string(&target).unwrap();
    assert!(
        data.contains("symlink-target-probe"),
        "symlink target {data:?}"
    );

    // Non-regular file: NOT refused on that basis. /dev/null is
    // the portable character device.
    if std::path::Path::new("/dev/null").exists() {
        let h = new_factory(settings("/dev/null"), Some(Box::new(buf.clone())));
        match h {
            Ok(h) => {
                h.logger("castctl").info("devnull-probe");
                h.close();
            }
            Err(e) => panic!("NewFactory(Output=/dev/null) = {e}, want success"),
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn factory_sink_redacts_singbox_lines() {
    let line = format!(
        "wireguard: setup failed: wss://gateway.example.invalid/v1/noise?vm_id={FIX_VMID}&auth_token={FIX_HATCH_TOKEN} private_key={FIX_WG_PRIV} public_key={FIX_WG_PUB}"
    );
    let scan = |got: &str, loc: &str| {
        assert!(
            !got.is_empty(),
            "{loc} capture empty: positive control failed"
        );
        for v in [FIX_VMID, FIX_HATCH_TOKEN, FIX_WG_PRIV, FIX_WG_PUB] {
            assert!(
                !got.contains(v),
                "{loc} capture contains fixture value {v:?}: {got:?}"
            );
        }
        assert!(
            got.contains("[redacted]"),
            "{loc} capture {got:?}, want a [redacted] marker"
        );
        // WG public key: at most the 8-char prefix may survive.
        assert!(
            got.contains(&format!("public_key={}", &FIX_WG_PUB[..8])),
            "{loc} capture {got:?}, want the 8-char public-key prefix"
        );
    };

    let buf = SharedBuf::default();
    let h = factory("trace", &buf);
    h.logger("wireguard").debug(&line);
    h.close();
    scan(&strip_ansi(&buf.take()), "stderr");

    let dir = temp_dir("sink");
    let path = dir.join("sink.log");
    let h = new_factory(
        Settings {
            level: "trace".to_string(),
            output: path.to_str().unwrap().to_string(),
            ..Default::default()
        },
        Some(Box::new(buf.clone())),
    )
    .unwrap();
    h.logger("wireguard").debug(&line);
    h.close();
    let data = std::fs::read_to_string(&path).unwrap();
    scan(&data, "file");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn factory_output_stdout() {
    // "stdout" names the real stdout (sing-box log/log.go:40-41).
    // ADAPTED: Rust cannot swap the process stdout hermetically
    // (the Go test swaps os.Stdout for a pipe), so this asserts
    // construction + emission without panic, not the captured
    // bytes. See PORTING.md §M7a.
    let buf = SharedBuf::default();
    let h = new_factory(
        Settings {
            level: "info".to_string(),
            output: "stdout".to_string(),
            ..Default::default()
        },
        Some(Box::new(buf.clone())),
    )
    .unwrap();
    h.logger("castctl").info("stdout-probe");
    h.close();
}

#[test]
fn factory_refused_paths_by_identity() {
    let dir = temp_dir("refused-id");
    let config_path = dir.join("config.json");
    let cookie_path = dir.join("cookies.txt");
    let orig_config = "FIXTURE-CONFIG\n";
    let orig_cookie = "FIXTURE-COOKIE\n";
    std::fs::write(&config_path, orig_config).unwrap();
    std::fs::write(&cookie_path, orig_cookie).unwrap();
    let refused = vec![
        config_path.to_str().unwrap().to_string(),
        cookie_path.to_str().unwrap().to_string(),
    ];
    let assert_protected = || {
        for (p, want) in [(&config_path, orig_config), (&cookie_path, orig_cookie)] {
            let data = std::fs::read_to_string(p).unwrap();
            assert_eq!(data, want, "protected file {p:?} changed");
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(p).unwrap().permissions().mode() & 0o777,
                0o600,
                "protected file {p:?} mode changed"
            );
        }
    };
    let refused_output = |name: &str, out: &str, refused: &[String]| {
        let buf = SharedBuf::default();
        assert!(
            new_factory(
                Settings {
                    level: "trace".to_string(),
                    output: out.to_string(),
                    refused: refused.to_vec(),
                    ..Default::default()
                },
                Some(Box::new(buf.clone())),
            )
            .is_err(),
            "NewFactory(Output={name} {out:?}) = ok, want error"
        );
        assert_protected();
    };

    refused_output("direct-config", config_path.to_str().unwrap(), &refused);

    // Hardlink to the config file: same inode, different path.
    let hard_config = dir.join("hard-config.json");
    std::fs::hard_link(&config_path, &hard_config).unwrap();
    refused_output("hardlink-config", hard_config.to_str().unwrap(), &refused);
    // Hardlink to the cookies file.
    let hard_cookie = dir.join("hard-cookies.txt");
    std::fs::hard_link(&cookie_path, &hard_cookie).unwrap();
    refused_output("hardlink-cookies", hard_cookie.to_str().unwrap(), &refused);

    // Symlink to an ABSENT cookies target: the refused path does
    // not exist yet; the link must still be refused, and the
    // target must not be created.
    let absent_target = dir.join("cookies-absent.txt");
    let absent_link = dir.join("absent-link.txt");
    std::os::unix::fs::symlink(&absent_target, &absent_link).unwrap();
    let refused_absent = vec![
        config_path.to_str().unwrap().to_string(),
        absent_target.to_str().unwrap().to_string(),
    ];
    let buf = SharedBuf::default();
    assert!(
        new_factory(
            Settings {
                level: "trace".to_string(),
                output: absent_link.to_str().unwrap().to_string(),
                refused: refused_absent,
                ..Default::default()
            },
            Some(Box::new(buf.clone())),
        )
        .is_err(),
        "NewFactory(Output=symlink-to-absent-cookies-target) = ok, want error"
    );
    assert!(
        std::fs::symlink_metadata(&absent_target).is_err(),
        "absent refused target was created by the refused open"
    );
    assert_protected();

    // Symlink to the EXISTING config file.
    let alias = dir.join("alias2.json");
    std::os::unix::fs::symlink(&config_path, &alias).unwrap();
    refused_output("symlink-existing-config", alias.to_str().unwrap(), &refused);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn factory_invalid_level_never_echoes() {
    let buf = SharedBuf::default();
    let err = new_factory(
        Settings {
            level: "LOGFIX-LEVEL-9d2e41".to_string(),
            ..Default::default()
        },
        Some(Box::new(buf.clone())),
    )
    .unwrap_err();
    assert!(
        !err.to_string().contains("LOGFIX-LEVEL-9d2e41"),
        "factory error {err:?} echoes the supplied level value"
    );
    assert!(
        err.to_string().contains("unknown log level"),
        "factory error {err:?}, want the fixed unknown-level message"
    );
}

// ---- level_test.go ----

const LEVEL_BODY_PAYLOAD: &str = "plain body words BODYFIX-9d2e41 with no secret label"; // 52 bytes

fn gateway_500(payload: &str) -> TransportError {
    TransportError::Gateway(BodySummary {
        status: 500,
        body_length: Some(payload.len()),
        content_type: None,
        error_code: None,
    })
}

/// A wrapper error (Go's `fmt.Errorf("outer: %w", gw)`) whose
/// `source()` is the wrapped error.
#[derive(Debug)]
struct OuterError {
    source: Box<dyn Error + Send + Sync>,
}

impl fmt::Display for OuterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "outer: {}", self.source)
    }
}

impl Error for OuterError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

#[test]
fn summarize_err() {
    let gw = gateway_500(LEVEL_BODY_PAYLOAD);
    assert_eq!(
        summarize_err(Some(&gw)),
        "conn: gateway status=500 body_length=52"
    );
    let ae = TransportError::Auth {
        message: format!("hatch/token -> 403 {LEVEL_BODY_PAYLOAD}"),
    };
    assert_eq!(
        summarize_err(Some(&ae)),
        "conn: auth_failed message_length=71"
    );
    let wrapped = OuterError {
        source: Box::new(gateway_500(LEVEL_BODY_PAYLOAD)),
    };
    assert_eq!(
        summarize_err(Some(&wrapped)),
        "conn: gateway status=500 body_length=52"
    );
    // ConnectionError wrapping a GatewayError: Go's
    // `ConnectionError.LogSummary` delegates to the inner
    // summary; in Rust the same shape is a wrapper error
    // whose source is the Gateway error (see the adaptation
    // note at the top of this file).
    let conn_wrapped = OuterError {
        source: Box::new(gateway_500(LEVEL_BODY_PAYLOAD)),
    };
    assert_eq!(
        summarize_err(Some(&conn_wrapped)),
        "conn: gateway status=500 body_length=52"
    );
    let plain = std::io::Error::new(std::io::ErrorKind::Other, "connection refused");
    assert_eq!(summarize_err(Some(&plain)), "connection refused");
    assert_eq!(summarize_err(None), "");
}

#[test]
fn safe_err_for_level() {
    let payload = format!(
        "{{\"token\": \"LOGFIX-LEVEL-83af10\"}} and {}",
        "tailword ".repeat(200)
    );
    let gw = gateway_500(&payload);
    for level in [
        Level::TRACE,
        Level::DEBUG,
        Level::INFO,
        Level::WARN,
        Level::ERROR,
    ] {
        let got = safe_err_for_level(Some(&gw), level);
        assert!(
            !got.contains("tailword") && !got.contains("LOGFIX-LEVEL"),
            "level {level} rendering {got:?} carries body bytes"
        );
        assert!(
            got.contains("status=500") && got.contains("body_length="),
            "level {level} rendering {got:?}, want status + class + length only"
        );
    }
}

#[test]
fn slog_bridge_above_trace_summarizes_body() {
    let buf = SharedBuf::default();
    let h = factory("info", &buf);
    let logger = h.slog_logger("castctl");
    let gw = gateway_500(LEVEL_BODY_PAYLOAD);
    logger.info("gateway probe", &[("err", SlogValue::error(gw))]);
    h.close();
    let got = buf.take();
    assert!(!got.is_empty(), "capture empty: positive control failed");
    assert!(
        !got.contains("BODYFIX-9d2e41") && !got.contains("plain body words"),
        "info capture {got:?} carries server body bytes above trace"
    );
    assert!(
        got.contains("status=500") && got.contains("body_length=52"),
        "info capture {got:?}, want status=500 and body_length=52"
    );
}

#[test]
fn slog_bridge_trace_summarizes_body() {
    let buf = SharedBuf::default();
    let h = factory("trace", &buf);
    let logger = h.slog_logger("castctl");
    let payload = format!(
        "{{\"token\": \"LOGFIX-LEVELTRACE-83af10\"}} and {}",
        "tailword ".repeat(200)
    );
    let gw = gateway_500(&payload);
    logger.log(
        SlogLevel(SlogLevel::DEBUG.0 - 4),
        "trace-body-probe",
        &[("err", SlogValue::error(gw))],
    );
    h.close();
    let got = buf.take();
    assert!(
        got.contains("trace-body-probe"),
        "capture {got:?}, want the trace probe line"
    );
    assert!(
        !got.contains("LOGFIX-LEVELTRACE-83af10") && !got.contains("tailword"),
        "trace capture {got:?} carries body bytes"
    );
    assert!(
        got.contains("status=500") && got.contains("body_length="),
        "trace capture {got:?}, want status + class + length only"
    );
}

#[test]
fn slog_bridge_warn_summarizes_auth_error() {
    let buf = SharedBuf::default();
    let h = factory("warn", &buf);
    let logger = h.slog_logger("castctl");
    let ae = TransportError::Auth {
        message: format!("hatch/token -> 403 {LEVEL_BODY_PAYLOAD}"),
    };
    logger.warn("auth probe", &[("err", SlogValue::error(ae))]);
    h.close();
    let got = buf.take();
    assert!(!got.is_empty(), "capture empty: positive control failed");
    assert!(
        !got.contains("BODYFIX-9d2e41") && !got.contains("plain body words"),
        "warn capture {got:?} carries server body bytes above trace"
    );
    assert!(
        got.contains("auth_failed") && got.contains("message_length="),
        "warn capture {got:?}, want class + length only"
    );
}

// ---- allowlist_test.go ----

#[test]
fn safe_err_for_level_trace_is_summary() {
    let payload = format!("plain body words ALLOW5TRACE-9d2e41");
    let gw = gateway_500(&payload);
    for level in [
        Level::TRACE,
        Level::DEBUG,
        Level::INFO,
        Level::WARN,
        Level::ERROR,
    ] {
        let got = safe_err_for_level(Some(&gw), level);
        assert!(
            !got.contains("ALLOW5TRACE-9d2e41") && !got.contains("plain body words"),
            "level {level} rendering {got:?} carries body bytes"
        );
        assert!(
            got.contains("status=500") && got.contains("body_length="),
            "level {level} rendering {got:?}, want status + class + length only"
        );
    }
    let ae = TransportError::Auth {
        message: "hatch/token -> 403 plain body words ALLOW5TRACE-9d2e41".to_string(),
    };
    let got = safe_err_for_level(Some(&ae), Level::TRACE);
    assert!(
        !got.contains("ALLOW5TRACE-9d2e41"),
        "trace AuthError rendering {got:?} carries body bytes"
    );
    assert!(
        got.contains("auth_failed") && got.contains("message_length="),
        "trace AuthError rendering {got:?}, want class + length only"
    );
}

// ---- profile/log_test.go: ResolveLogSettings ----

#[test]
fn resolve_log_settings() {
    let config_with_log = |l: LogConfig| Some(l);
    let cases: Vec<(&str, Option<LogConfig>, &str, bool, Option<LogConfig>, bool)> = vec![
        (
            "absent block",
            None,
            "",
            false,
            Some(LogConfig {
                disabled: true,
                level: "trace".to_string(),
                ..Default::default()
            }),
            false,
        ),
        (
            "empty block present turns logging on",
            config_with_log(LogConfig::default()),
            "",
            false,
            Some(LogConfig {
                disabled: false,
                level: "trace".to_string(),
                ..Default::default()
            }),
            false,
        ),
        (
            "explicit disabled:false block",
            config_with_log(LogConfig {
                disabled: false,
                ..Default::default()
            }),
            "",
            false,
            Some(LogConfig {
                disabled: false,
                level: "trace".to_string(),
                ..Default::default()
            }),
            false,
        ),
        (
            "config level",
            config_with_log(LogConfig {
                level: "debug".to_string(),
                output: "stderr".to_string(),
                ..Default::default()
            }),
            "",
            false,
            Some(LogConfig {
                level: "debug".to_string(),
                output: "stderr".to_string(),
                ..Default::default()
            }),
            false,
        ),
        (
            "warning alias normalises",
            config_with_log(LogConfig {
                level: "warning".to_string(),
                ..Default::default()
            }),
            "",
            false,
            Some(LogConfig {
                level: "warn".to_string(),
                ..Default::default()
            }),
            false,
        ),
        (
            "CLI beats config upward",
            config_with_log(LogConfig {
                level: "error".to_string(),
                ..Default::default()
            }),
            "trace",
            true,
            Some(LogConfig {
                level: "trace".to_string(),
                ..Default::default()
            }),
            false,
        ),
        (
            "CLI beats config downward",
            config_with_log(LogConfig {
                level: "debug".to_string(),
                ..Default::default()
            }),
            "warn",
            true,
            Some(LogConfig {
                level: "warn".to_string(),
                ..Default::default()
            }),
            false,
        ),
        (
            "CLI only",
            None,
            "info",
            true,
            Some(LogConfig {
                level: "info".to_string(),
                ..Default::default()
            }),
            false,
        ),
        (
            "config disabled kept",
            config_with_log(LogConfig {
                disabled: true,
                level: "trace".to_string(),
                ..Default::default()
            }),
            "",
            false,
            Some(LogConfig {
                disabled: true,
                level: "trace".to_string(),
                ..Default::default()
            }),
            false,
        ),
        (
            "CLI does not clear disabled",
            config_with_log(LogConfig {
                disabled: true,
                level: "trace".to_string(),
                ..Default::default()
            }),
            "debug",
            true,
            Some(LogConfig {
                disabled: true,
                level: "debug".to_string(),
                ..Default::default()
            }),
            false,
        ),
        (
            "config file output kept",
            config_with_log(LogConfig {
                level: "info".to_string(),
                output: "/tmp/x.log".to_string(),
                timestamp: true,
            }),
            "",
            false,
            Some(LogConfig {
                level: "info".to_string(),
                output: "/tmp/x.log".to_string(),
                timestamp: true,
            }),
            false,
        ),
        (
            "stdout in config accepted at resolve",
            config_with_log(LogConfig {
                level: "debug".to_string(),
                output: "stdout".to_string(),
                ..Default::default()
            }),
            "",
            false,
            Some(LogConfig {
                level: "debug".to_string(),
                output: "stdout".to_string(),
                ..Default::default()
            }),
            false,
        ),
        (
            "invalid CLI level",
            config_with_log(LogConfig {
                level: "debug".to_string(),
                ..Default::default()
            }),
            "verbose",
            true,
            None,
            true,
        ),
        ("empty CLI level", None, "", true, None, true),
        (
            "invalid config level",
            config_with_log(LogConfig {
                level: "bogus".to_string(),
                ..Default::default()
            }),
            "",
            false,
            None,
            true,
        ),
    ];
    for (name, cfg, cli, cli_set, want, want_err) in cases {
        let got = resolve_log_settings(cfg.as_ref(), cli, cli_set);
        if want_err {
            let err = got.unwrap_err();
            assert_eq!(
                err.exit_code(),
                2,
                "{name}: error exit code = {}, want 2",
                err.exit_code()
            );
            continue;
        }
        let got =
            got.unwrap_or_else(|e| panic!("{name}: ResolveLogSettings = {e}, want {:?}", want));
        assert_eq!(got, want.unwrap(), "{name}: ResolveLogSettings mismatch");
    }
}

// ---- WrapErr (no Go test; minimal unit test, not a port) ----

#[test]
fn wrap_err_redacts_display_but_keeps_source() {
    let inner = std::io::Error::new(
        std::io::ErrorKind::Other,
        format!("boom auth_token={FIX_HATCH_TOKEN}"),
    );
    let wrapped = castctl_logging::wrap_error(inner);
    assert!(
        !wrapped.to_string().contains(FIX_HATCH_TOKEN),
        "wrapped Display carries the secret: {}",
        wrapped.to_string()
    );
    assert!(wrapped.to_string().contains("[redacted]"));
    assert!(
        wrapped.source().is_some(),
        "WrapErr must expose the original via source()"
    );
    assert!(
        castctl_logging::wrap_err(None).is_none(),
        "WrapErr(nil) must be None"
    );
}
