// SPDX-License-Identifier: GPL-3.0-only
// Live logs: tail of the configured log FILE, gated exactly
// like the log pipeline (docs/config.md). Port of Go
// internal/webui/logs.go.
//
// No log block, a disabled block, or stderr/stdout output
// means the page reports disabled: no ring is invented and
// no logging is started to serve the page. Every returned
// line passes `safe_string` at the API boundary. Cookie
// material stays out because the identity guard refuses
// cookie-adjacent outputs, not because SafeString would
// catch it.
//
// The cursor is a decimal byte offset into the file. A
// request without a cursor returns the tail (last `limit`
// lines); a request with a cursor returns lines appended
// after it.

use crate::contain::{clean_path, path_within, resolve_against, resolve_path_best_effort};
use crate::error::{ApiError, err_internal, err_validation};
use crate::server::{Resp, envelope_resp, error_resp};
use crate::store::{ConfigLoad, legacy_profile_names_in, profile_cookies_files};
use castctl_config::jsonvalue::decode_ordered_json;
use castctl_config::jsonvalue::{JsonValue, OrderedObject};
use castctl_config::profile::{Paths, profile_paths};
use castctl_log_redact::safe_string;
use regex::Regex;
use std::fs;
use std::io::{Read, Seek};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub const MAX_LOG_READ_BYTES: usize = 256 << 10;
pub const MAX_LOG_LIMIT: i64 = 500;
pub const DEFAULT_LOG_LIMIT: i64 = 100;

/// The log gate verdict: `(path, disabled, reason)`.
/// `path` is set only when the log file may be served.
pub struct LogGate {
    pub path: Option<PathBuf>,
    pub disabled: bool,
    pub reason: String,
}

fn re_full_ts() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^([+-]\d{4} \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|PANIC) (.*)$").expect("log full-ts regex compiles")
    })
}

fn re_relative() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^(TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|PANIC)\[\d+\] (.*)$")
            .expect("log relative regex compiles")
    })
}

fn re_bare() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^(TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|PANIC) (.*)$")
            .expect("log bare regex compiles")
    })
}

fn re_tag() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^([A-Za-z0-9_.\-]+): (.*)$").expect("log tag regex compiles"))
}

fn re_ansi() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new("\u{1b}\\[[0-9;]*m").expect("ANSI regex compiles"))
}

/// One parsed log line (the frozen LogEntry shape).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    pub ts: String,
    pub level: String,
    pub kind: String,
    pub message: String,
}

impl LogEntry {
    fn to_json(&self) -> JsonValue {
        let mut obj = OrderedObject::new();
        obj.set("ts", JsonValue::Str(self.ts.clone()));
        obj.set("level", JsonValue::Str(self.level.clone()));
        obj.set("kind", JsonValue::Str(self.kind.clone()));
        obj.set("message", JsonValue::Str(self.message.clone()));
        JsonValue::Object(obj)
    }
}

fn normalize_level(level: &str) -> String {
    if level == "WARNING" {
        "warn".to_string()
    } else {
        level.to_lowercase()
    }
}

/// `parseLogLine` (Go logs.go): parses one log file line
/// best-effort. Unparseable lines keep level/kind empty and
/// carry the SafeString'd line as the message.
pub fn parse_log_line(line: &str) -> LogEntry {
    let line = re_ansi().replace_all(line, "");
    let line = line.strip_suffix('\r').unwrap_or(&line);
    let mut ts = String::new();
    let mut level = String::new();
    let mut rest = line.to_string();
    if let Some(m) = re_full_ts().captures(line) {
        ts = m[1].to_string();
        level = normalize_level(&m[2]);
        rest = m[3].to_string();
    } else if let Some(m) = re_relative().captures(line) {
        level = normalize_level(&m[1]);
        rest = m[2].to_string();
    } else if let Some(m) = re_bare().captures(line) {
        level = normalize_level(&m[1]);
        rest = m[2].to_string();
    }
    let mut kind = String::new();
    if !level.is_empty()
        && let Some(m) = re_tag().captures(&rest)
    {
        kind = m[1].to_string();
        rest = m[2].to_string();
    }
    LogEntry {
        ts: safe_string(&ts),
        level: safe_string(&level),
        kind: safe_string(&kind),
        message: safe_string(&rest),
    }
}

/// `ResolveLogSettings` for the web UI (no CLI flags):
/// absent log block → Disabled; present block (including
/// `{}`) follows sing-box defaults (level trace, output ""
/// = stderr, timestamp false, disabled false). "warning"
/// normalises to "warn". Returns Err for an unknown level
/// (the message is never echoed — fixed expected list).
pub struct LogSettings {
    pub disabled: bool,
    pub level: String,
    pub output: String,
}

const VALID_LOG_LEVELS: [&str; 8] = [
    "trace", "debug", "info", "warn", "warning", "error", "fatal", "panic",
];

pub fn resolve_log_settings(
    cfg: &castctl_config::config::SingleConfig,
) -> Result<LogSettings, ApiError> {
    let block_present = cfg.log.is_some();
    let mut disabled = !block_present;
    let mut level = "trace".to_string();
    let mut output = String::new();
    if let Some(block) = &cfg.log {
        disabled = block.disabled;
        if !block.level.is_empty() {
            level = block.level.clone();
        }
        output = block.output.clone();
    }
    if level == "warning" {
        level = "warn".to_string();
    }
    if !VALID_LOG_LEVELS.contains(&level.as_str()) {
        return Err(err_internal());
    }
    if output.trim().is_empty() {
        output.clear();
    }
    Ok(LogSettings {
        disabled,
        level,
        output,
    })
}

/// `sameFile` (Go logs.go): same device+inode when both
/// exist, else resolved lexical path comparison. A stat
/// failure on either side is "not the same file" only when
/// the lexical paths also differ.
pub fn same_file(a: &Path, b: &Path) -> bool {
    if let (Ok(ai), Ok(bi)) = (fs::metadata(a), fs::metadata(b)) {
        return ai.dev() == bi.dev() && ai.ino() == bi.ino();
    }
    let ra = std::fs::canonicalize(a)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| {
            clean_path(Path::new(a.to_string_lossy().as_ref()))
                .to_string_lossy()
                .into_owned()
        });
    let rb = std::fs::canonicalize(b)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| {
            clean_path(Path::new(b.to_string_lossy().as_ref()))
                .to_string_lossy()
                .into_owned()
        });
    ra == rb
}

/// `legacyCookiesFileRefusals` (Go logs.go): the refusal
/// forms for a legacy profile's OWN cookies_file override.
/// `corrupt` is true when the file cannot be stat'ed as a
/// regular file or read, cannot be decoded as a JSON
/// object, or carries a cookies_file that is present but
/// not a string (null counts as absent, as in the parser).
pub fn legacy_cookies_file_refusals(config_dir: &Path, paths: &Paths) -> (Vec<String>, bool) {
    let st = match fs::metadata(&paths.config) {
        Ok(st) => st,
        Err(_) => return (Vec::new(), true),
    };
    if !st.is_file() {
        return (Vec::new(), true);
    }
    let data = match fs::read(&paths.config) {
        Ok(d) => d,
        Err(_) => return (Vec::new(), true),
    };
    let doc = match crate::go_decode::decode_first_value(&data) {
        // Go decodes the legacy config with `decodeGeneric`:
        // first value only, trailing data ignored.
        Ok(JsonValue::Object(obj)) => obj,
        _ => return (Vec::new(), true),
    };
    let Some(v) = doc.get("cookies_file") else {
        return (Vec::new(), false);
    };
    if v.is_null() {
        return (Vec::new(), false);
    }
    let JsonValue::Str(s) = v else {
        return (Vec::new(), true);
    };
    if s.trim().is_empty() {
        return (Vec::new(), false);
    }
    let mut lexical = s.clone();
    if !Path::new(&lexical).is_absolute() {
        lexical = format!("{}/{}", config_dir.to_string_lossy(), lexical);
    }
    let lexical = clean_path(Path::new(&lexical))
        .to_string_lossy()
        .into_owned();
    let resolved_raw = resolve_against(config_dir, s);
    (
        vec![
            lexical.clone(),
            format!("{}.bak", lexical),
            resolved_raw.to_string_lossy().into_owned(),
            format!("{}.bak", resolved_raw.display()),
        ],
        false,
    )
}

/// `logGate` (Go logs.go): resolves the live-log gate for
/// the current config. Returns the log file path, or
/// disabled=true with a fixed reason. The identity guard
/// (A7) refuses a log output that resolves to the config
/// file, any cookies file, any cookies `.bak` sibling, any
/// legacy-layout cookies file or its `.bak`, or any file
/// under the config dir's `profiles/` subtree.
pub fn log_gate(
    config_dir: &Path,
    load: &ConfigLoad,
    cfg: &castctl_config::config::SingleConfig,
) -> Result<LogGate, ApiError> {
    let settings = resolve_log_settings(cfg)?;
    if settings.disabled {
        return Ok(LogGate {
            path: None,
            disabled: true,
            reason: "logging_disabled".to_string(),
        });
    }
    match settings.output.as_str() {
        "" | "stderr" | "stdout" => {
            return Ok(LogGate {
                path: None,
                disabled: true,
                reason: "log_output_not_file".to_string(),
            });
        }
        _ => {}
    }
    // sing-box opens a relative output against the process
    // working directory; the server resolves the same way.
    let base = if Path::new(&settings.output).is_absolute() {
        config_dir.to_path_buf()
    } else {
        std::env::current_dir().map_err(|_| err_internal())?
    };
    let resolved = resolve_against(&base, &settings.output);
    // A7 identity guard.
    let mut refused: Vec<String> = vec![format!("{}/config.json", config_dir.to_string_lossy())];
    for name in cfg.profile_names() {
        if let Some(p) = cfg.profiles.get(&name)
            && !p.cookies_file.is_empty()
        {
            refused.push(p.cookies_file.clone());
            refused.push(format!("{}.bak", p.cookies_file));
        }
    }
    let legacy_names = match legacy_profile_names_in(config_dir, cfg) {
        Ok(names) => names,
        Err(_) => {
            // The refused set cannot be enumerated: fail
            // the whole gate closed.
            return Ok(LogGate {
                path: None,
                disabled: true,
                reason: "log_output_refused".to_string(),
            });
        }
    };
    for name in &legacy_names {
        let paths = match profile_paths(&config_dir.to_string_lossy(), name) {
            Ok(p) => p,
            Err(_) => {
                return Ok(LogGate {
                    path: None,
                    disabled: true,
                    reason: "log_output_refused".to_string(),
                });
            }
        };
        refused.push(paths.cookies.clone());
        refused.push(format!("{}.bak", paths.cookies));
        let (forms, corrupt) = legacy_cookies_file_refusals(config_dir, &paths);
        if corrupt {
            return Ok(LogGate {
                path: None,
                disabled: true,
                reason: "log_output_refused".to_string(),
            });
        }
        refused.extend(forms);
    }
    let profiles_dir = resolve_path_best_effort(&config_dir.join("profiles"));
    if path_within(&resolved, &profiles_dir) {
        return Ok(LogGate {
            path: None,
            disabled: true,
            reason: "log_output_refused".to_string(),
        });
    }
    // Raw configured values: the parser rejects some
    // cookies_file values, but a stored document written
    // before that rule — or a legacy override — can still
    // carry one.
    if let Ok(doc) = decode_ordered_json(&load.raw) {
        for (_, v) in profile_cookies_files(&doc) {
            let mut lexical = v.clone();
            if !Path::new(&lexical).is_absolute() {
                lexical = format!("{}/{}", config_dir.to_string_lossy(), lexical);
            }
            let lexical = clean_path(Path::new(&lexical))
                .to_string_lossy()
                .into_owned();
            let resolved_raw = resolve_against(config_dir, &v);
            refused.push(lexical.clone());
            refused.push(format!("{lexical}.bak"));
            refused.push(resolved_raw.to_string_lossy().into_owned());
            refused.push(format!("{}.bak", resolved_raw.display()));
        }
    }
    let resolved_real = resolve_path_best_effort(Path::new(&resolved));
    for other in &refused {
        if same_file(Path::new(&resolved), Path::new(other))
            || resolved_real == resolve_path_best_effort(Path::new(other))
        {
            return Ok(LogGate {
                path: None,
                disabled: true,
                reason: "log_output_refused".to_string(),
            });
        }
    }
    Ok(LogGate {
        path: Some(resolved),
        disabled: false,
        reason: String::new(),
    })
}

fn disabled_envelope(reason: &str) -> Resp {
    let mut map = OrderedObject::new();
    map.set("disabled", JsonValue::Bool(true));
    map.set("entries", JsonValue::Array(Vec::new()));
    map.set("more", JsonValue::Bool(false));
    map.set("next_cursor", JsonValue::Null);
    map.set("reason", JsonValue::Str(reason.to_string()));
    envelope_resp(200, JsonValue::Object(map))
}

/// GET /logs. `query` is the query string parsed into
/// key/value pairs; `load` is the current config load.
pub fn handle_get_logs(
    config_dir: &Path,
    load: &ConfigLoad,
    query: &[(String, String)],
) -> Result<Resp, ApiError> {
    let (cfg, _) = crate::store::parse_loaded(load, config_dir)?;
    let gate = log_gate(config_dir, load, &cfg)?;
    if gate.disabled {
        return Ok(disabled_envelope(&gate.reason));
    }
    let path = gate.path.expect("gate enabled implies a path");
    let mut limit = DEFAULT_LOG_LIMIT;
    if let Some(q) = query_value(query, "limit") {
        let n: i64 = q.parse().map_err(|_| err_validation("invalid limit"))?;
        if !(1..=MAX_LOG_LIMIT).contains(&n) {
            return Err(err_validation("invalid limit"));
        }
        limit = n;
    }
    let mut level_filter = query_value(query, "level").unwrap_or_default();
    if level_filter == "all" {
        level_filter = String::new();
    }
    level_filter = normalize_level(&level_filter.to_uppercase());
    if level_filter == "warning" {
        level_filter = "warn".to_string();
    }

    let mut f = match fs::File::open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // The file is created on first write: no
            // entries yet is an empty page, not an error.
            let mut map = OrderedObject::new();
            map.set("disabled", JsonValue::Bool(false));
            map.set("entries", JsonValue::Array(Vec::new()));
            map.set("more", JsonValue::Bool(false));
            map.set("next_cursor", JsonValue::Str("0".to_string()));
            return Ok(envelope_resp(200, JsonValue::Object(map)));
        }
        Err(_) => return Err(err_internal()),
    };
    let size = f.metadata().map_err(|_| err_internal())?.len() as i64;

    let cursor = query_value(query, "cursor").unwrap_or_default();
    let (data, start_offset) = if !cursor.is_empty() {
        let offset: i64 = cursor
            .parse()
            .map_err(|_| err_validation("invalid cursor"))?;
        if offset < 0 {
            return Err(err_validation("invalid cursor"));
        }
        if offset >= size {
            // No new bytes: return the requested cursor
            // unchanged so the next poll resumes at the
            // same line boundary.
            let mut map = OrderedObject::new();
            map.set("disabled", JsonValue::Bool(false));
            map.set("entries", JsonValue::Array(Vec::new()));
            map.set("more", JsonValue::Bool(false));
            map.set("next_cursor", JsonValue::Str(offset.to_string()));
            return Ok(envelope_resp(200, JsonValue::Object(map)));
        }
        let mut n = size - offset;
        if n > MAX_LOG_READ_BYTES as i64 {
            n = MAX_LOG_READ_BYTES as i64;
        }
        let mut data = vec![0u8; n as usize];
        f.seek(std::io::SeekFrom::Start(offset as u64))
            .map_err(|_| err_internal())?;
        f.read_exact(&mut data).map_err(|_| err_internal())?;
        (data, offset)
    } else {
        let mut start_offset = 0i64;
        if size > MAX_LOG_READ_BYTES as i64 {
            start_offset = size - MAX_LOG_READ_BYTES as i64;
        }
        let n = size - start_offset;
        let mut data = vec![0u8; n as usize];
        f.seek(std::io::SeekFrom::Start(start_offset as u64))
            .map_err(|_| err_internal())?;
        f.read_exact(&mut data).map_err(|_| err_internal())?;
        (data, start_offset)
    };

    // Line-boundary discipline: a cursor is always the
    // offset just after a newline. Drop a leading partial
    // line when the window starts mid-line, and drop a
    // trailing partial line (it is delivered whole on the
    // poll after its newline lands).
    let mut window_start = start_offset;
    let mut window_end = size;
    let mut text = String::from_utf8_lossy(&data).into_owned();
    if start_offset > 0 && !text.is_empty() {
        let mut one = [0u8; 1];
        if f.seek(std::io::SeekFrom::Start((start_offset - 1) as u64))
            .is_ok()
            && f.read_exact(&mut one).is_ok()
            && one[0] != b'\n'
        {
            if let Some(i) = text.find('\n') {
                window_start += i as i64 + 1;
                text = text[i + 1..].to_string();
            } else {
                text.clear();
            }
        }
    }
    if !text.is_empty() && !text.ends_with('\n') {
        if let Some(i) = text.rfind('\n') {
            window_end = window_start + i as i64 + 1;
            text.truncate(i + 1);
        } else {
            window_end = window_start;
            text.clear();
        }
    }
    // Split into lines with their end offsets, so the
    // cursor advances only past delivered lines.
    struct LogLine {
        text: String,
        end: i64,
    }
    let mut lines: Vec<LogLine> = Vec::new();
    if !text.is_empty() {
        let mut off = window_start;
        for raw in text.strip_suffix('\n').unwrap_or(&text).split('\n') {
            off += raw.len() as i64 + 1;
            lines.push(LogLine {
                text: raw.to_string(),
                end: off,
            });
        }
    }
    // Filter BEFORE truncating.
    let mut filtered: Vec<&LogLine> = Vec::new();
    for ln in &lines {
        let entry = parse_log_line(&ln.text);
        if !level_filter.is_empty() && entry.level != level_filter {
            continue;
        }
        filtered.push(ln);
    }
    // Tail reads keep the LAST limit lines; cursor reads
    // keep the FIRST limit lines (oldest-first append
    // order). more is true only when undelivered filtered
    // lines remain in this window, or bytes remain past
    // the window end; the cursor is the end offset of the
    // last delivered line, or the window end when nothing
    // remains undelivered.
    let delivered: Vec<&LogLine>;
    let mut more = false;
    let mut next_cursor = window_end;
    if cursor.is_empty() && filtered.len() as i64 > limit {
        delivered = filtered[filtered.len() - limit as usize..].to_vec();
    } else if !cursor.is_empty() && filtered.len() as i64 > limit {
        delivered = filtered[..limit as usize].to_vec();
        more = true;
        next_cursor = delivered[delivered.len() - 1].end;
    } else {
        delivered = filtered;
    }
    if !more && window_end < size {
        more = true;
        next_cursor = window_end;
    }
    let mut entries: Vec<JsonValue> = Vec::new();
    for ln in &delivered {
        if ln.text.is_empty() {
            continue;
        }
        entries.push(parse_log_line(&ln.text).to_json());
    }
    let mut map = OrderedObject::new();
    map.set("disabled", JsonValue::Bool(false));
    map.set("entries", JsonValue::Array(entries));
    map.set("more", JsonValue::Bool(more));
    map.set("next_cursor", JsonValue::Str(next_cursor.to_string()));
    Ok(envelope_resp(200, JsonValue::Object(map)))
}

/// DELETE /logs: truncating a live log file from the web
/// UI would destroy the only record of the server's own
/// emissions. The refusal is explicit, not silent.
pub fn handle_logs_delete_refused() -> Resp {
    error_resp(
        405,
        "method_not_allowed",
        "logs cannot be cleared from the web UI",
    )
}

pub fn query_value(query: &[(String, String)], key: &str) -> Option<String> {
    query.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
}

/// Parse a raw query string the way Go's
/// `url.ParseQuery` does: `&`-separated pairs, `+` decodes
/// to a space, `%XX` percent-decoding; a pair with an
/// invalid escape is dropped silently (Go's `Query()`
/// ignores the parse error and returns what parsed). A
/// bare key with no `=` is a key with an empty value.
pub fn parse_query(raw: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    if raw.is_empty() {
        return out;
    }
    for pair in raw.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        let (Some(k), Some(v)) = (decode_query_component(k), decode_query_component(v)) else {
            continue;
        };
        out.push((k, v));
    }
    out
}

fn decode_query_component(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' => {
                if i + 2 >= bytes.len() {
                    return None;
                }
                let hi = hex_val(bytes[i + 1])?;
                let lo = hex_val(bytes[i + 2])?;
                out.push((hi << 4) | lo);
                i += 3;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn test_load(dir: &Path, raw: &[u8]) -> ConfigLoad {
        ConfigLoad {
            raw: raw.to_vec(),
            hash: String::new(),
            state: crate::guarded::ConfigState {
                found: true,
                exists: true,
                sha256: String::new(),
                raw: raw.to_vec(),
                base_dir: dir.to_path_buf(),
            },
        }
    }

    #[test]
    fn parse_log_line_full_timestamp() {
        let e = parse_log_line("+0700 2026-10-31 13:00:00 INFO sing-box: started");
        assert_eq!(e.ts, "+0700 2026-10-31 13:00:00");
        assert_eq!(e.level, "info");
        assert_eq!(e.kind, "sing-box");
        assert_eq!(e.message, "started");
    }

    #[test]
    fn parse_log_line_warning_normalises() {
        let e = parse_log_line("WARNING keeper: tick");
        assert_eq!(e.level, "warn");
        assert_eq!(e.kind, "keeper");
    }

    #[test]
    fn parse_log_line_relative_and_bare() {
        let e = parse_log_line("INFO[0001] hello");
        assert_eq!(e.level, "info");
        assert_eq!(e.message, "hello");
        let e = parse_log_line("ERROR boom");
        assert_eq!(e.level, "error");
        assert_eq!(e.message, "boom");
    }

    #[test]
    fn parse_log_line_unparseable_keeps_message() {
        let e = parse_log_line("not a log line at all");
        assert_eq!(e.level, "");
        assert_eq!(e.kind, "");
        assert_eq!(e.message, "not a log line at all");
    }

    #[test]
    fn parse_log_line_strips_ansi_and_cr() {
        let e = parse_log_line("\u{1b}[31mERROR\u{1b}[0m fail\r");
        assert_eq!(e.level, "error");
        assert_eq!(e.message, "fail");
    }

    #[test]
    fn log_gate_disabled_no_block() {
        let dir = std::env::temp_dir().join(format!("m6b-log-gate-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let cfg = castctl_config::config::SingleConfig::default();
        let load = test_load(&dir, b"{}");
        let gate = log_gate(&dir, &load, &cfg).unwrap();
        assert!(gate.disabled);
        assert_eq!(gate.reason, "logging_disabled");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn log_gate_refuses_config_file() {
        let dir = std::env::temp_dir().join(format!("m6b-log-refuse-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        // Absolute output pointing at the config file: the
        // A7 identity guard refuses it whatever the process
        // CWD is (a relative "config.json" resolves against
        // the CWD, per Go logs.go, so it cannot pin this).
        let output = dir.join("config.json");
        let doc = format!(
            "{{\"profiles\":{{}},\"log\": {{\"output\": \"{}\"}}}}",
            output.to_string_lossy()
        );
        fs::write(dir.join("config.json"), doc.as_bytes()).unwrap();
        let cfg =
            castctl_config::config::parse_single_config(doc.as_bytes(), dir.to_str().unwrap())
                .unwrap();
        let load = test_load(&dir, doc.as_bytes());
        let gate = log_gate(&dir, &load, &cfg).unwrap();
        assert!(gate.disabled);
        assert_eq!(gate.reason, "log_output_refused");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn get_logs_missing_file_empty_page() {
        let dir = std::env::temp_dir().join(format!("m6b-log-missing-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let log_path = dir.join("castctl.log");
        let doc = format!(
            "{{\"profiles\":{{}},\"log\": {{\"output\": \"{}\"}}}}",
            log_path.to_string_lossy()
        );
        let cfg =
            castctl_config::config::parse_single_config(doc.as_bytes(), dir.to_str().unwrap())
                .unwrap();
        let _ = cfg;
        let load = test_load(&dir, doc.as_bytes());
        let resp = handle_get_logs(&dir, &load, &[]).unwrap();
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body).unwrap();
        assert!(body.contains("\"next_cursor\":\"0\""));
        assert!(body.contains("\"disabled\":false"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn get_logs_tail_and_cursor() {
        let dir = std::env::temp_dir().join(format!("m6b-log-tail-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let log_path = dir.join("castctl.log");
        {
            let mut f = fs::File::create(&log_path).unwrap();
            writeln!(f, "INFO first").unwrap();
            writeln!(f, "INFO second").unwrap();
            writeln!(f, "INFO third").unwrap();
        }
        let doc = format!(
            "{{\"profiles\":{{}},\"log\": {{\"output\": \"{}\"}}}}",
            log_path.to_string_lossy()
        );
        let load = test_load(&dir, doc.as_bytes());
        let resp = handle_get_logs(&dir, &load, &[]).unwrap();
        let body = String::from_utf8(resp.body).unwrap();
        assert!(body.contains("first"));
        assert!(body.contains("third"));
        // Cursor past the end echoes the cursor back.
        let size = fs::metadata(&log_path).unwrap().len();
        let q = vec![("cursor".to_string(), size.to_string())];
        let resp = handle_get_logs(&dir, &load, &q).unwrap();
        let body = String::from_utf8(resp.body).unwrap();
        assert!(body.contains(&format!("\"next_cursor\":\"{}\"", size)));
        // Invalid cursor → 400.
        let q = vec![("cursor".to_string(), "abc".to_string())];
        assert!(handle_get_logs(&dir, &load, &q).is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
