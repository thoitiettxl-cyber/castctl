// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! System Files client (M7a): port of Go
//! `internal/fsclient` (`fsclient.go`, `editor.go`).
//!
//! `FS` is the client over one unary JSON gateway call
//! (`FsGateway::call_json`); it never opens a stream,
//! subscribes, or downloads, so the contract carries only
//! that one method (Go's `Gateway` interface, same
//! reasoning). The 12 methods are `ListDir`, `Stat`,
//! `ReadChunk`, `ReadFile`, `Search`, `Walk`, `WriteFile`,
//! `Mkdir`, `Move`, `Delete`, `Get`, `Put`.
//!
//! Deliberate adaptations (recorded in PORTING.md §M7a):
//! - Go's `context.Context` is dropped: cancellation is by
//!   dropping the future, as everywhere else in the Rust
//!   port. The one Go test asserting a cancelled context
//!   errors is not portable and is recorded, not ported.
//! - Go's `ChunkSize` / `WriteChunkSize` package variables
//!   are per-`FS` constructor parameters here (same
//!   defaults, same `<= 0` → default rule): mutable
//!   globals would make tests order-dependent.
//! - Go's `FS` is built with `New(gw)` where `gw` may be
//!   nil; here the gateway is `Option<Arc<G>>` and a
//!   `None` gateway fails every method with the same
//!   `fsclient: nil gateway` text.
//! - Local-filesystem error text differs from Go's
//!   `*PathError` rendering (Rust's `io::Error` prints
//!   `No such file or directory (os error 2)` where Go
//!   prints `open <path>: no such file or directory`);
//!   the error kind and the failing operation are the
//!   same, only the platform rendering differs.
//!
//! No `unsafe`, no `unwrap()`/`expect()` on external input.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use castctl_config::gopath::go_clean;
use castctl_transport::TransportError;
use serde_json::Value;

pub mod editor;

/// The `fs.read` window, ported from `fs.py`'s `CHUNK`
/// (Go `fsclient.go:16` `ChunkSize` = 4 MiB).
pub const CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// The raw bytes per `fs.write` call, ported from
/// `fs.py`'s `WRITE_CHUNK` (Go `fsclient.go:22`
/// `WriteChunkSize` = 1 MiB).
pub const WRITE_CHUNK_SIZE: usize = 1024 * 1024;

/// Bounds one `fs.read` call (Go `readTimeout` = 120s).
pub const READ_TIMEOUT: Duration = Duration::from_secs(120);

/// Bounds one `fs.write` call (Go `writeTimeout` = 120s).
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(120);

/// Bounds the remaining `fs.*` calls (Go `callTimeout` =
/// 60s).
pub const CALL_TIMEOUT: Duration = Duration::from_secs(60);

/// The unlimited-walk sentinel (Go `unlimitedDepth` = -1):
/// only internal callers (`Get`) may pass it. CLI depths
/// are clamped by the command layer before they reach
/// `Walk`.
pub const UNLIMITED_DEPTH: i64 = -1;

/// Errors from the FS client. `Transport` carries a
/// gateway failure verbatim (so the CLI can still
/// classify auth); `Io` carries a local-filesystem
/// failure verbatim (Go returns the raw `os` error too);
/// `Other` carries a plain message or a wrapped error
/// (e.g. a test sentinel).
#[derive(Debug)]
pub enum FsError {
    /// A gateway failure, verbatim.
    Transport(TransportError),
    /// A local-filesystem failure, verbatim.
    Io(std::io::Error),
    /// A plain message or wrapped error.
    Other(Arc<dyn Error + Send + Sync>),
}

impl FsError {
    /// A plain-message error (Go's `fmt.Errorf` /
    /// `errors.New` with a literal).
    pub fn msg(message: impl Into<String>) -> FsError {
        FsError::Other(Arc::new(MsgError(message.into())))
    }

    /// Whether this error is an auth failure (Go
    /// `errors.As(err, &AuthError)`).
    pub fn is_auth(&self) -> bool {
        matches!(self, FsError::Transport(TransportError::Auth { .. }))
    }

    /// Downcast the wrapped error of an `Other` error, if
    /// it is of type `T` (the `errors.Is` / `errors.As`
    /// equivalent for carried sentinels).
    pub fn other_as<T: Error + 'static>(&self) -> Option<&T> {
        match self {
            FsError::Other(e) => e.downcast_ref::<T>(),
            _ => None,
        }
    }
}

/// A plain-message error value.
#[derive(Debug)]
struct MsgError(String);

impl fmt::Display for MsgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for MsgError {}

impl fmt::Display for FsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FsError::Transport(e) => fmt::Display::fmt(e, f),
            FsError::Io(e) => fmt::Display::fmt(e, f),
            FsError::Other(e) => fmt::Display::fmt(e, f),
        }
    }
}

impl Error for FsError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            FsError::Transport(e) => Some(e),
            FsError::Io(e) => Some(e),
            FsError::Other(e) => Some(e.as_ref() as &(dyn Error + 'static)),
        }
    }
}

impl From<TransportError> for FsError {
    fn from(e: TransportError) -> FsError {
        FsError::Transport(e)
    }
}

impl From<std::io::Error> for FsError {
    fn from(e: std::io::Error) -> FsError {
        FsError::Io(e)
    }
}

/// The narrow gateway contract FS needs: one unary JSON
/// call (Go `fsclient.Gateway`). The body is a JSON
/// object; the result must be a JSON object.
pub trait FsGateway: Send + Sync {
    /// One `fs.*` call. `timeout` bounds the call.
    fn call_json(
        &self,
        method: &str,
        body: Value,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<Value, FsError>> + Send + '_>>;
}

/// Normalizes a remote path, ported verbatim from
/// `fs.py:6-15` (Go `Norm`): strips surrounding
/// whitespace, maps backslashes to slashes, strips one
/// leading `sandbox://` prefix, and resolves `.` and
/// duplicate slashes against the root, so `/` and `""`
/// both become `""` and `/config/home.yaml` becomes
/// `config/home.yaml`. A `..` segment that survives
/// rooting is a traversal error; for rooted input
/// `go_clean` clamps `..` away (`norm("../etc")` is
/// `"etc"`), so the error is unreachable in practice but
/// is kept, as in Python, so the check fails closed if
/// the rooting ever changes. POSIX paths always, even on
/// non-POSIX hosts.
pub fn norm(p: &str) -> Result<String, FsError> {
    let s = p.trim();
    let s = s.replace('\\', "/");
    let s = s.strip_prefix("sandbox://").unwrap_or(&s).to_string();
    let mut cleaned = go_clean(&format!("/{s}"));
    if cleaned.starts_with('/') {
        cleaned = cleaned[1..].to_string();
    }
    if cleaned == "." {
        cleaned = String::new();
    }
    for part in cleaned.split('/') {
        if part == ".." {
            return Err(FsError::msg(format!(
                "path traversal not allowed: {}",
                python_repr(p)
            )));
        }
    }
    Ok(cleaned)
}

/// Renders `s` the way Python's `repr()` renders a str
/// for the common cases (Go `pythonRepr`): single quotes,
/// with backslash, single-quote, newline,
/// carriage-return and tab escaped.
pub fn python_repr(s: &str) -> String {
    let mut b = String::with_capacity(s.len() + 2);
    b.push('\'');
    for r in s.chars() {
        match r {
            '\\' => b.push_str("\\\\"),
            '\'' => b.push_str("\\'"),
            '\n' => b.push_str("\\n"),
            '\r' => b.push_str("\\r"),
            '\t' => b.push_str("\\t"),
            _ => b.push(r),
        }
    }
    b.push('\'');
    b
}

/// Go's `%T` for a decoded JSON value (the `not an
/// object` / `not an array` errors): numbers decode as
/// `json.Number` (Go `decodeJSONValue` uses `UseNumber`),
/// never `float64`.
pub fn go_type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "<nil>",
        Value::Bool(_) => "bool",
        Value::Number(_) => "json.Number",
        Value::String(_) => "string",
        Value::Array(_) => "[]interface {}",
        Value::Object(_) => "map[string]interface {}",
    }
}

/// Escape one string the way Go's `encoding/json`
/// marshals it: `"` → `\"`, `\` → `\\`, control chars →
/// `\b` / `\f` / `\n` / `\r` / `\t` / `\u00XX`, and `<`
/// `>` `&` → `\u003c` `\u003e` `\u0026` (HTML escaping is
/// ON for plain `json.Marshal` — unlike the wait output,
/// which sets `SetEscapeHTML(false)`).
pub fn go_json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            // Go `encoding/json` short escapes
            // (`appendString`, `encode.go:1012-1015`):
            // `\b` and `\f` are NOT `\u0008`/`\u000c`.
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Marshal one decoded JSON value the way Go's
/// `json.Marshal` does (HTML escaping on, numbers kept
/// as literals). Object keys render in sorted order
/// (`serde_json::Map` is a `BTreeMap` without the
/// `preserve_order` feature, and Go sorts map keys too).
pub fn go_json_value(v: &Value) -> String {
    match v {
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => go_json_string(s),
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(go_json_value).collect();
            format!("[{}]", parts.join(","))
        }
        Value::Object(obj) => {
            let parts: Vec<String> = obj
                .iter()
                .map(|(k, val)| format!("{}:{}", go_json_string(k), go_json_value(val)))
                .collect();
            format!("{{{}}}", parts.join(","))
        }
    }
}

/// One `fs.list` / `fs.search` entry (Go `Entry`).
/// `Name`, `Type`, `Size` and `ModifiedAt` are the fields
/// the fs commands read; every other server field is
/// preserved verbatim in `Extra` so `--json` output keeps
/// it. JSON field order is name, type, size, modifiedAt,
/// then Extra keys in sorted order; a hand-built Extra key
/// never shadows a known field.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Entry {
    /// The entry's file name (never a path).
    pub name: String,
    /// The entry's type (`"file"`, `"directory"`, ...), or
    /// `""` when the server sent none.
    pub entry_type: String,
    /// The entry's size in bytes, or `None` when the
    /// server sent none.
    pub size: Option<i64>,
    /// The entry's modification timestamp string, or `""`
    /// when the server sent none.
    pub modified_at: String,
    /// Every server field beyond the four above, decoded
    /// verbatim.
    pub extra: BTreeMap<String, Value>,
}

impl Entry {
    /// Marshal an entry with the known fields first (in
    /// struct order) and Extra keys after, sorted (Go
    /// `Entry.MarshalJSON`).
    pub fn to_json(&self) -> String {
        let mut b = String::new();
        b.push_str("{\"name\":");
        b.push_str(&go_json_string(&self.name));
        if !self.entry_type.is_empty() {
            b.push_str(",\"type\":");
            b.push_str(&go_json_string(&self.entry_type));
        }
        if let Some(size) = self.size {
            b.push_str(",\"size\":");
            b.push_str(&size.to_string());
        }
        if !self.modified_at.is_empty() {
            b.push_str(",\"modifiedAt\":");
            b.push_str(&go_json_string(&self.modified_at));
        }
        for (k, v) in &self.extra {
            match k.as_str() {
                "name" | "type" | "size" | "modifiedAt" => continue,
                _ => {}
            }
            b.push(',');
            b.push_str(&go_json_string(k));
            b.push(':');
            b.push_str(&go_json_value(v));
        }
        b.push('}');
        b
    }
}

/// Convert one decoded entry object into an `Entry`,
/// keeping unknown fields in `Extra` (Go `decodeEntry`).
pub fn decode_entry(v: &Value) -> Result<Entry, FsError> {
    let m = match v.as_object() {
        Some(m) => m,
        None => {
            return Err(FsError::msg(format!(
                "fsclient: entry is {}, want object",
                go_type_name(v)
            )));
        }
    };
    let mut e = Entry::default();
    if let Some(s) = m.get("name").and_then(Value::as_str) {
        e.name = s.to_string();
    }
    if let Some(s) = m.get("type").and_then(Value::as_str) {
        e.entry_type = s.to_string();
    }
    if let Some(n) = m.get("size").and_then(number_value) {
        e.size = Some(n);
    }
    if let Some(s) = m.get("modifiedAt").and_then(Value::as_str) {
        e.modified_at = s.to_string();
    }
    for (k, val) in m {
        match k.as_str() {
            "name" | "type" | "size" | "modifiedAt" => continue,
            _ => {}
        }
        e.extra.insert(k.clone(), val.clone());
    }
    Ok(e)
}

/// Convert a decoded JSON number to `i64`, truncating a
/// fractional part toward zero (Go `numberValue`).
/// Non-numbers report `None`.
pub fn number_value(v: &Value) -> Option<i64> {
    match v {
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Some(i)
            } else {
                n.as_f64().map(|f| f as i64)
            }
        }
        _ => None,
    }
}

/// Extract the `"entries"` list of an `fs.list` /
/// `fs.search` result (Go `decodeEntries`). A missing
/// entries key yields no entries; a non-object result or
/// a non-object entry is an error.
pub fn decode_entries(result: &Value, method: &str) -> Result<Vec<Entry>, FsError> {
    let m = match result.as_object() {
        Some(m) => m,
        None => {
            return Err(FsError::msg(format!(
                "fsclient: {method}: response is {}, want object",
                go_type_name(result)
            )));
        }
    };
    let raw = match m.get("entries") {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(raw) => raw,
    };
    let list = match raw.as_array() {
        Some(list) => list,
        None => {
            return Err(FsError::msg(format!(
                "fsclient: {method}: entries is {}, want array",
                go_type_name(raw)
            )));
        }
    };
    let mut entries = Vec::with_capacity(list.len());
    for (i, item) in list.iter().enumerate() {
        match decode_entry(item) {
            Ok(e) => entries.push(e),
            Err(e) => {
                return Err(FsError::msg(format!("fsclient: {method}: entry {i}: {e}")));
            }
        }
    }
    Ok(entries)
}

/// Mirrors Python's `bool()` for the values a server flag
/// may carry (Go `truthyValue`): nil/false/0/`""` are
/// false, everything else true.
pub fn truthy_value(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::String(s) => !s.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(obj) => !obj.is_empty(),
        Value::Number(_) => number_value(v).map(|n| n != 0).unwrap_or(true),
    }
}

/// One step of a depth-first walk (Go `WalkEntry`): the
/// entry's path relative to the System Files root, the
/// entry itself, and its depth level (0 for the top
/// directory's children).
#[derive(Debug, Clone)]
pub struct WalkEntry {
    /// The entry path relative to the root, e.g.
    /// `"memory/a/b.md"`.
    pub rel: String,
    /// The listed entry.
    pub entry: Entry,
    /// 0 for children of the walked path, 1 for their
    /// children, and so on.
    pub level: i64,
}

/// The result of `WriteFile` (Go `WriteResult`): the
/// written path with a leading slash and the number of
/// bytes written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteResult {
    /// The written path with a leading slash.
    pub path: String,
    /// The number of bytes written.
    pub bytes_written: i64,
}

impl WriteResult {
    /// Marshal as Go's `json.Marshal` does
    /// (`{"path":...,"bytes_written":...}`).
    pub fn to_json(&self) -> String {
        format!(
            "{{\"path\":{},\"bytes_written\":{}}}",
            go_json_string(&self.path),
            self.bytes_written
        )
    }
}

/// The System Files client, ported from `fs.py`'s `FS`
/// class (Go `FS`). An `FS` is safe for concurrent use
/// when its gateway is.
pub struct Fs<G: FsGateway> {
    gw: Option<Arc<G>>,
    chunk_size: usize,
    write_chunk_size: usize,
}

impl<G: FsGateway> Fs<G> {
    /// Build an `FS` over `gw` (Go `New`). A `None`
    /// gateway is accepted and makes every method return
    /// an error instead of panicking.
    pub fn new(gw: Option<Arc<G>>) -> Self {
        Fs {
            gw,
            chunk_size: CHUNK_SIZE,
            write_chunk_size: WRITE_CHUNK_SIZE,
        }
    }

    /// Build an `FS` with explicit chunk sizes (Go's
    /// `ChunkSize` / `WriteChunkSize` package variables,
    /// per-instance here). A zero size behaves as the
    /// default, so a mis-set size can never wedge
    /// `ReadFile` in an empty-chunk loop.
    pub fn with_chunk_sizes(
        gw: Option<Arc<G>>,
        chunk_size: usize,
        write_chunk_size: usize,
    ) -> Self {
        Fs {
            gw,
            chunk_size,
            write_chunk_size,
        }
    }

    fn read_chunk_size(&self) -> usize {
        if self.chunk_size == 0 {
            CHUNK_SIZE
        } else {
            self.chunk_size
        }
    }

    fn write_chunk_size(&self) -> usize {
        if self.write_chunk_size == 0 {
            WRITE_CHUNK_SIZE
        } else {
            self.write_chunk_size
        }
    }

    /// One `fs.*` call, returning its decoded object
    /// result (Go `FS.call`). A nil gateway, a non-object
    /// result, and a gateway error are all errors.
    async fn call(&self, method: &str, body: Value, timeout: Duration) -> Result<Value, FsError> {
        let gw = match &self.gw {
            Some(gw) => gw,
            None => return Err(FsError::msg("fsclient: nil gateway")),
        };
        let result = gw.call_json(method, body, timeout).await?;
        match result.as_object() {
            Some(_) => Ok(result),
            None => Err(FsError::msg(format!(
                "fsclient: {method}: response is {}, want object",
                go_type_name(&result)
            ))),
        }
    }

    /// List a remote directory (Go `ListDir`): `fs.list`
    /// with the normalized path, returning the entries
    /// list (empty when the server sends none).
    pub async fn list_dir(&self, path: &str) -> Result<Vec<Entry>, FsError> {
        let p = norm(path)?;
        let result = self
            .call("fs.list", serde_json::json!({"path": p}), CALL_TIMEOUT)
            .await?;
        decode_entries(&result, "fs.list")
    }

    /// Stat a remote path (Go `Stat`): `fs.stat` with the
    /// normalized path, returning the server's result
    /// object verbatim.
    pub async fn stat(&self, path: &str) -> Result<Value, FsError> {
        let p = norm(path)?;
        self.call("fs.stat", serde_json::json!({"path": p}), CALL_TIMEOUT)
            .await
    }

    /// Read one window of a remote file (Go `ReadChunk`):
    /// `fs.read` with offset/len, a 120s timeout, and a
    /// base64-decoded body. Returns the bytes and whether
    /// the server reported end-of-file (defaulting to
    /// `true` when the server sends no eof flag).
    pub async fn read_chunk(
        &self,
        path: &str,
        offset: i64,
        length: i64,
    ) -> Result<(Vec<u8>, bool), FsError> {
        let p = norm(path)?;
        let result = self
            .call(
                "fs.read",
                serde_json::json!({"path": p, "offset": offset, "len": length}),
                READ_TIMEOUT,
            )
            .await?;
        let encoded = result
            .get("data_base64")
            .and_then(Value::as_str)
            .unwrap_or("");
        // Python's b64decode (validate=False) ignores
        // whitespace; strip it so wrapped base64 decodes.
        let stripped: String = encoded
            .chars()
            .filter(|c| !matches!(c, ' ' | '\t' | '\n' | '\r' | '\x0c' | '\x0b'))
            .collect();
        let data = base64::engine::general_purpose::STANDARD
            .decode(&stripped)
            .map_err(|e| FsError::msg(format!("fsclient: fs.read: decode data_base64: {e}")))?;
        let eof = match result.get("eof") {
            Some(v) => truthy_value(v),
            None => true,
        };
        Ok((data, eof))
    }

    /// Read a whole remote file (Go `ReadFile`): loops
    /// `ReadChunk` windows to EOF or an empty chunk,
    /// stopping early once `max_bytes` bytes have been
    /// read. A `None` max reads to EOF; a non-positive max
    /// reads nothing and makes no call.
    pub async fn read_file(&self, path: &str, max_bytes: Option<i64>) -> Result<Vec<u8>, FsError> {
        let mut out: Vec<u8> = Vec::new();
        let mut off: i64 = 0;
        loop {
            let n = match max_bytes {
                None => self.read_chunk_size() as i64,
                Some(max) => std::cmp::min(self.read_chunk_size() as i64, max - off),
            };
            if n <= 0 {
                break;
            }
            let (data, eof) = self.read_chunk(path, off, n).await?;
            let len = data.len() as i64;
            out.extend_from_slice(&data);
            off += len;
            if eof || data.is_empty() {
                break;
            }
        }
        Ok(out)
    }

    /// Search remote file names (Go `Search`): `fs.search`
    /// with `{name: {contains}}`, plus `"limit"` only when
    /// limit is positive.
    pub async fn search(&self, contains: &str, limit: i64) -> Result<Vec<Entry>, FsError> {
        let mut body = serde_json::json!({"name": {"contains": contains}});
        if limit > 0
            && let Some(obj) = body.as_object_mut()
        {
            obj.insert("limit".to_string(), Value::from(limit));
        }
        let result = self.call("fs.search", body, CALL_TIMEOUT).await?;
        decode_entries(&result, "fs.search")
    }

    /// List a subtree depth-first (Go `Walk`). `depth`
    /// caps recursion: a directory at level L is
    /// descended into only when depth is negative
    /// (unlimited, the internal sentinel) or `L+1 <
    /// depth`, so depth 1 yields only the top directory's
    /// children and depth 2 yields two levels. A negative
    /// depth is unlimited ONLY as the internal sentinel:
    /// the command layer must clamp negative CLI depths to
    /// 0 before calling `Walk`.
    pub async fn walk(&self, path: &str, depth: i64) -> Result<Vec<WalkEntry>, FsError> {
        let base = norm(path)?;
        let mut out = Vec::new();
        self.walk_into(&base, 0, depth, &mut out).await?;
        Ok(out)
    }

    async fn walk_into(
        &self,
        base: &str,
        level: i64,
        depth: i64,
        out: &mut Vec<WalkEntry>,
    ) -> Result<(), FsError> {
        let entries = self.list_dir(base).await?;
        for e in entries {
            let rel = if base.is_empty() {
                e.name.clone()
            } else {
                format!("{base}/{}", e.name)
            };
            let is_dir = e.entry_type == "directory";
            out.push(WalkEntry {
                rel: rel.clone(),
                entry: e,
                level,
            });
            if is_dir && (depth < 0 || level + 1 < depth) {
                Box::pin(self.walk_into(&rel, level + 1, depth, out)).await?;
            }
        }
        Ok(())
    }

    /// Write data to a remote path (Go `WriteFile`). Data
    /// is sent in `write_chunk_size` raw-byte chunks,
    /// each base64-encoded with a 120s timeout. The first
    /// chunk carries the caller's overwrite flag and
    /// `create_parent`; later chunks carry
    /// `overwrite=true` and `append=true`. Empty data
    /// still makes one (empty) call. The server's
    /// per-chunk replies are discarded; the returned
    /// result is built locally.
    pub async fn write_file(
        &self,
        path: &str,
        data: &[u8],
        overwrite: bool,
        create_parent: bool,
    ) -> Result<WriteResult, FsError> {
        let p = norm(path)?;
        let mut off: usize = 0;
        let mut first = true;
        while first || off < data.len() {
            let end = std::cmp::min(off + self.write_chunk_size(), data.len());
            let part = &data[off..end];
            let chunk_overwrite = if first { overwrite } else { true };
            let encoded = base64::engine::general_purpose::STANDARD.encode(part);
            self.call(
                "fs.write",
                serde_json::json!({
                    "path": p,
                    "overwrite": chunk_overwrite,
                    "append": !first,
                    "create_parent": create_parent,
                    "data_base64": encoded,
                }),
                WRITE_TIMEOUT,
            )
            .await?;
            off = end;
            first = false;
        }
        Ok(WriteResult {
            path: format!("/{p}"),
            bytes_written: data.len() as i64,
        })
    }

    /// Create a remote directory (Go `Mkdir`): `fs.mkdir`
    /// with the normalized path and the recursive flag.
    /// The server's result object passes through verbatim.
    pub async fn mkdir(&self, path: &str, parents: bool) -> Result<Value, FsError> {
        let p = norm(path)?;
        self.call(
            "fs.mkdir",
            serde_json::json!({"path": p, "recursive": parents}),
            CALL_TIMEOUT,
        )
        .await
    }

    /// Rename a remote path (Go `Move`). The method is
    /// `fs.rename` — routes.json has no `fs.move` — with
    /// source, destination, overwrite and create_parent,
    /// all paths normalized.
    pub async fn move_path(
        &self,
        src: &str,
        dst: &str,
        overwrite: bool,
        create_parent: bool,
    ) -> Result<Value, FsError> {
        let source = norm(src)?;
        let destination = norm(dst)?;
        self.call(
            "fs.rename",
            serde_json::json!({
                "source": source,
                "destination": destination,
                "overwrite": overwrite,
                "create_parent": create_parent,
            }),
            CALL_TIMEOUT,
        )
        .await
    }

    /// Delete a remote path (Go `Delete`): `fs.delete`
    /// with the normalized path and the recursive flag.
    pub async fn delete(&self, path: &str, recursive: bool) -> Result<Value, FsError> {
        let p = norm(path)?;
        self.call(
            "fs.delete",
            serde_json::json!({"path": p, "recursive": recursive}),
            CALL_TIMEOUT,
        )
        .await
    }

    /// Download a remote file (or, with recursive, a
    /// folder) into a local destination (Go `Get`). Returns
    /// the local paths written. For a folder, the
    /// destination gains a subdirectory named after the
    /// folder (`"system-files"` for the root) and the
    /// folder structure is kept; for a file, the
    /// destination is a directory to place the file in, or
    /// the exact file path when it is not an existing
    /// directory. Files are written directly, with no
    /// `.part` staging, no skip-if-exists and no byte_len
    /// warning. A folder without recursive is an error
    /// naming the original path argument.
    pub async fn get(
        &self,
        path: &str,
        dest: &std::path::Path,
        recursive: bool,
    ) -> Result<Vec<std::path::PathBuf>, FsError> {
        let p = norm(path)?;
        let st = self.stat(&p).await?;
        let name = if p.is_empty() {
            "system-files".to_string()
        } else {
            posix_base(&p).to_string()
        };
        let kind = st.get("kind").and_then(Value::as_str).unwrap_or("");
        if kind == "dir" || kind == "directory" {
            if !recursive {
                return Err(FsError::msg(format!("{path} is a folder; use -r")));
            }
            let root = dest.join(&name);
            std::fs::create_dir_all(&root)?;
            let entries = self.walk(&p, UNLIMITED_DEPTH).await?;
            let mut got = Vec::new();
            for we in entries {
                let suffix = we
                    .rel
                    .strip_prefix(p.as_str())
                    .unwrap_or(we.rel.as_str())
                    .trim_start_matches('/');
                let parts: Vec<&str> = suffix.split('/').collect();
                let mut local = root.clone();
                for part in parts {
                    local.push(part);
                }
                if we.entry.entry_type == "directory" {
                    std::fs::create_dir_all(&local)?;
                    continue;
                }
                if let Some(parent) = local.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let data = self.read_file(&we.rel, None).await?;
                std::fs::write(&local, data)?;
                got.push(local);
            }
            return Ok(got);
        }
        let mut local = dest.to_path_buf();
        if let Ok(meta) = std::fs::metadata(dest)
            && meta.is_dir()
        {
            local = dest.join(&name);
        }
        let data = self.read_file(&p, None).await?;
        std::fs::write(&local, data)?;
        Ok(vec![local])
    }

    /// Upload a local file (or, with recursive, a folder)
    /// to a remote path (Go `Put`). For a folder, every
    /// local directory is created remotely (parents
    /// included) and every file is written under the
    /// matching remote directory; for a file, the single
    /// file is written to the normalized remote path.
    /// Returns one `WriteResult` per file written. A
    /// folder without recursive is an error naming the
    /// local path. A symlink to a directory inside the
    /// walked folder is skipped silently; a symlink to a
    /// file uploads the target content as a file.
    pub async fn put(
        &self,
        local: &std::path::Path,
        remote: &str,
        recursive: bool,
        overwrite: bool,
    ) -> Result<Vec<WriteResult>, FsError> {
        let r = norm(remote)?;
        let meta = std::fs::metadata(local)?;
        if meta.is_dir() {
            if !recursive {
                return Err(FsError::msg(format!(
                    "{} is a folder; use -r",
                    local.display()
                )));
            }
            // Lstat the root BEFORE walking: Go's
            // `filepath.WalkDir` Lstats the root, so a
            // symlink-to-directory root is a symlink
            // entry (not a directory entry) and the walk
            // never descends — nothing is uploaded
            // (`fsclient.go:707-738`). `metadata` above
            // follows the link, so without this check
            // the whole target tree would be uploaded
            // (red-team F2, fix loop 1). The
            // recursive check above stays first: Go
            // errors on a non-recursive folder put
            // before walking.
            let root_is_symlink = std::fs::symlink_metadata(local)
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false);
            if root_is_symlink {
                return Ok(vec![]);
            }
            let items = walk_local_dir(local)?;
            let mut done = Vec::new();
            for item in items {
                if item.is_symlink {
                    let is_dir_target = std::fs::metadata(&item.path)
                        .map(|m| m.is_dir())
                        .unwrap_or(false);
                    if is_dir_target {
                        // A symlink to a directory:
                        // listed without descending and
                        // never uploaded, mirroring Python.
                        continue;
                    }
                    // A broken symlink, or a symlink to a
                    // file: fall through. Reading follows
                    // the link for a file and errors for a
                    // broken one, as Python's open() does.
                }
                let rd = if item.rel_slash == "." {
                    r.clone()
                } else {
                    posix_join(&r, &item.rel_slash)
                };
                if item.is_dir {
                    self.mkdir(&rd, true).await?;
                    continue;
                }
                let data = std::fs::read(&item.path)?;
                let res = self.write_file(&rd, &data, overwrite, true).await?;
                done.push(res);
            }
            return Ok(done);
        }
        let data = std::fs::read(local)?;
        let res = self.write_file(&r, &data, overwrite, true).await?;
        Ok(vec![res])
    }
}

/// The POSIX base name of a normalized remote path (Go
/// `posixpath.Base`): the part after the last `/`.
pub fn posix_base(p: &str) -> &str {
    match p.rfind('/') {
        Some(i) => &p[i + 1..],
        None => p,
    }
}

/// Join POSIX path elements, ignoring empty ones, then
/// clean (Go `posixpath.Join`).
pub fn posix_join(a: &str, b: &str) -> String {
    if a.is_empty() {
        return go_clean(b);
    }
    if b.is_empty() {
        return go_clean(a);
    }
    go_clean(&format!("{a}/{b}"))
}

/// One entry of a local directory walk for `Put` (Go
/// `filepath.WalkDir`, lexical order, depth-first
/// pre-order).
struct LocalWalkItem {
    /// Absolute local path.
    path: std::path::PathBuf,
    /// Path relative to the walk root, `/`-separated
    /// (`"."` for the root itself).
    rel_slash: String,
    /// True for a real directory (never for a symlink).
    is_dir: bool,
    /// True when the entry itself is a symlink.
    is_symlink: bool,
}

/// Walk a local directory the way Go's
/// `filepath.WalkDir` does: lexical order at each level,
/// depth-first pre-order, root first. Symlinks are never
/// followed (`file_type` from the directory entry, not
/// `metadata`).
fn walk_local_dir(root: &std::path::Path) -> Result<Vec<LocalWalkItem>, FsError> {
    let mut out = Vec::new();
    out.push(LocalWalkItem {
        path: root.to_path_buf(),
        rel_slash: ".".to_string(),
        is_dir: true,
        is_symlink: false,
    });
    collect_local_dir(root, "", &mut out)?;
    Ok(out)
}

fn collect_local_dir(
    dir: &std::path::Path,
    prefix: &str,
    out: &mut Vec<LocalWalkItem>,
) -> Result<(), FsError> {
    let mut entries: Vec<std::fs::DirEntry> = std::fs::read_dir(dir)?.collect::<Result<_, _>>()?;
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let ft = e.file_type()?;
        let name = e.file_name().to_string_lossy().into_owned();
        let rel = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let is_symlink = ft.is_symlink();
        let is_dir = ft.is_dir();
        out.push(LocalWalkItem {
            path: e.path(),
            rel_slash: rel.clone(),
            is_dir,
            is_symlink,
        });
        if is_dir {
            collect_local_dir(&e.path(), &rel, out)?;
        }
    }
    Ok(())
}
