// Copyright (C) 2026 castctl contributors
// SPDX-License-Identifier: GPL-3.0-only

//! Strict sing-box option validation (M7f).
//!
//! Go's `ParseSingleConfig` validates the `outbounds` / `endpoints` /
//! `dns` sections (and per-profile `dns` / inline `outbound`) with the
//! sing-box option decoders, which are built on the context-JSON fork of
//! `encoding/json` plus `badjson` excluded-field decoding. The error
//! texts are byte-identical to Go's: wrong types, unknown fields,
//! unknown dispatch types, and the value-validated custom types all
//! render exactly as the Go decoder renders them.
//!
//! Error model (derived from `sing/common/json` +
//! `sing/common/json/badjson` + Go 1.27 `encoding/json/decode.go`):
//!
//! * **Saved** errors get the JSON path at the save point (as a
//!   `contextError` prefix) and, for `UnmarshalTypeError`s, the
//!   `Go struct field <Struct>.<Field>` stamp from the decoder's
//!   `errorContext` at that point. Saved errors include wrong-type
//!   errors, unknown-field errors, and `UnmarshalJSON` /
//!   `UnmarshalJSONContext` errors.
//! * **Returned** errors propagate verbatim with no path and no stamp:
//!   exactly the `encoding.TextUnmarshaler` errors (`netip.ParseAddr`,
//!   `netip.ParsePrefix`, `netip.ParseAddrPort` / `not an ip:port`).
//! * Each fresh `UnmarshalContext` (a dispatch level, a `Listable`
//!   attempt, a `TypedMap` value decode, a custom unmarshaler's inner
//!   decode) renders its errors relative to its own root; the outer
//!   decoder only prepends its own JSON path (joined with `.` when the
//!   inner error already carries a path, with `: ` otherwise) and never
//!   re-stamps the inner `Struct` / `Field`.
//!
//! `SbErr` carries exactly those four shapes. Field validators inside
//! one struct decode render with the full path immediately (the walker
//! threads the whole context); fresh-boundary validators run with an
//! empty context and the caller applies [`save`] to merge the result
//! into the outer context.

use crate::gostr::go_quote;
use crate::jsonvalue::JsonValue;
use crate::singbox_tables as tables;

// ---------------------------------------------------------------------------
// Error model
// ---------------------------------------------------------------------------

/// One sing-box validation failure, in Go-decoder coordinates.
///
/// * `Pathed` — fully rendered, carrying its own JSON path
///   (`servers[0].bogus: json: unknown field "bogus"`). An outer decoder
///   only prepends its own path with `.`.
/// * `BareUte` — a bare `UnmarshalTypeError` from a fresh decode's
///   top-level value (`json: cannot unmarshal number into Go value of
///   type option._Outbound` once stamped). The outer decoder stamps it
///   with its own `(Struct, FieldStack)` and prepends its path with
///   `: `.
/// * `Bare` — a bare custom error (`unknown outbound type: socks`).
///   The outer decoder prepends its path with `: `.
/// * `Returned` — a `TextUnmarshaler` error (`netip.ParsePrefix("bad"):
///   no '/'`, `not an ip:port`). Verbatim forever: no path, no stamp.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SbErr {
    Pathed(String),
    BareUte { value: String, typ: String },
    Bare(String),
    Returned(String),
}

impl SbErr {
    /// Render the error as the final message text (for a top-level
    /// caller such as `parse dns:` / `parse outbound:`).
    pub fn text(self) -> String {
        match self {
            SbErr::Pathed(s) | SbErr::Bare(s) | SbErr::Returned(s) => s,
            SbErr::BareUte { value, typ } => {
                format!("json: cannot unmarshal {value} into Go value of type {typ}")
            }
        }
    }
}

/// One JSON-path segment (the context-JSON `decodePathSegment`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Seg {
    Key(String),
    Idx(usize),
}

/// Decoder context: the JSON path plus the `errorContext` (Struct /
/// FieldStack) at the current point. Threaded through one struct
/// decode; reset to empty at every fresh `UnmarshalContext` boundary.
#[derive(Clone, Debug, Default)]
pub struct Ctx {
    pub path: Vec<Seg>,
    pub struct_name: Option<&'static str>,
    pub field_stack: Vec<String>,
}

impl Ctx {
    pub fn fresh() -> Ctx {
        Ctx::default()
    }

    /// Render the JSON path the way `contextError` does: first simple
    /// key bare, later simple keys `.key`, non-simple keys `["key"]`
    /// (Go-quoted), indices `[i]` appended directly.
    pub fn fmt_path(&self) -> String {
        let mut out = String::new();
        for seg in &self.path {
            match seg {
                Seg::Key(k) => {
                    if is_simple_key(k) {
                        if !out.is_empty() {
                            out.push('.');
                        }
                        out.push_str(k);
                    } else {
                        out.push('[');
                        out.push_str(&go_quote(k));
                        out.push(']');
                    }
                }
                Seg::Idx(i) => {
                    out.push('[');
                    out.push_str(&i.to_string());
                    out.push(']');
                }
            }
        }
        out
    }

    /// The `Go struct field <Struct>.<Field>` stamp for a
    /// `UnmarshalTypeError` saved in this context, or `None` when the
    /// context is empty (top-level value: the `Go value` form).
    pub fn ute_stamp(&self) -> Option<String> {
        let s = self.struct_name?;
        Some(format!("{s}.{}", self.field_stack.join(".")))
    }
}

pub fn is_simple_key(k: &str) -> bool {
    !k.is_empty() && !k.contains(['.', '[', ']'])
}

/// The `UnmarshalTypeError` value description for a JSON value:
/// `string`, `bool`, `array`, `object`, `number`, or
/// `number <literal>` (the literal only for int/uint targets — the
/// caller picks via [`num_value`]).
pub fn kind_desc(v: &JsonValue) -> &'static str {
    match v {
        JsonValue::Null => "null",
        JsonValue::Bool(_) => "bool",
        JsonValue::Str(_) => "string",
        JsonValue::Number(_) => "number",
        JsonValue::Array(_) => "array",
        JsonValue::Object(_) => "object",
    }
}

/// `number` for a plain kind description, `number <literal>` for
/// int/uint targets (Go includes the literal only when a number does
/// not fit an int/uint type).
pub fn num_value(v: &JsonValue) -> String {
    match v {
        JsonValue::Number(lit) => format!("number {lit}"),
        _ => kind_desc(v).to_string(),
    }
}

/// Render a `UnmarshalTypeError` in this context: the
/// `Go struct field` form when the context names a struct, the
/// `Go value` form at a fresh top level.
pub fn ute_text(value: &str, typ: &str, ctx: &Ctx) -> String {
    match ctx.ute_stamp() {
        Some(stamp) => {
            format!("json: cannot unmarshal {value} into Go struct field {stamp} of type {typ}")
        }
        None => format!("json: cannot unmarshal {value} into Go value of type {typ}"),
    }
}

/// The outer decoder's `saveError`: merge a fresh-boundary error into
/// this context. `Pathed` errors only gain the outer path (joined
/// with `.`); `BareUte` gains the outer stamp and path (joined with
/// `: `); `Bare` gains the path; `Returned` passes through verbatim.
pub fn save(ctx: &Ctx, err: SbErr) -> SbErr {
    let path = ctx.fmt_path();
    match err {
        SbErr::Pathed(s) => {
            if path.is_empty() {
                SbErr::Pathed(s)
            } else {
                SbErr::Pathed(format!("{path}.{s}"))
            }
        }
        SbErr::BareUte { value, typ } => {
            let text = ute_text(&value, &typ, ctx);
            if path.is_empty() {
                SbErr::Pathed(text)
            } else {
                SbErr::Pathed(format!("{path}: {text}"))
            }
        }
        SbErr::Bare(s) => {
            if path.is_empty() {
                SbErr::Pathed(s)
            } else {
                SbErr::Pathed(format!("{path}: {s}"))
            }
        }
        SbErr::Returned(s) => SbErr::Returned(s),
    }
}

/// A wrong-type error rendered immediately in this (field) context.
pub fn ute_at(ctx: &Ctx, value: &str, typ: &str) -> SbErr {
    let path = ctx.fmt_path();
    let text = ute_text(value, typ, ctx);
    if path.is_empty() {
        SbErr::Pathed(text)
    } else {
        SbErr::Pathed(format!("{path}: {text}"))
    }
}

/// A custom error rendered immediately in this (field) context.
pub fn bare_at(ctx: &Ctx, msg: impl Into<String>) -> SbErr {
    let path = ctx.fmt_path();
    let msg = msg.into();
    if path.is_empty() {
        SbErr::Pathed(msg)
    } else {
        SbErr::Pathed(format!("{path}: {msg}"))
    }
}

// ---------------------------------------------------------------------------
// badjson empty-value filtering
// ---------------------------------------------------------------------------

/// Whether a JSON value is "empty" in the `badjson` sense: an object
/// or array is empty iff it has no entries/elements or all of them are
/// empty (recursive). Scalars (including null) are never empty.
pub fn is_empty_json(v: &JsonValue) -> bool {
    match v {
        JsonValue::Object(o) => o.iter().all(|(_, val)| is_empty_json(val)),
        JsonValue::Array(a) => a.iter().all(is_empty_json),
        _ => false,
    }
}

/// Drop empty values recursively, as `JSONObject.MarshalJSONContext`
/// does when a `badjson` excluded pass re-marshals its remainder.
/// Returns `None` when the value itself is dropped. Array elements
/// are never dropped (only filtered in place); an empty object/array
/// element stays as an empty container.
pub fn filter_empty(v: &JsonValue) -> Option<JsonValue> {
    match v {
        JsonValue::Object(o) => {
            if o.iter().all(|(_, val)| is_empty_json(val)) {
                return None;
            }
            let mut out = crate::jsonvalue::OrderedObject::new();
            for (k, val) in o.iter() {
                if let Some(f) = filter_empty(val) {
                    out.set(k.clone(), f);
                }
            }
            Some(JsonValue::Object(out))
        }
        JsonValue::Array(a) => {
            let mut out = Vec::with_capacity(a.len());
            for val in a {
                match filter_empty(val) {
                    Some(f) => out.push(f),
                    None => match val {
                        JsonValue::Object(_) => {
                            out.push(JsonValue::Object(crate::jsonvalue::OrderedObject::new()));
                        }
                        JsonValue::Array(_) => out.push(JsonValue::Array(Vec::new())),
                        _ => out.push(val.clone()),
                    },
                }
            }
            Some(JsonValue::Array(out))
        }
        _ => Some(v.clone()),
    }
}

/// The `badjson` excluded pass: remove the parent struct's keys from
/// an object, then filter empty values recursively.
pub fn excluded_remainder(
    obj: &crate::jsonvalue::OrderedObject,
    parent_struct: &str,
) -> crate::jsonvalue::OrderedObject {
    let parent_keys: Vec<String> = struct_keys(parent_struct)
        .iter()
        .map(|k| (*k).to_string())
        .collect();
    excluded_remainder_keys(obj, &parent_keys)
}

/// The `badjson` excluded pass with an explicit parent key list.
pub fn excluded_remainder_keys(
    obj: &crate::jsonvalue::OrderedObject,
    parent_keys: &[String],
) -> crate::jsonvalue::OrderedObject {
    let mut out = crate::jsonvalue::OrderedObject::new();
    for (k, v) in obj.iter() {
        if parent_keys.iter().any(|pk| pk == k) {
            continue;
        }
        if let Some(f) = filter_empty(v) {
            out.set(k.clone(), f);
        }
    }
    out
}

/// All JSON keys of a struct table (including embedded fields).
pub fn struct_keys(struct_name: &str) -> Vec<&'static str> {
    match tables::struct_by_name(struct_name) {
        Some(s) => s.fields.iter().map(|f| f.json).collect(),
        None => Vec::new(),
    }
}

/// The raw JSON bytes of a value, for error messages that echo the
/// input (`unknown DNS query type: ["a"]`). Numbers keep their
/// literal; strings keep their quotes.
pub fn raw_json(v: &JsonValue) -> String {
    match v {
        JsonValue::Null => "null".to_string(),
        JsonValue::Bool(b) => b.to_string(),
        JsonValue::Str(s) => go_quote(s),
        JsonValue::Number(lit) => lit.clone(),
        JsonValue::Array(items) => {
            let inner: Vec<String> = items.iter().map(raw_json).collect();
            format!("[{}]", inner.join(","))
        }
        JsonValue::Object(o) => {
            let inner: Vec<String> = o
                .iter()
                .map(|(k, val)| format!("{}:{}", go_quote(k), raw_json(val)))
                .collect();
            format!("{{{}}}", inner.join(","))
        }
    }
}

// ---------------------------------------------------------------------------
// Go `time.ParseDuration` replica (sing fork: `my_time.ParseDuration`,
// identical to stdlib except the unit map also has "d" = 24h).
// ---------------------------------------------------------------------------

/// Parse a Go duration string. Returns nanoseconds, or the exact Go
/// error text (`time: invalid duration "..."`,
/// `time: missing unit in duration "..."`,
/// `time: unknown unit "..." in duration "..."`).
pub fn go_parse_duration(s: &str) -> Result<i64, String> {
    let orig = s;
    let invalid = || format!("time: invalid duration {}", go_quote(orig));
    let bytes = s.as_bytes();
    let mut rest = s;
    let mut neg = false;
    if !rest.is_empty() {
        let c = bytes[0];
        if c == b'-' || c == b'+' {
            neg = c == b'-';
            rest = &rest[1..];
        }
    }
    if rest == "0" {
        return Ok(0);
    }
    if rest.is_empty() {
        return Err(invalid());
    }
    let mut d: u64 = 0;
    while !rest.is_empty() {
        let rb = rest.as_bytes();
        if !(rb[0] == b'.' || rb[0].is_ascii_digit()) {
            return Err(invalid());
        }
        let (v, after_int, ok) = leading_int(rest);
        if !ok {
            return Err(invalid());
        }
        let pre = after_int.len() != rest.len();
        rest = after_int;
        let mut f: u64 = 0;
        let mut scale: f64 = 1.0;
        let mut post = false;
        if !rest.is_empty() && rest.as_bytes()[0] == b'.' {
            rest = &rest[1..];
            let before = rest.len();
            let (frac, sc, after) = leading_fraction(rest);
            f = frac;
            scale = sc;
            rest = after;
            post = before != rest.len();
        }
        if !pre && !post {
            return Err(invalid());
        }
        // Consume unit.
        let rb = rest.as_bytes();
        let mut i = 0;
        while i < rb.len() && rb[i] != b'.' && !rb[i].is_ascii_digit() {
            i += 1;
        }
        if i == 0 {
            return Err(format!("time: missing unit in duration {}", go_quote(orig)));
        }
        let u = &rest[..i];
        rest = &rest[i..];
        let unit: u64 = match u {
            "ns" => 1,
            "us" | "µs" | "μs" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60_000_000_000,
            "h" => 3_600_000_000_000,
            "d" => 86_400_000_000_000,
            _ => {
                return Err(format!(
                    "time: unknown unit {} in duration {}",
                    go_quote(u),
                    go_quote(orig)
                ));
            }
        };
        let mut v = v;
        if v > (1u64 << 63) / unit {
            return Err(invalid());
        }
        v *= unit;
        if f > 0 {
            v += (f as f64 * (unit as f64 / scale)) as u64;
            if v > 1u64 << 63 {
                return Err(invalid());
            }
        }
        d += v;
        if d > 1u64 << 63 {
            return Err(invalid());
        }
    }
    if neg {
        return Ok((d as i64).wrapping_neg());
    }
    if d > (1u64 << 63) - 1 {
        return Err(invalid());
    }
    Ok(d as i64)
}

fn leading_int(s: &str) -> (u64, &str, bool) {
    let b = s.as_bytes();
    let mut x: u64 = 0;
    let mut i = 0;
    while i < b.len() && b[i].is_ascii_digit() {
        if x > (1u64 << 63) / 10 {
            return (0, "", false);
        }
        x = x * 10 + (b[i] - b'0') as u64;
        if x > 1u64 << 63 {
            return (0, "", false);
        }
        i += 1;
    }
    (x, &s[i..], true)
}

fn leading_fraction(s: &str) -> (u64, f64, &str) {
    let b = s.as_bytes();
    let mut x: u64 = 0;
    let mut scale: f64 = 1.0;
    let mut overflow = false;
    let mut i = 0;
    while i < b.len() && b[i].is_ascii_digit() {
        if !overflow {
            if x > ((1u64 << 63) - 1) / 10 {
                overflow = true;
            } else {
                let y = x * 10 + (b[i] - b'0') as u64;
                if y > 1u64 << 63 {
                    overflow = true;
                } else {
                    x = y;
                    scale *= 10.0;
                }
            }
        }
        i += 1;
    }
    (x, scale, &s[i..])
}

// ---------------------------------------------------------------------------
// Go `strconv.ParseUint(s, 0, 32)` replica (FwMark strings).
// ---------------------------------------------------------------------------

/// Parse an unsigned integer with base 0 (like Go's
/// `strconv.ParseUint(s, 0, 32)`): `0x` hex, leading-`0` octal,
/// `0b` binary, `0o` octal, underscores allowed between digits.
/// Returns the Go error text on failure.
pub fn go_parse_uint_base0_32(s: &str) -> Result<u32, String> {
    let syntax = || {
        format!(
            "strconv.ParseUint: parsing {s}: invalid syntax",
            s = go_quote(s)
        )
    };
    let range_err = || {
        format!(
            "strconv.ParseUint: parsing {s}: value out of range",
            s = go_quote(s)
        )
    };
    if s.is_empty() {
        return Err(syntax());
    }
    // Go `strconv.ParseUint` rejects a sign; underscores follow the
    // Go literal rules (between digits, or after a base prefix).
    if s.as_bytes()[0] == b'+' || s.as_bytes()[0] == b'-' {
        return Err(syntax());
    }
    if !underscore_ok(s) {
        return Err(syntax());
    }
    let (digits, radix): (&str, u32) =
        if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            (hex, 16)
        } else if let Some(bin) = s.strip_prefix("0b").or_else(|| s.strip_prefix("0B")) {
            (bin, 2)
        } else if let Some(oct) = s.strip_prefix("0o").or_else(|| s.strip_prefix("0O")) {
            (oct, 8)
        } else if s.len() > 1 && s.as_bytes()[0] == b'0' {
            (&s[1..], 8)
        } else {
            (s, 10)
        };
    if digits.is_empty() {
        return Err(syntax());
    }
    let clean: String = digits.chars().filter(|&c| c != '_').collect();
    if clean.is_empty() {
        return Err(syntax());
    }
    let mut v: u64 = 0;
    for c in clean.chars() {
        let d = match c.to_digit(radix) {
            Some(d) => d as u64,
            None => return Err(syntax()),
        };
        v = v
            .checked_mul(radix as u64)
            .and_then(|x| x.checked_add(d))
            .ok_or_else(range_err)?;
        if v > u32::MAX as u64 {
            return Err(range_err());
        }
    }
    Ok(v as u32)
}

/// Go `strconv.underscoreOK`: underscores only between digits or
/// between a base prefix and a digit.
fn underscore_ok(s: &str) -> bool {
    let b = s.as_bytes();
    // saw: '^' beginning, '0' digit or base prefix, '_' underscore.
    let mut saw = b'^';
    let mut i = 0;
    let mut hex = false;
    if b.len() >= 2 && b[0] == b'0' && matches!(b[1], b'x' | b'X' | b'b' | b'B' | b'o' | b'O') {
        i = 2;
        saw = b'0';
        hex = matches!(b[1], b'x' | b'X');
    }
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_digit() || (hex && matches!(c.to_ascii_lowercase(), b'a'..=b'f')) {
            saw = b'0';
            i += 1;
            continue;
        }
        if c == b'_' {
            if saw != b'0' {
                return false;
            }
            saw = b'_';
            i += 1;
            continue;
        }
        if saw == b'_' {
            return false;
        }
        saw = b'!';
        i += 1;
    }
    saw != b'_'
}

// ---------------------------------------------------------------------------
// Go `netip` replicas (ParseAddr / ParsePrefix / ParseAddrPort).
// Error texts are `parseAddrError` / `parsePrefixError` verbatim.
// ---------------------------------------------------------------------------

fn addr_err(input: &str, msg: &str, at: Option<&str>) -> String {
    match at {
        Some(at) => format!(
            "ParseAddr({}): {msg} (at {})",
            go_quote(input),
            go_quote(at)
        ),
        None => format!("ParseAddr({}): {msg}", go_quote(input)),
    }
}

fn parse_ipv4_fields(input: &str, s: &str) -> Result<[u8; 4], String> {
    let b = s.as_bytes();
    let mut fields = [0u8; 4];
    let mut val: u32 = 0;
    let mut pos = 0usize;
    let mut dig_len = 0usize;
    for i in 0..b.len() {
        let c = b[i];
        if c.is_ascii_digit() {
            if dig_len == 1 && val == 0 {
                return Err(addr_err(
                    input,
                    "IPv4 field has octet with leading zero",
                    None,
                ));
            }
            val = val * 10 + (c - b'0') as u32;
            dig_len += 1;
            if val > 255 {
                return Err(addr_err(input, "IPv4 field has value >255", None));
            }
        } else if c == b'.' {
            if i == 0 || i == b.len() - 1 || b[i - 1] == b'.' {
                return Err(addr_err(
                    input,
                    "IPv4 field must have at least one digit",
                    Some(&s[i..]),
                ));
            }
            if pos == 3 {
                return Err(addr_err(input, "IPv4 address too long", None));
            }
            fields[pos] = val as u8;
            pos += 1;
            val = 0;
            dig_len = 0;
        } else {
            return Err(addr_err(input, "unexpected character", Some(&s[i..])));
        }
    }
    if pos < 3 {
        return Err(addr_err(input, "IPv4 address too short", None));
    }
    fields[3] = val as u8;
    Ok(fields)
}

/// Go `netip.ParseAddr`, returning `()` on success or the exact
/// `ParseAddr("..."): ...` error text. Zones (`%zone`) are accepted
/// for IPv6 (as Go does); a bare `%` with no address is
/// `missing IPv6 address`.
pub fn netip_parse_addr(s: &str) -> Result<(), String> {
    for (i, c) in s.char_indices() {
        match c {
            '.' => return parse_ipv4_fields(s, s).map(|_| ()),
            ':' => return netip_parse_ipv6(s).map(|_| ()),
            '%' => {
                return Err(addr_err(s, "missing IPv6 address", None));
            }
            _ => {
                let _ = i;
            }
        }
    }
    Err(addr_err(s, "unable to parse IP", None))
}

fn netip_parse_ipv6(input: &str) -> Result<(), String> {
    let err = |msg: &str, at: Option<&str>| addr_err(input, msg, at);
    let mut s = input;
    let mut zone = "";
    if let Some(i) = s.find('%') {
        zone = &s[i + 1..];
        s = &s[..i];
        if zone.is_empty() {
            return Err(err("zone must be a non-empty string", None));
        }
    }
    let mut ip = [0u8; 16];
    let mut ellipsis: i64 = -1;
    if s.len() >= 2 && s.as_bytes()[0] == b':' && s.as_bytes()[1] == b':' {
        ellipsis = 0;
        s = &s[2..];
        if s.is_empty() {
            return Ok(());
        }
    }
    let mut i = 0usize;
    while i < 16 {
        let sb = s.as_bytes();
        let mut off = 0usize;
        let mut acc: u32 = 0;
        while off < sb.len() {
            let c = sb[off];
            let d = match c {
                b'0'..=b'9' => (c - b'0') as u32,
                b'a'..=b'f' => (c - b'a' + 10) as u32,
                b'A'..=b'F' => (c - b'A' + 10) as u32,
                _ => break,
            };
            acc = (acc << 4) + d;
            if off > 3 {
                return Err(err("each group must have 4 or less digits", Some(s)));
            }
            if acc > 0xffff {
                return Err(err("IPv6 field has value >=2^16", Some(s)));
            }
            off += 1;
        }
        if off == 0 {
            return Err(err(
                "each colon-separated field must have at least one digit",
                Some(s),
            ));
        }
        if off < sb.len() && sb[off] == b'.' {
            if ellipsis < 0 && i != 12 {
                return Err(err(
                    "embedded IPv4 address must replace the final 2 fields of the address",
                    Some(s),
                ));
            }
            if i + 4 > 16 {
                return Err(err(
                    "too many hex fields to fit an embedded IPv4 at the end of the address",
                    Some(s),
                ));
            }
            let mut end = input.len();
            if !zone.is_empty() {
                end -= zone.len() + 1;
            }
            let start = end - s.len();
            let fields = parse_ipv4_fields(input, &input[start..end])?;
            ip[i..i + 4].copy_from_slice(&fields);
            s = "";
            i += 4;
            break;
        }
        ip[i] = (acc >> 8) as u8;
        ip[i + 1] = acc as u8;
        i += 2;
        s = &s[off..];
        if s.is_empty() {
            break;
        }
        if s.as_bytes()[0] != b':' {
            return Err(err("unexpected character, want colon", Some(s)));
        } else if s.len() == 1 {
            return Err(err("colon must be followed by more characters", Some(s)));
        }
        s = &s[1..];
        if s.as_bytes()[0] == b':' {
            if ellipsis >= 0 {
                return Err(err("multiple :: in address", Some(s)));
            }
            ellipsis = i as i64;
            s = &s[1..];
            if s.is_empty() {
                break;
            }
        }
    }
    if !s.is_empty() {
        return Err(err("trailing garbage after address", Some(s)));
    }
    if i < 16 {
        if ellipsis < 0 {
            return Err(err("missing colon in address", Some(s)));
        }
        // Expand the ellipsis: shift the tail right.
        let e = ellipsis as usize;
        let tail_len = i - e;
        for j in (0..tail_len).rev() {
            ip[16 - tail_len + j] = ip[e + j];
            ip[e + j] = 0;
        }
    } else if ellipsis >= 0 {
        return Err(err("multiple :: in address", Some(s)));
    }
    Ok(())
}

/// Go `netip.ParsePrefix`, returning `()` on success or the exact
/// `netip.ParsePrefix("..."): ...` error text.
pub fn netip_parse_prefix(s: &str) -> Result<(), String> {
    let perr = |msg: String| format!("netip.ParsePrefix({}): {msg}", go_quote(s));
    let i = match s.rfind('/') {
        Some(i) => i,
        None => return Err(perr("no '/'".to_string())),
    };
    let ip_part = &s[..i];
    if let Err(e) = netip_parse_addr(ip_part) {
        return Err(perr(e));
    }
    // IPv6 zones are not allowed in a prefix (Go issue 51899).
    if ip_part.contains(':') && ip_part.contains('%') {
        return Err(perr("IPv6 zones cannot be present in a prefix".to_string()));
    }
    let bits_str = &s[i + 1..];
    if bits_str.len() > 1 && (bits_str.as_bytes()[0] < b'1' || bits_str.as_bytes()[0] > b'9') {
        return Err(perr(format!(
            "bad bits after slash: {}",
            go_quote(bits_str)
        )));
    }
    let bits: i64 = match bits_str.parse::<i64>() {
        Ok(b) => b,
        Err(_) => {
            return Err(perr(format!(
                "bad bits after slash: {}",
                go_quote(bits_str)
            )));
        }
    };
    let max_bits = if ip_part.contains(':') { 128 } else { 32 };
    if bits < 0 || bits > max_bits {
        return Err(perr("prefix length out of range".to_string()));
    }
    Ok(())
}

/// Go `netip.ParseAddrPort`, returning `()` on success or the exact
/// error text (`not an ip:port`, or the `ParseAddr` error of the IP
/// part, or `too large port` / `bad port` for the port part).
pub fn netip_parse_addr_port(s: &str) -> Result<(), String> {
    // Mirrors Go `netip.ParseAddrPort` (splitAddrPort, then port
    // first, then the IP, then the bracket/family check).
    let i = match s.rfind(':') {
        Some(i) => i,
        None => return Err("not an ip:port".to_string()),
    };
    let (mut ip, port) = (&s[..i], &s[i + 1..]);
    if ip.is_empty() {
        return Err("no IP".to_string());
    }
    if port.is_empty() {
        return Err("no port".to_string());
    }
    let mut v6 = false;
    if ip.starts_with('[') {
        if ip.len() < 2 || !ip.ends_with(']') {
            return Err("missing ]".to_string());
        }
        ip = &ip[1..ip.len() - 1];
        v6 = true;
    }
    // strconv.ParseUint(port, 10, 16): digits only, <= 65535.
    let port_ok = !port.is_empty()
        && port.bytes().all(|b| b.is_ascii_digit())
        && port.parse::<u64>().map(|n| n <= 65535).unwrap_or(false);
    if !port_ok {
        return Err(format!(
            "invalid port {} parsing {}",
            go_quote(port),
            go_quote(s)
        ));
    }
    netip_parse_addr(ip)?;
    // Family/bracket consistency (Is4 = no ':' before any '%').
    let ip_no_zone = ip.split('%').next().unwrap_or(ip);
    let is4 = !ip_no_zone.contains(':');
    if v6 && is4 {
        return Err(format!(
            "invalid ip:port {}, square brackets can only be used with IPv6 addresses",
            go_quote(s)
        ));
    }
    if !v6 && !is4 {
        return Err(format!(
            "invalid ip:port {}, IPv6 addresses must be surrounded by square brackets",
            go_quote(s)
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Go `byteformats` unit parsing (MemoryBytes / NetworkBytes /
// NetworkBytesCompat) and FwMark.
// ---------------------------------------------------------------------------

fn parse_unit_bytes(s: &str, table: &[(&str, u64)], case_sensitive: bool) -> Result<u64, String> {
    // int64 first (any integer, incl. negative, wraps to uint64).
    if let Ok(n) = s.parse::<i64>() {
        return Ok(n as u64);
    }
    // String form: leading digits, then a unit.
    let b = s.as_bytes();
    let mut unit_index = 0usize;
    for (i, &c) in b.iter().enumerate() {
        if !c.is_ascii_digit() {
            unit_index = i;
            break;
        }
    }
    if unit_index == 0 {
        return Err(format!("invalid format: {s}"));
    }
    let digits = &s[..unit_index];
    let value: u64 = match digits.parse::<u64>() {
        Ok(v) => v,
        Err(_) => {
            // The digits are all 0-9 by construction, so the only
            // failure is overflow (Go: `strconv.ParseUint`).
            return Err(format!(
                "parse {digits}: strconv.ParseUint: parsing {d}: value out of range",
                d = go_quote(digits)
            ));
        }
    };
    let raw_unit = &s[unit_index..];
    let unit_key = if case_sensitive {
        raw_unit.trim().to_string()
    } else {
        raw_unit.trim().to_lowercase()
    };
    let Some((_, mult)) = table.iter().find(|(k, _)| *k == unit_key) else {
        return Err(format!("unsupported unit: {raw_unit}"));
    };
    Ok(value * mult)
}

const UNIT_TABLE: &[(&str, u64)] = &[
    ("b", 1),
    ("k", 1_000),
    ("kb", 1_000),
    ("ki", 1_024),
    ("kib", 1_024),
    ("m", 1_000_000),
    ("mb", 1_000_000),
    ("mi", 1_048_576),
    ("mib", 1_048_576),
    ("g", 1_000_000_000),
    ("gb", 1_000_000_000),
    ("gi", 1_073_741_824),
    ("gib", 1_073_741_824),
    ("t", 1_000_000_000_000),
    ("tb", 1_000_000_000_000),
    ("ti", 1_099_511_627_776),
    ("tib", 1_099_511_627_776),
    ("p", 1_000_000_000_000_000),
    ("pb", 1_000_000_000_000_000),
    ("pi", 1_125_899_906_842_624),
    ("pib", 1_125_899_906_842_624),
    ("e", 1_000_000_000_000_000_000),
    ("eb", 1_000_000_000_000_000_000),
    ("ei", 1_152_921_504_606_846_976),
    ("eib", 1_152_921_504_606_846_976),
];

const MEMORY_UNIT_TABLE: &[(&str, u64)] = &[
    ("b", 1),
    ("k", 1_024),
    ("kb", 1_024),
    ("m", 1_048_576),
    ("mb", 1_048_576),
    ("g", 1_073_741_824),
    ("gb", 1_073_741_824),
    ("t", 1_099_511_627_776),
    ("tb", 1_099_511_627_776),
    ("p", 1_125_899_906_842_624),
    ("pb", 1_125_899_906_842_624),
    ("e", 1_152_921_504_606_846_976),
    ("eb", 1_152_921_504_606_846_976),
];

const NETWORK_UNIT_TABLE: &[(&str, u64)] = &[
    ("Bps", 1),
    ("Kbps", 125),
    ("KBps", 1_000),
    ("Mbps", 125_000),
    ("MBps", 1_000_000),
    ("Gbps", 125_000_000),
    ("GBps", 1_000_000_000),
    ("Tbps", 125_000_000_000),
    ("TBps", 1_000_000_000_000),
    ("Pbps", 125_000_000_000_000),
    ("PBps", 1_000_000_000_000_000),
    ("Ebps", 125_000_000_000_000_000),
    ("EBps", 1_000_000_000_000_000_000),
];

/// `byteformats.MemoryBytes`: int64 first, else a memory-unit string.
/// Non-int non-string inputs produce the string-attempt UTE (returned
/// by the caller as a `BareUte` with type `string`).
pub fn memory_bytes_value(v: &JsonValue) -> Result<(), SbErr> {
    match v {
        JsonValue::Number(lit) => {
            if lit.parse::<i64>().is_ok() {
                return Ok(());
            }
            Err(SbErr::BareUte {
                value: kind_desc(v).to_string(),
                typ: "string".to_string(),
            })
        }
        JsonValue::Str(s) => parse_unit_bytes(s, MEMORY_UNIT_TABLE, false)
            .map(|_| ())
            .map_err(SbErr::Bare),
        _ => Err(SbErr::BareUte {
            value: kind_desc(v).to_string(),
            typ: "string".to_string(),
        }),
    }
}

/// `byteformats.NetworkBytesCompat` (hysteria `up` / `down`): try the
/// case-sensitive network table first; on failure try the plain byte
/// table; if the second succeeds the value is accepted, otherwise the
/// FIRST error is returned.
pub fn network_bytes_compat_value(v: &JsonValue) -> Result<(), SbErr> {
    match v {
        JsonValue::Number(lit) => {
            if lit.parse::<i64>().is_ok() {
                return Ok(());
            }
            Err(SbErr::BareUte {
                value: kind_desc(v).to_string(),
                typ: "string".to_string(),
            })
        }
        JsonValue::Str(s) => match parse_unit_bytes(s, NETWORK_UNIT_TABLE, true) {
            Ok(_) => Ok(()),
            Err(first) => match parse_unit_bytes(s, UNIT_TABLE, false) {
                Ok(_) => Ok(()),
                Err(_) => Err(SbErr::Bare(first)),
            },
        },
        _ => Err(SbErr::BareUte {
            value: kind_desc(v).to_string(),
            typ: "string".to_string(),
        }),
    }
}

/// Go `option.FwMark`: a string is parsed with `ParseUint(s, 0, 32)`;
/// a number is accepted iff it fits in a uint32, otherwise the
/// string-attempt error is returned wrapped in
/// `invalid number or string mark: ...`.
pub fn fwmark_value(v: &JsonValue) -> Result<(), SbErr> {
    match v {
        JsonValue::Str(s) => go_parse_uint_base0_32(s).map(|_| ()).map_err(SbErr::Bare),
        JsonValue::Number(lit) => {
            let ok = lit
                .parse::<i64>()
                .map(|n| (0..=u32::MAX as i64).contains(&n))
                .unwrap_or(false);
            if ok {
                Ok(())
            } else {
                Err(SbErr::Bare(
                    "invalid number or string mark: json: cannot unmarshal number into Go value of type string"
                        .to_string(),
                ))
            }
        }
        _ => Err(SbErr::Bare(format!(
            "invalid number or string mark: json: cannot unmarshal {} into Go value of type string",
            kind_desc(v)
        ))),
    }
}

// ---------------------------------------------------------------------------
// Field kinds (must match `singbox_tables.rs`, generated from the schema).
// ---------------------------------------------------------------------------

/// The validation kind of one sing-box option field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldKind {
    Bool,
    Str,
    Uint,
    Int,
    Duration,
    DomainStrategy,
    NetworkStrategy,
    FwMark,
    Addr,
    Prefix,
    Prefixable,
    Listable,
    Slice,
    SliceStruct,
    Object,
    Map,
    TypedMap,
    HttpHeader,
    Bytes,
    MemoryBytes,
    NetworkList,
    Transport,
    Obfs,
    HttpClientOptions,
    UdpOverTcp,
    Optimistic,
    DomainResolver,
    DnsRcode,
    MatchResponse,
    UdpNatBehavior,
    UdpTimeoutCompat,
    NetworkBytesCompat,
}

use crate::singbox_tables::FieldDef;

/// The Go type name without a leading `*` (Go's `UnmarshalTypeError`
/// renders the element type for pointer fields).
pub fn deref_go(go: &str) -> &str {
    go.strip_prefix('*').unwrap_or(go)
}

/// Whether a JSON number literal is an integer (`-?[0-9]+`).
pub fn number_int(lit: &str) -> Option<i128> {
    let b = lit.as_bytes();
    if b.is_empty() {
        return None;
    }
    let digits = if b[0] == b'-' { &b[1..] } else { b };
    if digits.is_empty() || !digits.iter().all(|c| c.is_ascii_digit()) {
        return None;
    }
    lit.parse::<i128>().ok()
}

fn uint_bits(go: &str) -> u32 {
    match deref_go(go) {
        "uint8" => 8,
        "uint16" => 16,
        "uint32" => 32,
        "uint64" => 64,
        _ => 64,
    }
}

// ---------------------------------------------------------------------------
// Leaf validators: each validates one field value in its field context
// and returns errors already rendered with the full path.
// ---------------------------------------------------------------------------

fn leaf_ute(ctx: &Ctx, v: &JsonValue, typ: &str) -> SbErr {
    ute_at(ctx, kind_desc(v), typ)
}

fn leaf_ute_num(ctx: &Ctx, v: &JsonValue, typ: &str) -> SbErr {
    ute_at(ctx, &num_value(v), typ)
}

/// Validate one field value against its table definition.
/// `ctx` is the field's context (path includes the field key,
/// field_stack includes the embedded names + JSON name, struct_name
/// is the containing struct). `depth` is the nested-DNS-rule depth
/// (0 outside DNS rules).
pub fn validate_field(
    field: &FieldDef,
    value: &JsonValue,
    ctx: &Ctx,
    depth: usize,
) -> Result<(), SbErr> {
    if value.is_null() {
        return Ok(());
    }
    let err = match field.kind {
        FieldKind::Bool => match value {
            JsonValue::Bool(_) => return Ok(()),
            _ => leaf_ute(ctx, value, "bool"),
        },
        FieldKind::Str => match value {
            JsonValue::Str(_) => return Ok(()),
            _ => leaf_ute(ctx, value, "string"),
        },
        FieldKind::Uint => match value {
            JsonValue::Number(lit) => {
                let bits = uint_bits(field.go);
                let max: i128 = if bits >= 128 {
                    i128::MAX
                } else {
                    (1i128 << bits) - 1
                };
                match number_int(lit) {
                    Some(n) if (0..=max).contains(&n) => return Ok(()),
                    _ => leaf_ute_num(ctx, value, deref_go(field.go)),
                }
            }
            _ => leaf_ute(ctx, value, deref_go(field.go)),
        },
        FieldKind::Int => match value {
            JsonValue::Number(lit) => match number_int(lit) {
                Some(n) if (-(1i128 << 63)..=(1i128 << 63) - 1).contains(&n) => {
                    return Ok(());
                }
                _ => leaf_ute_num(ctx, value, deref_go(field.go)),
            },
            _ => leaf_ute(ctx, value, deref_go(field.go)),
        },
        FieldKind::Duration => match value {
            JsonValue::Str(s) => match go_parse_duration(s) {
                Ok(_) => return Ok(()),
                Err(msg) => bare_at(ctx, msg),
            },
            _ => leaf_ute(ctx, value, "string"),
        },
        FieldKind::DomainStrategy => match value {
            JsonValue::Str(s) => match s.as_str() {
                "" | "as_is" | "prefer_ipv4" | "prefer_ipv6" | "ipv4_only" | "ipv6_only" => {
                    return Ok(());
                }
                _ => bare_at(ctx, format!("unknown domain strategy: {s}")),
            },
            _ => leaf_ute(ctx, value, "string"),
        },
        FieldKind::NetworkStrategy => match value {
            JsonValue::Str(s) => match s.as_str() {
                "default" | "fallback" | "hybrid" => return Ok(()),
                _ => bare_at(ctx, format!("unknown network strategy: {s}")),
            },
            _ => leaf_ute(ctx, value, "string"),
        },
        FieldKind::FwMark => return fwmark_value(value).map_err(|e| save(ctx, e)),
        FieldKind::Addr => match value {
            JsonValue::Str(s) => match netip_parse_addr(s) {
                Ok(()) => return Ok(()),
                Err(msg) => bare_at(ctx, msg),
            },
            _ => leaf_ute(ctx, value, "string"),
        },
        FieldKind::Prefix => match value {
            JsonValue::Str(s) => match netip_parse_prefix(s) {
                Ok(()) => return Ok(()),
                Err(msg) => bare_at(ctx, msg),
            },
            _ => leaf_ute(ctx, value, "string"),
        },
        FieldKind::Prefixable => match value {
            JsonValue::Str(s) => match netip_parse_prefix(s) {
                Ok(()) => return Ok(()),
                Err(_) => match netip_parse_addr(s) {
                    Ok(()) => return Ok(()),
                    Err(_) => {
                        // Prefixable returns the *prefix* error.
                        let msg = netip_parse_prefix(s).unwrap_err();
                        bare_at(ctx, msg)
                    }
                },
            },
            _ => leaf_ute(ctx, value, "string"),
        },
        FieldKind::Listable => {
            return listable_validate(field.elem.unwrap_or("string"), value, ctx);
        }
        FieldKind::Slice => match value {
            JsonValue::Array(items) => {
                for (i, item) in items.iter().enumerate() {
                    if item.is_null() {
                        continue;
                    }
                    if !matches!(item, JsonValue::Str(_)) {
                        let mut ectx = ctx.clone();
                        ectx.path.push(Seg::Idx(i));
                        return Err(ute_at(&ectx, kind_desc(item), "string"));
                    }
                }
                return Ok(());
            }
            _ => leaf_ute(ctx, value, "[]string"),
        },
        FieldKind::SliceStruct => {
            return slice_struct_validate(field, value, ctx, depth);
        }
        FieldKind::Object => {
            return object_field_validate(field, value, ctx, depth);
        }
        FieldKind::Map => match value {
            JsonValue::Object(o) => {
                for (k, item) in o.iter() {
                    if item.is_null() {
                        continue;
                    }
                    if !matches!(item, JsonValue::Str(_)) {
                        let mut ectx = ctx.clone();
                        ectx.path.push(Seg::Key(k.clone()));
                        return Err(ute_at(&ectx, kind_desc(item), "string"));
                    }
                }
                return Ok(());
            }
            _ => leaf_ute(ctx, value, "map[string]string"),
        },
        FieldKind::TypedMap => {
            return typedmap_validate(field, value, ctx);
        }
        FieldKind::HttpHeader => match value {
            JsonValue::Object(o) => {
                for (k, item) in o.iter() {
                    if item.is_null() {
                        continue;
                    }
                    let mut ectx = ctx.clone();
                    ectx.path.push(Seg::Key(k.clone()));
                    listable_validate("string", item, &ectx)?;
                }
                return Ok(());
            }
            _ => leaf_ute(ctx, value, "badoption.HTTPHeader"),
        },
        FieldKind::Bytes => match value {
            JsonValue::Str(s) => match base64_decode(s) {
                Ok(()) => return Ok(()),
                Err(msg) => bare_at(ctx, msg),
            },
            JsonValue::Array(items) => {
                for (i, item) in items.iter().enumerate() {
                    if item.is_null() {
                        continue;
                    }
                    match item {
                        JsonValue::Number(lit) => match number_int(lit) {
                            Some(n) if (0..=255).contains(&n) => {}
                            _ => {
                                let mut ectx = ctx.clone();
                                ectx.path.push(Seg::Idx(i));
                                return Err(ute_at(&ectx, &num_value(item), "uint8"));
                            }
                        },
                        _ => {
                            let mut ectx = ctx.clone();
                            ectx.path.push(Seg::Idx(i));
                            return Err(ute_at(&ectx, kind_desc(item), "uint8"));
                        }
                    }
                }
                return Ok(());
            }
            _ => leaf_ute(ctx, value, "[]uint8"),
        },
        FieldKind::MemoryBytes => {
            return memory_bytes_value(value).map_err(|e| save(ctx, e));
        }
        FieldKind::NetworkList => {
            return network_list_validate(value, ctx);
        }
        FieldKind::Transport => {
            return transport_validate(value, ctx);
        }
        FieldKind::Obfs => {
            return obfs_validate(value, ctx);
        }
        FieldKind::HttpClientOptions => {
            return http_client_validate(value, ctx);
        }
        FieldKind::UdpOverTcp => {
            return custom_bool_or_object(value, ctx, "_UDPOverTCPOptions");
        }
        FieldKind::Optimistic => {
            return custom_bool_or_object(value, ctx, "_OptimisticDNSOptions");
        }
        FieldKind::DomainResolver => {
            return domain_resolver_validate(value, ctx);
        }
        FieldKind::DnsRcode => match value {
            JsonValue::Number(lit) => match number_int(lit) {
                Some(_) => return Ok(()),
                None => {
                    // A non-integer number falls through to the string
                    // attempt (Go tries int, then string).
                    return Err(save(
                        ctx,
                        SbErr::BareUte {
                            value: kind_desc(value).to_string(),
                            typ: "string".to_string(),
                        },
                    ));
                }
            },
            JsonValue::Str(s) => {
                if tables::DNSRCODE.contains(&s.as_str()) {
                    return Ok(());
                }
                bare_at(ctx, format!("unknown rcode: {s}"))
            }
            _ => {
                return Err(save(
                    ctx,
                    SbErr::BareUte {
                        value: kind_desc(value).to_string(),
                        typ: "string".to_string(),
                    },
                ));
            }
        },
        FieldKind::MatchResponse => match value {
            JsonValue::Bool(_) => return Ok(()),
            JsonValue::Str(s) => {
                if s.is_empty() {
                    bare_at(ctx, "empty match_response tag")
                } else {
                    return Ok(());
                }
            }
            _ => bare_at(ctx, "invalid match_response value"),
        },
        FieldKind::UdpNatBehavior => match value {
            JsonValue::Str(s) => match s.as_str() {
                ""
                | "endpoint_independent"
                | "address_dependent"
                | "address_and_port_dependent" => return Ok(()),
                _ => bare_at(ctx, format!("unknown UDP NAT behavior: {s}")),
            },
            _ => leaf_ute(ctx, value, "string"),
        },
        FieldKind::UdpTimeoutCompat => match value {
            JsonValue::Number(lit) => match number_int(lit) {
                Some(_) => return Ok(()),
                None => {
                    return Err(save(
                        ctx,
                        SbErr::BareUte {
                            value: kind_desc(value).to_string(),
                            typ: "string".to_string(),
                        },
                    ));
                }
            },
            JsonValue::Str(s) => match go_parse_duration(s) {
                Ok(_) => return Ok(()),
                Err(msg) => bare_at(ctx, msg),
            },
            _ => {
                return Err(save(
                    ctx,
                    SbErr::BareUte {
                        value: kind_desc(value).to_string(),
                        typ: "string".to_string(),
                    },
                ));
            }
        },
        FieldKind::NetworkBytesCompat => {
            return network_bytes_compat_value(value).map_err(|e| save(ctx, e));
        }
    };
    Err(err)
}

/// Go `encoding/base64` decoding of a `[]byte` JSON string
/// (`StdEncoding`, padding required): `illegal base64 data at input
/// byte {n}` on the first bad byte.
pub fn base64_decode(s: &str) -> Result<(), String> {
    base64_decode_bytes(s).map(|_| ())
}

/// Go `StdEncoding.DecodeString`: validates and decodes.
pub fn base64_decode_bytes(s: &str) -> Result<Vec<u8>, String> {
    let b = s.as_bytes();
    // Validate characters + padding the way Go's StdEncoding does.
    let mut n = 0usize;
    let mut pad = 0usize;
    for (i, &c) in b.iter().enumerate() {
        let ok = c.is_ascii_alphanumeric() || c == b'+' || c == b'/' || c == b'=';
        if !ok {
            return Err(format!("illegal base64 data at input byte {i}"));
        }
        if c == b'=' {
            pad += 1;
        } else if pad > 0 {
            return Err(format!("illegal base64 data at input byte {i}"));
        } else {
            n += 1;
        }
    }
    if pad > 2 || !(n + pad).is_multiple_of(4) {
        let at = if pad > 2 { b.len() - pad + 2 } else { b.len() };
        return Err(format!("illegal base64 data at input byte {at}"));
    }
    let val = |c: u8| -> u8 {
        match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => 0,
        }
    };
    let mut out = Vec::with_capacity(b.len() * 3 / 4);
    for chunk in b.chunks(4) {
        if chunk.len() < 4 {
            break;
        }
        let (mut v0, mut v1, mut v2, mut v3) =
            (val(chunk[0]), val(chunk[1]), val(chunk[2]), val(chunk[3]));
        let _ = (&mut v0, &mut v1, &mut v2, &mut v3);
        if chunk[3] == b'=' {
            if chunk[2] == b'=' {
                out.push((v0 << 2) | (v1 >> 4));
            } else {
                out.push((v0 << 2) | (v1 >> 4));
                out.push((v1 << 4) | (v2 >> 2));
            }
        } else {
            out.push((v0 << 2) | (v1 >> 4));
            out.push((v1 << 4) | (v2 >> 2));
            out.push((v2 << 6) | v3);
        }
    }
    Ok(out)
}

/// `badoption.NetworkList`: tries `[]string` first, then a single
/// string; when both fail the single-attempt error is returned.
/// Values must be exactly `tcp` / `udp`.
fn network_list_validate(value: &JsonValue, ctx: &Ctx) -> Result<(), SbErr> {
    let single_err = || match value {
        JsonValue::Str(s) => {
            if s == "tcp" || s == "udp" {
                None
            } else {
                Some(format!("unknown network: {s}"))
            }
        }
        _ => Some(format!(
            "json: cannot unmarshal {} into Go value of type string",
            kind_desc(value)
        )),
    };
    match value {
        JsonValue::Array(items) => {
            for item in items {
                if item.is_null() {
                    continue;
                }
                match item {
                    JsonValue::Str(s) if s == "tcp" || s == "udp" => {}
                    _ => {
                        // The []string attempt failed: return the
                        // single-attempt error (array into string).
                        return Err(bare_at(
                            ctx,
                            "json: cannot unmarshal array into Go value of type string",
                        ));
                    }
                }
            }
            Ok(())
        }
        JsonValue::Str(_) => match single_err() {
            None => Ok(()),
            Some(msg) => Err(bare_at(ctx, msg)),
        },
        _ => Err(bare_at(
            ctx,
            single_err().unwrap_or_else(|| {
                format!(
                    "json: cannot unmarshal {} into Go value of type string",
                    kind_desc(value)
                )
            }),
        )),
    }
}

// ---------------------------------------------------------------------------
// `badoption.Listable[T]`: single attempt first, then the array
// attempt; on total failure `(single | array)`.
// ---------------------------------------------------------------------------

/// One `Listable` attempt error: the bare text plus whether it is a
/// `TextUnmarshaler` (returned) error, which never gains a `[i]`
/// prefix inside the array attempt.
struct AttemptErr {
    text: String,
    returned: bool,
}

fn attempt_ute(value: &str, typ: &str) -> AttemptErr {
    AttemptErr {
        text: format!("json: cannot unmarshal {value} into Go value of type {typ}"),
        returned: false,
    }
}

fn prefixable_single(s: &str) -> Result<(), String> {
    match netip_parse_prefix(s) {
        Ok(()) => Ok(()),
        Err(_) => match netip_parse_addr(s) {
            Ok(()) => Ok(()),
            Err(_) => Err(netip_parse_prefix(s).unwrap_err()),
        },
    }
}

/// The single attempt: decode `value` as one `T` (fresh decode).
fn listable_single(elem: &str, value: &JsonValue) -> Result<(), AttemptErr> {
    if value.is_null() {
        return Ok(());
    }
    match elem {
        "string" => match value {
            JsonValue::Str(_) => Ok(()),
            _ => Err(attempt_ute(kind_desc(value), "string")),
        },
        "uint16" => match value {
            JsonValue::Number(lit) => match number_int(lit) {
                Some(n) if (0..=65535).contains(&n) => Ok(()),
                _ => Err(attempt_ute(&num_value(value), "uint16")),
            },
            _ => Err(attempt_ute(kind_desc(value), "uint16")),
        },
        "int32" => match value {
            JsonValue::Number(lit) => match number_int(lit) {
                Some(n) if (-(1i128 << 31)..=(1i128 << 31) - 1).contains(&n) => Ok(()),
                _ => Err(attempt_ute(&num_value(value), "int32")),
            },
            _ => Err(attempt_ute(kind_desc(value), "int32")),
        },
        "netip.Addr" => match value {
            JsonValue::Str(s) => netip_parse_addr(s).map_err(|msg| AttemptErr {
                text: msg,
                returned: true,
            }),
            _ => Err(attempt_ute(kind_desc(value), "**netip.Addr")),
        },
        "netip.Prefix" => match value {
            JsonValue::Str(s) => netip_parse_prefix(s).map_err(|msg| AttemptErr {
                text: msg,
                returned: true,
            }),
            _ => Err(attempt_ute(kind_desc(value), "**netip.Prefix")),
        },
        "*badoption.Prefixable" => match value {
            JsonValue::Str(s) => prefixable_single(s).map_err(|msg| AttemptErr {
                text: msg,
                returned: false,
            }),
            _ => Err(attempt_ute(kind_desc(value), "string")),
        },
        "[]uint8" => match value {
            JsonValue::Str(s) => base64_decode(s).map_err(|msg| AttemptErr {
                text: msg,
                returned: false,
            }),
            JsonValue::Array(items) => {
                for (i, item) in items.iter().enumerate() {
                    if item.is_null() {
                        continue;
                    }
                    match item {
                        JsonValue::Number(lit) => match number_int(lit) {
                            Some(n) if (0..=255).contains(&n) => {}
                            _ => {
                                return Err(AttemptErr {
                                    text: format!(
                                        "[{i}]: json: cannot unmarshal {} into Go value of type uint8",
                                        num_value(item)
                                    ),
                                    returned: false,
                                });
                            }
                        },
                        _ => {
                            return Err(AttemptErr {
                                text: format!(
                                    "[{i}]: json: cannot unmarshal {} into Go value of type uint8",
                                    kind_desc(item)
                                ),
                                returned: false,
                            });
                        }
                    }
                }
                Ok(())
            }
            _ => Err(attempt_ute(kind_desc(value), "[]uint8")),
        },
        "option.CurvePreference" => match value {
            JsonValue::Str(s) => match s.to_ascii_uppercase().as_str() {
                "P256" | "P384" | "P521" | "X25519" | "X25519MLKEM768" => Ok(()),
                _ => Err(AttemptErr {
                    text: format!("unknown curve name: {s}"),
                    returned: false,
                }),
            },
            _ => Err(attempt_ute(kind_desc(value), "string")),
        },
        "option.DNSQueryType" => match value {
            JsonValue::Number(lit) => match number_int(lit) {
                Some(n) if (0..=65535).contains(&n) => Ok(()),
                _ => Err(AttemptErr {
                    text: format!("unknown DNS query type: {}", raw_json(value)),
                    returned: false,
                }),
            },
            JsonValue::Str(s) => {
                if tables::DNSQUERYTYPE.contains(&s.as_str()) {
                    Ok(())
                } else {
                    Err(AttemptErr {
                        text: format!("unknown DNS query type: {}", raw_json(value)),
                        returned: false,
                    })
                }
            }
            _ => Err(AttemptErr {
                text: format!("unknown DNS query type: {}", raw_json(value)),
                returned: false,
            }),
        },
        "option.DNSRecordOptions" => match value {
            JsonValue::Str(s) => dns_record_validate(s).map_err(|msg| AttemptErr {
                text: msg,
                returned: false,
            }),
            _ => Err(attempt_ute(kind_desc(value), "string")),
        },
        "option.InterfaceType" => match value {
            JsonValue::Str(s) => {
                if tables::INTERFACETYPE.contains(&s.as_str()) {
                    Ok(())
                } else {
                    Err(AttemptErr {
                        text: format!("unknown interface type: {s}"),
                        returned: false,
                    })
                }
            }
            _ => Err(attempt_ute(kind_desc(value), "string")),
        },
        _ => Err(attempt_ute(kind_desc(value), "string")),
    }
}

fn listable_slice_go(elem: &str) -> String {
    match elem {
        "string" => "[]string".to_string(),
        "uint16" => "[]uint16".to_string(),
        "int32" => "[]int32".to_string(),
        "netip.Addr" => "[]netip.Addr".to_string(),
        "netip.Prefix" => "[]netip.Prefix".to_string(),
        "*badoption.Prefixable" => "[]*badoption.Prefixable".to_string(),
        "[]uint8" => "[][]uint8".to_string(),
        "option.CurvePreference" => "[]option.CurvePreference".to_string(),
        "option.DNSQueryType" => "[]option.DNSQueryType".to_string(),
        "option.DNSRecordOptions" => "[]option.DNSRecordOptions".to_string(),
        "option.InterfaceType" => "[]option.InterfaceType".to_string(),
        _ => "[]string".to_string(),
    }
}

/// The array attempt: decode `value` as `[]T` (fresh decode).
fn listable_array(elem: &str, value: &JsonValue) -> Result<(), AttemptErr> {
    let items = match value {
        JsonValue::Array(items) => items,
        _ => {
            return Err(attempt_ute(kind_desc(value), &listable_slice_go(elem)));
        }
    };
    for (i, item) in items.iter().enumerate() {
        if item.is_null() {
            continue;
        }
        if let Err(e) = listable_single(elem, item) {
            if e.returned {
                return Err(e);
            }
            return Err(AttemptErr {
                text: format!("[{i}]: {}", e.text),
                returned: false,
            });
        }
    }
    Ok(())
}

pub fn listable_validate(elem: &str, value: &JsonValue, ctx: &Ctx) -> Result<(), SbErr> {
    let single = listable_single(elem, value);
    if single.is_ok() {
        return Ok(());
    }
    let array = listable_array(elem, value);
    if array.is_ok() {
        return Ok(());
    }
    Err(bare_at(
        ctx,
        format!(
            "({} | {})",
            single.unwrap_err().text,
            array.unwrap_err().text
        ),
    ))
}

// ---------------------------------------------------------------------------
// Container fields.
// ---------------------------------------------------------------------------

fn slice_struct_validate(
    field: &FieldDef,
    value: &JsonValue,
    ctx: &Ctx,
    depth: usize,
) -> Result<(), SbErr> {
    let sub = field.sub.unwrap_or("");
    let slice_go = match sub {
        "AddrPort" => "[]netip.AddrPort".to_string(),
        "Prefix" => "[]netip.Prefix".to_string(),
        _ => format!("[]option.{sub}"),
    };
    let items = match value {
        JsonValue::Array(items) => items,
        _ => return Err(ute_at(ctx, kind_desc(value), &slice_go)),
    };
    for (i, item) in items.iter().enumerate() {
        // Null elements are a no-op for plain structs, but types
        // with a custom unmarshaler (`DNSServerOptions`, `DNSRule`)
        // receive the null and fail inside it.
        let custom_unmarshaler = matches!(sub, "DNSServerOptions" | "DNSRule");
        if item.is_null() && !custom_unmarshaler {
            continue;
        }
        let mut ectx = ctx.clone();
        ectx.path.push(Seg::Idx(i));
        match sub {
            "AddrPort" => match item {
                JsonValue::Str(s) => {
                    if let Err(msg) = netip_parse_addr_port(s) {
                        return Err(SbErr::Returned(msg));
                    }
                }
                _ => return Err(ute_at(&ectx, kind_desc(item), "netip.AddrPort")),
            },
            "Prefix" => match item {
                JsonValue::Str(s) => {
                    if let Err(msg) = netip_parse_prefix(s) {
                        return Err(SbErr::Returned(msg));
                    }
                }
                _ => return Err(ute_at(&ectx, kind_desc(item), "netip.Prefix")),
            },
            "DNSRule" => {
                if let Err(e) = validate_dns_rule(item, depth) {
                    return Err(save(&ectx, e));
                }
            }
            "DNSServerOptions" => {
                if let Err(e) = validate_dns_server(item) {
                    return Err(save(&ectx, e));
                }
            }
            _ => match item {
                JsonValue::Object(_) => {
                    let mut nctx = ectx.clone();
                    nctx.struct_name = Some(sub);
                    validate_struct(sub, item, &nctx, depth)?;
                }
                _ => {
                    return Err(ute_at(&ectx, kind_desc(item), &format!("option.{sub}")));
                }
            },
        }
    }
    Ok(())
}

fn object_field_validate(
    field: &FieldDef,
    value: &JsonValue,
    ctx: &Ctx,
    depth: usize,
) -> Result<(), SbErr> {
    let sub = field.sub.unwrap_or("");
    if sub == "NetworkBytesCompat" {
        return network_bytes_compat_value(value).map_err(|e| save(ctx, e));
    }
    match value {
        JsonValue::Object(_) => {
            let mut nctx = ctx.clone();
            nctx.struct_name = Some(sub);
            validate_struct(sub, value, &nctx, depth)
        }
        _ => Err(ute_at(ctx, kind_desc(value), &format!("option.{sub}"))),
    }
}

fn typedmap_validate(field: &FieldDef, value: &JsonValue, ctx: &Ctx) -> Result<(), SbErr> {
    let obj = match value {
        JsonValue::Object(o) => o,
        _ => {
            let token = match value {
                JsonValue::Null => "nil".to_string(),
                JsonValue::Bool(b) => b.to_string(),
                JsonValue::Number(lit) => lit.clone(),
                JsonValue::Str(s) => s.clone(),
                JsonValue::Array(_) => "[".to_string(),
                JsonValue::Object(_) => unreachable!(),
            };
            return Err(bare_at(
                ctx,
                format!("expected json object start, but starts with {token}"),
            ));
        }
    };
    let key_go = field.key.unwrap_or("string");
    let val_go = field.val.unwrap_or("string");
    for (k, item) in obj.iter() {
        if matches!(key_go, "option.InterfaceType") && !tables::INTERFACETYPE.contains(&k.as_str())
        {
            return Err(bare_at(
                ctx,
                format!("decode json object content: unknown interface type: {k}"),
            ));
        }
        if item.is_null() {
            continue;
        }
        // The value decode is a fresh decode; its error is wrapped
        // in `decode json object content: ...`.
        let mut vctx = Ctx::fresh();
        vctx.struct_name = None;
        if let Err(e) = listable_validate(val_go, item, &vctx) {
            return Err(bare_at(
                ctx,
                format!("decode json object content: {}", e.text()),
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Nested dispatches (field-level): V2Ray transport, hysteria2 obfs,
// HTTPClient, bool-or-object customs, domain resolver.
// ---------------------------------------------------------------------------

/// Strict-decode `value` into the struct table `name` with a fresh
/// context (one `UnmarshalContextDisallowUnknownFields` pass).
fn strict_struct(name: &'static str, value: &JsonValue) -> Result<(), SbErr> {
    validate_struct(name, value, &Ctx::fresh(), 0)
}

/// Loose-decode `value` into the struct table `name` (plain pass:
/// unknown keys ignored) with a fresh context.
fn loose_struct(name: &'static str, value: &JsonValue) -> Result<(), SbErr> {
    validate_struct_loose(name, value, &Ctx::fresh(), 0)
}

fn field_str<'a>(obj: &'a crate::jsonvalue::OrderedObject, key: &str) -> Option<&'a str> {
    match obj.get(key) {
        Some(JsonValue::Str(s)) => Some(s.as_str()),
        _ => None,
    }
}

fn transport_validate(value: &JsonValue, ctx: &Ctx) -> Result<(), SbErr> {
    let obj = match value {
        JsonValue::Object(o) => o,
        _ => {
            return Err(save(
                ctx,
                SbErr::BareUte {
                    value: kind_desc(value).to_string(),
                    typ: "option._V2RayTransportOptions".to_string(),
                },
            ));
        }
    };
    if let Err(e) = loose_struct("_V2RayTransportOptions", value) {
        return Err(save(ctx, e));
    }
    let typ = field_str(obj, "type").unwrap_or("");
    let Some((_, variant)) = tables::V2RAY_TRANSPORT.iter().find(|(k, _)| *k == typ) else {
        return Err(bare_at(ctx, format!("unknown transport type: {typ}")));
    };
    if variant.is_empty() {
        return Ok(());
    }
    let remainder = excluded_remainder_keys(obj, &["type".to_string()]);
    let value = JsonValue::Object(remainder);
    strict_struct(variant, &value).map_err(|e| save(ctx, e))
}

fn obfs_validate(value: &JsonValue, ctx: &Ctx) -> Result<(), SbErr> {
    let obj = match value {
        JsonValue::Object(o) => o,
        _ => {
            return Err(save(
                ctx,
                SbErr::BareUte {
                    value: kind_desc(value).to_string(),
                    typ: "option._Hysteria2Obfs".to_string(),
                },
            ));
        }
    };
    if let Err(e) = loose_struct("_Hysteria2Obfs", value) {
        return Err(save(ctx, e));
    }
    let typ = field_str(obj, "type").unwrap_or("");
    match typ {
        "salamander" => Ok(()),
        "gecko" => {
            let remainder =
                excluded_remainder_keys(obj, &["type".to_string(), "password".to_string()]);
            let value = JsonValue::Object(remainder);
            strict_struct("Hysteria2ObfsGecko", &value).map_err(|e| save(ctx, e))
        }
        _ => Err(bare_at(ctx, format!("unknown obfs type: {typ}"))),
    }
}

fn http_client_validate(value: &JsonValue, ctx: &Ctx) -> Result<(), SbErr> {
    match value {
        JsonValue::Str(_) => Ok(()),
        JsonValue::Object(obj) => {
            if let Err(e) = loose_struct("_HTTPClientOptions", value) {
                return Err(save(ctx, e));
            }
            let version: i64 = match obj.get("version") {
                Some(JsonValue::Number(lit)) => number_int(lit).map(|n| n as i64).unwrap_or(0),
                _ => 0,
            };
            match version {
                1 => {
                    // Version 1: the whole content must contain only
                    // `_HTTPClientOptions` keys (strict, unfiltered
                    // beyond the outer boundary's filter).
                    strict_struct("_HTTPClientOptions", value).map_err(|e| save(ctx, e))
                }
                0 | 2 => {
                    let remainder = excluded_remainder(obj, "_HTTPClientOptions");
                    let value = JsonValue::Object(remainder);
                    strict_struct("HTTP2Options", &value).map_err(|e| save(ctx, e))
                }
                3 => {
                    let remainder = excluded_remainder(obj, "_HTTPClientOptions");
                    let value = JsonValue::Object(remainder);
                    strict_struct("QUICOptions", &value).map_err(|e| save(ctx, e))
                }
                _ => Err(bare_at(ctx, format!("unknown HTTP version: {version}"))),
            }
        }
        _ => Err(save(
            ctx,
            SbErr::BareUte {
                value: kind_desc(value).to_string(),
                typ: "option._HTTPClientOptions".to_string(),
            },
        )),
    }
}

/// `OptimisticDNSOptions` / `UDPOverTCPOptions`: a bool, or a strict
/// object of the alias struct; anything else is the alias UTE.
fn custom_bool_or_object(value: &JsonValue, ctx: &Ctx, alias: &'static str) -> Result<(), SbErr> {
    match value {
        JsonValue::Bool(_) => Ok(()),
        JsonValue::Object(_) => strict_struct(alias, value).map_err(|e| save(ctx, e)),
        _ => Err(save(
            ctx,
            SbErr::BareUte {
                value: kind_desc(value).to_string(),
                typ: format!("option.{alias}"),
            },
        )),
    }
}

fn domain_resolver_validate(value: &JsonValue, ctx: &Ctx) -> Result<(), SbErr> {
    match value {
        JsonValue::Str(_) => Ok(()),
        JsonValue::Object(obj) => {
            // Plain (non-strict) unmarshal into `_DomainResolveOptions`:
            // unknown fields are ignored, `server` / `strategy` types
            // are checked with the alias struct path.
            if let Err(e) = loose_struct("_DomainResolveOptions", value) {
                return Err(save(ctx, e));
            }
            match field_str(obj, "server") {
                Some(s) if !s.is_empty() => Ok(()),
                _ => Err(bare_at(ctx, "empty domain_resolver.server")),
            }
        }
        _ => Err(save(
            ctx,
            SbErr::BareUte {
                value: kind_desc(value).to_string(),
                typ: "option._DomainResolveOptions".to_string(),
            },
        )),
    }
}

// ---------------------------------------------------------------------------
// Strict / plain struct decode over a generated table.
// ---------------------------------------------------------------------------

/// JSON keys of the fields of `table` whose embedded chain is
/// exactly `[emb_filter]` (e.g. the `RawDefaultDNSRule` fields of
/// the `DefaultDNSRule` table).
fn raw_field_keys(table: &str, emb_filter: &str) -> Vec<String> {
    match tables::struct_by_name(table) {
        Some(t) => t
            .fields
            .iter()
            .filter(|f| f.emb.len() == 1 && f.emb[0] == emb_filter)
            .map(|f| f.json.to_string())
            .collect(),
        None => Vec::new(),
    }
}

pub fn validate_struct(
    name: &'static str,
    value: &JsonValue,
    ctx: &Ctx,
    depth: usize,
) -> Result<(), SbErr> {
    validate_struct_inner(name, value, ctx, depth, true, None, None)
}

pub fn validate_struct_loose(
    name: &'static str,
    value: &JsonValue,
    ctx: &Ctx,
    depth: usize,
) -> Result<(), SbErr> {
    validate_struct_inner(name, value, ctx, depth, false, None, None)
}

fn validate_struct_named(
    table: &'static str,
    value: &JsonValue,
    ctx: &Ctx,
    depth: usize,
    strict: bool,
    struct_override: &'static str,
) -> Result<(), SbErr> {
    validate_struct_inner(
        table,
        value,
        ctx,
        depth,
        strict,
        Some(struct_override),
        None,
    )
}

fn validate_struct_filtered(
    table: &'static str,
    value: &JsonValue,
    ctx: &Ctx,
    depth: usize,
    strict: bool,
    emb_filter: &str,
    struct_override: &'static str,
) -> Result<(), SbErr> {
    validate_struct_inner(
        table,
        value,
        ctx,
        depth,
        strict,
        Some(struct_override),
        Some(emb_filter),
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_struct_inner(
    table_name: &'static str,
    value: &JsonValue,
    ctx: &Ctx,
    depth: usize,
    strict: bool,
    struct_override: Option<&'static str>,
    emb_filter: Option<&str>,
) -> Result<(), SbErr> {
    let Some(table) = tables::struct_by_name(table_name) else {
        return Ok(());
    };
    let obj = match value {
        JsonValue::Object(o) => o,
        JsonValue::Null => return Ok(()),
        _ => {
            return Err(SbErr::BareUte {
                value: kind_desc(value).to_string(),
                typ: format!("option.{}", struct_override.unwrap_or(table_name)),
            });
        }
    };
    let struct_name = struct_override.unwrap_or(table_name);
    for (k, item) in obj.iter() {
        let Some(field) = table.fields.iter().find(|f| f.json == *k) else {
            if strict {
                let mut pctx = ctx.clone();
                pctx.path.push(Seg::Key(k.clone()));
                return Err(bare_at(
                    &pctx,
                    format!("json: unknown field {}", go_quote(k)),
                ));
            }
            continue;
        };
        if let Some(filter) = emb_filter
            && !(field.emb.len() == 1 && field.emb[0] == filter)
        {
            continue;
        }
        if item.is_null() {
            continue;
        }
        let mut fctx = ctx.clone();
        fctx.struct_name = Some(struct_name);
        // When a filtered pass decodes a sub-struct (e.g. the
        // `RawDefaultDNSRule` fields of `DefaultDNSRule`), the
        // filter name itself is the struct being decoded, not an
        // intermediate embedded name: drop it from the field stack.
        let emb_push: &[&str] = match emb_filter {
            Some(f) if field.emb.first() == Some(&f) => &field.emb[1..],
            _ => field.emb,
        };
        for emb in emb_push {
            fctx.field_stack.push((*emb).to_string());
        }
        fctx.field_stack.push(field.json.to_string());
        fctx.path.push(Seg::Key(k.clone()));
        validate_field(field, item, &fctx, depth)?;
    }
    Ok(())
}

/// The badjson excluded pass: remove the parent struct's keys,
/// drop empty values recursively, and strict-decode the remainder
/// into `options_table` with a fresh context.
fn excluded_pass(
    obj: &crate::jsonvalue::OrderedObject,
    parent_keys: &[String],
    options_table: &'static str,
) -> Result<(), SbErr> {
    let remainder = excluded_remainder_keys(obj, parent_keys);
    let value = JsonValue::Object(remainder);
    validate_struct(options_table, &value, &Ctx::fresh(), 0)
}

// ---------------------------------------------------------------------------
// Top-level dispatches: outbound / endpoint / dns / dns server / dns rule.
// ---------------------------------------------------------------------------

/// Plain (non-strict) decode of a `{type, tag}` header object with
/// the given alias struct path (e.g. `_Outbound`).
fn plain_type_tag(value: &JsonValue, alias: &'static str) -> Result<(String, String), SbErr> {
    let obj = match value {
        JsonValue::Object(o) => o,
        JsonValue::Null => return Ok((String::new(), String::new())),
        _ => {
            return Err(SbErr::BareUte {
                value: kind_desc(value).to_string(),
                typ: format!("option.{alias}"),
            });
        }
    };
    let mut ctx = Ctx::fresh();
    ctx.struct_name = Some(alias);
    for (k, item) in obj.iter() {
        if item.is_null() {
            continue;
        }
        if k != "type" && k != "tag" {
            continue;
        }
        if !matches!(item, JsonValue::Str(_)) {
            let mut fctx = ctx.clone();
            fctx.field_stack.push(k.clone());
            fctx.path.push(Seg::Key(k.clone()));
            return Err(ute_at(&fctx, kind_desc(item), "string"));
        }
    }
    Ok((
        field_str(obj, "type").unwrap_or("").to_string(),
        field_str(obj, "tag").unwrap_or("").to_string(),
    ))
}

/// Validate one top-level `outbounds` element. Returns the outbound
/// type on success (the caller applies the `wireguard` rejection
/// and the tag check after the parse, as Go does).
pub fn validate_outbound(value: &JsonValue) -> Result<String, SbErr> {
    let (typ, _tag) = plain_type_tag(value, "_Outbound")?;
    if typ == "dns" {
        return Err(SbErr::Bare(
            "dns outbound is deprecated in sing-box 1.11.0 and removed in sing-box 1.13.0, use rule actions instead"
                .to_string(),
        ));
    }
    let Some((_, options)) = tables::OUTBOUND_OPTIONS.iter().find(|(k, _)| *k == typ) else {
        return Err(SbErr::Bare(format!("unknown outbound type: {typ}")));
    };
    let obj = match value {
        JsonValue::Object(o) => o,
        _ => unreachable!("plain_type_tag accepted a non-object"),
    };
    match *options {
        "DirectOutboundOptions" => {
            // The outer excluded pass removed `type`/`tag`; the
            // remainder is strict-decoded into `_DirectOutboundOptions`.
            let remainder = excluded_remainder_keys(obj, &["type".to_string(), "tag".to_string()]);
            let value = JsonValue::Object(remainder.clone());
            strict_struct("_DirectOutboundOptions", &value)?;
            let override_address = matches!(remainder.get("override_address"), Some(JsonValue::Str(s)) if !s.is_empty());
            let override_port = matches!(remainder.get("override_port"), Some(JsonValue::Number(lit)) if number_int(lit).map(|n| n != 0).unwrap_or(false));
            if override_address || override_port {
                return Err(SbErr::Bare(
                    "destination override fields in direct outbound are deprecated in sing-box 1.11.0 and removed in sing-box 1.13.0, use route options instead"
                        .to_string(),
                ));
            }
        }
        "SnellOutboundOptions" => {
            // Plain unmarshal into `_SnellOutboundOptions` on the
            // remainder (type/tag removed), then the version
            // dispatch, then the variant excluded pass.
            let remainder = excluded_remainder_keys(obj, &["type".to_string(), "tag".to_string()]);
            let rvalue = JsonValue::Object(remainder.clone());
            loose_struct("_SnellOutboundOptions", &rvalue)?;
            let version: i64 = match remainder.get("version") {
                Some(JsonValue::Number(lit)) => number_int(lit).map(|n| n as i64).unwrap_or(0),
                _ => 0,
            };
            let variant = match version {
                0 => return Err(SbErr::Bare("snell: missing version".to_string())),
                4 => "SnellObfsClientOptions",
                6 => "SnellV6Options",
                n => {
                    return Err(SbErr::Bare(format!("snell: unsupported version: {n}")));
                }
            };
            let keys = struct_keys("_SnellOutboundOptions");
            let keys: Vec<String> = keys.iter().map(|k| (*k).to_string()).collect();
            let value = JsonValue::Object(excluded_remainder_keys(&remainder, &keys));
            validate_struct(variant, &value, &Ctx::fresh(), 0)?;
        }
        _ => {
            let remainder = excluded_remainder_keys(obj, &["type".to_string(), "tag".to_string()]);
            let value = JsonValue::Object(remainder);
            validate_struct(options, &value, &Ctx::fresh(), 0)?;
            // `wireguard` parses as a stub, then is rejected
            // AFTER the strict parse (Go `outbound.go`): an
            // unknown field beats the type rejection.
            if typ == "wireguard" {
                return Err(SbErr::Bare(WIREGUARD_OUTBOUND_MESSAGE.to_string()));
            }
        }
    }
    Ok(typ.to_string())
}

/// Validate one top-level `endpoints` element. Returns the endpoint
/// type on success.
pub fn validate_endpoint(value: &JsonValue) -> Result<String, SbErr> {
    let (typ, _tag) = plain_type_tag(value, "_Endpoint")?;
    let Some((_, options)) = tables::ENDPOINT_OPTIONS.iter().find(|(k, _)| *k == typ) else {
        return Err(SbErr::Bare(format!("unknown endpoint type: {typ}")));
    };
    let obj = match value {
        JsonValue::Object(o) => o,
        _ => unreachable!("plain_type_tag accepted a non-object"),
    };
    let remainder = excluded_remainder_keys(obj, &["type".to_string(), "tag".to_string()]);
    let value = JsonValue::Object(remainder);
    validate_struct(options, &value, &Ctx::fresh(), 0)?;
    Ok(typ.to_string())
}

/// Validate the top-level `dns` block (Go `parseDNS`).
pub fn validate_dns(value: &JsonValue) -> Result<(), SbErr> {
    match value {
        JsonValue::Object(obj) => {
            if obj.has("fakeip") {
                return Err(SbErr::Bare(
                    "legacy DNS fakeip options are deprecated in sing-box 1.12.0 and removed in sing-box 1.14.0, checkout migration: https://sing-box.sagernet.org/migration/#migrate-to-new-dns-server-formats"
                        .to_string(),
                ));
            }
            excluded_pass(obj, &["fakeip".to_string()], "RawDNSOptions")
        }
        JsonValue::Null => Err(SbErr::Bare(
            "expected json object start, but starts with nil".to_string(),
        )),
        _ => Err(SbErr::BareUte {
            value: kind_desc(value).to_string(),
            typ: "option.removedLegacyDNSOptions".to_string(),
        }),
    }
}

/// Validate one `dns.servers` element.
pub fn validate_dns_server(value: &JsonValue) -> Result<(), SbErr> {
    let (typ, _tag) = plain_type_tag(value, "_DNSServerOptions")?;
    if typ.is_empty() {
        return Err(SbErr::Bare(
            "legacy DNS server formats are deprecated in sing-box 1.12.0 and removed in sing-box 1.14.0, checkout migration: https://sing-box.sagernet.org/migration/#migrate-to-new-dns-server-formats"
                .to_string(),
        ));
    }
    let Some((_, options)) = tables::DNS_SERVER_OPTIONS.iter().find(|(k, _)| *k == typ) else {
        return Err(SbErr::Bare(format!("unknown transport type: {typ}")));
    };
    let obj = match value {
        JsonValue::Object(o) => o,
        _ => unreachable!("plain_type_tag accepted a non-object"),
    };
    let remainder = excluded_remainder_keys(obj, &["type".to_string(), "tag".to_string()]);
    let value = JsonValue::Object(remainder);
    validate_struct(options, &value, &Ctx::fresh(), 0)
}

// ---------------------------------------------------------------------------
// DNS rules (depth-threaded; the content is badjson-filtered first).
// ---------------------------------------------------------------------------

/// Action keys for the nested-rule check (`_DNSRuleAction` +
/// `DNSRouteActionOptions` + `DNSEvaluateActionOptions` json keys).
const DNS_RULE_ACTION_KEYS: &[&str] = &[
    "action",
    "race",
    "server",
    "speculative",
    "timeout",
    "strategy",
    "disable_cache",
    "disable_optimistic_cache",
    "rewrite_ttl",
    "client_subnet",
    "remove_client_subnet",
    "tag",
];

/// `inspectDNSRuleAction`: plain `_DNSRuleAction` + plain
/// `DNSRouteActionOptions`, on the filtered rule object.
fn inspect_dns_rule_action(obj: &crate::jsonvalue::OrderedObject) -> Result<(), SbErr> {
    let value = JsonValue::Object(obj.clone());
    validate_struct_named(
        "DNSRuleAction",
        &value,
        &Ctx::fresh(),
        0,
        false,
        "_DNSRuleAction",
    )?;
    validate_struct_loose("DNSRouteActionOptions", &value, &Ctx::fresh(), 0)
}

fn validate_dns_rule(value: &JsonValue, depth: usize) -> Result<(), SbErr> {
    match value {
        JsonValue::Object(_) => {}
        JsonValue::Null => {
            return Err(SbErr::Bare(
                "expected json object start, but starts with nil".to_string(),
            ));
        }
        _ => {
            return Err(SbErr::BareUte {
                value: kind_desc(value).to_string(),
                typ: "option._DNSRule".to_string(),
            });
        }
    };
    // The `DNSRule` excluded pass filters empty values before the
    // rule body is decoded (batch 11: `{"server": {}}` is invisible
    // to `inspect` and to the nested check).
    let fobj = match filter_empty(value) {
        Some(JsonValue::Object(o)) => o,
        _ => crate::jsonvalue::OrderedObject::new(),
    };
    // Step 1: plain `_DNSRule` (type only).
    let fvalue = JsonValue::Object(fobj.clone());
    let (typ, _tag) = plain_type_tag(&fvalue, "_DNSRule")?;
    let logical = match typ.as_str() {
        "" | "default" => false,
        "logical" => true,
        _ => {
            return Err(SbErr::Bare(format!("unknown rule type: {typ}")));
        }
    };
    // Step 2: inspect (runs before the nested check).
    inspect_dns_rule_action(&fobj)?;
    // Step 3: nested-rule action rejection (depth > 0, on the
    // filtered content: empty objects/arrays do not count).
    if depth > 0 && DNS_RULE_ACTION_KEYS.iter().any(|k| fobj.has(k)) {
        return Err(SbErr::Bare(
            "DNS rule action is not supported in nested rules".to_string(),
        ));
    }
    // Step 4: plain pass into the raw rule fields.
    let raw_value = fvalue.clone();
    if logical {
        validate_struct_filtered(
            "LogicalDNSRule",
            &raw_value,
            &Ctx::fresh(),
            depth + 1,
            false,
            "RawLogicalDNSRule",
            "RawLogicalDNSRule",
        )?;
    } else {
        validate_struct_filtered(
            "DefaultDNSRule",
            &raw_value,
            &Ctx::fresh(),
            depth,
            false,
            "RawDefaultDNSRule",
            "RawDefaultDNSRule",
        )?;
    }
    // Step 5: the action dispatch. The `DNSRule`-level excluded
    // pass (parent `_DNSRule`) removed `type` before the rule body
    // was decoded, so the remainder here is the rule object minus
    // `type` and minus the RAW struct's keys; the variant pass
    // (parent `_DNSRuleAction`) then also removes `action`/`race`.
    let mut parent_keys = if logical {
        raw_field_keys("LogicalDNSRule", "RawLogicalDNSRule")
    } else {
        raw_field_keys("DefaultDNSRule", "RawDefaultDNSRule")
    };
    parent_keys.push("type".to_string());
    let remainder = excluded_remainder_keys(&fobj, &parent_keys);
    let variant_remainder =
        excluded_remainder_keys(&remainder, &["action".to_string(), "race".to_string()]);
    let action = field_str(&fobj, "action").unwrap_or("");
    let remainder_value = JsonValue::Object(variant_remainder.clone());
    match action {
        "" | "route" => {
            validate_struct("DNSRouteActionOptions", &remainder_value, &Ctx::fresh(), 0)?;
        }
        "evaluate" => {
            validate_struct(
                "DNSEvaluateActionOptions",
                &remainder_value,
                &Ctx::fresh(),
                0,
            )?;
        }
        "respond" => {
            // `v == nil`: the whole remainder must contain only
            // `_DNSRuleAction` keys.
            validate_struct_named(
                "DNSRuleAction",
                &remainder_value,
                &Ctx::fresh(),
                0,
                true,
                "_DNSRuleAction",
            )?;
        }
        "route-options" => {
            // Plain unmarshal into `AbstractDNSRouteActionOptions`
            // (unknown keys ignored), then the empty check (the
            // PARSED struct must be non-zero).
            validate_struct_named(
                "DNSRouteOptionsActionOptions",
                &remainder_value,
                &Ctx::fresh(),
                0,
                false,
                "AbstractDNSRouteActionOptions",
            )?;
            let mut all_zero = true;
            for (k, v) in variant_remainder.iter() {
                match k.as_str() {
                    "timeout" => {
                        if let JsonValue::Str(s) = v
                            && go_parse_duration(s).map(|d| d != 0).unwrap_or(false)
                        {
                            all_zero = false;
                        }
                    }
                    "strategy" => {
                        if let JsonValue::Str(s) = v
                            && !s.is_empty()
                        {
                            all_zero = false;
                        }
                    }
                    "disable_cache" | "disable_optimistic_cache" | "remove_client_subnet" => {
                        if matches!(v, JsonValue::Bool(true)) {
                            all_zero = false;
                        }
                    }
                    "rewrite_ttl" => {
                        if let JsonValue::Number(lit) = v
                            && number_int(lit).map(|n| n != 0).unwrap_or(false)
                        {
                            all_zero = false;
                        }
                    }
                    "client_subnet" if !v.is_null() => {
                        all_zero = false;
                    }
                    _ => {}
                }
            }
            if all_zero {
                return Err(SbErr::Bare("empty DNS route option action".to_string()));
            }
        }
        "reject" => {
            // Plain unmarshal into `_RejectActionOptions`
            // (unknown keys ignored), then the method checks.
            validate_struct_loose("_RejectActionOptions", &remainder_value, &Ctx::fresh(), 0)?;
            let method = field_str(&variant_remainder, "method").unwrap_or("");
            match method {
                "" | "default" | "drop" | "reply" => {}
                _ => {
                    return Err(SbErr::Bare(format!("unknown reject method: {method}")));
                }
            }
            if method == "drop"
                && matches!(
                    variant_remainder.get("no_drop"),
                    Some(JsonValue::Bool(true))
                )
            {
                return Err(SbErr::Bare(
                    "no_drop is not available in current context".to_string(),
                ));
            }
        }
        "predefined" => {
            validate_struct(
                "DNSRouteActionPredefined",
                &remainder_value,
                &Ctx::fresh(),
                0,
            )?;
        }
        _ => {
            return Err(SbErr::Bare(format!("unknown DNS rule action: {action}")));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// DNS records (zone text): a small port of miekg/dns `zlexer` +
// `ZoneParser` for the first record, plus the base64 wire form.
// ---------------------------------------------------------------------------

/// A zone token with its 1-based start column and terminator.
struct ZTok {
    text: String,
    /// 1-based column of the token's last character (for a
    /// newline/EOF-terminated token) or of its delimiter (space/tab).
    col: usize,
    /// Whether the token was terminated by a blank (space/tab).
    blank_after: bool,
}

const KNOWN_RR_TYPES: &[&str] = &[
    "A",
    "NS",
    "MD",
    "MF",
    "CNAME",
    "SOA",
    "MB",
    "MG",
    "MR",
    "NULL",
    "WKS",
    "PTR",
    "HINFO",
    "MINFO",
    "MX",
    "TXT",
    "RP",
    "AFSDB",
    "X25",
    "ISDN",
    "RT",
    "NSAP",
    "NSAP_PTR",
    "SIG",
    "KEY",
    "PX",
    "GPOS",
    "AAAA",
    "LOC",
    "NXT",
    "EID",
    "NIMLOC",
    "SRV",
    "ATMA",
    "NAPTR",
    "KX",
    "CERT",
    "A6",
    "DNAME",
    "SINK",
    "OPT",
    "APL",
    "DS",
    "SSHFP",
    "IPSECKEY",
    "RRSIG",
    "NSEC",
    "DNSKEY",
    "DHCID",
    "NSEC3",
    "NSEC3PARAM",
    "TLSA",
    "SMIMEA",
    "HIP",
    "NINFO",
    "RKEY",
    "TALINK",
    "CDS",
    "CDNSKEY",
    "OPENPGPKEY",
    "CSYNC",
    "ZONEMD",
    "SVCB",
    "HTTPS",
    "SPF",
    "UINFO",
    "UID",
    "GID",
    "UNSPEC",
    "NID",
    "L32",
    "L64",
    "LP",
    "EUI48",
    "EUI64",
    "TKEY",
    "TSIG",
    "IXFR",
    "AXFR",
    "MAILB",
    "MAILA",
    "ANY",
    "URI",
    "CAA",
    "TA",
    "DLV",
];

const KNOWN_CLASSES: &[&str] = &["IN", "CH", "HS", "CS", "ANY"];

fn is_rr_type(tok: &str) -> bool {
    let up = tok.to_ascii_uppercase();
    if KNOWN_RR_TYPES.contains(&up.as_str()) {
        return true;
    }
    // `TYPE<n>` (decimal).
    if let Some(rest) = up.strip_prefix("TYPE") {
        return !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit());
    }
    false
}

fn is_class(tok: &str) -> bool {
    let up = tok.to_ascii_uppercase();
    if KNOWN_CLASSES.contains(&up.as_str()) {
        return true;
    }
    if let Some(rest) = up.strip_prefix("CLASS") {
        return !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit());
    }
    false
}

fn rr_type_num(tok: &str) -> Option<u16> {
    let up = tok.to_ascii_uppercase();
    up.strip_prefix("TYPE")
        .and_then(|rest| rest.parse::<u32>().ok())
        .filter(|n| *n <= 65535)
        .map(|n| n as u16)
}

/// Tokenize the first record's line: strip `;` comments, skip
/// blank lines, honour `()` grouping (newlines inside parens are
/// blanks) and `"..."` quoted strings.
fn zone_tokens(input: &str) -> (Vec<ZTok>, usize) {
    let mut tokens: Vec<ZTok> = Vec::new();
    let mut cur = String::new();
    let mut cur_start_col = 1usize; // 1-based column of cur's first char
    let mut col = 0usize; // chars consumed on this line
    let mut paren_depth = 0usize;
    let mut in_quote = false;
    let mut escaped = false;
    let mut line_has_token = false;

    let flush = |tokens: &mut Vec<ZTok>,
                 cur: &mut String,
                 cur_start_col: usize,
                 col: usize,
                 blank_after: bool,
                 line_end: bool| {
        if cur.is_empty() {
            return;
        }
        let tok_col = if line_end {
            // Newline/EOF does not advance the column: the token's
            // last character.
            cur_start_col + cur.chars().count() - 1
        } else {
            // The delimiter's column (1-based).
            col + 1
        };
        tokens.push(ZTok {
            text: std::mem::take(cur),
            col: tok_col,
            blank_after,
        });
    };

    let chars: Vec<char> = input.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        let c = chars[i];
        if in_quote {
            cur.push(c);
            col += 1;
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_quote = false;
            }
            i += 1;
            continue;
        }
        match c {
            ';' => {
                // Comment to end of line.
                flush(&mut tokens, &mut cur, cur_start_col, col, false, true);
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            '(' => {
                paren_depth += 1;
                if cur.is_empty() {
                    cur_start_col = col + 1;
                }
                cur.push(c);
                col += 1;
                i += 1;
            }
            ')' => {
                paren_depth = paren_depth.saturating_sub(1);
                cur.push(c);
                col += 1;
                i += 1;
            }
            '"' => {
                if cur.is_empty() {
                    cur_start_col = col + 1;
                }
                in_quote = true;
                cur.push(c);
                col += 1;
                i += 1;
            }
            ' ' | '\t' => {
                flush(&mut tokens, &mut cur, cur_start_col, col, true, false);
                col += 1;
                i += 1;
            }
            '\n' | '\r' => {
                if paren_depth > 0 {
                    // Newline inside parens is a blank.
                    flush(&mut tokens, &mut cur, cur_start_col, col, true, false);
                    col = 0;
                    i += 1;
                    continue;
                }
                flush(&mut tokens, &mut cur, cur_start_col, col, false, true);
                if !tokens.is_empty() {
                    // The first record's line is complete.
                    return (tokens, col);
                }
                col = 0;
                line_has_token = false;
                i += 1;
                // Skip the newline itself.
                if c == '\r' && i < chars.len() && chars[i] == '\n' {
                    i += 1;
                }
            }
            _ => {
                if cur.is_empty() {
                    cur_start_col = col + 1;
                    line_has_token = true;
                }
                cur.push(c);
                col += 1;
                i += 1;
            }
        }
    }
    let _ = line_has_token;
    flush(&mut tokens, &mut cur, cur_start_col, col, false, true);
    (tokens, col)
}

fn zone_err(msg: &str, tok: &str, col: usize) -> String {
    format!("dns: {msg}: {} at line: 1:{col}", go_quote(tok))
}

/// miekg `stringToTTL`: the Go loop — digits accumulate, each
/// `s/m/h/d/w` suffix (either case) adds the accumulated value
/// times its multiplier; any other character rejects. An empty
/// string is a valid TTL of 0.
fn string_to_ttl(s: &str) -> Option<u32> {
    let mut total: u64 = 0;
    let mut i: u64 = 0;
    for c in s.chars() {
        match c {
            's' | 'S' => {
                total += i;
                i = 0;
            }
            'm' | 'M' => {
                total += i * 60;
                i = 0;
            }
            'h' | 'H' => {
                total += i * 60 * 60;
                i = 0;
            }
            'd' | 'D' => {
                total += i * 60 * 60 * 24;
                i = 0;
            }
            'w' | 'W' => {
                total += i * 60 * 60 * 24 * 7;
                i = 0;
            }
            '0'..='9' => {
                i = i * 10 + (c as u64 - '0' as u64);
            }
            _ => return None,
        }
    }
    let v = total + i;
    if v > u32::MAX as u64 {
        return None;
    }
    Some(v as u32)
}

/// miekg `toAbsoluteName` with an empty origin: the name must end
/// in `.`, must not contain empty labels, and `@` is not a name.
fn absolute_name_ok(s: &str) -> bool {
    if s.is_empty() || s == "@" {
        return false;
    }
    if !s.ends_with('.') {
        return false;
    }
    if s.contains("..") {
        return false;
    }
    true
}

fn parse_uint_bits(s: &str, bits: u32) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: u64 = s.parse().ok()?;
    let max = if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    if n > max {
        return None;
    }
    Some(n)
}

/// Validate one zone-text DNS record (`parseDNSRecord`).
/// Returns the error text (without any `parse dns:` prefix).
pub fn dns_record_validate(s: &str) -> Result<(), String> {
    // An empty string base64-decodes to nothing and `UnpackRR` on
    // it succeeds with a nil RR (probed: exit 0).
    if s.is_empty() {
        return Ok(());
    }
    // Base64 first: a decodable string is a binary (wire) record.
    if let Ok(decoded) = base64_decode_bytes(s) {
        return wire_record_ok(&decoded)
            .then_some(())
            .ok_or_else(|| "parse binary DNS record".to_string());
    }
    zone_record_validate(s)
}

/// Minimal wire-format check for `dns.UnpackRR`: a name (label
/// lengths, zero-terminated) followed by type/class/ttl/rdlen with
/// `rdlen` bytes of rdata.
fn wire_record_ok(b: &[u8]) -> bool {
    let mut i = 0usize;
    loop {
        if i >= b.len() {
            return false;
        }
        let len = b[i] as usize;
        if len == 0 {
            i += 1;
            break;
        }
        if len & 0xC0 != 0 {
            return false;
        }
        i += 1 + len;
        if i > b.len() {
            return false;
        }
    }
    if b.len() < i + 10 {
        return false;
    }
    let rdlen = u16::from_be_bytes([b[i + 8], b[i + 9]]) as usize;
    b.len() >= i + 10 + rdlen
}

fn zone_record_validate(s: &str) -> Result<(), String> {
    let input = if s.ends_with('\n') {
        s.to_string()
    } else {
        format!("{s}\n")
    };
    let (mut toks, line_len) = zone_tokens(&input);
    if toks.is_empty() {
        return Err("empty DNS record".to_string());
    }
    // The token after the last real token is the newline (its
    // column is the line's char count); the parser reads it as the
    // next token when the line ends.
    toks.push(ZTok {
        text: "\n".to_string(),
        col: line_len,
        blank_after: false,
    });
    // Directives (`$TTL`, `$ORIGIN`, ...) consume the line without
    // producing a record: a single-line directive value is an
    // empty record (documented residual: no multi-line handling).
    if toks[0].blank_after
        && matches!(
            toks[0].text.to_ascii_uppercase().as_str(),
            "$TTL" | "$ORIGIN" | "$INCLUDE" | "$GENERATE"
        )
    {
        return Err("empty DNS record".to_string());
    }
    let mut idx: usize;
    // zExpectOwnerDir: the first token.
    let first = &toks[0];
    let rr_type: String = if first.blank_after {
        // zOwner (the first blank-terminated token is always the
        // owner, even if it looks like a type or a TTL).
        if !absolute_name_ok(&first.text) {
            return Err(zone_err("bad owner name", &first.text, first.col));
        }
        idx = 1;
        // zExpectAny (the owner's blank is consumed).
        let (t, ni) = expect_any(&toks, idx)?;
        idx = ni;
        t.ok_or_else(|| "empty DNS record".to_string())?
    } else if is_rr_type(&first.text) {
        // zRrtpe as the lone token on the line: a dynamic-update
        // RR (no rdata) — accepted.
        return Ok(());
    } else {
        // zString: must be a TTL; a TTL with no blank after it
        // errors in the blank state.
        if string_to_ttl(&first.text).is_none() {
            return Err(zone_err("not a TTL", &first.text, first.col));
        }
        return Err(zone_err("no blank before TTL", "\n", first.col));
    };
    // zExpectRdata: the tokens after the type. A lone newline
    // means no rdata (dynamic-update RR, accepted).
    let rest: Vec<&ZTok> = toks[idx..].iter().filter(|t| t.text != "\n").collect();
    if rest.is_empty() {
        return Ok(());
    }
    let type_col = toks
        .iter()
        .find(|t| is_rr_type(&t.text))
        .map(|t| t.col)
        .unwrap_or(line_len);
    validate_rdata(&rr_type, &rest, type_col)
}

/// zExpectAny: after the owner. Returns the RR type and the index
/// of the first rdata token.
fn expect_any(toks: &[ZTok], mut idx: usize) -> Result<(Option<String>, usize), String> {
    let t = &toks[idx];
    if is_rr_type(&t.text) {
        return Ok((Some(t.text.clone()), idx + 1));
    }
    if is_class(&t.text) {
        // zExpectAnyNoClassBl: the class needs a blank after it.
        if !t.blank_after {
            return Err(zone_err("no blank before class", "\n", t.col));
        }
        idx += 1;
        // zExpectAnyNoClass.
        let t2 = &toks[idx];
        if is_rr_type(&t2.text) {
            return Ok((Some(t2.text.clone()), idx + 1));
        }
        if t2.text == "\n" || is_class(&t2.text) {
            return Err(zone_err(
                "expecting RR type or TTL, not this...",
                &t2.text,
                t2.col,
            ));
        }
        if string_to_ttl(&t2.text).is_some() {
            // TTL after the class.
            if !t2.blank_after {
                return Err(zone_err("no blank before RR type", "\n", t2.col));
            }
            idx += 1;
            // zExpectRrtype.
            let t3 = &toks[idx];
            if is_rr_type(&t3.text) {
                return Ok((Some(t3.text.clone()), idx + 1));
            }
            return Err(zone_err("unknown RR type", &t3.text, t3.col));
        }
        return Err(zone_err("not a TTL", &t2.text, t2.col));
    }
    if string_to_ttl(&t.text).is_some() {
        // TTL after the owner.
        if !t.blank_after {
            return Err(zone_err("no blank before TTL", "\n", t.col));
        }
        idx += 1;
        // zExpectAnyNoTTL.
        let t2 = &toks[idx];
        if is_class(&t2.text) {
            if !t2.blank_after {
                return Err(zone_err("no blank before RR type", "\n", t2.col));
            }
            idx += 1;
            // zExpectRrtype.
            let t3 = &toks[idx];
            if is_rr_type(&t3.text) {
                return Ok((Some(t3.text.clone()), idx + 1));
            }
            return Err(zone_err("unknown RR type", &t3.text, t3.col));
        }
        if is_rr_type(&t2.text) {
            return Ok((Some(t2.text.clone()), idx + 1));
        }
        return Err(zone_err(
            "expecting RR type or class, not this...",
            &t2.text,
            t2.col,
        ));
    }
    Err(zone_err("not a TTL", &t.text, t.col))
}

fn validate_rdata(rr_type: &str, rest: &[&ZTok], type_col: usize) -> Result<(), String> {
    let up = rr_type.to_ascii_uppercase();
    // A missing field at end-of-line reports the blank after the
    // type token (`" "`, the type token's column): the rdata
    // error's lex is the zero lex, substituted by the parser with
    // its current token.
    let missing = |msg: &str| zone_err(msg, " ", type_col);
    // RFC 3597 unknown numeric types need the `\#` form; a known
    // type may also use it (the parser dispatches on the first
    // rdata token).
    if rest[0].text == "\\#" || rr_type_num(&up).is_some() {
        if rest[0].text != "\\#" {
            return Err(zone_err("bad RFC3597 Rdata", &rest[0].text, rest[0].col));
        }
        if rest.len() < 2 {
            return Err(missing("bad RFC3597 Rdata"));
        }
        let len: usize = match rest[1].text.parse() {
            Ok(n) => n,
            Err(_) => {
                return Err(zone_err("bad RFC3597 Rdata", &rest[1].text, rest[1].col));
            }
        };
        if rest.len() < 3 {
            return Err(missing("bad RFC3597 Rdata"));
        }
        let hex = &rest[2].text;
        if hex.len() != len * 2 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(zone_err("bad RFC3597 Rdata", &rest[1].text, rest[1].col));
        }
        return check_trailing(rest, 3);
    }
    match up.as_str() {
        "A" => {
            let v = &rest[0].text;
            let ok = !v.contains(':') && netip_parse_addr(v).is_ok() && v.contains('.');
            if !ok {
                return Err(zone_err("bad A A", v, rest[0].col));
            }
            check_trailing(rest, 1)
        }
        "AAAA" => {
            let v = &rest[0].text;
            let ok = v.contains(':') && netip_parse_addr(v).is_ok();
            if !ok {
                return Err(zone_err("bad AAAA AAAA", v, rest[0].col));
            }
            check_trailing(rest, 1)
        }
        "NS" => {
            if !absolute_name_ok(&rest[0].text) {
                return Err(zone_err("bad NS Ns", &rest[0].text, rest[0].col));
            }
            check_trailing(rest, 1)
        }
        "CNAME" => {
            if !absolute_name_ok(&rest[0].text) {
                return Err(zone_err("bad CNAME Target", &rest[0].text, rest[0].col));
            }
            check_trailing(rest, 1)
        }
        "PTR" => {
            if !absolute_name_ok(&rest[0].text) {
                return Err(zone_err("bad PTR Ptr", &rest[0].text, rest[0].col));
            }
            check_trailing(rest, 1)
        }
        "MX" => {
            if parse_uint_bits(&rest[0].text, 16).is_none() {
                return Err(zone_err("bad MX Pref", &rest[0].text, rest[0].col));
            }
            if rest.len() < 2 {
                return Err(missing("bad MX Mx"));
            }
            if !absolute_name_ok(&rest[1].text) {
                return Err(zone_err("bad MX Mx", &rest[1].text, rest[1].col));
            }
            check_trailing(rest, 2)
        }
        "TXT" => {
            // Quoted or plain strings are both accepted; an
            // unterminated quote errors with the substituted lex.
            for t in rest {
                if t.text.starts_with('"') && !t.text.ends_with('"') {
                    return Err(missing("bad TXT Txt"));
                }
            }
            Ok(())
        }
        "SOA" => {
            if !absolute_name_ok(&rest[0].text) {
                return Err(zone_err("bad SOA Ns", &rest[0].text, rest[0].col));
            }
            if rest.len() < 2 {
                return Err(missing("bad SOA Mbox"));
            }
            if !absolute_name_ok(&rest[1].text) {
                return Err(zone_err("bad SOA Mbox", &rest[1].text, rest[1].col));
            }
            // Serial must be a number; the other four parameters
            // accept unitful durations, and a missing one is 0
            // (`stringToTTL("")` is valid).
            if rest.len() < 3 {
                return Err(missing("bad SOA zone parameter"));
            }
            if parse_uint_bits(&rest[2].text, 32).is_none() {
                return Err(zone_err(
                    "bad SOA zone parameter",
                    &rest[2].text,
                    rest[2].col,
                ));
            }
            for t in rest.iter().skip(3).take(4) {
                if string_to_ttl(&t.text).is_none() {
                    return Err(zone_err("bad SOA zone parameter", &t.text, t.col));
                }
            }
            check_trailing(rest, 7)
        }
        "SRV" => {
            for (i, field) in ["Priority", "Weight", "Port"].iter().enumerate() {
                if rest.len() <= i {
                    return Err(missing(&format!("bad SRV {field}")));
                }
                if parse_uint_bits(&rest[i].text, 16).is_none() {
                    return Err(zone_err(
                        &format!("bad SRV {field}"),
                        &rest[i].text,
                        rest[i].col,
                    ));
                }
            }
            if rest.len() < 4 {
                return Err(missing("bad SRV Target"));
            }
            if !absolute_name_ok(&rest[3].text) {
                return Err(zone_err("bad SRV Target", &rest[3].text, rest[3].col));
            }
            check_trailing(rest, 4)
        }
        // Other known types: accepted without deep rdata validation
        // (documented residual in PORTING).
        _ => Ok(()),
    }
}

fn check_trailing(rest: &[&ZTok], used: usize) -> Result<(), String> {
    if rest.len() > used {
        let t = rest[used];
        return Err(zone_err("garbage after rdata", &t.text, t.col));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Public API: strict sing-box validation for one config block.
// The returned error is the INNER message (without the `profile: `
// prefix); the caller wraps it with `config_error`.
// ---------------------------------------------------------------------------

/// The wireguard-as-outbound rejection: Go returns it WITHOUT the
/// `parse outbound: ` prefix (`outbound.go`); every other outbound
/// error carries the prefix.
const WIREGUARD_OUTBOUND_MESSAGE: &str = "outbound type \"wireguard\" is not an outbound; declare it in \"endpoints\" and reference its tag";

/// Validate one `outbounds` element; on success returns its type.
/// The error is wrapped exactly as Go wraps it (`config.go` adds
/// the single `profile: ` prefix via `config_error`).
pub fn validate_outbound_strict(value: &JsonValue) -> Result<String, crate::errors::ConfigError> {
    match validate_outbound(value) {
        Ok(typ) => Ok(typ),
        Err(SbErr::Bare(msg)) if msg == WIREGUARD_OUTBOUND_MESSAGE => {
            Err(crate::errors::config_error(msg))
        }
        Err(e) => Err(crate::errors::config_error(format!(
            "parse outbound: {}",
            e.text()
        ))),
    }
}

/// Validate one `endpoints` element; on success returns its type.
pub fn validate_endpoint_strict(value: &JsonValue) -> Result<String, crate::errors::ConfigError> {
    validate_endpoint(value)
        .map_err(|e| crate::errors::config_error(format!("parse endpoint: {}", e.text())))
}

/// The inner error text for a `dns` block (`parse dns: ...`),
/// without the `profile: ` prefix. Per-profile dns errors are
/// wrapped once more by the profile entry (`profile "<name>":
/// profile: parse dns: ...`, the double prefix Go produces).
pub fn dns_error_text(value: &JsonValue) -> Option<String> {
    validate_dns(value)
        .err()
        .map(|e| format!("parse dns: {}", e.text()))
}

/// Validate the `dns` block.
pub fn validate_dns_strict(value: &JsonValue) -> Result<(), crate::errors::ConfigError> {
    match dns_error_text(value) {
        Some(text) => Err(crate::errors::config_error(text)),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jsonvalue::decode_ordered_json;

    fn val(json: &str) -> JsonValue {
        decode_ordered_json(json.as_bytes()).unwrap()
    }

    fn dns_err(json: &str) -> String {
        validate_dns(&val(json)).unwrap_err().text()
    }

    fn out_err(json: &str) -> String {
        validate_outbound(&val(json)).unwrap_err().text()
    }

    fn ep_err(json: &str) -> String {
        validate_endpoint(&val(json)).unwrap_err().text()
    }

    #[test]
    fn dns_array_rejected() {
        assert_eq!(
            dns_err("[]"),
            "json: cannot unmarshal array into Go value of type option.removedLegacyDNSOptions"
        );
    }

    #[test]
    fn dns_string_rejected() {
        assert_eq!(
            dns_err("\"s\""),
            "json: cannot unmarshal string into Go value of type option.removedLegacyDNSOptions"
        );
    }

    #[test]
    fn dns_null_is_nil_error() {
        assert_eq!(
            dns_err("null"),
            "expected json object start, but starts with nil"
        );
    }

    #[test]
    fn dns_unknown_field() {
        assert_eq!(
            dns_err("{\"bogus\":1}"),
            "bogus: json: unknown field \"bogus\""
        );
    }

    #[test]
    fn dns_empty_object_filtered() {
        assert!(validate_dns(&val("{\"bogus\":{}}")).is_ok());
        assert!(validate_dns(&val("{\"servers\":{}}")).is_ok());
    }

    #[test]
    fn dns_fakeip_any_value() {
        assert!(dns_err("{\"fakeip\":null}").contains("legacy DNS fakeip options"));
        assert!(dns_err("{\"fakeip\":{}}").contains("legacy DNS fakeip options"));
    }

    #[test]
    fn dns_strategy_validation() {
        assert_eq!(
            dns_err("{\"strategy\":\"bogus\"}"),
            "strategy: unknown domain strategy: bogus"
        );
        assert_eq!(
            dns_err("{\"strategy\":5}"),
            "strategy: json: cannot unmarshal number into Go struct field RawDNSOptions.DNSClientOptions.strategy of type string"
        );
    }

    #[test]
    fn dns_final_wrong_type() {
        assert_eq!(
            dns_err("{\"final\":1}"),
            "final: json: cannot unmarshal number into Go struct field RawDNSOptions.final of type string"
        );
    }

    #[test]
    fn dns_server_unknown_type() {
        assert_eq!(
            dns_err("{\"servers\":[{\"type\":\"bogus\"}]}"),
            "servers[0]: unknown transport type: bogus"
        );
    }

    #[test]
    fn dns_server_null_element_is_legacy() {
        assert!(dns_err("{\"servers\":[null]}").contains("legacy DNS server formats"));
    }

    #[test]
    fn dns_server_local_unknown_field() {
        assert_eq!(
            dns_err("{\"servers\":[{\"type\":\"local\",\"tag\":\"l\",\"bogus\":1}]}"),
            "servers[0].bogus: json: unknown field \"bogus\""
        );
    }

    #[test]
    fn dns_server_https_tls_type() {
        assert_eq!(
            dns_err("{\"servers\":[{\"type\":\"https\",\"tag\":\"h\",\"tls\":1}]}"),
            "servers[0].tls: json: cannot unmarshal number into Go struct field RemoteHTTPSDNSServerOptions.RemoteTLSDNSServerOptions.OutboundTLSOptionsContainer.tls of type option.OutboundTLSOptions"
        );
    }

    #[test]
    fn dns_rule_null_element() {
        assert_eq!(
            dns_err("{\"rules\":[null]}"),
            "rules[0]: expected json object start, but starts with nil"
        );
    }

    #[test]
    fn dns_rule_unknown_type() {
        assert_eq!(
            dns_err("{\"rules\":[{\"type\":\"bogus\"}]}"),
            "rules[0]: unknown rule type: bogus"
        );
    }

    #[test]
    fn dns_rule_respond_unknown_field() {
        assert_eq!(
            dns_err("{\"rules\":[{\"action\":\"respond\",\"server\":\"x\"}]}"),
            "rules[0].server: json: unknown field \"server\""
        );
    }

    #[test]
    fn dns_rule_route_options_empty() {
        assert_eq!(
            dns_err("{\"rules\":[{\"action\":\"route-options\"}]}"),
            "rules[0]: empty DNS route option action"
        );
        assert_eq!(
            dns_err("{\"rules\":[{\"action\":\"route-options\",\"bogus\":1}]}"),
            "rules[0]: empty DNS route option action"
        );
        assert!(
            validate_dns(&val(
                "{\"rules\":[{\"action\":\"route-options\",\"timeout\":\"1s\"}]}"
            ))
            .is_ok()
        );
    }

    #[test]
    fn dns_rule_reject_checks() {
        assert_eq!(
            dns_err("{\"rules\":[{\"action\":\"reject\",\"method\":\"bogus\"}]}"),
            "rules[0]: unknown reject method: bogus"
        );
        assert_eq!(
            dns_err("{\"rules\":[{\"action\":\"reject\",\"method\":\"drop\",\"no_drop\":true}]}"),
            "rules[0]: no_drop is not available in current context"
        );
        assert!(
            validate_dns(&val(
                "{\"rules\":[{\"action\":\"reject\",\"method\":\"drop\"}]}"
            ))
            .is_ok()
        );
    }

    #[test]
    fn dns_rule_nested_rejected() {
        assert_eq!(
            dns_err(
                "{\"rules\":[{\"type\":\"logical\",\"mode\":\"and\",\"rules\":[{\"server\":\"l\"}]}]}"
            ),
            "rules[0].rules[0]: DNS rule action is not supported in nested rules"
        );
        // An empty object does not count as an action key.
        assert!(
            validate_dns(&val(
                "{\"rules\":[{\"type\":\"logical\",\"mode\":\"and\",\"rules\":[{\"server\":{}}]}]}"
            ))
            .is_ok()
        );
    }

    #[test]
    fn dns_rule_inspect_before_nested() {
        // The inspect error (timeout type) wins over the nested check.
        assert_eq!(
            dns_err(
                "{\"rules\":[{\"type\":\"logical\",\"mode\":\"and\",\"rules\":[{\"timeout\":0}]}]}"
            ),
            "rules[0].rules[0].timeout: json: cannot unmarshal number into Go struct field DNSRouteActionOptions.AbstractDNSRouteActionOptions.timeout of type string"
        );
    }

    #[test]
    fn dns_rule_record_errors() {
        assert_eq!(
            dns_err("{\"rules\":[{\"action\":\"predefined\",\"answer\":[\"not a record\"]}]}"),
            "rules[0].answer: (json: cannot unmarshal array into Go value of type string | [0]: dns: bad owner name: \"not\" at line: 1:4)"
        );
        assert_eq!(
            dns_err(
                "{\"rules\":[{\"action\":\"predefined\",\"answer\":[\"example.com. 300 IN A bad-ip\"]}]}"
            ),
            "rules[0].answer: (json: cannot unmarshal array into Go value of type string | [0]: dns: bad A A: \"bad-ip\" at line: 1:28)"
        );
    }

    #[test]
    fn outbound_missing_type() {
        assert_eq!(out_err("{\"tag\":\"a\"}"), "unknown outbound type: ");
        assert!(out_err("[123]").contains("option._Outbound"));
        assert_eq!(out_err("null"), "unknown outbound type: ");
    }

    #[test]
    fn outbound_dns_type_deprecated() {
        assert!(out_err("{\"type\":\"dns\"}").contains("dns outbound is deprecated"));
    }

    #[test]
    fn outbound_wireguard_parses_then_rejects() {
        // The strict parse accepts the stub, then the type is
        // rejected (Go `outbound.go`); the rejection carries no
        // `parse outbound: ` prefix (tested in config.rs).
        assert_eq!(
            out_err("{\"type\":\"wireguard\",\"tag\":\"w\"}"),
            "outbound type \"wireguard\" is not an outbound; declare it in \"endpoints\" and reference its tag"
        );
        // An unknown field beats the type rejection: the strict
        // parse runs first.
        assert_eq!(
            out_err("{\"type\":\"wireguard\",\"tag\":\"w\",\"bogus\":1}"),
            "bogus: json: unknown field \"bogus\""
        );
    }

    #[test]
    fn outbound_socks_wrong_types() {
        assert_eq!(
            out_err("{\"type\":\"socks\",\"tag\":\"a\",\"server_port\":70000}"),
            "server_port: json: cannot unmarshal number 70000 into Go struct field SOCKSOutboundOptions.ServerOptions.server_port of type uint16"
        );
        assert_eq!(
            out_err("{\"type\":\"socks\",\"tag\":\"a\",\"server_port\":\"1080\"}"),
            "server_port: json: cannot unmarshal string into Go struct field SOCKSOutboundOptions.ServerOptions.server_port of type uint16"
        );
    }

    #[test]
    fn outbound_direct_override_deprecated() {
        assert!(
            out_err("{\"type\":\"direct\",\"tag\":\"a\",\"override_port\":8080}")
                .contains("destination override fields")
        );
        assert!(validate_outbound(&val("{\"type\":\"direct\",\"tag\":\"a\"}")).is_ok());
    }

    #[test]
    fn outbound_snell_versions() {
        assert_eq!(
            out_err("{\"type\":\"snell\",\"tag\":\"a\"}"),
            "snell: missing version"
        );
        assert_eq!(
            out_err("{\"type\":\"snell\",\"tag\":\"a\",\"version\":5}"),
            "snell: unsupported version: 5"
        );
        assert_eq!(
            out_err("{\"type\":\"snell\",\"tag\":\"a\",\"version\":4,\"mode\":\"x\"}"),
            "mode: json: unknown field \"mode\""
        );
    }

    #[test]
    fn outbound_listable_paren() {
        assert_eq!(
            out_err("{\"type\":\"selector\",\"tag\":\"s\",\"outbounds\":[1]}"),
            "outbounds[0]: json: cannot unmarshal number into Go struct field SelectorOutboundOptions.outbounds of type string"
        );
    }

    #[test]
    fn outbound_fwmark() {
        assert!(
            validate_outbound(&val(
                "{\"type\":\"socks\",\"tag\":\"a\",\"routing_mark\":\"0x10\"}"
            ))
            .is_ok()
        );
        assert_eq!(
            out_err("{\"type\":\"socks\",\"tag\":\"a\",\"routing_mark\":4294967296}"),
            "routing_mark: invalid number or string mark: json: cannot unmarshal number into Go value of type string"
        );
        assert_eq!(
            out_err("{\"type\":\"socks\",\"tag\":\"a\",\"routing_mark\":\"+5\"}"),
            "routing_mark: strconv.ParseUint: parsing \"+5\": invalid syntax"
        );
    }

    #[test]
    fn outbound_duration_errors() {
        assert_eq!(
            out_err("{\"type\":\"socks\",\"tag\":\"a\",\"connect_timeout\":\"xx\"}"),
            "connect_timeout: time: invalid duration \"xx\""
        );
        assert_eq!(
            out_err("{\"type\":\"socks\",\"tag\":\"a\",\"connect_timeout\":5}"),
            "connect_timeout: json: cannot unmarshal number into Go struct field SOCKSOutboundOptions.DialerOptions.AbstractDialerOptions.connect_timeout of type string"
        );
    }

    #[test]
    fn endpoint_unknown_type() {
        assert_eq!(ep_err("{\"tag\":\"a\"}"), "unknown endpoint type: ");
        assert_eq!(ep_err("null"), "unknown endpoint type: ");
    }

    #[test]
    fn endpoint_wireguard_peers() {
        assert_eq!(
            ep_err("{\"type\":\"wireguard\",\"tag\":\"w\",\"peers\":[123]}"),
            "peers[0]: json: cannot unmarshal number into Go struct field WireGuardEndpointOptions.peers of type option.WireGuardPeer"
        );
        assert_eq!(
            ep_err("{\"type\":\"wireguard\",\"tag\":\"w\",\"peers\":1}"),
            "peers: json: cannot unmarshal number into Go struct field WireGuardEndpointOptions.peers of type []option.WireGuardPeer"
        );
    }

    #[test]
    fn endpoint_tailscale_addrport() {
        assert_eq!(
            ep_err(
                "{\"type\":\"tailscale\",\"tag\":\"t\",\"relay_server_static_endpoints\":[\"bad\"]}"
            ),
            "not an ip:port"
        );
        assert_eq!(
            ep_err(
                "{\"type\":\"tailscale\",\"tag\":\"t\",\"relay_server_static_endpoints\":[\"1.2.3.4:70000\"]}"
            ),
            "invalid port \"70000\" parsing \"1.2.3.4:70000\""
        );
        assert!(validate_endpoint(&val(
            "{\"type\":\"tailscale\",\"tag\":\"t\",\"relay_server_static_endpoints\":[\"[fe80::1%eth0]:80\"]}"
        ))
        .is_ok());
    }

    #[test]
    fn duration_parsing() {
        assert_eq!(go_parse_duration("1h30m").unwrap(), 5_400_000_000_000);
        assert_eq!(go_parse_duration("1d").unwrap(), 86_400_000_000_000);
        assert_eq!(
            go_parse_duration("-9223372036854775808ns").unwrap(),
            i64::MIN
        );
        assert_eq!(go_parse_duration("1.s").unwrap(), 1_000_000_000);
        assert!(go_parse_duration("").is_err());
        assert!(go_parse_duration(".s").is_err());
        assert_eq!(
            go_parse_duration("xx").unwrap_err(),
            "time: invalid duration \"xx\""
        );
        assert_eq!(
            go_parse_duration("5").unwrap_err(),
            "time: missing unit in duration \"5\""
        );
        assert_eq!(
            go_parse_duration("1x").unwrap_err(),
            "time: unknown unit \"x\" in duration \"1x\""
        );
    }

    #[test]
    fn record_zone_text() {
        assert!(dns_record_validate("example.com. 300 IN A 1.2.3.4").is_ok());
        assert!(dns_record_validate("example.com. A 1.2.3.4").is_ok());
        assert!(dns_record_validate("").is_ok());
        assert_eq!(dns_record_validate("   ").unwrap_err(), "empty DNS record");
        assert_eq!(
            dns_record_validate("hello").unwrap_err(),
            "dns: not a TTL: \"hello\" at line: 1:5"
        );
        assert_eq!(
            dns_record_validate("example.com.").unwrap_err(),
            "dns: not a TTL: \"example.com.\" at line: 1:12"
        );
        assert_eq!(
            dns_record_validate("example.com. 300 IN BOGUSTYPE 1.2.3.4").unwrap_err(),
            "dns: unknown RR type: \"BOGUSTYPE\" at line: 1:30"
        );
        assert_eq!(
            dns_record_validate("example.com. 300 IN A 1.2.3.4 extra").unwrap_err(),
            "dns: garbage after rdata: \"extra\" at line: 1:35"
        );
        assert_eq!(
            dns_record_validate("example.com. 300 IN MX 10").unwrap_err(),
            "dns: bad MX Mx: \" \" at line: 1:23"
        );
        assert_eq!(
            dns_record_validate("example.com. 300 IN TYPE123 \\# 4 0102").unwrap_err(),
            "dns: bad RFC3597 Rdata: \"4\" at line: 1:33"
        );
        assert!(dns_record_validate("example.com. 300 IN TYPE123 \\# 4 01020304").is_ok());
        assert_eq!(
            dns_record_validate("aGVsbG8=").unwrap_err(),
            "parse binary DNS record"
        );
    }

    #[test]
    fn record_first_token_is_owner() {
        // The first blank-terminated token is always the owner.
        assert_eq!(
            dns_record_validate("300 IN A 1.2.3.4").unwrap_err(),
            "dns: bad owner name: \"300\" at line: 1:4"
        );
        assert_eq!(
            dns_record_validate("A 1.2.3.4").unwrap_err(),
            "dns: bad owner name: \"A\" at line: 1:2"
        );
    }

    #[test]
    fn record_batch14_first_token_corners() {
        // Batch 14, probed against Go 0.9.0 on cue 2026-11-07.
        assert_eq!(
            dns_record_validate("IN A 1.2.3.4").unwrap_err(),
            "dns: bad owner name: \"IN\" at line: 1:3"
        );
        assert!(dns_record_validate("A").is_ok());
        assert_eq!(
            dns_record_validate("IN").unwrap_err(),
            "dns: not a TTL: \"IN\" at line: 1:2"
        );
        assert_eq!(
            dns_record_validate("example.com. bogus 1.2.3.4").unwrap_err(),
            "dns: not a TTL: \"bogus\" at line: 1:19"
        );
        assert_eq!(
            dns_record_validate("example.com. 300 IN ").unwrap_err(),
            "dns: unknown RR type: \"\\n\" at line: 1:20"
        );
        assert_eq!(
            dns_record_validate("example.com. IN ").unwrap_err(),
            "dns: expecting RR type or TTL, not this...: \"\\n\" at line: 1:16"
        );
        assert_eq!(
            dns_record_validate("$TTL 300").unwrap_err(),
            "empty DNS record"
        );
    }

    #[test]
    fn record_double_class() {
        assert_eq!(
            dns_record_validate("example.com. IN CH A 1.2.3.4").unwrap_err(),
            "dns: expecting RR type or TTL, not this...: \"CH\" at line: 1:19"
        );
    }

    #[test]
    fn netip_addrs() {
        assert!(netip_parse_addr("1.2.3.4").is_ok());
        assert!(netip_parse_addr("::1").is_ok());
        assert!(netip_parse_addr("fe80::1%eth0").is_ok());
        assert_eq!(
            netip_parse_addr("999.999.999.999").unwrap_err(),
            "ParseAddr(\"999.999.999.999\"): IPv4 field has value >255"
        );
        assert_eq!(
            netip_parse_prefix("bad").unwrap_err(),
            "netip.ParsePrefix(\"bad\"): no '/'"
        );
        assert_eq!(
            netip_parse_addr_port("1.2.3.4:70000").unwrap_err(),
            "invalid port \"70000\" parsing \"1.2.3.4:70000\""
        );
        assert_eq!(
            netip_parse_addr_port("no-colon").unwrap_err(),
            "not an ip:port"
        );
    }
}
