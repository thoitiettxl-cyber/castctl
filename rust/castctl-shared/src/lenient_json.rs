// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Lenient JSON decoding with Go `encoding/json` semantics.
//!
//! Go's `json.Unmarshal` is lenient where `serde_json` is
//! strict, and the M6c crates must match Go on untrusted
//! input. The model is Go's `encoding/json` decoder
//! itself (`decode.go:object`, `literalStore`, `saveError`,
//! `fold.go:foldName`, `scanner.go:pushParseState`), NOT
//! "last-wins + null is a no-op" — that fix-loop-2 model
//! was WRONG (phase-3 round-3 R3-B1/B2/B3/B4) and is
//! replaced here by sequential apply:
//!
//! - occurrences are applied IN DOCUMENT ORDER, one at
//!   a time, each against the field it resolves to;
//! - a key resolves to a field by EXACT match first,
//!   then by case-insensitive match on the folded name
//!   (Go `foldName`: ASCII letters fold to uppercase,
//!   any other rune folds to the smallest rune in its
//!   `unicode.SimpleFold` orbit — so Kelvin sign U+212A
//!   folds to `K` and long-s U+017F folds to `S`, NOT
//!   ASCII-only lowercase);
//! - `null` is a no-op for SCALAR fields (string /
//!   bool / int keep the previously applied value)
//!   but RESETS pointer / slice fields to nil / empty
//!   (Go `literalStore`: only Interface / Pointer /
//!   Map / Slice are zeroed by `null`); a `RawMessage`
//!   field keeps the last raw bytes INCLUDING the
//!   literal `null` (Go `RawMessage.UnmarshalJSON`
//!   copies the bytes verbatim);
//! - a type error on ANY occurrence is saved (Go
//!   `saveError`: the FIRST error only) and decoding
//!   CONTINUES — the struct keeps whatever later
//!   valid occurrences applied, but `Unmarshal`
//!   still returns the saved error at the end;
//! - invalid UTF-8 bytes inside a string are coerced to
//!   U+FFFD, one per bad byte (Go `utf8.DecodeRune`
//!   semantics — the same rule `castctl-pluginhost`
//!   already uses in `text.rs::decode_rune`);
//! - nesting depth is capped at 10000 containers
//!   inclusive (Go `scanner.go:maxNestingDepth`);
//!   the 10001st open container is a syntax error.
//!
//! This cannot be a serde `Deserialize` impl:
//! `serde_json::from_slice` validates UTF-8 for the
//! whole document (including inside
//! `serde_json::value::RawValue`) before any visitor
//! runs, so no serde-based decoder can accept the
//! R2-B2 triggers. The parser here works directly on
//! bytes instead.
//!
//! The scanner is iterative (explicit `Expect` state +
//! a stack of open containers), never recursive, so a
//! hostile deeply-nested value cannot exhaust the
//! stack; the depth cap above is Go's, not a stack
//! guard. Typed decoders built on top of it
//! (`match_fields` + the `apply_*_field` helpers +
//! `FirstError`) recurse only over known shallow shapes
//! (envelope / release / asset / error objects).
//!
//! What this parser does NOT do: it keeps the raw byte
//! span of every value, and decodes a string only when
//! the caller asks (`as_str`). A caller that needs the
//! raw bytes of a value (Go `json.RawMessage`, e.g.
//! the envelope `result`) takes `as_raw` and never
//! pays for — or trips over — string decoding.

use std::fmt;

/// Go `encoding/json` `scanner.go:maxNestingDepth`:
/// at most 10000 open containers, inclusive — the
/// 10001st is `exceeded max depth`.
const MAX_NESTING_DEPTH: usize = 10_000;

/// The error of a lenient decode: a short message with
/// a byte offset, never echoing input bytes (hostile
/// input must not leak into logs through an error).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LenientError(String);

impl LenientError {
    fn at(pos: usize, what: &str) -> Self {
        LenientError(format!("invalid JSON at byte {pos}: {what}"))
    }

    /// A type error (Go `cannot unmarshal`): the first
    /// one saved wins the decode (see `FirstError`).
    /// Public so typed decoders in other crates can
    /// record a composite-field type error (e.g. an
    /// object where a slice was expected) in the same
    /// first-error slot as a scalar one.
    pub fn typed(what: &str) -> Self {
        LenientError(format!("type error: {what}"))
    }
}

impl fmt::Display for LenientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for LenientError {}

/// The kind of a parsed JSON value, from its first byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Null,
    Bool,
    Number,
    Str,
    Array,
    Object,
}

/// One parsed JSON value: the byte span `[start, end)`
/// of the value inside the original input. Strings are
/// decoded lazily (`as_str`); object fields and array
/// elements are re-walked from the span (`fields`,
/// `elements`).
#[derive(Debug, Clone, Copy)]
pub struct Parsed<'a> {
    input: &'a [u8],
    start: usize,
    end: usize,
}

impl<'a> Parsed<'a> {
    /// Parse one top-level JSON value; trailing bytes
    /// other than JSON whitespace refuse, like Go's
    /// `json.Unmarshal`.
    pub fn parse_document(input: &'a [u8]) -> Result<Self, LenientError> {
        let (start, end) = value_span(input, 0)?;
        let mut pos = end;
        pos = skip_ws(input, pos)?;
        if pos != input.len() {
            return Err(LenientError::at(
                pos,
                "trailing characters after top-level value",
            ));
        }
        Ok(Parsed { input, start, end })
    }

    /// The kind of this value.
    #[must_use]
    pub fn kind(&self) -> Kind {
        match self.input[self.start] {
            b'n' => Kind::Null,
            b't' | b'f' => Kind::Bool,
            b'"' => Kind::Str,
            b'[' => Kind::Array,
            b'{' => Kind::Object,
            _ => Kind::Number,
        }
    }

    /// Whether this value is the JSON literal `null`.
    #[must_use]
    pub fn is_null(&self) -> bool {
        self.kind() == Kind::Null
    }

    /// The raw bytes of this value, verbatim (for a
    /// string: including the quotes; for an object:
    /// including braces and the original key order and
    /// whitespace). This is the Go `json.RawMessage`
    /// view of the value.
    #[must_use]
    pub fn as_raw(&self) -> &'a [u8] {
        &self.input[self.start..self.end]
    }

    /// Decode this value as a bool; `null` and every
    /// other kind refuse (callers map `null` to the
    /// zero value themselves).
    pub fn as_bool(&self) -> Result<bool, LenientError> {
        if self.kind() != Kind::Bool {
            return Err(LenientError::typed("expected a boolean"));
        }
        Ok(self.input[self.start] == b't')
    }

    /// Decode this value as an `i64`: only a plain
    /// integer literal parses — `1e3`, `1.0`, `1.5`
    /// and overflows refuse, exactly like Go
    /// unmarshalling into an `int64` (probed on cue
    /// 2026-11-06).
    pub fn as_i64(&self) -> Result<i64, LenientError> {
        if self.kind() != Kind::Number {
            return Err(LenientError::typed("expected a number"));
        }
        let lit = std::str::from_utf8(self.as_raw())
            .map_err(|_| LenientError::typed("expected a number"))?;
        lit.parse::<i64>()
            .map_err(|_| LenientError::typed("number is not a valid i64"))
    }

    /// Decode this value as a string, coercing invalid
    /// UTF-8 bytes to U+FFFD like Go; every other kind
    /// refuses.
    pub fn as_str(&self) -> Result<String, LenientError> {
        if self.kind() != Kind::Str {
            return Err(LenientError::typed("expected a string"));
        }
        decode_string(self.as_raw())
    }

    /// The fields of an object, in document order,
    /// duplicates kept (callers that want Go's
    /// last-wins use `field`).
    pub fn fields(&self) -> Result<Vec<(String, Parsed<'a>)>, LenientError> {
        if self.kind() != Kind::Object {
            return Err(LenientError::typed("expected an object"));
        }
        let input = self.input;
        let mut out = Vec::new();
        let mut pos = skip_ws(input, self.start + 1)?;
        if input[pos] == b'}' {
            return Ok(out);
        }
        loop {
            pos = skip_ws(input, pos)?;
            let key_end = scan_string(input, pos)?;
            let key = decode_string(&input[pos..key_end])?;
            pos = skip_ws(input, key_end)?;
            if input.get(pos) != Some(&b':') {
                return Err(LenientError::at(pos, "expected ':' after object key"));
            }
            let (vs, ve) = value_span(input, pos + 1)?;
            out.push((
                key,
                Parsed {
                    input,
                    start: vs,
                    end: ve,
                },
            ));
            pos = skip_ws(input, ve)?;
            match input.get(pos) {
                Some(b',') => {
                    pos += 1;
                }
                Some(b'}') => return Ok(out),
                _ => return Err(LenientError::at(pos, "expected ',' or '}' in object")),
            }
        }
    }

    /// Every occurrence of a KNOWN field of this object,
    /// in document order, as `(index into names, value)`.
    /// A key resolves to a field the way Go's
    /// `encoding/json` resolves it (`decode.go:object`):
    /// exact match against the whole field set first,
    /// then case-insensitive match on the folded name
    /// (`go_fold_name`) — again against the whole set,
    /// first field wins on a fold collision. Unknown
    /// keys are skipped (Go skips their values without
    /// a type error). One pass over the object: callers
    /// that apply occurrences sequentially call this
    /// once, never `fields()` in a loop.
    ///
    /// This is the shared sequential-apply entry point
    /// (fix loop 3, R3-B1/B2/B3): typed decoders iterate
    /// the returned occurrences in order and apply each
    /// one with the `apply_*_field` helpers, recording
    /// the first type error in a `FirstError`.
    pub fn match_fields(&self, names: &[&str]) -> Result<Vec<(usize, Parsed<'a>)>, LenientError> {
        let folded: Vec<String> = names.iter().map(|n| go_fold_name(n)).collect();
        let mut out = Vec::new();
        for (key, value) in self.fields()? {
            if let Some(idx) = names.iter().position(|n| *n == key) {
                out.push((idx, value));
            } else if let Some(idx) = folded.iter().position(|f| *f == go_fold_name(&key)) {
                out.push((idx, value));
            }
            // Else unknown: skipped, like Go.
        }
        Ok(out)
    }

    /// The elements of an array, in order. A `null`
    /// element is returned as a null `Parsed` (callers
    /// map it to the zero value); it never errors.
    pub fn elements(&self) -> Result<Vec<Parsed<'a>>, LenientError> {
        if self.kind() != Kind::Array {
            return Err(LenientError::typed("expected an array"));
        }
        let input = self.input;
        let mut out = Vec::new();
        let mut pos = skip_ws(input, self.start + 1)?;
        if input[pos] == b']' {
            return Ok(out);
        }
        loop {
            let (vs, ve) = value_span(input, pos)?;
            out.push(Parsed {
                input,
                start: vs,
                end: ve,
            });
            pos = skip_ws(input, ve)?;
            match input.get(pos) {
                Some(b',') => {
                    pos = skip_ws(input, pos + 1)?;
                }
                Some(b']') => return Ok(out),
                _ => return Err(LenientError::at(pos, "expected ',' or ']' in array")),
            }
        }
    }
}

/// Go `encoding/json` `foldName` (`fold.go`): the
/// folded name of `s`, such that `go_fold_name(x) ==
/// go_fold_name(y)` exactly when Go considers `x` and
/// `y` equal case-insensitively. ASCII letters fold
/// to uppercase; any other rune folds to the smallest
/// rune in its `unicode.SimpleFold` orbit
/// (`foldRune`).
///
/// The orbit minimum is found by walking the
/// single-char lower/upper neighbours of each rune
/// (Go's orbit is generated by case mappings; a
/// multi-char mapping such as `ß` → `SS` is NOT a
/// simple fold, so it contributes no neighbour and
/// `ß` folds to itself, like Go). Pinned by
/// `fold_match_is_go_foldname`: ASCII, Kelvin sign
/// U+212A → `K`, long-s U+017F → `S`.
#[must_use]
pub fn go_fold_name(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        out.push(go_fold_rune(c));
    }
    out
}

/// Go `encoding/json` `foldRune` (`fold.go`): the
/// smallest rune in the `unicode.SimpleFold` orbit of
/// `r`. ASCII letters fold to uppercase; any other
/// rune folds to the orbit minimum found by the walk
/// in `go_fold_name`.
fn go_fold_rune(r: char) -> char {
    if r.is_ascii() {
        return r.to_ascii_uppercase();
    }
    // BFS over the orbit via single-char case
    // neighbours; the orbit is tiny (≤ 4 runes in
    // Unicode data), the visited cap is a belt-and-
    // braces bound, never reached in practice.
    let mut best = r;
    let mut seen: Vec<char> = vec![r];
    let mut stack: Vec<char> = vec![r];
    while let Some(x) = stack.pop() {
        if x < best {
            best = x;
        }
        if seen.len() >= 16 {
            break;
        }
        for next in [single_lower(x), single_upper(x)] {
            if let Some(n) = next
                && !seen.contains(&n)
            {
                seen.push(n);
                stack.push(n);
            }
        }
    }
    best
}

/// The single-char lowercase of `c`, or `None` when
/// the lowercase mapping is empty or multi-char (and
/// therefore not a simple fold).
fn single_lower(c: char) -> Option<char> {
    let mut it = c.to_lowercase();
    match (it.next(), it.next()) {
        (Some(l), None) => Some(l),
        _ => None,
    }
}

/// The single-char uppercase of `c`, or `None` when
/// the uppercase mapping is empty or multi-char (and
/// therefore not a simple fold).
fn single_upper(c: char) -> Option<char> {
    let mut it = c.to_uppercase();
    match (it.next(), it.next()) {
        (Some(u), None) => Some(u),
        _ => None,
    }
}

/// Go `encoding/json` `saveError` (`decode.go`):
/// keeps the FIRST type error only; decoding
/// continues and the saved error is returned at the
/// end, even when a later occurrence applied cleanly
/// (fix loop 3, R3-B3). Typed decoders record into
/// this instead of returning on the first bad
/// occurrence.
#[derive(Debug, Default)]
pub struct FirstError(pub Option<LenientError>);

impl FirstError {
    /// Record `err` unless an earlier error was
    /// already saved (Go keeps the first).
    pub fn record(&mut self, err: LenientError) {
        if self.0.is_none() {
            self.0 = Some(err);
        }
    }

    /// Record the error of a single-occurrence apply,
    /// if it failed.
    pub fn record_result(&mut self, r: Result<(), LenientError>) {
        if let Err(e) = r {
            self.record(e);
        }
    }

    /// Record an error produced by a nested decode,
    /// if any.
    pub fn record_opt(&mut self, err: Option<LenientError>) {
        if let Some(e) = err {
            self.record(e);
        }
    }

    /// The saved error as an `Option`, for a nested
    /// decode to hand up to its caller (the caller
    /// records it and keeps applying).
    #[must_use]
    pub fn into_option(self) -> Option<LenientError> {
        self.0
    }

    /// The saved error, if any — the decode refuses
    /// with this even when later occurrences applied.
    /// (No `#[must_use]`: `Result` is already `#[must_use]`,
    /// and clippy's `double_must_use` fires otherwise.)
    pub fn into_result<T>(self, value: T) -> Result<T, LenientError> {
        match self.0 {
            Some(e) => Err(e),
            None => Ok(value),
        }
    }
}

/// Apply one occurrence of a STRING field, Go
/// `encoding/json` `literalStore` rules
/// (`decode.go`): `null` is a no-op (the current
/// value is kept — fix loop 3, R3-B2); a string sets
/// it; anything else is a type error (returned, the
/// slot untouched).
pub fn apply_str_field(slot: &mut String, v: Parsed<'_>) -> Result<(), LenientError> {
    if v.is_null() {
        return Ok(());
    }
    *slot = v.as_str()?;
    Ok(())
}

/// Apply one occurrence of a BOOL field: `null` is a
/// no-op; a bool literal sets it; anything else is a
/// type error.
pub fn apply_bool_field(slot: &mut bool, v: Parsed<'_>) -> Result<(), LenientError> {
    if v.is_null() {
        return Ok(());
    }
    *slot = v.as_bool()?;
    Ok(())
}

/// Apply one occurrence of an `i64` field: `null` is
/// a no-op; a plain integer literal sets it
/// (`1e3` / `1.0` / overflow refuse, like Go into
/// `int64`); anything else is a type error.
pub fn apply_i64_field(slot: &mut i64, v: Parsed<'_>) -> Result<(), LenientError> {
    if v.is_null() {
        return Ok(());
    }
    *slot = v.as_i64()?;
    Ok(())
}

/// Apply one occurrence of a `RawMessage` field (the
/// envelope `result`): EVERY occurrence sets the raw
/// bytes, including the literal `null` (4 bytes) —
/// Go `RawMessage.UnmarshalJSON` copies the bytes
/// verbatim, and `null` into a `RawMessage` does NOT
/// zero it. Never a type error.
pub fn apply_raw_field(slot: &mut Option<Vec<u8>>, v: Parsed<'_>) {
    *slot = Some(v.as_raw().to_vec());
}

/// What the scanner expects next. `Key` (after a comma
/// in an object) must be a string — unlike `KeyOrEnd`
/// (right after `{`) it does not accept `}`: a trailing
/// comma is a syntax error, like Go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    Value,
    KeyOrEnd,
    Key,
    Colon,
    ValueOrEnd,
    SepOrEnd,
}

/// Skip JSON whitespace (`space`, `\t`, `\n`, `\r`
/// only — Go's `encoding/json` accepts no other
/// whitespace). Returns the first non-whitespace
/// position, which may be `input.len()` (end of
/// input); callers treat that as "unexpected end of
/// input" via `.get(pos)`.
fn skip_ws(input: &[u8], mut pos: usize) -> Result<usize, LenientError> {
    while pos < input.len() && matches!(input[pos], b' ' | b'\t' | b'\n' | b'\r') {
        pos += 1;
    }
    Ok(pos)
}

/// The byte span `[start, end)` of the single JSON
/// value starting at or after `start` (leading
/// whitespace skipped). Iterative: an explicit stack
/// of open containers (`b'{'` / `b'['`), so nesting
/// depth is bounded by Go's `maxNestingDepth`
/// (10000, inclusive — the 10001st open container
/// errors `exceeded max depth`, like Go's scanner),
/// never by the call stack.
fn value_span(input: &[u8], start: usize) -> Result<(usize, usize), LenientError> {
    let mut stack: Vec<u8> = Vec::new();
    let mut expect = Expect::Value;
    let mut pos = skip_ws(input, start)?;
    let value_start = pos;
    loop {
        match expect {
            Expect::Value | Expect::ValueOrEnd => {
                pos = skip_ws(input, pos)?;
                let b = *input
                    .get(pos)
                    .ok_or_else(|| LenientError::at(pos, "unexpected end of input"))?;
                if expect == Expect::ValueOrEnd && b == b']' {
                    if stack.pop() != Some(b'[') {
                        return Err(LenientError::at(pos, "unmatched ']'"));
                    }
                    pos += 1;
                    if stack.is_empty() {
                        return Ok((value_start, pos));
                    }
                    expect = Expect::SepOrEnd;
                    continue;
                }
                match b {
                    b'"' => {
                        pos = scan_string(input, pos)?;
                    }
                    b'{' => {
                        stack.push(b'{');
                        if stack.len() > MAX_NESTING_DEPTH {
                            return Err(LenientError::at(pos, "exceeded max depth"));
                        }
                        pos += 1;
                        expect = Expect::KeyOrEnd;
                        continue;
                    }
                    b'[' => {
                        stack.push(b'[');
                        if stack.len() > MAX_NESTING_DEPTH {
                            return Err(LenientError::at(pos, "exceeded max depth"));
                        }
                        pos += 1;
                        expect = Expect::ValueOrEnd;
                        continue;
                    }
                    b't' => {
                        expect_literal(input, pos, b"true")?;
                        pos += 4;
                    }
                    b'f' => {
                        expect_literal(input, pos, b"false")?;
                        pos += 5;
                    }
                    b'n' => {
                        expect_literal(input, pos, b"null")?;
                        pos += 4;
                    }
                    b'-' | b'0'..=b'9' => {
                        pos = scan_number(input, pos)?;
                    }
                    _ => {
                        return Err(LenientError::at(pos, "expected a JSON value"));
                    }
                }
                if stack.is_empty() {
                    return Ok((value_start, pos));
                }
                expect = Expect::SepOrEnd;
            }
            Expect::KeyOrEnd | Expect::Key => {
                pos = skip_ws(input, pos)?;
                let b = *input
                    .get(pos)
                    .ok_or_else(|| LenientError::at(pos, "unexpected end of input"))?;
                if expect == Expect::KeyOrEnd && b == b'}' {
                    if stack.pop() != Some(b'{') {
                        return Err(LenientError::at(pos, "unmatched '}'"));
                    }
                    pos += 1;
                    if stack.is_empty() {
                        return Ok((value_start, pos));
                    }
                    expect = Expect::SepOrEnd;
                } else if b == b'"' {
                    pos = scan_string(input, pos)?;
                    expect = Expect::Colon;
                } else {
                    return Err(LenientError::at(pos, "expected an object key"));
                }
            }
            Expect::Colon => {
                pos = skip_ws(input, pos)?;
                let b = *input
                    .get(pos)
                    .ok_or_else(|| LenientError::at(pos, "unexpected end of input"))?;
                if b != b':' {
                    return Err(LenientError::at(pos, "expected ':' after object key"));
                }
                pos += 1;
                expect = Expect::Value;
            }
            Expect::SepOrEnd => {
                pos = skip_ws(input, pos)?;
                let b = *input
                    .get(pos)
                    .ok_or_else(|| LenientError::at(pos, "unexpected end of input"))?;
                if b == b',' {
                    pos += 1;
                    match stack.last() {
                        Some(b'[') => expect = Expect::Value,
                        Some(b'{') => expect = Expect::Key,
                        _ => return Err(LenientError::at(pos, "comma outside a container")),
                    }
                } else if b == b']' || b == b'}' {
                    let want = if b == b']' { b'[' } else { b'{' };
                    if stack.pop() != Some(want) {
                        return Err(LenientError::at(pos, "unmatched closing bracket"));
                    }
                    pos += 1;
                    if stack.is_empty() {
                        return Ok((value_start, pos));
                    }
                    expect = Expect::SepOrEnd;
                } else {
                    return Err(LenientError::at(pos, "expected ',' or a closing bracket"));
                }
            }
        }
    }
}

/// Expect the literal `lit` at `pos` (e.g. `true`):
/// a prefix mismatch or a truncated input is a syntax
/// error, like Go's `invalid character` errors.
fn expect_literal(input: &[u8], pos: usize, lit: &[u8]) -> Result<(), LenientError> {
    if input.len() < pos + lit.len() || &input[pos..pos + lit.len()] != lit {
        return Err(LenientError::at(pos, "invalid literal"));
    }
    Ok(())
}

/// The end index (one past the closing quote) of the
/// JSON string starting at `pos` (`input[pos]` is
/// `"`). Validates escapes (`\"\\/bfnrtu` + 4 hex
/// digits) and refuses unescaped control bytes, like
/// Go — but never validates UTF-8: invalid bytes
/// inside the string are content, coerced later by
/// `decode_string`.
fn scan_string(input: &[u8], pos: usize) -> Result<usize, LenientError> {
    debug_assert_eq!(input[pos], b'"');
    let mut i = pos + 1;
    while let Some(&b) = input.get(i) {
        match b {
            b'"' => return Ok(i + 1),
            b'\\' => {
                let e = *input
                    .get(i + 1)
                    .ok_or_else(|| LenientError::at(i, "unterminated escape"))?;
                match e {
                    b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => i += 2,
                    b'u' => {
                        for k in 0..4 {
                            let h = *input
                                .get(i + 2 + k)
                                .ok_or_else(|| LenientError::at(i, "unterminated \\u escape"))?;
                            if !h.is_ascii_hexdigit() {
                                return Err(LenientError::at(
                                    i + 2 + k,
                                    "invalid hex digit in \\u escape",
                                ));
                            }
                        }
                        i += 6;
                    }
                    _ => return Err(LenientError::at(i + 1, "invalid escape")),
                }
            }
            0x00..=0x1f => {
                return Err(LenientError::at(i, "unescaped control character in string"));
            }
            _ => i += 1,
        }
    }
    Err(LenientError::at(i, "unterminated string"))
}

/// The end index of the JSON number starting at `pos`.
/// Strict grammar: `-`? (`0` | `[1-9][0-9]*`)
/// (`.` `[0-9]+`)? (`e`/`E` `[+-]`? `[0-9]+`)? —
/// `01`, `1.`, `.5`, `+1`, `NaN`, `Infinity` all
/// refuse, like Go.
fn scan_number(input: &[u8], pos: usize) -> Result<usize, LenientError> {
    let mut i = pos;
    if input.get(i) == Some(&b'-') {
        i += 1;
    }
    match input.get(i) {
        Some(b'0') => i += 1,
        Some(b'1'..=b'9') => {
            while input.get(i).is_some_and(|b| b.is_ascii_digit()) {
                i += 1;
            }
        }
        _ => return Err(LenientError::at(i, "invalid number")),
    }
    if input.get(i) == Some(&b'.') {
        i += 1;
        if !input.get(i).is_some_and(|b| b.is_ascii_digit()) {
            return Err(LenientError::at(i, "invalid number fraction"));
        }
        while input.get(i).is_some_and(|b| b.is_ascii_digit()) {
            i += 1;
        }
    }
    if matches!(input.get(i), Some(b'e') | Some(b'E')) {
        i += 1;
        if matches!(input.get(i), Some(b'+') | Some(b'-')) {
            i += 1;
        }
        if !input.get(i).is_some_and(|b| b.is_ascii_digit()) {
            return Err(LenientError::at(i, "invalid number exponent"));
        }
        while input.get(i).is_some_and(|b| b.is_ascii_digit()) {
            i += 1;
        }
    }
    Ok(i)
}

/// Decode one rune from the front of `b`, Go
/// `utf8.DecodeRune` semantics: an invalid or
/// truncated sequence decodes to U+FFFD consuming
/// exactly 1 byte. Same rule as `castctl-pluginhost`
/// `text.rs::decode_rune` (duplicated here because
/// this crate cannot depend on the pluginhost crate).
fn decode_rune_go(b: &[u8]) -> (char, usize) {
    if b.is_empty() {
        return ('\u{FFFD}', 0);
    }
    for len in 1..=4.min(b.len()) {
        if let Ok(s) = std::str::from_utf8(&b[..len])
            && let Some(c) = s.chars().next()
            && c.len_utf8() == len
        {
            return (c, len);
        }
    }
    ('\u{FFFD}', 1)
}

fn hex_val(b: u8) -> Option<u16> {
    match b {
        b'0'..=b'9' => Some((b - b'0') as u16),
        b'a'..=b'f' => Some((b - b'a' + 10) as u16),
        b'A'..=b'F' => Some((b - b'A' + 10) as u16),
        _ => None,
    }
}

/// The `\uXXXX` escape at `body[i]` (if any) as a code
/// unit; `None` when the bytes are not a `\u` escape
/// with 4 hex digits.
fn peek_u_escape(body: &[u8], i: usize) -> Option<u16> {
    if body.get(i) != Some(&b'\\') || body.get(i + 1) != Some(&b'u') {
        return None;
    }
    let mut unit: u16 = 0;
    for k in 0..4 {
        unit = unit * 16 + hex_val(*body.get(i + 2 + k)?)?;
    }
    Some(unit)
}

/// Decode a JSON string literal (including its quotes)
/// into a Rust `String`, coercing invalid UTF-8 bytes
/// to U+FFFD like Go's `encoding/json` (one U+FFFD
/// per bad byte) and lone `\u` surrogates to U+FFFD.
/// The input must be a single string value (as
/// produced by the scanner); anything else errors.
fn decode_string(raw: &[u8]) -> Result<String, LenientError> {
    if raw.len() < 2 || raw[0] != b'"' || raw[raw.len() - 1] != b'"' {
        return Err(LenientError::typed("expected a string"));
    }
    let body = &raw[1..raw.len() - 1];
    let mut out = String::with_capacity(body.len());
    let mut i = 0;
    while i < body.len() {
        let b = body[i];
        match b {
            b'\\' => {
                let e = *body
                    .get(i + 1)
                    .ok_or_else(|| LenientError::at(i, "unterminated escape"))?;
                match e {
                    b'"' => {
                        out.push('"');
                        i += 2;
                    }
                    b'\\' => {
                        out.push('\\');
                        i += 2;
                    }
                    b'/' => {
                        out.push('/');
                        i += 2;
                    }
                    b'b' => {
                        out.push('\u{8}');
                        i += 2;
                    }
                    b'f' => {
                        out.push('\u{c}');
                        i += 2;
                    }
                    b'n' => {
                        out.push('\n');
                        i += 2;
                    }
                    b'r' => {
                        out.push('\r');
                        i += 2;
                    }
                    b't' => {
                        out.push('\t');
                        i += 2;
                    }
                    b'u' => {
                        let mut unit: u16 = 0;
                        for k in 0..4 {
                            let h = *body
                                .get(i + 2 + k)
                                .ok_or_else(|| LenientError::at(i, "unterminated \\u escape"))?;
                            unit = unit * 16
                                + hex_val(h).ok_or_else(|| {
                                    LenientError::at(i, "invalid hex digit in \\u escape")
                                })?;
                        }
                        i += 6;
                        if (0xd800..0xdc00).contains(&unit) {
                            // High surrogate: a following
                            // `\uDC00..DFFF` pairs with it;
                            // anything else is a lone
                            // surrogate → U+FFFD (Go).
                            match peek_u_escape(body, i) {
                                Some(low) if (0xdc00..0xe000).contains(&low) => {
                                    let c = 0x10000
                                        + ((unit - 0xd800) as u32) * 0x400
                                        + (low - 0xdc00) as u32;
                                    out.push(char::from_u32(c).unwrap_or('\u{FFFD}'));
                                    i += 6;
                                }
                                _ => out.push('\u{FFFD}'),
                            }
                        } else if (0xdc00..0xe000).contains(&unit) {
                            out.push('\u{FFFD}');
                        } else {
                            out.push(char::from_u32(unit as u32).unwrap_or('\u{FFFD}'));
                        }
                    }
                    _ => return Err(LenientError::at(i + 1, "invalid escape")),
                }
            }
            0x00..=0x1f => {
                return Err(LenientError::at(i, "unescaped control character in string"));
            }
            b'"' => {
                // Unreachable for scanner-validated spans
                // (an interior quote is always `\"`), but
                // refuse rather than silently keeping it.
                return Err(LenientError::at(i, "unescaped quote in string"));
            }
            0x20..=0x7f => {
                out.push(b as char);
                i += 1;
            }
            _ => {
                let (c, size) = decode_rune_go(&body[i..]);
                out.push(c);
                i += size;
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(input: &[u8]) -> Parsed<'_> {
        Parsed::parse_document(input).unwrap()
    }

    /// The value of the LAST occurrence of `name`
    /// (exact or fold match) — the value Go's
    /// sequential apply leaves in the slot when every
    /// occurrence is valid. Test helper only; typed
    /// decoders use `match_fields` + `apply_*_field`
    /// and must NOT read a field through this.
    fn last_occurrence<'a>(d: &Parsed<'a>, name: &str) -> Option<Parsed<'a>> {
        d.match_fields(&[name])
            .unwrap()
            .into_iter()
            .last()
            .map(|(_, v)| v)
    }

    #[test]
    fn document_null_is_a_value() {
        let d = doc(b"null");
        assert!(d.is_null());
        assert_eq!(d.kind(), Kind::Null);
    }

    #[test]
    fn sequential_occurrences_keep_document_order() {
        // Duplicate keys apply in document order; with
        // only valid occurrences the last one wins.
        let d = doc(br#"{"a":1,"a":2,"b":"x","b":"y"}"#);
        assert_eq!(last_occurrence(&d, "a").unwrap().as_i64().unwrap(), 2);
        assert_eq!(last_occurrence(&d, "b").unwrap().as_str().unwrap(), "y");
        assert_eq!(d.fields().unwrap().len(), 4);
        // ... and `match_fields` reports every
        // occurrence, in order, not just the last.
        let occ = d.match_fields(&["a", "b"]).unwrap();
        assert_eq!(occ.len(), 4);
        assert_eq!(occ[0].0, 0);
        assert_eq!(occ[1].0, 0);
        assert_eq!(occ[2].0, 1);
        assert_eq!(occ[3].0, 1);
        assert_eq!(occ[1].1.as_i64().unwrap(), 2);
        // A key spelled with an escape resolves to the
        // same field (technical F-4): the escaped
        // duplicate is a second occurrence, last wins.
        let d = doc(br#"{"tag_name":"a","tag_\u006eame":"b"}"#);
        let occ = d.match_fields(&["tag_name"]).unwrap();
        assert_eq!(occ.len(), 2);
        assert_eq!(occ[1].1.as_str().unwrap(), "b");
    }

    #[test]
    fn fold_match_is_go_foldname() {
        // Go `foldName` (fold.go): ASCII letters fold
        // to uppercase; Kelvin sign U+212A folds to
        // `K`, long-s U+017F folds to `S`.
        assert_eq!(go_fold_name("ok"), "OK");
        assert_eq!(go_fold_name("Ok"), "OK");
        assert_eq!(go_fold_name("o\u{212a}"), "OK");
        assert_eq!(go_fold_name("\u{17f}ize"), "SIZE");
        assert_eq!(go_fold_name("tag_name"), "TAG_NAME");
        // `ß` has no simple fold: it folds to itself,
        // NOT to `SS` (the multi-char uppercase is not
        // a simple fold).
        assert_eq!(go_fold_name("\u{df}"), "\u{df}");
        // Exact match wins over fold match: a key that
        // is exactly `ok` resolves to `ok` even when a
        // fold-only field is listed first.
        let d = doc(br#"{"ok":true}"#);
        let occ = d.match_fields(&["OK", "ok"]).unwrap();
        assert_eq!(occ.len(), 1);
        assert_eq!(occ[0].0, 1);
        // Fold-only keys resolve in document order.
        let d = doc("{\"OK\":true,\"Ok\":false}".as_bytes());
        let occ = d.match_fields(&["ok"]).unwrap();
        assert_eq!(occ.len(), 2);
        assert!(occ[0].1.as_bool().unwrap());
        assert!(!occ[1].1.as_bool().unwrap());
        // Kelvin-sign and long-s keys fold-match.
        let d = doc("{\"o\u{212a}\":false}".as_bytes());
        assert_eq!(d.match_fields(&["ok"]).unwrap().len(), 1);
        let d = doc("{\"\u{17f}ize\":7}".as_bytes());
        let occ = d.match_fields(&["size"]).unwrap();
        assert_eq!(occ.len(), 1);
        assert_eq!(occ[0].1.as_i64().unwrap(), 7);
    }

    #[test]
    fn sequential_apply_first_type_error_wins() {
        // Go `saveError`: a type error on a non-last
        // occurrence is saved and refuses at the end
        // even when a later occurrence is valid — but
        // the later valid value IS applied to the slot
        // (R3-B3).
        let d = doc(br#"{"tag":123,"tag":"v0.6.4"}"#);
        let occ = d.match_fields(&["tag"]).unwrap();
        let mut slot = String::new();
        let mut first = FirstError::default();
        for (_, v) in occ {
            first.record_result(apply_str_field(&mut slot, v));
        }
        assert_eq!(slot, "v0.6.4");
        assert!(first.into_result(()).is_err());
        // `null` on a scalar is a no-op (R3-B2): the
        // previously applied value survives.
        let d = doc(br#"{"tag":"v0.6.4","tag":null}"#);
        let occ = d.match_fields(&["tag"]).unwrap();
        let mut slot = String::new();
        let mut first = FirstError::default();
        for (_, v) in occ {
            first.record_result(apply_str_field(&mut slot, v));
        }
        assert_eq!(slot, "v0.6.4");
        assert!(first.into_result(()).is_ok());
        // A type error on the LAST occurrence refuses
        // too, and the slot keeps the earlier value.
        let d = doc(br#"{"tag":"v0.6.4","tag":123}"#);
        let occ = d.match_fields(&["tag"]).unwrap();
        let mut slot = String::new();
        let mut first = FirstError::default();
        for (_, v) in occ {
            first.record_result(apply_str_field(&mut slot, v));
        }
        assert_eq!(slot, "v0.6.4");
        assert!(first.into_result(()).is_err());
        // `null` first, valid later: applies normally.
        let d = doc(br#"{"ok":null,"ok":true}"#);
        let occ = d.match_fields(&["ok"]).unwrap();
        let mut slot = false;
        let mut first = FirstError::default();
        for (_, v) in occ {
            first.record_result(apply_bool_field(&mut slot, v));
        }
        assert!(slot);
        assert!(first.into_result(()).is_ok());
        // RawMessage keeps the last raw bytes including
        // literal `null`.
        let d = doc(br#"{"result":2,"result":null}"#);
        let occ = d.match_fields(&["result"]).unwrap();
        let mut slot: Option<Vec<u8>> = None;
        for (_, v) in occ {
            apply_raw_field(&mut slot, v);
        }
        assert_eq!(slot.as_deref(), Some(b"null".as_slice()));
    }

    #[test]
    fn invalid_utf8_coerces_to_fffd_go_style() {
        // One 0xFF byte -> one U+FFFD.
        let d = doc(b"{\"s\":\"a\xffb\"}");
        assert_eq!(
            last_occurrence(&d, "s").unwrap().as_str().unwrap(),
            "a\u{FFFD}b"
        );
        // Truncated 2-byte sequence [E2, 82] -> TWO U+FFFD
        // (Go DecodeRune consumes 1 byte per failure;
        // `from_utf8_lossy` would give one — that is why
        // this parser does not use it).
        let d = doc(b"{\"s\":\"\xe2\x82\"}");
        assert_eq!(
            last_occurrence(&d, "s").unwrap().as_str().unwrap(),
            "\u{FFFD}\u{FFFD}"
        );
        // Valid multi-byte stays intact.
        let d = doc("{\"s\":\"caf\u{e9}\"}".as_bytes());
        assert_eq!(
            last_occurrence(&d, "s").unwrap().as_str().unwrap(),
            "caf\u{e9}"
        );
        // A genuine U+FFFD (EF BF BD) stays one char.
        let d = doc(b"{\"s\":\"\xef\xbf\xbd\"}");
        assert_eq!(
            last_occurrence(&d, "s").unwrap().as_str().unwrap(),
            "\u{FFFD}"
        );
    }

    #[test]
    fn lone_surrogate_escapes_coerce() {
        let d = doc(br#"{"s":"\ud800"}"#);
        assert_eq!(
            last_occurrence(&d, "s").unwrap().as_str().unwrap(),
            "\u{FFFD}"
        );
        let d = doc(br#"{"s":"\ud800\udc00"}"#);
        assert_eq!(
            last_occurrence(&d, "s").unwrap().as_str().unwrap(),
            "\u{10000}"
        );
        let d = doc("{\"s\":\"Aé\"}".as_bytes());
        assert_eq!(
            last_occurrence(&d, "s").unwrap().as_str().unwrap(),
            "A\u{e9}"
        );
    }

    #[test]
    fn type_errors_still_refuse() {
        let d = doc(br#"{"size":"x","tag":123,"ok":1}"#);
        assert!(last_occurrence(&d, "size").unwrap().as_i64().is_err());
        assert!(last_occurrence(&d, "tag").unwrap().as_str().is_err());
        assert!(last_occurrence(&d, "ok").unwrap().as_bool().is_err());
        assert!(doc(b"1e3").as_i64().is_err());
        assert!(doc(b"1.0").as_i64().is_err());
        assert!(doc(b"9223372036854775808").as_i64().is_err());
        assert_eq!(doc(b"-5").as_i64().unwrap(), -5);
        assert_eq!(doc(b"100").as_i64().unwrap(), 100);
    }

    #[test]
    fn syntax_errors_refuse() {
        let cases: &[&[u8]] = &[
            b"",
            b" ",
            b"{",
            b"[1,]",
            b"{\"a\":1,}",
            b"{\"a\" 1}",
            b"{\"a\":01}",
            b"[1.]",
            b"[.5]",
            b"[+1]",
            b"[NaN]",
            b"[1e]",
            b"{\"a\":\"unterminated}",
            "{\"a\":\"bad\x01escape\"}".as_bytes(),
            b"{\"a\":tru}",
            b"{\"a\":1} garbage",
            b"{} {}",
            b"[1 2]",
        ];
        for bad in cases {
            assert!(Parsed::parse_document(bad).is_err(), "must refuse {bad:?}");
        }
    }

    #[test]
    fn raw_spans_keep_bytes_verbatim() {
        let d = doc(br#"{"ok":true,"result":{"b":1,"a":2}}"#);
        assert_eq!(
            last_occurrence(&d, "result").unwrap().as_raw(),
            br#"{"b":1,"a":2}"#
        );
        let d = doc(b"{\"ok\":true,\"result\":\"a\xffb\"}");
        assert_eq!(
            last_occurrence(&d, "result").unwrap().as_raw(),
            b"\"a\xffb\""
        );
        // Null stays 4 raw bytes, distinct from absent.
        let d = doc(br#"{"ok":true,"result":null}"#);
        let r = last_occurrence(&d, "result").unwrap();
        assert!(r.is_null());
        assert_eq!(r.as_raw(), b"null");
        assert!(last_occurrence(&doc(br#"{"ok":true}"#), "result").is_none());
    }

    #[test]
    fn deep_nesting_does_not_overflow() {
        // 200 and 1000 deep: Go accepts both, and the
        // round-1 B4 probe pinned 150/200 ACCEPT — the
        // scanner must not recurse.
        for depth in [200, 1000] {
            let mut input = Vec::new();
            for _ in 0..depth {
                input.extend_from_slice(b"{\"a\":");
            }
            input.extend_from_slice(b"1");
            input.extend(std::iter::repeat_n(b'}', depth));
            let d = Parsed::parse_document(&input).unwrap();
            assert_eq!(d.kind(), Kind::Object);
        }
        // Boundary (fix loop 3, R3-B4 / NB-R3-5): Go
        // `maxNestingDepth` is 10000 INCLUSIVE — total
        // depth 10000 accepts, 10001 refuses — for
        // objects AND arrays.
        for (depth, ok) in [(9999, true), (10000, true), (10001, false)] {
            for (open, close) in [(b'{', b'}'), (b'[', b']')] {
                let mut input = Vec::new();
                for _ in 0..depth {
                    input.push(open);
                    if open == b'{' {
                        input.extend_from_slice(b"\"a\":");
                    }
                }
                input.extend_from_slice(b"1");
                input.extend(std::iter::repeat_n(close, depth));
                let parsed = Parsed::parse_document(&input);
                assert_eq!(
                    parsed.is_ok(),
                    ok,
                    "depth {depth} with {open} must accept={ok}"
                );
            }
        }
        // ... nor does an unbalanced deep input hang or panic.
        let mut input = vec![b'['; 5000];
        input.push(b'1');
        assert!(Parsed::parse_document(&input).is_err());
    }

    #[test]
    fn array_null_elements_survive() {
        let d = doc(b"[null, 1, null]");
        let els = d.elements().unwrap();
        assert_eq!(els.len(), 3);
        assert!(els[0].is_null());
        assert_eq!(els[1].as_i64().unwrap(), 1);
        assert!(els[2].is_null());
    }

    #[test]
    fn unknown_fields_with_bad_bytes_are_skipped() {
        let d = doc(b"{\"ok\":true,\"zzz\":\"a\xff\",\"zzz\":2}");
        assert!(last_occurrence(&d, "ok").unwrap().as_bool().unwrap());
    }
}
