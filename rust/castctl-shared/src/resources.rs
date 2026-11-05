// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! History-event resource shaping, ported from Go.
//!
//! Source: `internal/shared/resources.go` at `origin/main` `1396697`.
//! `SaveResources` / `Downloader` / `SaveRow` / `downloadRef` are
//! out of scope for M1 (filesystem + gateway); see
//! `rust/PORTING.md`.

use std::collections::{BTreeMap, HashMap};
use std::sync::OnceLock;

use regex::Regex;

use crate::value::{
    JsonObject, JsonValue, as_list, as_map, as_string, first_string_ptr, get_or_null,
    int_ptr_field, payload_of, string_field, string_ptr_field, truthy,
};

/// One downloadable file referenced by a history event.
/// Source: `internal/shared/resources.go:32`.
#[derive(Debug, Clone, PartialEq)]
pub struct Resource {
    /// Sandbox path or `/media/raw/` URL.
    pub path: String,
    /// Data key with trailing `s` stripped, `"resource"`, or `"link"`.
    pub kind: String,
    /// Entry mime, when present and non-null.
    pub mime: Option<String>,
    /// Entry byte length, when present and non-null.
    pub byte_len: Option<i64>,
    /// Entry label, when present and non-null.
    pub label: Option<String>,
    /// Entry variants object, kept verbatim when present and non-null.
    pub variants: Option<JsonValue>,
}

impl Resource {
    /// A resource with only path and kind set, as `EventResources`
    /// creates a first-seen slot.
    ///
    /// Source: the `Resource` struct definition in
    /// `internal/shared/resources.go:32-50` and the first-seen
    /// slot creation in `EventResources` at
    /// `resources.go:113-118` (`&Resource{Path: ..., Kind: ...}`).
    /// There is no direct Go function counterpart for this
    /// constructor: Go creates the struct literal inline; this
    /// is a Rust-side constructor for building a [`Resource`].
    #[must_use]
    pub fn new(path: String, kind: String) -> Self {
        Resource {
            path,
            kind,
            mime: None,
            byte_len: None,
            label: None,
            variants: None,
        }
    }
}

/// One row of the `files` command output: the event's seq and
/// message_id plus the resource fields, flattened, in that order.
/// Source: `internal/shared/resources.go:55`.
#[derive(Debug, Clone, PartialEq)]
pub struct FileRow {
    /// Event seq, or `None` (serializes as `null`, no `omitempty`).
    pub seq: Option<i64>,
    /// Payload message_id, falling back to the event's.
    pub message_id: Option<String>,
    /// Resource path.
    pub path: String,
    /// Resource kind.
    pub kind: String,
    /// Resource mime.
    pub mime: Option<String>,
    /// Resource byte length.
    pub byte_len: Option<i64>,
    /// Resource label.
    pub label: Option<String>,
    /// Resource variants.
    pub variants: Option<JsonValue>,
}

fn sandbox_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Go: `sandbox://[^\s)\]"'>]+` (resources.go:25). Go \s is
        // ASCII-only; the Rust class spells the ASCII whitespace
        // set explicitly.
        Regex::new(r#"sandbox://[^\t\n\f\r )\]\"'>]+"#).expect("static sandbox regex is valid")
    })
}

/// Resolves an entry's downloadable path: its `"path"` wins when
/// non-empty, else `variants.original`. Returns `""` when there
/// is no path or the path is neither `sandbox://` nor contains
/// `/media/raw/`.
/// Source: `internal/shared/resources.go:182` (`resourcePath`).
fn resource_path(item: &JsonObject) -> String {
    let mut resolved = string_field(item, "path").to_string();
    if resolved.is_empty() {
        if let Some(variants) = item.get("variants").and_then(as_map) {
            resolved = string_field(variants, "original").to_string();
        }
    }
    if resolved.starts_with("sandbox://") || resolved.contains("/media/raw/") {
        resolved
    } else {
        String::new()
    }
}

struct Collector {
    order: Vec<String>,
    index: HashMap<String, usize>,
    items: Vec<Resource>,
}

impl Collector {
    fn add(&mut self, item: &JsonValue, kind: &str) {
        let single;
        let m = if let JsonValue::Str(s) = item {
            single = BTreeMap::from([("path".to_string(), JsonValue::Str(s.clone()))]);
            &single
        } else {
            match as_map(item) {
                Some(m) => m,
                None => return,
            }
        };
        let resolved = resource_path(m);
        if resolved.is_empty() {
            return;
        }
        if truthy(get_or_null(m, "missing")) {
            return;
        }
        let idx = match self.index.get(&resolved) {
            Some(&i) => i,
            None => {
                let i = self.items.len();
                self.index.insert(resolved.clone(), i);
                self.order.push(resolved.clone());
                self.items.push(Resource::new(resolved, kind.to_string()));
                i
            }
        };
        let r = &mut self.items[idx];
        if let Some(v) = string_ptr_field(m, "mime") {
            r.mime = Some(v);
        }
        if let Some(v) = int_ptr_field(m, "byte_len") {
            r.byte_len = Some(v);
        }
        if let Some(v) = string_ptr_field(m, "label") {
            r.label = Some(v);
        }
        if let Some(v) = m.get("variants") {
            if *v != JsonValue::Null {
                r.variants = Some(v.clone());
            }
        }
    }
}

/// Lists the downloadable files referenced by one history event.
/// Sources are visited in order: sorted `payload.data` keys,
/// the event's then the payload's `resources` lists, then
/// `sandbox://` links in text fields. First kind wins; later
/// entries overwrite non-null fields. A non-object event yields
/// no resources.
/// Source: `internal/shared/resources.go:93` (`EventResources`).
pub fn event_resources(ev: &JsonValue) -> Vec<Resource> {
    let Some(ev_map) = as_map(ev) else {
        return Vec::new();
    };
    event_resources_map(ev_map)
}

fn event_resources_map(ev: &JsonObject) -> Vec<Resource> {
    let p = payload_of(ev);
    let mut collector = Collector {
        order: Vec::new(),
        index: HashMap::new(),
        items: Vec::new(),
    };

    // Data keys visit in sorted order: JsonObject is a BTreeMap,
    // so iteration is already byte-sorted (decision D9).
    let empty: JsonObject = BTreeMap::new();
    let data = match p.get("data") {
        Some(v) => as_map(v).unwrap_or(&empty),
        None => &empty,
    };
    for (key, items) in data {
        let Some(items) = as_list(items) else {
            continue;
        };
        let kind = key.trim_end_matches('s');
        for item in items {
            collector.add(item, kind);
        }
    }
    for src in [ev.get("resources"), p.get("resources")] {
        let Some(src) = src else { continue };
        let Some(items) = as_list(src) else {
            continue;
        };
        for item in items {
            collector.add(item, "resource");
        }
    }
    for text in [
        p.get("fallback_text"),
        data.get("fallback_text"),
        p.get("display_text"),
        p.get("content"),
    ] {
        let Some(text) = text else { continue };
        let Some(s) = as_string(text) else {
            continue;
        };
        for m in sandbox_re().find_iter(s) {
            let link = JsonValue::Str(m.as_str().to_string());
            collector.add(&link, "link");
        }
    }

    let mut out = Vec::with_capacity(collector.order.len());
    for k in collector.order {
        let idx = collector.index[&k];
        out.push(collector.items[idx].clone());
    }
    out
}

/// One row per file referenced by these history events.
/// Non-object events are skipped.
/// Source: `internal/shared/resources.go:198` (`FileRows`).
pub fn file_rows(events: &[JsonValue]) -> Vec<FileRow> {
    let mut rows = Vec::new();
    for e in events {
        let Some(ev) = as_map(e) else {
            continue;
        };
        let p = payload_of(ev);
        for r in event_resources_map(ev) {
            rows.push(FileRow {
                seq: int_ptr_field(ev, "seq"),
                message_id: first_string_ptr(&[
                    get_or_null(p, "message_id"),
                    get_or_null(ev, "message_id"),
                ]),
                path: r.path,
                kind: r.kind,
                mime: r.mime,
                byte_len: r.byte_len,
                label: r.label,
                variants: r.variants,
            });
        }
    }
    rows
}

/// Local file name for a resource path inside `directory`:
/// basename with any `?...` query stripped and trailing
/// slashes removed, or `"download"` when nothing remains.
/// Source: `internal/shared/resources.go:338` (`LocalName`).
pub fn local_name(resource_path: &str, directory: &str) -> String {
    let s = resource_path.split('?').next().unwrap_or("");
    let s = s.trim_end_matches('/');
    let mut name = path_base(s);
    if name.is_empty() || name == "." || name == "/" {
        name = "download";
    }
    filepath_join(directory, name)
}

/// Go `path.Base` (slash-only): empty → `"."`; all slashes →
/// `"/"`; otherwise the element after the last `/`.
fn path_base(s: &str) -> &str {
    if s.is_empty() {
        return ".";
    }
    let t = s.trim_end_matches('/');
    if t.is_empty() {
        return "/";
    }
    match t.rfind('/') {
        Some(i) => &t[i + 1..],
        None => t,
    }
}

/// Go `filepath.Join` for Unix: join non-empty elements with
/// `/`, then `Clean`.
fn filepath_join(directory: &str, name: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    if !directory.is_empty() {
        parts.push(directory);
    }
    if !name.is_empty() {
        parts.push(name);
    }
    if parts.is_empty() {
        return String::new();
    }
    clean_path(&parts.join("/"))
}

/// Go `path/filepath.Clean` for Unix paths.
fn clean_path(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let rooted = path.starts_with('/');
    let mut out: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if !out.is_empty() && *out.last().unwrap() != ".." {
                    out.pop();
                } else if !rooted {
                    out.push("..");
                }
            }
            _ => out.push(part),
        }
    }
    let mut result = String::new();
    if rooted {
        result.push('/');
    }
    result.push_str(&out.join("/"));
    if result.is_empty() {
        return if rooted {
            "/".to_string()
        } else {
            ".".to_string()
        };
    }
    result
}

/// Go `encoding/json` float formatting for one finite float.
// The `abs != 0.0` guard makes the range form inequivalent
// (`!(1e-6..1e21).contains(&0.0)` is true), so the manual
// comparison is kept deliberately.
#[allow(clippy::manual_range_contains)]
fn format_json_float(f: f64) -> String {
    let abs = f.abs();
    if abs != 0.0 && (abs < 1e-6 || abs >= 1e21) {
        let s = format!("{f:e}");
        if let Some(pos) = s.find('e') {
            let (mantissa, exp) = s.split_at(pos + 1);
            if !exp.starts_with('-') {
                return format!("{mantissa}+{exp}");
            }
        }
        s
    } else {
        format!("{f}")
    }
}

/// Escapes a string the way Go's `encoding/json` does:
/// `"`/`\`/control chars, plus `<`, `>`, `&` and U+2028/U+2029
/// as `\u00XX` escapes.
fn escape_json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
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
}

/// Serializes a JSON value the way Go's `encoding/json` does
/// (object keys sorted, same string escaping). Floats use Go's
/// `encoding/json` float format: shortest round-trip digits,
/// scientific notation when `|f| < 1e-6` or `|f| >= 1e21`, with
/// the exponent's leading zero stripped (`1e-7`, `1e+21`).
/// Non-finite floats serialize as `null` (Go would error;
/// no pinned case covers this).
fn write_json_value(v: &JsonValue, out: &mut String) {
    match v {
        JsonValue::Null => out.push_str("null"),
        JsonValue::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        JsonValue::Int(n) => out.push_str(&n.to_string()),
        JsonValue::Float(f) => {
            if f.is_nan() || f.is_infinite() {
                out.push_str("null");
            } else {
                out.push_str(&format_json_float(*f));
            }
        }
        JsonValue::Str(s) => escape_json_string(s, out),
        JsonValue::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json_value(item, out);
            }
            out.push(']');
        }
        JsonValue::Object(map) => {
            out.push('{');
            for (i, (k, val)) in map.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                escape_json_string(k, out);
                out.push(':');
                write_json_value(val, out);
            }
            out.push('}');
        }
    }
}

/// Serializes a [`FileRow`] exactly as Go's `encoding/json`
/// would: field order `seq`, `message_id`, `path`, `kind`,
/// `mime`, `byte_len`, `label`, `variants`; `seq`/`message_id`
/// always emitted (`null` when `None`); the four optional
/// resource fields omitted when `None`.
/// Hand-rolled per decision D-json (no serde); see
/// `rust/PORTING.md`.
/// Source: `internal/shared/resources.go:55` (struct tags).
pub fn file_row_to_json(row: &FileRow) -> String {
    let mut out = String::new();
    out.push('{');
    out.push_str("\"seq\":");
    match row.seq {
        Some(n) => out.push_str(&n.to_string()),
        None => out.push_str("null"),
    }
    out.push_str(",\"message_id\":");
    match &row.message_id {
        Some(s) => escape_json_string(s, &mut out),
        None => out.push_str("null"),
    }
    out.push_str(",\"path\":");
    escape_json_string(&row.path, &mut out);
    out.push_str(",\"kind\":");
    escape_json_string(&row.kind, &mut out);
    if let Some(mime) = &row.mime {
        out.push_str(",\"mime\":");
        escape_json_string(mime, &mut out);
    }
    if let Some(n) = row.byte_len {
        out.push_str(",\"byte_len\":");
        out.push_str(&n.to_string());
    }
    if let Some(label) = &row.label {
        out.push_str(",\"label\":");
        escape_json_string(label, &mut out);
    }
    if let Some(variants) = &row.variants {
        out.push_str(",\"variants\":");
        write_json_value(variants, &mut out);
    }
    out.push('}');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::JsonValue;
    use std::collections::BTreeMap;

    // Ported from internal/shared/resources_test.go: 6 test fns
    // (2 standalone + 13-rule table + FileRows + JSON-order +
    // 6-case LocalName). Literals copied verbatim; comparison is
    // full structural equality, as reflect.DeepEqual in Go.
    //
    // Excluded (Go-only, reasons in rust/PORTING.md): the 4
    // TestSaveResources* fns — they need a fake Downloader,
    // temp dirs, and conn error types (filesystem + network
    // trait + context cancellation).
    //
    // D5 note: values.go has no test file of its own; its
    // helpers are covered only indirectly through these cases.
    // No values-helper test table was invented.

    fn s(v: &str) -> JsonValue {
        JsonValue::Str(v.to_string())
    }

    fn i(v: i64) -> JsonValue {
        JsonValue::Int(v)
    }

    fn obj(pairs: &[(&str, JsonValue)]) -> JsonValue {
        let mut m = BTreeMap::new();
        for (k, v) in pairs {
            m.insert((*k).to_string(), v.clone());
        }
        JsonValue::Object(m)
    }

    fn arr(items: &[JsonValue]) -> JsonValue {
        JsonValue::Array(items.to_vec())
    }

    fn res(path: &str, kind: &str) -> Resource {
        Resource::new(path.to_string(), kind.to_string())
    }

    fn with_mime(mut r: Resource, mime: &str) -> Resource {
        r.mime = Some(mime.to_string());
        r
    }

    fn with_label(mut r: Resource, label: &str) -> Resource {
        r.label = Some(label.to_string());
        r
    }

    fn with_variants(mut r: Resource, v: JsonValue) -> Resource {
        r.variants = Some(v);
        r
    }

    #[test]
    fn test_event_resources_videos_and_links_dedupe() {
        // TestEventResourcesVideosAndLinksDedupe.
        let p = "sandbox://workspace/imagine_media/cat-1.mp4";
        let ev = obj(&[
            ("seq", i(1)),
            (
                "payload",
                obj(&[
                    ("fallback_text", s(&format!("![v]({p})"))),
                    (
                        "data",
                        obj(&[
                            (
                                "videos",
                                arr(&[obj(&[
                                    ("path", s(p)),
                                    ("mime", s("video/mp4")),
                                    ("byte_len", i(5)),
                                ])]),
                            ),
                            (
                                "images",
                                arr(&[obj(&[
                                    ("path", s("sandbox://workspace/x.png")),
                                    ("missing", JsonValue::Bool(true)),
                                ])]),
                            ),
                        ]),
                    ),
                ]),
            ),
        ]);
        let got = event_resources(&ev);
        assert_eq!(
            got.len(),
            1,
            "len(EventResources) = {}, want 1: {got:?}",
            got.len()
        );
        assert_eq!(got[0].kind, "video", "kind");
        assert_eq!(got[0].byte_len, Some(5), "byte_len");
        assert_eq!(got[0].path, p, "path");
    }

    #[test]
    fn test_event_resources_no_files() {
        // TestEventResourcesNoFiles.
        let ev = obj(&[("payload", obj(&[("display_text", s("hi"))]))]);
        let got = event_resources(&ev);
        assert!(got.is_empty(), "EventResources = {got:?}, want empty");
    }

    #[test]
    fn test_event_resources_rules() {
        // TestEventResourcesRules: 13 cases.
        struct Case {
            name: &'static str,
            ev: JsonValue,
            want: Vec<Resource>,
        }
        let cases = [
            Case {
                name: "resources lists use kind resource",
                ev: obj(&[(
                    "resources",
                    arr(&[obj(&[
                        ("path", s("sandbox://workspace/a.bin")),
                        ("label", s("A")),
                    ])]),
                )]),
                want: vec![with_label(
                    res("sandbox://workspace/a.bin", "resource"),
                    "A",
                )],
            },
            Case {
                name: "payload resources after event resources",
                ev: obj(&[
                    (
                        "resources",
                        arr(&[obj(&[("path", s("sandbox://workspace/a.bin"))])]),
                    ),
                    (
                        "payload",
                        obj(&[(
                            "resources",
                            arr(&[obj(&[("path", s("sandbox://workspace/b.bin"))])]),
                        )]),
                    ),
                ]),
                want: vec![
                    res("sandbox://workspace/a.bin", "resource"),
                    res("sandbox://workspace/b.bin", "resource"),
                ],
            },
            Case {
                name: "string item becomes path dict",
                ev: obj(&[(
                    "payload",
                    obj(&[(
                        "data",
                        obj(&[("files", arr(&[s("sandbox://workspace/s.txt")]))]),
                    )]),
                )]),
                want: vec![res("sandbox://workspace/s.txt", "file")],
            },
            Case {
                name: "non sandbox path dropped",
                ev: obj(&[(
                    "payload",
                    obj(&[(
                        "data",
                        obj(&[(
                            "files",
                            arr(&[obj(&[("path", s("https://example.com/x.png"))])]),
                        )]),
                    )]),
                )]),
                want: vec![],
            },
            Case {
                name: "media raw url kept",
                ev: obj(&[(
                    "payload",
                    obj(&[(
                        "data",
                        obj(&[(
                            "files",
                            arr(&[obj(&[(
                                "path",
                                s("https://abc.metaaivm.com/media/raw/workspace/x.png"),
                            )])]),
                        )]),
                    )]),
                )]),
                want: vec![res(
                    "https://abc.metaaivm.com/media/raw/workspace/x.png",
                    "file",
                )],
            },
            Case {
                name: "variants original resolves path when path empty",
                ev: obj(&[(
                    "payload",
                    obj(&[(
                        "data",
                        obj(&[(
                            "images",
                            arr(&[obj(&[(
                                "variants",
                                obj(&[("original", s("sandbox://workspace/v.png"))]),
                            )])]),
                        )]),
                    )]),
                )]),
                want: vec![with_variants(
                    res("sandbox://workspace/v.png", "image"),
                    obj(&[("original", s("sandbox://workspace/v.png"))]),
                )],
            },
            Case {
                name: "first kind wins later fields overwrite",
                ev: obj(&[(
                    "payload",
                    obj(&[(
                        "data",
                        obj(&[
                            (
                                "videos",
                                arr(&[obj(&[
                                    ("path", s("sandbox://workspace/d.mp4")),
                                    ("mime", s("video/mp4")),
                                ])]),
                            ),
                            (
                                "files",
                                arr(&[obj(&[
                                    ("path", s("sandbox://workspace/d.mp4")),
                                    ("mime", s("video/other")),
                                    ("label", s("L")),
                                ])]),
                            ),
                        ]),
                    )]),
                )]),
                want: vec![with_label(
                    with_mime(res("sandbox://workspace/d.mp4", "file"), "video/mp4"),
                    "L",
                )],
            },
            Case {
                name: "key rstrip s verbatim",
                ev: obj(&[(
                    "payload",
                    obj(&[(
                        "data",
                        obj(&[(
                            "class",
                            arr(&[obj(&[("path", s("sandbox://workspace/c.bin"))])]),
                        )]),
                    )]),
                )]),
                want: vec![res("sandbox://workspace/c.bin", "cla")],
            },
            Case {
                name: "non-list data value skipped",
                ev: obj(&[(
                    "payload",
                    obj(&[(
                        "data",
                        obj(&[("video", obj(&[("path", s("sandbox://workspace/d.mp4"))]))]),
                    )]),
                )]),
                want: vec![],
            },
            Case {
                name: "link in display text",
                ev: obj(&[(
                    "payload",
                    obj(&[("display_text", s("see sandbox://workspace/doc.pdf ok"))]),
                )]),
                want: vec![res("sandbox://workspace/doc.pdf", "link")],
            },
            Case {
                name: "link stops at closing paren",
                ev: obj(&[(
                    "payload",
                    obj(&[("display_text", s("![v](sandbox://workspace/a.mp4) tail"))]),
                )]),
                want: vec![res("sandbox://workspace/a.mp4", "link")],
            },
            Case {
                name: "missing false is kept",
                ev: obj(&[(
                    "payload",
                    obj(&[(
                        "data",
                        obj(&[(
                            "files",
                            arr(&[obj(&[
                                ("path", s("sandbox://workspace/k.bin")),
                                ("missing", JsonValue::Bool(false)),
                            ])]),
                        )]),
                    )]),
                )]),
                want: vec![res("sandbox://workspace/k.bin", "file")],
            },
            Case {
                name: "variants kept verbatim",
                ev: obj(&[(
                    "payload",
                    obj(&[(
                        "data",
                        obj(&[(
                            "images",
                            arr(&[obj(&[
                                ("path", s("sandbox://workspace/i.png")),
                                (
                                    "variants",
                                    obj(&[
                                        ("original", s("https://x/media/raw/workspace/i.png")),
                                        ("thumb", s("https://x/t.png")),
                                    ]),
                                ),
                            ])]),
                        )]),
                    )]),
                )]),
                want: vec![with_variants(
                    res("sandbox://workspace/i.png", "image"),
                    obj(&[
                        ("original", s("https://x/media/raw/workspace/i.png")),
                        ("thumb", s("https://x/t.png")),
                    ]),
                )],
            },
        ];
        assert_eq!(cases.len(), 13, "ported case count");
        for tc in cases {
            let got = event_resources(&tc.ev);
            assert_eq!(got, tc.want, "case {}: EventResources = {got:?}", tc.name);
        }
    }

    #[test]
    fn test_file_rows() {
        // TestFileRows.
        let events = [
            obj(&[
                ("seq", i(9)),
                (
                    "payload",
                    obj(&[
                        ("message_id", s("m9")),
                        (
                            "data",
                            obj(&[(
                                "videos",
                                arr(&[obj(&[("path", s("sandbox://workspace/v.mp4"))])]),
                            )]),
                        ),
                    ]),
                ),
            ]),
            obj(&[
                ("seq", i(10)),
                ("payload", obj(&[("display_text", s("no files"))])),
            ]),
            s("not an event"),
        ];
        let rows = file_rows(&events);
        assert_eq!(rows.len(), 1, "len(FileRows) = {}, want 1", rows.len());
        let want = FileRow {
            seq: Some(9),
            message_id: Some("m9".to_string()),
            path: "sandbox://workspace/v.mp4".to_string(),
            kind: "video".to_string(),
            mime: None,
            byte_len: None,
            label: None,
            variants: None,
        };
        assert_eq!(rows[0], want, "FileRows[0]");
    }

    #[test]
    fn test_file_row_json_order() {
        // TestFileRowJSONOrder: exact bytes, field order + omitempty.
        let row = FileRow {
            seq: Some(9),
            message_id: Some("m9".to_string()),
            path: "sandbox://workspace/v.mp4".to_string(),
            kind: "video".to_string(),
            mime: Some("video/mp4".to_string()),
            byte_len: Some(5),
            label: None,
            variants: None,
        };
        let got = file_row_to_json(&row);
        let want = r#"{"seq":9,"message_id":"m9","path":"sandbox://workspace/v.mp4","kind":"video","mime":"video/mp4","byte_len":5}"#;
        assert_eq!(got, want, "Marshal(FileRow)");
    }

    #[test]
    fn test_local_name() {
        // TestLocalName: the Go test asserts only the basename
        // (filepath.Base); the test-local base() below mirrors
        // that assertion without reusing production code.
        fn base(p: &str) -> &str {
            p.rsplit('/').next().unwrap_or(p)
        }
        let cases = [
            ("sandbox://workspace/a/b.png", "b.png"),
            (
                "https://h/media/raw/workspace/cat%201.mp4?x=1",
                "cat%201.mp4",
            ),
            ("sandbox://workspace/", "workspace"),
            ("", "download"),
            ("/", "download"),
            ("sandbox://workspace/a/", "a"),
        ];
        for (input, want) in cases {
            let got = local_name(input, "/tmp/d");
            assert_eq!(
                base(&got),
                want,
                "LocalName({input:?}) = {got:?}, want basename {want:?}"
            );
        }
    }

    // Differential probes (NOT ported Go cases): float/escaping
    // goldens measured against Go `encoding/json` on cue (probe P-6
    // follow-up). No Go test pins variant floats; these guard the
    // hand-rolled serializer's float format only.
    #[test]
    // The long literal is the Go golden input verbatim;
    // its rounded value is what the golden pins.
    #[allow(clippy::excessive_precision)]
    fn probe_json_float_format() {
        let cases: &[(f64, &str)] = &[
            (1.5, "1.5"),
            (1e21, "1e+21"),
            (1e-7, "1e-7"),
            (0.000001, "0.000001"),
            (123456789.123456789, "123456789.12345679"),
            (1e100, "1e+100"),
            (0.1, "0.1"),
            (0.0, "0"),
            (-0.0, "-0"),
            (-1.5e-7, "-1.5e-7"),
            (1e20, "100000000000000000000"),
        ];
        for (f, want) in cases {
            assert_eq!(format_json_float(*f), *want, "float {f}");
            let mut out = String::new();
            write_json_value(&JsonValue::Float(*f), &mut out);
            assert_eq!(out, *want, "json float {f}");
        }
        let mut out = String::new();
        escape_json_string("<a>&\u{2028}\u{2029}\u{1}\u{7f}é", &mut out);
        assert_eq!(
            out, "\"\\u003ca\\u003e\\u0026\\u2028\\u2029\\u0001\u{7f}é\"",
            "json string escaping"
        );
    }
}
