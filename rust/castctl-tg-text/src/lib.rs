//! Telegram message-text formatting, ported from Go.
//!
//! Source: `internal/telegram/text.go` at `origin/main` `1396697`.
//! Lengths count Unicode scalar values (Go runes / Rust `char`s);
//! byte lengths are never used for splitting or limits.

mod entities;
mod unescape;

use regex::Regex;
use std::sync::OnceLock;
use unescape::unescape_html;

/// Telegram chunk size: one message carries at most this
/// many chars (room for markup).
/// Source: `internal/telegram/text.go:26` (`ChunkSize`).
pub const CHUNK_SIZE: usize = 3800;
/// Telegram's hard per-message limit, in chars.
/// Source: `internal/telegram/text.go:30` (`TextLimit`).
pub const TEXT_LIMIT: usize = 4096;
/// File-caption limit, in chars.
/// Source: `internal/telegram/text.go:34` (`CaptionLimit`).
pub const CAPTION_LIMIT: usize = 1024;

/// Escapes `&`, `<`, `>` only (quote=False).
/// Source: `internal/telegram/text.go:38`.
pub fn escape_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(c),
        }
    }
    out
}

fn fence_match_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?s)```([A-Za-z0-9_+.-]*)\n?(.*?)```").expect("fenceMatchRe"))
}

fn fence_marker_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"```([A-Za-z0-9_+.-]*)").expect("fenceMarkerRe"))
}

fn inline_code_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"`([^`\n]+)`").expect("inlineCodeRe"))
}

fn link_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Go `\s` is ASCII-only (RE2); the Rust class spells the same set.
    RE.get_or_init(|| Regex::new(r"\[([^\]\n]+)\]\((https?://[^\t\n\f\r )]+)\)").expect("linkRe"))
}

fn heading_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)^(#{1,6}) +(.+)$").expect("headingRe"))
}

fn stash_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Go `\d` is ASCII-only (RE2).
    RE.get_or_init(|| Regex::new("\x00([0-9]+)\x00").expect("stashRe"))
}

fn tag_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"<[^>]+>").expect("tagRe"))
}

/// Converts Markdown to Telegram HTML: code fences, `` `code` ``,
/// `**bold**`, links.
/// Source: `internal/telegram/text.go:62`.
pub fn md_to_html(text: &str) -> String {
    let re = fence_match_re();
    let mut out = String::new();
    let mut pos = 0usize;
    for caps in re.captures_iter(text) {
        let m = caps.get(0).expect("fence match");
        out.push_str(&inline_html(&text[pos..m.start()]));
        let lang = caps.get(1).map_or("", |g| g.as_str());
        let code = caps.get(2).map_or("", |g| g.as_str());
        let cls = if lang.is_empty() {
            String::new()
        } else {
            format!(" class=\"language-{}\"", escape_text(lang))
        };
        // Go TrimRightFunc(code, unicode.IsSpace): Rust
        // `char::is_whitespace` is the same White_Space set (probe P-1).
        let trimmed = code.trim_end_matches(char::is_whitespace);
        out.push_str(&format!(
            "<pre><code{cls}>{}</code></pre>",
            escape_text(trimmed)
        ));
        pos = m.end();
    }
    out.push_str(&inline_html(&text[pos..]));
    out
}

/// Inline-code/link stash, escaping, bold and headings, in order.
/// Source: `internal/telegram/text.go:88`.
pub(crate) fn inline_html(text: &str) -> String {
    let mut stash: Vec<String> = Vec::new();
    let mut keep = |s: String| -> String {
        stash.push(s);
        format!("\x00{}\x00", stash.len() - 1)
    };
    let t = inline_code_re().replace_all(text, |caps: &regex::Captures<'_>| {
        let inner = caps.get(1).map_or("", |g| g.as_str());
        keep(format!("<code>{}</code>", escape_text(inner)))
    });
    let t = link_re().replace_all(&t, |caps: &regex::Captures<'_>| {
        let label = caps.get(1).map_or("", |g| g.as_str());
        let href = caps.get(2).map_or("", |g| g.as_str());
        // Go `html.EscapeString` escapes five chars: & < > ' ".
        keep(format!(
            "<a href=\"{}\">{}</a>",
            escape_html_string(href),
            escape_text(label)
        ))
    });
    let t = escape_text(&t);
    let t = apply_bold(&t);
    let t = heading_re().replace_all(&t, |caps: &regex::Captures<'_>| {
        format!("<b>{}</b>", caps.get(2).map_or("", |g| g.as_str()))
    });
    // Single restore pass: a replacement is never re-scanned, so a
    // stash sentinel embedded in another stash entry (code span
    // inside a link label) survives literally, as in Go. An
    // out-of-range index is kept verbatim.
    stash_re()
        .replace_all(&t, |caps: &regex::Captures<'_>| {
            let idx = caps.get(1).map_or("", |g| g.as_str());
            match go_atoi(idx) {
                Some(i) if i < stash.len() => stash[i].clone(),
                _ => caps.get(0).map_or("", |g| g.as_str()).to_string(),
            }
        })
        .into_owned()
}

/// Go `html.EscapeString`: escapes `&`, `'`, `<`, `>`, `"` (in that
/// replacement order; single pass, no re-scan).
fn escape_html_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '\'' => out.push_str("&#39;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&#34;"),
            _ => out.push(c),
        }
    }
    out
}

/// Go `strconv.Atoi`: optional sign, ASCII digits, overflow is an
/// error. Only the index decision matters here.
fn go_atoi(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let (neg, digits) = match bytes[0] {
        b'+' => (false, &bytes[1..]),
        b'-' => (true, &bytes[1..]),
        _ => (false, bytes),
    };
    if digits.is_empty() || !digits.iter().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut value: usize = 0;
    for &b in digits {
        value = value.checked_mul(10)?.checked_add((b - b'0') as usize)?;
    }
    if neg {
        if value == 0 { Some(0) } else { None }
    } else {
        Some(value)
    }
}

/// Applies `**bold**` with the edge rules of the Go manual scan.
/// Source: `internal/telegram/text.go:117`.
pub(crate) fn apply_bold(text: &str) -> String {
    let r: Vec<char> = text.chars().collect();
    let mut out = String::new();
    let mut i = 0usize;
    while i < r.len() {
        if i + 1 < r.len()
            && r[i] == '*'
            && r[i + 1] == '*'
            && i + 2 < r.len()
            && !r[i + 2].is_whitespace()
        {
            // Find a closing `**` on the same line whose preceding
            // char is non-space; the first closing wins.
            let mut close: Option<usize> = None;
            let mut j = i + 2;
            while j + 1 < r.len() {
                if r[j] == '\n' {
                    break;
                }
                if r[j] == '*' && r[j + 1] == '*' && j > i + 2 && !r[j - 1].is_whitespace() {
                    close = Some(j);
                    break;
                }
                j += 1;
            }
            if let Some(close) = close {
                out.push_str("<b>");
                out.extend(r[i + 2..close].iter());
                out.push_str("</b>");
                i = close + 2;
                continue;
            }
        }
        out.push(r[i]);
        i += 1;
    }
    out
}

/// Removes HTML tags, then unescapes entities.
/// Source: `internal/telegram/text.go:151`.
pub fn strip_tags(text: &str) -> String {
    let stripped = tag_re().replace_all(text, "");
    unescape_html(&stripped)
}

/// Splits into pieces of at most [`CHUNK_SIZE`] chars.
/// Source: `internal/telegram/text.go:163`.
pub fn split_text(text: &str) -> Vec<String> {
    split_text_limit(text, CHUNK_SIZE)
}

/// Splits into pieces of at most `limit` chars, with fence carry.
/// Source: `internal/telegram/text.go:167`.
///
/// Deliberate deviation (D-split0): `limit == 0` returns the whole
/// text as one piece. Go loops forever on `limit == 0` (and on
/// limits 1-2 when a cut lands at 0 with a space/letter-led
/// remainder); no test pins that behaviour. The cut-at-zero guard
/// below forces a hard cut ONLY when the remainder does not start
/// with '\n' — the one non-progressing case. When the remainder
/// starts with '\n', Go terminates (empty piece + newline strip)
/// and the port reproduces its trace exactly.
pub(crate) fn split_text_limit(text: &str, limit: usize) -> Vec<String> {
    if limit == 0 {
        return vec![text.to_string()];
    }
    let mut r: Vec<char> = text.chars().collect();
    let mut pieces: Vec<String> = Vec::new();
    while r.len() > limit {
        // `None` when no break was found (Go `rfindRunes`
        // returns -1); below the `limit / 3` threshold the next
        // fallback runs, exactly as in Go. All comparisons are
        // in `usize`: no `isize` cast, so no wrapping for huge
        // limits (see safety finding S1).
        let threshold = limit / 3;
        let cut = rfind_runes(&r, &['\n', '\n'], limit)
            .filter(|&c| c >= threshold)
            .or_else(|| rfind_runes(&r, &['\n'], limit).filter(|&c| c >= threshold))
            .or_else(|| rfind_runes(&r, &[' '], limit).filter(|&c| c >= threshold))
            .unwrap_or(limit);
        let cut = if cut == 0 && r.first() != Some(&'\n') {
            // Go accepts cut == 0 when limit/3 == 0 and then
            // loops forever on a space/letter-led remainder
            // (empty piece, same remainder: the newline strip
            // is identity). Force the hard cut only in that
            // non-progressing case; a '\n'-led remainder
            // progresses in Go and keeps Go's empty-piece
            // trace here (cut == 0 is only accepted by Go
            // when limit < 3).
            limit
        } else {
            cut
        };
        let piece: String = r[..cut].iter().collect();
        pieces.push(piece.trim_end_matches(char::is_whitespace).to_string());
        let rest = &r[cut..];
        let stripped = rest.iter().position(|&c| c != '\n').unwrap_or(rest.len());
        r = rest[stripped..].to_vec();
    }
    let rest: String = r.iter().collect();
    if !rest.trim().is_empty() || pieces.is_empty() {
        pieces.push(rest);
    }
    // Fence carry: count MARKERS in each carry-prepended piece, not
    // complete pairs. An odd count closes the piece and carries the
    // last marker's language into the next piece.
    let mut fixed: Vec<String> = Vec::new();
    let mut carry: Option<String> = None;
    for mut p in pieces {
        if let Some(lang) = carry.take() {
            p = format!("```{lang}\n{p}");
        }
        let fences: Vec<_> = fence_marker_re().captures_iter(&p).collect();
        if fences.len() % 2 == 1 {
            let lang = fences[fences.len() - 1]
                .get(1)
                .map_or("", |g| g.as_str())
                .to_string();
            carry = Some(lang);
            p.push_str("\n```");
        }
        fixed.push(p);
    }
    fixed
}

/// Last match of `needle` fully inside `r[..limit]`, or `None`.
/// Mirrors Go `rfindRunes` (`text.go:208`), with absence as
/// `None` instead of Go's -1 sentinel.
fn rfind_runes(r: &[char], needle: &[char], limit: usize) -> Option<usize> {
    if needle.is_empty() || limit < needle.len() {
        return None;
    }
    let end = limit.min(r.len());
    if end < needle.len() {
        return None;
    }
    let mut i = end - needle.len();
    loop {
        if r[i..i + needle.len()] == *needle {
            return Some(i);
        }
        if i == 0 {
            return None;
        }
        i -= 1;
    }
}

/// Longest fenced code-block body in chars (complete pairs only).
/// Source: `internal/telegram/text.go:241`.
pub fn longest_code_block(text: &str) -> usize {
    let mut longest = 0usize;
    for caps in fence_match_re().captures_iter(text) {
        let body = caps.get(2).map_or("", |g| g.as_str());
        let n = body.chars().count();
        if n > longest {
            longest = n;
        }
    }
    longest
}

/// Whether a reply reads better as an attached file.
/// Source: `internal/telegram/text.go:254`.
pub fn needs_document(text: &str) -> bool {
    text.chars().count() > 3 * CHUNK_SIZE || longest_code_block(text) > 3000
}

/// Truncates a button label to 64 chars.
/// Source: `internal/telegram/text.go:260`.
pub fn button_text(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() > 64 {
        chars[..64].iter().collect()
    } else {
        text.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ported from internal/telegram/text_test.go (7 test fns, 20
    // assertions). Expected values are copied verbatim from the Go
    // test file, never re-derived from the Rust code.
    //
    // D6 note: the Go original has ZERO direct test cases for
    // `escape_text`, `longest_code_block`, `inline_html` and
    // `apply_bold`. They are ported with 0 direct cases; they are
    // pinned only indirectly through the `md_to_html` /
    // `needs_document` cases below. No new cases were invented.

    #[test]
    fn test_split_text() {
        // TestSplitText: SplitText("") -> [""].
        let got = split_text("");
        assert_eq!(got.len(), 1, "SplitText(\"\") piece count");
        assert_eq!(got[0], "", "SplitText(\"\") piece 0");
        // TestSplitText: SplitText("hello") -> ["hello"].
        let got = split_text("hello");
        assert_eq!(got.len(), 1, "SplitText(hello) piece count");
        assert_eq!(got[0], "hello", "SplitText(hello) piece 0");
        // No break at all: hard cut at the chunk limit.
        let long = "a".repeat(CHUNK_SIZE + 1);
        let got = split_text(&long);
        assert_eq!(got.len(), 2, "SplitText(3801 a's) piece count");
        assert_eq!(
            got[0],
            "a".repeat(CHUNK_SIZE),
            "SplitText(3801 a's) piece 0"
        );
        assert_eq!(got[1], "a", "SplitText(3801 a's) piece 1");
        // Paragraph break preferred over line/word breaks.
        let text = "a".repeat(2000) + "\n\n" + &"b".repeat(2000);
        let got = split_text(&text);
        assert_eq!(got.len(), 2, "SplitText(paragraph) piece count");
        assert_eq!(got[0], "a".repeat(2000), "SplitText(paragraph) piece 0");
        assert_eq!(got[1], "b".repeat(2000), "SplitText(paragraph) piece 1");
    }

    #[test]
    fn test_split_text_small_limit() {
        // TestSplitTextSmallLimit: hand trace, limit 10. Piece 3
        // keeps its leading space (only '\n' stripped on the left).
        let got = split_text_limit("AAA\n\nBBB CCC DDD EEE", 10);
        let want = ["AAA", "BBB CCC", " DDD EEE"];
        assert_eq!(
            got.len(),
            want.len(),
            "split_text_limit = {got:?}; want {want:?}"
        );
        for (i, w) in want.iter().enumerate() {
            assert_eq!(got[i], *w, "piece {i}");
        }
    }

    #[test]
    fn test_split_text_fence_carry() {
        // TestSplitTextFenceCarry: 3 cases, marker counting.
        struct Case {
            name: &'static str,
            text: String,
            limit: usize,
            want: Vec<String>,
        }
        let cases = [
            Case {
                name: "complete block in one piece carries nothing",
                text: "```a\nXX\n```\nYYYYYYYYYY".to_string(),
                limit: 14,
                want: vec!["```a\nXX\n```".to_string(), "YYYYYYYYYY".to_string()],
            },
            Case {
                name: "mid-fence cut carries the language",
                text: "```go\n".to_string() + &"x".repeat(20),
                limit: 14,
                want: vec![
                    "```go\n```".to_string(),
                    "```go\n".to_string() + &"x".repeat(14) + "\n```",
                    "```go\n".to_string() + &"x".repeat(6) + "\n```",
                ],
            },
            Case {
                name: "language carry survives across pieces",
                text: "a\n```py\n".to_string() + &"b".repeat(30),
                limit: 14,
                want: vec![
                    "a\n```py\n```".to_string(),
                    "```py\n".to_string() + &"b".repeat(14) + "\n```",
                    "```py\n".to_string() + &"b".repeat(14) + "\n```",
                    "```py\n".to_string() + &"b".repeat(2) + "\n```",
                ],
            },
        ];
        for tc in cases {
            let got = split_text_limit(&tc.text, tc.limit);
            assert_eq!(
                got.len(),
                tc.want.len(),
                "case {}: split_text_limit = {got:?}; want {:?}",
                tc.name,
                tc.want
            );
            for (i, w) in tc.want.iter().enumerate() {
                assert_eq!(got[i], *w, "case {}: piece {i}", tc.name);
            }
        }
    }

    #[test]
    fn test_md_to_html() {
        // TestMDToHTML, assertion 1.
        let got = md_to_html("**bold** and `code` and [link](https://example.com/x) and <tag>");
        let want = "<b>bold</b> and <code>code</code> and <a href=\"https://example.com/x\">link</a> and &lt;tag&gt;";
        assert_eq!(got, want, "MDToHTML basic");
        // Assertion 2: fence.
        let got = md_to_html("```go\nx < y\n```");
        let want = "<pre><code class=\"language-go\">x &lt; y</code></pre>";
        assert_eq!(got, want, "MDToHTML fence");
        // Assertion 3: heading.
        let got = md_to_html("# Title\nbody");
        assert_eq!(got, "<b>Title</b>\nbody", "MDToHTML heading");
        // Assertion 4: WEAK pin, kept weak on purpose — the Go test
        // asserts only that the fence text is preserved.
        let got = md_to_html("```go\nunclosed");
        assert!(
            got.contains("```go"),
            "MDToHTML(unclosed fence) = {got:?}; want the fence text preserved"
        );
    }

    #[test]
    fn test_strip_tags() {
        // TestStripTags.
        assert_eq!(strip_tags("<b>hi</b> &amp; bye"), "hi & bye");
        assert_eq!(strip_tags("plain"), "plain");
    }

    #[test]
    fn test_button_text() {
        // TestButtonText.
        let long = "x".repeat(70);
        assert_eq!(
            button_text(&long).chars().count(),
            64,
            "ButtonText(70) rune count"
        );
        assert_eq!(button_text("ok"), "ok");
    }

    #[test]
    fn test_needs_document() {
        // TestNeedsDocument.
        assert!(!needs_document("short"), "NeedsDocument(short)");
        assert!(
            needs_document(&"a".repeat(3 * CHUNK_SIZE + 1)),
            "NeedsDocument(3*CHUNK+1)"
        );
        assert!(
            needs_document(&("```\n".to_string() + &"c".repeat(3001) + "```")),
            "NeedsDocument(code block 3001)"
        );
        assert!(
            !needs_document(&("```\n".to_string() + &"c".repeat(3000) + "```")),
            "NeedsDocument(code block 3000)"
        );
    }

    // FIX-LOOP REGRESSION (Round 1 finding F2; not a ported
    // case): at limit 2, Go accepts cut == 0 and progresses
    // when the remainder starts with '\n' (empty piece +
    // newline strip). The cut-at-zero guard must fire only
    // when the remainder does NOT start with '\n'.
    #[test]
    fn regression_f2_split_limit2_newline_led() {
        assert_eq!(
            split_text_limit("\nABC", 2),
            vec!["".to_string(), "AB".to_string(), "C".to_string()]
        );
        assert_eq!(
            split_text_limit("\nABCDEF", 2),
            vec![
                "".to_string(),
                "AB".to_string(),
                "CD".to_string(),
                "EF".to_string()
            ]
        );
        // Limit-0 guard unchanged: whole text, one piece.
        assert_eq!(split_text_limit("abc", 0), vec!["abc".to_string()]);
        // Space-led remainder: the documented deviation — Go
        // hangs here, the port forces the hard cut and
        // terminates.
        assert_eq!(
            split_text_limit(" aaaa", 2),
            vec![" a".to_string(), "aa".to_string(), "a".to_string()]
        );
    }

    // FIX-LOOP REGRESSION (Round 1 safety finding S1; not a
    // ported case): a limit of `usize::MAX` must terminate
    // (whole text, one piece) instead of wrapping through
    // `isize` and panicking on an out-of-bounds cut.
    #[test]
    fn regression_s1_usize_max_limit_terminates() {
        assert_eq!(split_text_limit("abc", usize::MAX), vec!["abc".to_string()]);
    }
}
