//! Telegram file-kind and doc-name logic, ported from Go.
//!
//! Source: `internal/telegram/files.go` at `origin/main` `1396697`,
//! pure part only. `SendFile` / `sendFileKind` (Bot + HTTP) are out
//! of scope for M1; see `rust/PORTING.md` for the exclusion reasons.

use regex::Regex;
use std::sync::OnceLock;

/// Largest file the bot sends: 49 MiB.
/// Source: `internal/telegram/files.go:36`.
pub const UPLOAD_LIMIT: i64 = 49 << 20;

/// Largest file `sendPhoto` accepts: 10 MiB.
/// Source: `internal/telegram/files.go:41`.
pub const PHOTO_LIMIT: i64 = 10 << 20;

/// How Telegram should receive a file: the `send*` method.
/// Source: `internal/telegram/files.go:51`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileKind {
    /// `sendDocument`.
    Document,
    /// `sendPhoto`.
    Photo,
    /// `sendVideo`.
    Video,
    /// `sendAudio`.
    Audio,
}

impl FileKind {
    /// The Go string value (`"document"` / `"photo"` / `"video"` /
    /// `"audio"`).
    /// Source: `internal/telegram/files.go:55-61`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            FileKind::Document => "document",
            FileKind::Photo => "photo",
            FileKind::Video => "video",
            FileKind::Audio => "audio",
        }
    }
}

impl std::fmt::Display for FileKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Go `strings.ToLower`: simple per-rune case folding (no
/// context-sensitive mappings: `İ` folds to `i`, `ΣΣ` to `σσ`).
/// Rust `str::to_lowercase` would expand `İ` to `i` + combining
/// dot and apply final-sigma rules; taking only the first char of
/// each char's simple lowercase mapping reproduces Go here.
fn go_lower(s: &str) -> String {
    s.chars().flat_map(|c| c.to_lowercase().next()).collect()
}

/// Reports how Telegram should receive a file named `name` with
/// the given `mime` and `size`. Size `< 0` means unknown;
/// size `== 0` is a real empty file.
/// Source: `internal/telegram/files.go:76`.
pub fn file_kind_for(name: &str, mime: &str, size: i64) -> FileKind {
    let ext = file_extension(name);
    let m = go_lower(mime);
    if m == "image/jpeg"
        || m == "image/png"
        || m == "image/webp"
        || (m.is_empty() && (ext == ".jpg" || ext == ".jpeg" || ext == ".png" || ext == ".webp"))
    {
        if size < 0 || size <= PHOTO_LIMIT {
            return FileKind::Photo;
        }
        return FileKind::Document;
    }
    if m.starts_with("video/")
        || (m.is_empty() && (ext == ".mp4" || ext == ".mov" || ext == ".m4v"))
    {
        return FileKind::Video;
    }
    if m.starts_with("audio/")
        || (m.is_empty()
            && (ext == ".mp3"
                || ext == ".m4a"
                || ext == ".ogg"
                || ext == ".oga"
                || ext == ".wav"
                || ext == ".flac"))
    {
        return FileKind::Audio;
    }
    FileKind::Document
}

/// Returns the extension of `name` (last dot of the final path
/// element, including the dot), lowercased.
///
/// Deliberate deviation from the unexported Go helper's
/// precondition, per decision D8: Go's `fileExtension`
/// (`internal/telegram/files.go:101`, doc "lowercased by the
/// caller") relies on `FileKindFor` lowercasing the name first
/// (`files.go:77`). The Rust public function folds that
/// call-site lowercasing in, so `file_extension("PIC.PNG")` is
/// `".png"` when called directly.
pub fn file_extension(name: &str) -> String {
    let name = go_lower(name);
    let tail = match name.rfind('/') {
        Some(i) => &name[i + 1..],
        None => &name[..],
    };
    let i = match tail.rfind('.') {
        Some(i) => i,
        None => return String::new(),
    };
    if i == 0 {
        return String::new();
    }
    if tail[..i].trim_start_matches('.').is_empty() {
        return String::new();
    }
    tail[i..].to_string()
}

/// Builds the attached-reply file name from `stem` and `text`.
/// Source: `internal/telegram/files.go:125`.
pub fn doc_name(stem: &str, text: &str) -> String {
    let ext = if text.contains("```") || doc_name_markdown_re().is_match(text) {
        ".md"
    } else {
        ".txt"
    };
    let name = doc_name_sanitize_re().replace_all(stem, "-");
    let name = name.trim_matches('-');
    let capped: String = name.chars().take(40).collect();
    format!("{capped}{ext}")
}

fn doc_name_sanitize_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[^A-Za-z0-9._-]+").expect("docNameSanitizeRe"))
}

fn doc_name_markdown_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)^#{1,6} |\*\*").expect("docNameMarkdownRe"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ported from internal/telegram/files_test.go: TestFileKindFor
    // (37 cases) and TestDocName (13 cases), literals copied
    // verbatim. The 8 SendFile API test fns in that file are
    // excluded: they drive Bot.SendFile against a fake Telegram
    // HTTP server (Go-only); the reasons are recorded in
    // rust/PORTING.md and in the crate docs.

    #[test]
    fn test_file_kind_for() {
        struct Case {
            name: &'static str,
            file: &'static str,
            mime: &'static str,
            size: i64,
            want: FileKind,
        }
        let photo_limit: i64 = 10 << 20;
        let cases = [
            Case {
                name: "jpeg mime under limit",
                file: "pic.bin",
                mime: "image/jpeg",
                size: 100,
                want: FileKind::Photo,
            },
            Case {
                name: "png mime at limit",
                file: "pic.bin",
                mime: "image/png",
                size: photo_limit,
                want: FileKind::Photo,
            },
            Case {
                name: "webp mime",
                file: "pic.bin",
                mime: "image/webp",
                size: 100,
                want: FileKind::Photo,
            },
            Case {
                name: "png extension no mime",
                file: "pic.png",
                mime: "",
                size: 100,
                want: FileKind::Photo,
            },
            Case {
                name: "jpg extension no mime",
                file: "pic.jpg",
                mime: "",
                size: 100,
                want: FileKind::Photo,
            },
            Case {
                name: "jpeg extension no mime",
                file: "pic.jpeg",
                mime: "",
                size: 100,
                want: FileKind::Photo,
            },
            Case {
                name: "webp extension no mime",
                file: "pic.webp",
                mime: "",
                size: 100,
                want: FileKind::Photo,
            },
            Case {
                name: "uppercase mime",
                file: "pic.bin",
                mime: "IMAGE/JPEG",
                size: 100,
                want: FileKind::Photo,
            },
            Case {
                name: "uppercase extension",
                file: "PIC.PNG",
                mime: "",
                size: 100,
                want: FileKind::Photo,
            },
            Case {
                name: "unknown size photo eligible",
                file: "pic.jpg",
                mime: "",
                size: -1,
                want: FileKind::Photo,
            },
            Case {
                name: "empty file photo",
                file: "pic.jpg",
                mime: "",
                size: 0,
                want: FileKind::Photo,
            },
            Case {
                name: "photo over limit becomes document",
                file: "pic.jpg",
                mime: "",
                size: photo_limit + 1,
                want: FileKind::Document,
            },
            Case {
                name: "photo mime over limit becomes document",
                file: "pic.bin",
                mime: "image/jpeg",
                size: photo_limit + 1,
                want: FileKind::Document,
            },
            Case {
                name: "gif mime with png name is document",
                file: "pic.png",
                mime: "image/gif",
                size: 100,
                want: FileKind::Document,
            },
            Case {
                name: "video mime",
                file: "clip.bin",
                mime: "video/mp4",
                size: 100,
                want: FileKind::Video,
            },
            Case {
                name: "video mime over photo limit stays video",
                file: "clip.bin",
                mime: "video/mp4",
                size: photo_limit + 1,
                want: FileKind::Video,
            },
            Case {
                name: "video extension no mime",
                file: "clip.mov",
                mime: "",
                size: 100,
                want: FileKind::Video,
            },
            Case {
                name: "m4v extension no mime",
                file: "clip.m4v",
                mime: "",
                size: 100,
                want: FileKind::Video,
            },
            Case {
                name: "video mime beats png extension",
                file: "clip.png",
                mime: "video/mp4",
                size: 100,
                want: FileKind::Video,
            },
            Case {
                name: "audio mime",
                file: "song.bin",
                mime: "audio/mpeg",
                size: 100,
                want: FileKind::Audio,
            },
            Case {
                name: "audio mime over photo limit stays audio",
                file: "song.bin",
                mime: "audio/mpeg",
                size: photo_limit + 1,
                want: FileKind::Audio,
            },
            Case {
                name: "audio extension no mime",
                file: "song.flac",
                mime: "",
                size: 100,
                want: FileKind::Audio,
            },
            Case {
                name: "ogg extension no mime",
                file: "song.ogg",
                mime: "",
                size: 100,
                want: FileKind::Audio,
            },
            Case {
                name: "oga extension no mime",
                file: "song.oga",
                mime: "",
                size: 100,
                want: FileKind::Audio,
            },
            Case {
                name: "wav extension no mime",
                file: "song.wav",
                mime: "",
                size: 100,
                want: FileKind::Audio,
            },
            Case {
                name: "m4a extension no mime",
                file: "song.m4a",
                mime: "",
                size: 100,
                want: FileKind::Audio,
            },
            Case {
                name: "unknown extension",
                file: "data.bin",
                mime: "",
                size: 100,
                want: FileKind::Document,
            },
            Case {
                name: "unknown mime",
                file: "data.bin",
                mime: "application/octet-stream",
                size: 100,
                want: FileKind::Document,
            },
            Case {
                name: "no extension no mime",
                file: "README",
                mime: "",
                size: 100,
                want: FileKind::Document,
            },
            Case {
                name: "double extension uses last",
                file: "archive.tar.gz",
                mime: "",
                size: 100,
                want: FileKind::Document,
            },
            Case {
                name: "leading dot file has no extension",
                file: ".hidden",
                mime: "",
                size: 100,
                want: FileKind::Document,
            },
            Case {
                name: "all dots before last dot is no extension",
                file: "..png",
                mime: "",
                size: 100,
                want: FileKind::Document,
            },
            Case {
                name: "three leading dots is no extension",
                file: "...png",
                mime: "",
                size: 100,
                want: FileKind::Document,
            },
            Case {
                name: "dots then name before last dot has extension",
                file: "..a.png",
                mime: "",
                size: 100,
                want: FileKind::Photo,
            },
            Case {
                name: "all dots before last dot jpg is no extension",
                file: "..jpg",
                mime: "",
                size: 100,
                want: FileKind::Document,
            },
            Case {
                name: "trailing dot",
                file: "file.",
                mime: "",
                size: 100,
                want: FileKind::Document,
            },
            Case {
                name: "path prefix ignored for extension",
                file: "dir/sub/pic.jpg",
                mime: "",
                size: 100,
                want: FileKind::Photo,
            },
        ];
        assert_eq!(cases.len(), 37, "ported case count");
        for tc in cases {
            let got = file_kind_for(tc.file, tc.mime, tc.size);
            assert_eq!(
                got, tc.want,
                "case {}: file_kind_for({:?}, {:?}, {}) = {:?}; want {:?}",
                tc.name, tc.file, tc.mime, tc.size, got, tc.want
            );
        }
    }

    #[test]
    fn test_doc_name() {
        struct Case {
            name: &'static str,
            stem: String,
            text: &'static str,
            want: String,
        }
        let cases = [
            Case {
                name: "plain text",
                stem: "muse-reply".to_string(),
                text: "hello world",
                want: "muse-reply.txt".to_string(),
            },
            Case {
                name: "fenced code is markdown",
                stem: "muse-reply".to_string(),
                text: "see:\n```go\nx\n```",
                want: "muse-reply.md".to_string(),
            },
            Case {
                name: "heading is markdown",
                stem: "muse-reply".to_string(),
                text: "# Title\nbody",
                want: "muse-reply.md".to_string(),
            },
            Case {
                name: "heading without space is not",
                stem: "muse-reply".to_string(),
                text: "#Title\nbody",
                want: "muse-reply.txt".to_string(),
            },
            Case {
                name: "bold is markdown",
                stem: "muse-reply".to_string(),
                text: "a **bold** word",
                want: "muse-reply.md".to_string(),
            },
            Case {
                name: "sanitize spaces and slashes",
                stem: "my reply/2".to_string(),
                text: "plain",
                want: "my-reply-2.txt".to_string(),
            },
            Case {
                name: "sanitize collapses runs",
                stem: "a  b!!c".to_string(),
                text: "plain",
                want: "a-b-c.txt".to_string(),
            },
            Case {
                name: "strip leading and trailing dashes",
                stem: "---hi---".to_string(),
                text: "plain",
                want: "hi.txt".to_string(),
            },
            Case {
                name: "strip after sanitize",
                stem: "!!!hi!!!".to_string(),
                text: "plain",
                want: "hi.txt".to_string(),
            },
            Case {
                name: "dots and underscores kept",
                stem: "a.b_c-d".to_string(),
                text: "plain",
                want: "a.b_c-d.txt".to_string(),
            },
            Case {
                name: "cap at 40 runes",
                stem: "x".repeat(50),
                text: "plain",
                want: "x".repeat(40) + ".txt",
            },
            Case {
                name: "cap after strip",
                stem: "!!!".to_string() + &"y".repeat(45),
                text: "plain",
                want: "y".repeat(40) + ".txt",
            },
            Case {
                name: "multibyte stem sanitizes away entirely",
                stem: "é".repeat(50),
                text: "plain",
                want: ".txt".to_string(),
            },
        ];
        assert_eq!(cases.len(), 13, "ported case count");
        for tc in cases {
            let got = doc_name(&tc.stem, tc.text);
            assert_eq!(
                got, tc.want,
                "case {}: doc_name({:?}, {:?}) = {:?}; want {:?}",
                tc.name, tc.stem, tc.text, got, tc.want
            );
        }
    }
}
