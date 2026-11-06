"""Generate rust/castctl-cli/src/chat_texts.rs on cue.

Extracts byte-exact from Go source (no retyping):
- internal/commands/chat.go: chatHelpText (a raw string
  with a ` + "..." + ` interpolation for the
  `castctl auth export` backticks).
- internal/deliver/authexport.go: ExportGuidance (a raw
  string).
Emits both as Rust `pub const` raw strings. Fails if
either text contains `"#` (which would break the raw
string delimiter).
"""
import re

ROOT = "/tmp/m7b-rb-castctl"
CHAT_GO = ROOT + "/internal/commands/chat.go"
AUTH_GO = ROOT + "/internal/deliver/authexport.go"
DST = ROOT + "/rust/castctl-cli/src/chat_texts.rs"


def extract_raw(src, start_marker):
    """The backtick raw string starting at start_marker
    (the opening backtick itself), honouring Go's
    ` + "..." + ` interpolation (the quoted part is a
    Go interpreted string — unescape it)."""
    i = src.index(start_marker) + len(start_marker) - 1
    assert src[i] == "`", "expected opening backtick"
    out = []
    j = i + 1
    n = len(src)
    while j < n:
        c = src[j]
        if c == "`":
            # End, unless followed by ` + "..." + `.
            rest = src[j + 1:]
            m = re.match(r" \+ \"((?:[^\"\\]|\\.)*)\" \+ `", rest)
            if m:
                out.append(unescape_go(m.group(1)))
                j = j + 1 + m.end()
                continue
            return "".join(out)
        out.append(c)
        j += 1
    raise AssertionError("unterminated raw string")


def unescape_go(s):
    out = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            nxt = s[i + 1]
            mapping = {"n": "\n", "r": "\r", "t": "\t", "\\": "\\", '"': '"', "`": "`"}
            if nxt in mapping:
                out.append(mapping[nxt])
                i += 2
                continue
        out.append(c)
        i += 1
    return "".join(out)


chat_src = open(CHAT_GO).read()
auth_src = open(AUTH_GO).read()

help_text = extract_raw(chat_src, "chatHelpText    = `")
guidance = extract_raw(auth_src, "const ExportGuidance = `")
for name, text in [("CHAT_HELP_TEXT", help_text), ("EXPORT_GUIDANCE", guidance)]:
    assert '"#' not in text, "%s contains \"# — raw string delimiter breaks" % name
    assert text, "%s is empty" % name

out = """// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! User-facing chat texts, GENERATED from Go source — do
//! not hand-edit. Regenerate with
//! `python3 rust/parity/gen_chat_texts.py` (it extracts
//! the constants byte-exact from `internal/commands/chat.go`
//! (`chatHelpText`) and `internal/deliver/authexport.go`
//! (`ExportGuidance`)).

/// The `/help` text (`chat.go` `chatHelpText`).
pub const CHAT_HELP_TEXT: &str = r#\"%s\"#;

/// The `/login` + startup-auth guidance
/// (`deliver/authexport.go` `ExportGuidance`).
pub const EXPORT_GUIDANCE: &str = r#\"%s\"#;
""" % (
    help_text,
    guidance,
)
open(DST, "w").write(out)
print("wrote %s (%d bytes)" % (DST, len(out)))
print("CHAT_HELP_TEXT bytes=%d EXPORT_GUIDANCE bytes=%d" % (len(help_text), len(guidance)))
