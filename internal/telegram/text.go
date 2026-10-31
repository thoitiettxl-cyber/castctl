// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package telegram

// Message text formatting, mirrored from Python 0.6.1
// (src/muse_cli/tgapi.py). Every function below cites its Python
// source in its doc comment; behaviour is paraphrased, with short
// quoted identifiers only as citation evidence. No Go code is
// ported: this is a fresh implementation of the surveyed
// behaviour. Lengths count runes (Python len() counts code
// points); byte lengths are never used for splitting or limits.

import (
	"fmt"
	"html"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// ChunkSize is what one message carries (room for markup):
// CHUNK = 3800 (src/muse_cli/tgapi.py:17).
const ChunkSize = 3800

// TextLimit is Telegram's hard per-message limit:
// TEXT_LIMIT = 4096 (src/muse_cli/tgapi.py:16).
const TextLimit = 4096

// CaptionLimit caps file captions:
// CAPTION_LIMIT = 1024 (src/muse_cli/tgapi.py:18).
const CaptionLimit = 1024

// EscapeText escapes &, <, > only (quote=False):
// esc (src/muse_cli/tgapi.py:184-185).
func EscapeText(text string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(text)
}

// fenceMatchRe is Python's _FENCE_RE (re.S): ```lang, optional
// newline, non-greedy body, closing ```. It is used ONLY by
// MDToHTML and LongestCodeBlock, which need complete pairs.
// fenceMarkerRe is the marker regex split_text uses
// (re.findall(r"```([A-Za-z0-9_+.-]*)", p)): every marker,
// paired or not, counted, the last marker's language carried.
var fenceMatchRe = regexp.MustCompile("(?s)```([A-Za-z0-9_+.-]*)\\n?(.*?)```")
var fenceMarkerRe = regexp.MustCompile("```([A-Za-z0-9_+.-]*)")

var inlineCodeRe = regexp.MustCompile("`([^`\n]+)`")
var linkRe = regexp.MustCompile(`\[([^\]\n]+)\]\((https?://[^\s)]+)\)`)
var headingRe = regexp.MustCompile(`(?m)^(#{1,6}) +(.+)$`)
var stashRe = regexp.MustCompile("\x00(\\d+)\x00")
var tagRe = regexp.MustCompile(`<[^>]+>`)

// MDToHTML converts Muse's Markdown to Telegram HTML: code fences,
// `code`, **bold**, links (src/muse_cli/tgapi.py:188-204,
// md_to_html). Anything else is escaped as plain text, so the
// result always parses unless a fence is cut in half (callers
// fall back to plain text then).
func MDToHTML(text string) string {
	var out strings.Builder
	pos := 0
	for _, loc := range fenceMatchRe.FindAllStringSubmatchIndex(text, -1) {
		out.WriteString(inlineHTML(text[pos:loc[0]]))
		lang := text[loc[2]:loc[3]]
		code := text[loc[4]:loc[5]]
		cls := ""
		if lang != "" {
			cls = ` class="language-` + EscapeText(lang) + `"`
		}
		fmt.Fprintf(&out, "<pre><code%s>%s</code></pre>", cls, EscapeText(strings.TrimRightFunc(code, unicode.IsSpace)))
		pos = loc[1]
	}
	out.WriteString(inlineHTML(text[pos:]))
	return out.String()
}

// inlineHTML is _inline (src/muse_cli/tgapi.py:207-218): inline
// code spans and links are stashed before escaping, bold and
// headings are applied to the escaped text, then the stash is
// restored. Go's regexp has no lookahead/lookbehind, so the bold
// pattern \*\*(?=\S)(.+?)(?<=\S)\*\* is implemented as a manual
// scan with the same edge rules: the char after the opening **
// and the char before the closing ** must both be non-space, and
// the content must not cross a newline.
func inlineHTML(text string) string {
	var stash []string
	keep := func(s string) string {
		stash = append(stash, s)
		return "\x00" + strconv.Itoa(len(stash)-1) + "\x00"
	}
	t := inlineCodeRe.ReplaceAllStringFunc(text, func(m string) string {
		inner := inlineCodeRe.FindStringSubmatch(m)[1]
		return keep("<code>" + EscapeText(inner) + "</code>")
	})
	t = linkRe.ReplaceAllStringFunc(t, func(m string) string {
		parts := linkRe.FindStringSubmatch(m)
		return keep(`<a href="` + html.EscapeString(parts[2]) + `">` + EscapeText(parts[1]) + `</a>`)
	})
	t = EscapeText(t)
	t = applyBold(t)
	t = headingRe.ReplaceAllString(t, "<b>$2</b>")
	return stashRe.ReplaceAllStringFunc(t, func(m string) string {
		i, err := strconv.Atoi(stashRe.FindStringSubmatch(m)[1])
		if err != nil || i < 0 || i >= len(stash) {
			return m
		}
		return stash[i]
	})
}

// applyBold applies **bold** with Python's edge rules (see
// inlineHTML). Unmatched or space-adjacent ** pairs are left
// literal.
func applyBold(t string) string {
	r := []rune(t)
	var out strings.Builder
	i := 0
	for i < len(r) {
		if i+1 < len(r) && r[i] == '*' && r[i+1] == '*' && i+2 < len(r) && !unicode.IsSpace(r[i+2]) {
			// Find a closing ** on the same line whose preceding
			// char is non-space.
			close := -1
			for j := i + 2; j+1 < len(r); j++ {
				if r[j] == '\n' {
					break
				}
				if r[j] == '*' && r[j+1] == '*' && j > i+2 && !unicode.IsSpace(r[j-1]) {
					close = j
					break
				}
			}
			if close > 0 {
				out.WriteString("<b>")
				out.WriteString(string(r[i+2 : close]))
				out.WriteString("</b>")
				i = close + 2
				continue
			}
		}
		out.WriteRune(r[i])
		i++
	}
	return out.String()
}

// StripTags removes HTML tags and unescapes entities:
// _strip_tags (src/muse_cli/tgbot.py:285-287).
func StripTags(text string) string {
	return html.UnescapeString(tagRe.ReplaceAllString(text, ""))
}

// SplitText splits into pieces <= ChunkSize, preferring paragraph,
// then line, then word breaks (src/muse_cli/tgapi.py:219-247,
// split_text). A fenced code block cut by a split is closed and
// reopened in the next piece so each piece renders. The carry
// counts fence MARKERS in the piece (see fenceMarkerRe), not
// complete pairs: a complete block in one piece (2 markers)
// carries nothing; a piece cut mid-fence (1 marker) carries
// the last marker's language.
func SplitText(text string) []string {
	return splitTextLimit(text, ChunkSize)
}

func splitTextLimit(text string, limit int) []string {
	r := []rune(text)
	pieces := []string{}
	for len(r) > limit {
		cut := rfindRunes(r, []rune("\n\n"), limit)
		if cut < limit/3 {
			cut = rfindRunes(r, []rune("\n"), limit)
		}
		if cut < limit/3 {
			cut = rfindRunes(r, []rune(" "), limit)
		}
		if cut < limit/3 {
			cut = limit
		}
		pieces = append(pieces, strings.TrimRightFunc(string(r[:cut]), unicode.IsSpace))
		r = lstripNewlines(r[cut:])
	}
	rest := string(r)
	if strings.TrimSpace(rest) != "" || len(pieces) == 0 {
		pieces = append(pieces, rest)
	}
	fixed := []string{}
	var carry *string
	for _, p := range pieces {
		if carry != nil {
			p = "```" + *carry + "\n" + p
			carry = nil
		}
		fences := fenceMarkerRe.FindAllStringSubmatch(p, -1)
		if len(fences)%2 == 1 {
			lang := fences[len(fences)-1][1]
			carry = &lang
			p = p + "\n```"
		}
		fixed = append(fixed, p)
	}
	return fixed
}

// rfindRunes mirrors str.rfind(sub, 0, limit): the last match fully
// inside r[:limit], or -1.
func rfindRunes(r, needle []rune, limit int) int {
	if len(needle) == 0 || limit < len(needle) {
		return -1
	}
	end := limit
	if end > len(r) {
		end = len(r)
	}
	for i := end - len(needle); i >= 0; i-- {
		match := true
		for j := range needle {
			if r[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func lstripNewlines(r []rune) []rune {
	i := 0
	for i < len(r) && r[i] == '\n' {
		i++
	}
	return r[i:]
}

// LongestCodeBlock returns the longest fenced code block body in
// runes (src/muse_cli/tgapi.py:250-251, longest_code_block).
func LongestCodeBlock(text string) int {
	longest := 0
	for _, m := range fenceMatchRe.FindAllStringSubmatch(text, -1) {
		if n := len([]rune(m[2])); n > longest {
			longest = n
		}
	}
	return longest
}

// NeedsDocument reports whether a reply reads better as an
// attached file: longer than 3 chunks, or a code block over 3000
// chars (src/muse_cli/tgapi.py:253-255, needs_document).
func NeedsDocument(text string) bool {
	return len([]rune(text)) > 3*ChunkSize || LongestCodeBlock(text) > 3000
}

// ButtonText truncates a button label to 64 characters:
// button (src/muse_cli/tgapi.py:258-260).
func ButtonText(text string) string {
	r := []rune(text)
	if len(r) > 64 {
		return string(r[:64])
	}
	return text
}
