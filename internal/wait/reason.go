// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package wait

import (
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// waitPhrases is the complete waiting-phrase vocabulary from
// wait.py, in list order: 21 Vietnamese + 13 English = 34. Order
// decides which phrase is named in the returned reason when
// several match; the outcome is the same regardless. Matching is
// substring on the cleaned, lower-cased text, with no word
// boundaries.
//
// The vocabulary is unexported mutable state: no caller outside
// this package may rewrite it. WaitPhrases returns a copy.
var waitPhrases = []string{
	"chờ boss",
	"chờ bạn",
	"tôi chờ",
	"mình chờ",
	"đợi boss",
	"đợi bạn",
	"boss muốn",
	"bạn muốn",
	"boss có muốn",
	"bạn có muốn",
	"trước khi tiếp tục",
	"trước khi làm tiếp",
	"boss xác nhận",
	"bạn xác nhận",
	"cần boss",
	"cần bạn",
	"boss quyết",
	"bạn quyết",
	"hay không?",
	"được không?",
	"nhé?",
	"should i",
	"do you want",
	"would you like",
	"waiting for your",
	"let me know if",
	"let me know whether",
	"please confirm",
	"can you confirm",
	"before i continue",
	"before i proceed",
	"shall i",
	"which do you prefer",
	"your call",
}

// WaitPhrases returns a copy of the waiting-phrase vocabulary,
// in list order. Mutating the returned slice does not affect
// matching.
func WaitPhrases() []string {
	return slices.Clone(waitPhrases)
}

// Safety regex, verbatim from wait.py (case-insensitive).
var safetyRe = regexp.MustCompile(`(?i)(?:safety check|kiểm tra an toàn|cơ chế an toàn|tripped .{0,30}safety|refus(?:e|ed) to (?:run|do|continue)|từ chối (?:chạy|làm))`)

// Gate prefix: the literal "gate"/"policy" + optional
// separator + "question(s)". The whitespace around the ":"/"="
// separator is NOT in the regex: RE2 \s is ASCII-only, while
// Python's \s is Unicode, so gateMatches consumes the separator
// whitespace by hand with unicode.IsSpace (see below). The
// negative lookahead `(?!none\b)` in the Python pattern has no
// RE2 equivalent, so the remainder check is also done by hand;
// the two together are exactly the Python rule.
var gatePrefixRe = regexp.MustCompile(`(?i)(?:gate|policy)[ _-]?questions?`)

// gateMatches implements the Python gate regex
// `(gate|policy)[ _-]?questions?\s*[:=]\s*(?!none\b)\S`.
// For each prefix match, Unicode whitespace is skipped, a ":"
// or "=" separator is required, more Unicode whitespace is
// skipped, and the remainder must start with a non-whitespace
// character that is not the word "none": "gate questions: none"
// and "gate questions: none of these" do not match, while "gate
// questions: nonetheless" does. Unicode spaces count as \s on
// both sides of the separator: "gate questions:\u00a0none" and
// "gate questions:\vnone" do not match, exactly as in Python,
// where \s* consumes the space and \S then fails.
func gateMatches(t string) bool {
	for _, loc := range gatePrefixRe.FindAllStringIndex(t, -1) {
		rest := t[loc[1]:]
		i := 0
		for i < len(rest) {
			r, size := utf8.DecodeRuneInString(rest[i:])
			if !unicode.IsSpace(r) {
				break
			}
			i += size
		}
		if i >= len(rest) || (rest[i] != ':' && rest[i] != '=') {
			continue
		}
		i++
		for i < len(rest) {
			r, size := utf8.DecodeRuneInString(rest[i:])
			if !unicode.IsSpace(r) {
				break
			}
			i += size
		}
		if i >= len(rest) {
			continue
		}
		if startsWithNoneWord(rest[i:]) {
			continue
		}
		return true
	}
	return false
}

// startsWithNoneWord reports whether s starts with "none"
// followed by a word boundary (end of string or a non-word
// rune), case-insensitively.
func startsWithNoneWord(s string) bool {
	lower := strings.ToLower(s)
	if !strings.HasPrefix(lower, "none") {
		return false
	}
	rest := []rune(lower[4:])
	if len(rest) == 0 {
		return true
	}
	r := rest[0]
	return !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_')
}

// NeedsInputReason classifies the last reply's text, or returns
// "" when the reply does not ask for input. Precedence, first
// match wins: gate/policy regex, safety regex, waiting phrases
// in list order, trailing question mark. Only the last reply's
// text is ever examined, and only via OutcomeOf. Empty or
// whitespace-only text yields "".
func NeedsInputReason(text string) string {
	t := CleanText(text)
	if t == "" {
		return ""
	}
	if gateMatches(t) {
		return "gate/policy question"
	}
	if safetyRe.MatchString(t) {
		return "stopped by a safety check"
	}
	low := strings.ToLower(t)
	for _, ph := range waitPhrases {
		if strings.Contains(low, ph) {
			return "waiting phrase: '" + ph + "'"
		}
	}
	tail := lastLine(strings.TrimRight(t, " \n*_`)\"'"))
	if strings.HasSuffix(strings.TrimSpace(tail), "?") || strings.HasSuffix(strings.TrimSpace(tail), "？") {
		return "ends with a question"
	}
	return ""
}

// QuestionOf extracts the question from reply text for display:
// the last two question-bearing sentences (split after
// . / ! / ? / 。 followed by whitespace), or the last line when
// no sentence contains "?", or "" for empty text.
func QuestionOf(text string) string {
	t := CleanText(text)
	if t == "" {
		return ""
	}
	var qs []string
	for _, s := range splitSentences(t) {
		s = strings.TrimSpace(s)
		if strings.Contains(s, "?") {
			qs = append(qs, s)
		}
	}
	if len(qs) > 0 {
		if len(qs) > 2 {
			qs = qs[len(qs)-2:]
		}
		return strings.Join(qs, " ")
	}
	lines := splitLines(t)
	return lines[len(lines)-1]
}

// splitSentences splits after a sentence-ending rune (. ! ? 。)
// followed by a whitespace run, keeping the punctuation with
// the preceding sentence.
func splitSentences(t string) []string {
	var out []string
	runes := []rune(t)
	start := 0
	for i := 0; i < len(runes); i++ {
		if runes[i] != '.' && runes[i] != '!' && runes[i] != '?' && runes[i] != '。' {
			continue
		}
		j := i + 1
		if j < len(runes) && isSpaceRune(runes[j]) {
			for j < len(runes) && isSpaceRune(runes[j]) {
				j++
			}
			out = append(out, string(runes[start:i+1]))
			start = j
			i = j - 1
		}
	}
	out = append(out, string(runes[start:]))
	return out
}

func isSpaceRune(r rune) bool {
	return unicode.IsSpace(r)
}

// splitLines splits like Python's str.splitlines on \n, \r\n and
// \r. A trailing line break does not produce a final empty line,
// but "a\n\n" keeps its empty middle line.
func splitLines(t string) []string {
	t = strings.ReplaceAll(t, "\r\n", "\n")
	t = strings.ReplaceAll(t, "\r", "\n")
	lines := strings.Split(t, "\n")
	if len(lines) > 1 && lines[len(lines)-1] == "" && strings.HasSuffix(t, "\n") {
		lines = lines[:len(lines)-1]
	}
	return lines
}

func lastLine(t string) string {
	lines := splitLines(t)
	return lines[len(lines)-1]
}
