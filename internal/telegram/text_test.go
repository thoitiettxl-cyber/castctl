// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package telegram

// Text-formatting tests. Expected values are hand-traced literals
// from the Python implementations cited in text.go (tgapi.py), never
// recomputed from the Go code under test.

import (
	"strings"
	"testing"
)

func TestSplitText(t *testing.T) {
	t.Parallel()
	if got := SplitText(""); len(got) != 1 || got[0] != "" {
		t.Errorf("SplitText(%q) = %q; want [\"\"]", "", got)
	}
	if got := SplitText("hello"); len(got) != 1 || got[0] != "hello" {
		t.Errorf("SplitText(hello) = %q; want [hello]", got)
	}
	// No break at all: hard cut at the chunk limit.
	long := strings.Repeat("a", ChunkSize+1)
	got := SplitText(long)
	if len(got) != 2 || got[0] != strings.Repeat("a", ChunkSize) || got[1] != "a" {
		t.Errorf("SplitText(%d a's) = %d pieces lens %d/%d; want 3800/1", len(long), len(got), len(got[0]), len(got[1]))
	}
	// Paragraph break preferred over line/word breaks (hand trace in
	// text.go: cut at the "\n\n" at index 2000).
	text := strings.Repeat("a", 2000) + "\n\n" + strings.Repeat("b", 2000)
	got = SplitText(text)
	if len(got) != 2 || got[0] != strings.Repeat("a", 2000) || got[1] != strings.Repeat("b", 2000) {
		t.Errorf("SplitText(paragraph) = %d pieces; want [a*2000 b*2000]", len(got))
	}
}

func TestSplitTextSmallLimit(t *testing.T) {
	t.Parallel()
	// Hand trace, limit 10, text "AAA\n\nBBB CCC DDD EEE":
	// cut 3 ("\n\n") -> "AAA"; cut 7 (space) -> "BBB CCC";
	// remainder " DDD EEE" (leading space kept: only "\n" is
	// stripped from the left, as in Python's lstrip("\n")).
	got := splitTextLimit("AAA\n\nBBB CCC DDD EEE", 10)
	want := []string{"AAA", "BBB CCC", " DDD EEE"}
	if len(got) != len(want) {
		t.Fatalf("splitTextLimit = %q; want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("piece %d = %q; want %q", i, got[i], want[i])
		}
	}
}

func TestSplitTextFenceCarry(t *testing.T) {
	t.Parallel()
	// Python's fence fix (split_text, tgapi.py:219-247) counts
	// fence MARKERS in a piece: fences =
	// re.findall(r"```([A-Za-z0-9_+.-]*)", p); if len(fences) % 2:
	// carry = fences[-1]. It never uses _FENCE_RE (the pair
	// regex). So a piece holding a complete block (2 markers)
	// carries nothing, and a piece cut mid-fence (1 marker)
	// carries the last marker's language. Expected values were
	// re-derived by executing Python's exact algorithm.
	cases := []struct {
		name  string
		text  string
		limit int
		want  []string
	}{
		{
			name:  "complete block in one piece carries nothing",
			text:  "```a\nXX\n```\nYYYYYYYYYY",
			limit: 14,
			want:  []string{"```a\nXX\n```", "YYYYYYYYYY"},
		},
		{
			name:  "mid-fence cut carries the language",
			text:  "```go\n" + strings.Repeat("x", 20),
			limit: 14,
			want:  []string{"```go\n```", "```go\n" + strings.Repeat("x", 14) + "\n```", "```go\n" + strings.Repeat("x", 6) + "\n```"},
		},
		{
			name:  "language carry survives across pieces",
			text:  "a\n```py\n" + strings.Repeat("b", 30),
			limit: 14,
			want: []string{"a\n```py\n```",
				"```py\n" + strings.Repeat("b", 14) + "\n```",
				"```py\n" + strings.Repeat("b", 14) + "\n```",
				"```py\n" + strings.Repeat("b", 2) + "\n```"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := splitTextLimit(tc.text, tc.limit)
			if len(got) != len(tc.want) {
				t.Fatalf("splitTextLimit = %q; want %q", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("piece %d = %q; want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestMDToHTML(t *testing.T) {
	t.Parallel()
	got := MDToHTML("**bold** and `code` and [link](https://example.com/x) and <tag>")
	want := `<b>bold</b> and <code>code</code> and <a href="https://example.com/x">link</a> and &lt;tag&gt;`
	if got != want {
		t.Errorf("MDToHTML = %q; want %q", got, want)
	}
	got = MDToHTML("```go\nx < y\n```")
	want = `<pre><code class="language-go">x &lt; y</code></pre>`
	if got != want {
		t.Errorf("MDToHTML(fence) = %q; want %q", got, want)
	}
	got = MDToHTML("# Title\nbody")
	want = "<b>Title</b>\nbody"
	if got != want {
		t.Errorf("MDToHTML(heading) = %q; want %q", got, want)
	}
	// Unclosed fence: no fence match, the backticks are escaped as
	// plain text (the caller falls back to plain text on parse
	// error; the converter itself never invents a closing fence).
	got = MDToHTML("```go\nunclosed")
	if !strings.Contains(got, "```go") {
		t.Errorf("MDToHTML(unclosed fence) = %q; want the fence text preserved", got)
	}
}

func TestStripTags(t *testing.T) {
	t.Parallel()
	if got := StripTags("<b>hi</b> &amp; bye"); got != "hi & bye" {
		t.Errorf("StripTags = %q; want %q", got, "hi & bye")
	}
	if got := StripTags("plain"); got != "plain" {
		t.Errorf("StripTags(plain) = %q; want plain", got)
	}
}

func TestButtonText(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("x", 70)
	if got := ButtonText(long); len([]rune(got)) != 64 {
		t.Errorf("ButtonText(70) has %d runes; want 64", len([]rune(got)))
	}
	if got := ButtonText("ok"); got != "ok" {
		t.Errorf("ButtonText(ok) = %q; want ok", got)
	}
}

func TestNeedsDocument(t *testing.T) {
	t.Parallel()
	if NeedsDocument("short") {
		t.Error("NeedsDocument(short) = true; want false")
	}
	if !NeedsDocument(strings.Repeat("a", 3*ChunkSize+1)) {
		t.Error("NeedsDocument(3*CHUNK+1) = false; want true")
	}
	if !NeedsDocument("```\n" + strings.Repeat("c", 3001) + "```") {
		t.Error("NeedsDocument(code block 3001) = false; want true")
	}
	if NeedsDocument("```\n" + strings.Repeat("c", 3000) + "```") {
		t.Error("NeedsDocument(code block 3000) = true; want false")
	}
}
