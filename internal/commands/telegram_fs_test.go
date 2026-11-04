// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

// PR-E /fs command tests: ls, tree, cat, get, stat, find, mkdir,
// mv, rm (+ the fs_rm button) through the full `telegram run`
// harness (fake Telegram server + scripted fake gateway) and,
// for button taps, through a directly wired Bot. No live network,
// no token, no cookies: /fs uses WithGateway, not rt.Cookies().

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/telegram"
)

const fsGatewayError = "⚠️ Could not run /fs (gateway error)."
const fsFolderSentence = "That is a folder; /fs ls it and get the files one by one."
const fsTooBigSentence = "Too big for Telegram (50 MB)."

// fsEntry builds one fake fs.list/fs.search row.
func fsEntry(name, typ string, size *int64) map[string]any {
	row := map[string]any{"name": name, "type": typ}
	if size != nil {
		row["size"] = *size
	}
	return row
}

func fsSize(n int64) *int64 { return &n }

// sendFS stages one /fs command and requires exactly one reply.
func sendFS(t *testing.T, h *telegramBotHarness, text string) []string {
	t.Helper()
	h.fake.setBatches([]string{telegramUpdate(1, 111, text)})
	return waitForSends(t, h, 1)
}

// waitForDocs stages one /fs command and waits until the fake
// has recorded at least n documents, and returns them. Used
// where the correct behaviour produces a document and no send.
func waitForDocs(t *testing.T, h *telegramBotHarness, text string, n int) []cmdFakeDocument {
	t.Helper()
	h.fake.setBatches([]string{telegramUpdate(1, 111, text)})
	waitFor(t, fmt.Sprintf("%d documents", n), func() bool { return len(h.fake.documentsSeen()) >= n })
	return h.fake.documentsSeen()
}

func TestTelegramFSLs(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.fsListScript = map[string][]any{
		"": {
			fsEntry("notes", "directory", nil),
			fsEntry("a.txt", "file", fsSize(512)),
			fsEntry("big.bin", "file", fsSize(1536)),
			fsEntry("huge.bin", "file", fsSize(1073741824)),
			fsEntry("nosize", "file", nil),
			fsEntry(".secret", "file", fsSize(10)),
		},
	}
	h, cancel := runReadBot(t, gw)
	defer cancel()
	sends := sendFS(t, h, "/fs ls")
	if len(sends) != 1 {
		t.Fatalf("sends = %q; want exactly 1", sends)
	}
	want := "<pre>/\n📁 notes\n📄 a.txt  512B\n📄 big.bin  1.5K\n📄 huge.bin  1.0G\n📄 nosize  -</pre>"
	if sends[0] != want {
		t.Errorf("send = %q; want %q", sends[0], want)
	}
	if calls := gw.fsListCallsSeen(); len(calls) != 1 || calls[0] != "" {
		t.Errorf("fs.list paths = %q; want [\"\"]", calls)
	}
}

func TestTelegramFSLsAll(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.fsListScript = map[string][]any{
		"": {
			fsEntry(".hidden", "file", fsSize(10)),
			fsEntry("visible", "file", fsSize(1)),
		},
	}
	h, cancel := runReadBot(t, gw)
	defer cancel()
	sends := sendFS(t, h, "/fs ls -a")
	if len(sends) != 1 {
		t.Fatalf("sends = %q; want exactly 1", sends)
	}
	want := "<pre>/\n📄 .hidden  10B\n📄 visible  1B</pre>"
	if sends[0] != want {
		t.Errorf("send = %q; want %q", sends[0], want)
	}
	// "-ar" is not "-a": the dot filter stays on.
	h2, cancel2 := runReadBot(t, gw)
	defer cancel2()
	sends = sendFS(t, h2, "/fs ls -ar")
	if len(sends) != 1 {
		t.Fatalf("sends = %q; want exactly 1", sends)
	}
	want = "<pre>/\n📄 visible  1B</pre>"
	if sends[0] != want {
		t.Errorf("send = %q; want %q", sends[0], want)
	}
}

func TestTelegramFSLsEmpty(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.fsListScript = map[string][]any{"docs": {}}
	h, cancel := runReadBot(t, gw)
	defer cancel()
	sends := sendFS(t, h, "/fs ls docs/")
	if len(sends) != 1 {
		t.Fatalf("sends = %q; want exactly 1", sends)
	}
	want := "<pre>/docs\n(empty)</pre>"
	if sends[0] != want {
		t.Errorf("send = %q; want %q", sends[0], want)
	}
	if calls := gw.fsListCallsSeen(); len(calls) != 1 || calls[0] != "docs" {
		t.Errorf("fs.list paths = %q; want [\"docs\"] (trailing slash normalized)", calls)
	}
}

func TestTelegramFSTree(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.fsListScript = map[string][]any{
		"": {
			fsEntry("a", "directory", nil),
			fsEntry("top.txt", "file", fsSize(1)),
		},
		"a": {
			fsEntry("b", "directory", nil),
			fsEntry("a1.txt", "file", fsSize(1)),
		},
		"a/b":     {fsEntry("deep.txt", "file", fsSize(1))},
		".hidden": {fsEntry("x.txt", "file", fsSize(1))},
		"a/.h":    {fsEntry("y.txt", "file", fsSize(1))},
	}
	h, cancel := runReadBot(t, gw)
	defer cancel()

	sends := sendFS(t, h, "/fs tree")
	want := "<pre>/\n  a/\n    b/\n    a1.txt\n  top.txt</pre>"
	if len(sends) != 1 || sends[0] != want {
		t.Fatalf("default-depth sends = %q; want [%q]", sends, want)
	}

	h2, cancel2 := runReadBot(t, gw)
	defer cancel2()
	sends = sendFS(t, h2, "/fs tree a 0")
	want = "<pre>/a\n  b/\n  a1.txt</pre>"
	if len(sends) != 1 || sends[0] != want {
		t.Fatalf("depth-0 sends = %q; want [%q]", sends, want)
	}

	h3, cancel3 := runReadBot(t, gw)
	defer cancel3()
	sends = sendFS(t, h3, "/fs tree a 3")
	want = "<pre>/a\n  b/\n    deep.txt\n  a1.txt</pre>"
	if len(sends) != 1 || sends[0] != want {
		t.Fatalf("depth-3 sends = %q; want [%q]", sends, want)
	}

	// Non-digit depth (incl. Unicode digit) falls back to 2.
	h4, cancel4 := runReadBot(t, gw)
	defer cancel4()
	sends = sendFS(t, h4, "/fs tree a ²")
	want = "<pre>/a\n  b/\n    deep.txt\n  a1.txt</pre>"
	if len(sends) != 1 || sends[0] != want {
		t.Fatalf("non-digit-depth sends = %q; want [%q]", sends, want)
	}

	// "-1" is a flag, so the depth falls back to 2.
	h5, cancel5 := runReadBot(t, gw)
	defer cancel5()
	sends = sendFS(t, h5, "/fs tree a -1")
	if len(sends) != 1 || sends[0] != want {
		t.Fatalf("flag-depth sends = %q; want [%q]", sends, want)
	}
}

func TestTelegramFSTreeDotComponents(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.fsListScript = map[string][]any{
		".hidden": {fsEntry("x.txt", "file", fsSize(1))},
		"a/.h":    {fsEntry("y.txt", "file", fsSize(1))},
	}
	h, cancel := runReadBot(t, gw)
	defer cancel()
	// A dot component in the requested root hides every row,
	// but the header is still emitted.
	sends := sendFS(t, h, "/fs tree .hidden")
	want := "<pre>/.hidden\n</pre>"
	if len(sends) != 1 || sends[0] != want {
		t.Fatalf("sends = %q; want [%q]", sends, want)
	}
	h2, cancel2 := runReadBot(t, gw)
	defer cancel2()
	sends = sendFS(t, h2, "/fs tree a/.h")
	want = "<pre>/a/.h\n</pre>"
	if len(sends) != 1 || sends[0] != want {
		t.Fatalf("sends = %q; want [%q]", sends, want)
	}
}

func TestTelegramFSStat(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.fsStatScript = map[string]map[string]any{
		"a.txt": {"kind": "file", "size": 12, "name": "a.txt", "note": "<x> & y"},
	}
	h, cancel := runReadBot(t, gw)
	defer cancel()
	sends := sendFS(t, h, "/fs stat a.txt")
	if len(sends) != 1 {
		t.Fatalf("sends = %q; want exactly 1", sends)
	}
	want := "<pre>{\n \"kind\": \"file\",\n \"name\": \"a.txt\",\n \"note\": \"&lt;x&gt; &amp; y\",\n \"size\": 12\n}</pre>"
	if sends[0] != want {
		t.Errorf("send = %q; want %q", sends[0], want)
	}
	if calls := gw.fsStatCallsSeen(); len(calls) != 1 || calls[0] != "a.txt" {
		t.Errorf("fs.stat paths = %q; want [\"a.txt\"]", calls)
	}
}

func TestTelegramFSStatLongDocument(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.fsStatScript = map[string]map[string]any{
		"big": {"blob": strings.Repeat("x", 4000)},
	}
	h, cancel := runReadBot(t, gw)
	defer cancel()
	docs := waitForDocs(t, h, "/fs stat big", 1)
	if len(h.fake.sendsSeen()) != 0 {
		t.Fatalf("sends = %q; want none (long dump goes to a document)", h.fake.sendsSeen())
	}
	if len(docs) != 1 {
		t.Fatalf("documents = %+v; want exactly 1", docs)
	}
	if docs[0].Filename != "output.txt" {
		t.Errorf("document name = %q; want \"output.txt\" (reply_long default stem)", docs[0].Filename)
	}
	if !strings.HasPrefix(docs[0].Caption, "output.txt (") || !strings.HasSuffix(docs[0].Caption, " chars)") {
		t.Errorf("caption = %q; want \"output.txt (N chars)\"", docs[0].Caption)
	}
}

func TestTelegramFSFind(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.fsSearchScript = []any{
		map[string]any{"path": "a/b.txt", "name": "b.txt"},
		map[string]any{"name": "c.txt"},
		map[string]any{"other": 1},
	}
	h, cancel := runReadBot(t, gw)
	defer cancel()
	sends := sendFS(t, h, "/fs find txt")
	if len(sends) != 1 {
		t.Fatalf("sends = %q; want exactly 1", sends)
	}
	if !strings.HasPrefix(sends[0], "<pre>a/b.txt\nc.txt\n") || !strings.Contains(sends[0], `"other":1`) || !strings.HasSuffix(sends[0], "</pre>") {
		t.Errorf("send = %q; want path line, name line, and a JSON fallback line in <pre>", sends[0])
	}
	calls := gw.fsSearchCallsSeen()
	if len(calls) != 1 || calls[0].Contains != "txt" || !calls[0].HasLimit || calls[0].Limit != 50 {
		t.Errorf("fs.search calls = %+v; want one {txt, limit 50}", calls)
	}
}

func TestTelegramFSFindEmpty(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.fsSearchScript = []any{}
	h, cancel := runReadBot(t, gw)
	defer cancel()
	sends := sendFS(t, h, "/fs find nope")
	if len(sends) != 1 || sends[0] != "<pre>nothing found</pre>" {
		t.Fatalf("sends = %q; want [\"<pre>nothing found</pre>\"]", sends)
	}
}

func TestTelegramFSCat(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.fsReadScript = map[string][]byte{
		"hello.txt": []byte("hi <there> & bye"),
		"empty.txt": {},
		"bin.dat":   {0x00, 'a', 'b'},
		"long.txt":  []byte(strings.Repeat("x", 4000)),
	}
	h, cancel := runReadBot(t, gw)
	defer cancel()
	sends := sendFS(t, h, "/fs cat hello.txt")
	want := "<b>/hello.txt</b>\n<pre>hi &lt;there&gt; &amp; bye</pre>"
	if len(sends) != 1 || sends[0] != want {
		t.Fatalf("sends = %q; want [%q]", sends, want)
	}

	h2, cancel2 := runReadBot(t, gw)
	defer cancel2()
	sends = sendFS(t, h2, "/fs cat empty.txt")
	want = "<b>/empty.txt</b>\n<pre>(empty)</pre>"
	if len(sends) != 1 || sends[0] != want {
		t.Fatalf("sends = %q; want [%q]", sends, want)
	}

	h3, cancel3 := runReadBot(t, gw)
	defer cancel3()
	docs := waitForDocs(t, h3, "/fs cat bin.dat", 1)
	if len(h3.fake.sendsSeen()) != 0 {
		t.Fatalf("sends = %q; want none (binary goes to a document)", h3.fake.sendsSeen())
	}
	if len(docs) != 1 || docs[0].Filename != "bin.dat" || docs[0].Caption != "/bin.dat (binary)" || docs[0].Size != 3 {
		t.Fatalf("documents = %+v; want one {bin.dat, 3 bytes, caption \"/bin.dat (binary)\"}", docs)
	}

	h4, cancel4 := runReadBot(t, gw)
	defer cancel4()
	docs = waitForDocs(t, h4, "/fs cat long.txt", 1)
	if len(h4.fake.sendsSeen()) != 0 {
		t.Fatalf("sends = %q; want none (over-long text goes to a document)", h4.fake.sendsSeen())
	}
	if len(docs) != 1 || docs[0].Filename != "long.txt" || docs[0].Caption != "/long.txt" || docs[0].Size != 4000 {
		t.Fatalf("documents = %+v; want one {long.txt, 4000 bytes, caption \"/long.txt\"}", docs)
	}
}

func TestTelegramFSCatRuneBoundary(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.fsReadScript = map[string][]byte{
		"exact.txt": []byte(strings.Repeat("é", 3800)),
		"over.txt":  []byte(strings.Repeat("é", 3801)),
	}
	// 3800 runes (7600 bytes) stays a <pre> message: the
	// reply_long/cat threshold counts runes, not bytes. The
	// wrapped send is 3828 runes, so the bot's own splitter
	// delivers it in two pieces (as upstream's send does);
	// the concatenation is the one <pre> message.
	h, cancel := runReadBot(t, gw)
	defer cancel()
	h.fake.setBatches([]string{telegramUpdate(1, 111, "/fs cat exact.txt")})
	// Wait for BOTH split pieces: the wrapped send is 3828
	// runes, so the bot's splitter delivers it in two pieces;
	// returning on the first would race the second (PR-D F5).
	waitFor(t, "2 sends", func() bool { return len(h.fake.sendsSeen()) >= 2 })
	joined := strings.Join(h.fake.sendsSeen(), "")
	want := "<b>/exact.txt</b>\n<pre>" + strings.Repeat("é", 3800) + "</pre>"
	if joined != want {
		t.Fatalf("joined sends = %d runes; want the one <pre> message with 3800 é", utf8.RuneCountInString(joined))
	}
	if len(h.fake.documentsSeen()) != 0 {
		t.Fatalf("documents = %d; want 0 (exactly 3800 runes is not over the threshold)", len(h.fake.documentsSeen()))
	}
	h2, cancel2 := runReadBot(t, gw)
	defer cancel2()
	docs := waitForDocs(t, h2, "/fs cat over.txt", 1)
	if len(h2.fake.sendsSeen()) != 0 {
		t.Fatalf("sends = %q; want none (3801 runes goes to a document)", h2.fake.sendsSeen())
	}
	if len(docs) != 1 || docs[0].Filename != "over.txt" || docs[0].Caption != "/over.txt" {
		t.Fatalf("documents = %+v; want one {over.txt, caption \"/over.txt\"}", docs)
	}
}

func TestTelegramFSCatCap(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.fsReadScript = map[string][]byte{"big.bin": bytes.Repeat([]byte("x"), 6<<20)}
	h, cancel := runReadBot(t, gw)
	defer cancel()
	docs := waitForDocs(t, h, "/fs cat big.bin", 1)
	if len(h.fake.sendsSeen()) != 0 {
		t.Fatalf("sends = %q; want none (capped read goes to a document)", h.fake.sendsSeen())
	}
	if len(docs) != 1 || docs[0].Size != 5<<20 {
		t.Fatalf("documents = %+v; want one document of exactly 5 MiB (the cat cap)", docs)
	}
	calls := gw.fsReadCallsSeen()
	wantCalls := []fsReadCall{
		{Path: "big.bin", Offset: 0, Len: 4 << 20},
		{Path: "big.bin", Offset: 4 << 20, Len: 1 << 20},
	}
	if len(calls) != len(wantCalls) {
		t.Fatalf("fs.read calls = %+v; want %+v", calls, wantCalls)
	}
	for i, want := range wantCalls {
		if calls[i] != want {
			t.Errorf("fs.read call %d = %+v; want %+v", i, calls[i], want)
		}
	}
}

func TestTelegramFSGet(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.fsStatScript = map[string]map[string]any{
		"dir":   {"kind": "directory"},
		"dir2":  {"kind": "dir"},
		"f.txt": {"kind": "file"},
	}
	gw.fsReadScript = map[string][]byte{"f.txt": []byte("hello")}
	h, cancel := runReadBot(t, gw)
	defer cancel()
	sends := sendFS(t, h, "/fs get dir")
	if len(sends) != 1 || sends[0] != fsFolderSentence {
		t.Fatalf("sends = %q; want [%q]", sends, fsFolderSentence)
	}
	if len(gw.fsReadCallsSeen()) != 0 {
		t.Fatalf("fs.read calls = %d; want 0 (folder refused before any read)", len(gw.fsReadCallsSeen()))
	}

	h2, cancel2 := runReadBot(t, gw)
	defer cancel2()
	sends = sendFS(t, h2, "/fs get dir2")
	if len(sends) != 1 || sends[0] != fsFolderSentence {
		t.Fatalf("sends = %q; want [%q]", sends, fsFolderSentence)
	}

	h3, cancel3 := runReadBot(t, gw)
	defer cancel3()
	docs := waitForDocs(t, h3, "/fs get f.txt", 1)
	if len(h3.fake.sendsSeen()) != 0 {
		t.Fatalf("sends = %q; want none (file goes to a document)", h3.fake.sendsSeen())
	}
	if len(docs) != 1 || docs[0].Filename != "f.txt" || docs[0].Caption != "/f.txt" || docs[0].Size != 5 {
		t.Fatalf("documents = %+v; want one {f.txt, 5 bytes, caption \"/f.txt\"}", docs)
	}
}

func TestTelegramFSGetTooBig(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.fsStatScript = map[string]map[string]any{"big.bin": {"kind": "file"}}
	gw.fsReadScript = map[string][]byte{"big.bin": bytes.Repeat([]byte("x"), (49<<20)+1)}
	h, cancel := runReadBot(t, gw)
	defer cancel()
	h.fake.setBatches([]string{telegramUpdate(1, 111, "/fs get big.bin")})
	// 60s budget: shuttling 49 MiB+ through the fake's
	// base64 chunk loop is slow under -race and full-suite
	// contention (the 10s default timed out at 11.3s).
	waitForTimeout(t, "1 sends", 60*time.Second, func() bool { return len(h.fake.sendsSeen()) >= 1 })
	sends := h.fake.sendsSeen()
	if len(sends) != 1 || sends[0] != fsTooBigSentence {
		t.Fatalf("sends = %q; want [%q]", sends, fsTooBigSentence)
	}
	if n := len(h.fake.documentsSeen()); n != 0 {
		t.Fatalf("documents = %d; want 0 (over the upload limit)", n)
	}
}

func TestTelegramFSMkdir(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	h, cancel := runReadBot(t, gw)
	defer cancel()
	sends := sendFS(t, h, "/fs mkdir a/b")
	want := "📁 Created <code>/a/b</code>"
	if len(sends) != 1 || sends[0] != want {
		t.Fatalf("sends = %q; want [%q]", sends, want)
	}
	calls := gw.fsMkdirCallsSeen()
	if len(calls) != 1 || calls[0] != (fsMkdirCall{Path: "a/b", Recursive: true}) {
		t.Errorf("fs.mkdir calls = %+v; want one {a/b, parents=true}", calls)
	}
}

func TestTelegramFSMv(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	h, cancel := runReadBot(t, gw)
	defer cancel()
	sends := sendFS(t, h, "/fs mv a b")
	want := "Moved <code>/a</code> → <code>/b</code>"
	if len(sends) != 1 || sends[0] != want {
		t.Fatalf("sends = %q; want [%q]", sends, want)
	}
	calls := gw.fsRenameCallsSeen()
	if len(calls) != 1 || calls[0] != (fsRenameCall{Source: "a", Destination: "b", CreateParent: true}) {
		t.Errorf("fs.rename calls = %+v; want one {a→b, overwrite=false, create_parent=true}", calls)
	}

	h2, cancel2 := runReadBot(t, gw)
	defer cancel2()
	sends = sendFS(t, h2, "/fs mv -f a b")
	if len(sends) != 1 || sends[0] != want {
		t.Fatalf("sends = %q; want [%q]", sends, want)
	}
	calls = gw.fsRenameCallsSeen()
	if len(calls) != 2 || calls[1].Overwrite != true {
		t.Errorf("fs.rename calls = %+v; want the second with overwrite=true", calls)
	}

	// -f anywhere in the line counts.
	h3, cancel3 := runReadBot(t, gw)
	defer cancel3()
	sends = sendFS(t, h3, "/fs mv a -f b")
	if len(sends) != 1 || sends[0] != want {
		t.Fatalf("sends = %q; want [%q]", sends, want)
	}
	calls = gw.fsRenameCallsSeen()
	if len(calls) != 3 || calls[2].Overwrite != true {
		t.Errorf("fs.rename calls = %+v; want the third with overwrite=true", calls)
	}
}

func TestTelegramFSMvArity(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	h, cancel := runReadBot(t, gw)
	defer cancel()
	h.fake.setBatches([]string{
		telegramUpdate(1, 111, "/fs mv a"),
		telegramUpdate(2, 111, "/fs mv a b c"),
		telegramUpdate(3, 111, "/fs mv"),
	})
	sends := waitForSends(t, h, 3)
	if len(sends) != 3 {
		t.Fatalf("sends = %q; want exactly 3", sends)
	}
	for i, s := range sends {
		if s != fsUsage {
			t.Errorf("send %d = %q; want the usage sentence", i, s)
		}
	}
	if len(gw.fsRenameCallsSeen()) != 0 {
		t.Fatalf("fs.rename calls = %d; want 0 (arity failures never reach the gateway)", len(gw.fsRenameCallsSeen()))
	}
}

func TestTelegramFSRmPrompt(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	h, cancel := runReadBot(t, gw)
	defer cancel()
	sends := sendFS(t, h, "/fs rm old.txt")
	want := "Delete <code>/old.txt</code>?"
	if len(sends) != 1 || sends[0] != want {
		t.Fatalf("sends = %q; want [%q]", sends, want)
	}
	rows := markupButtons(t, h.fake.sendMarkupJSON[0])
	if len(rows) != 1 || len(rows[0]) != 2 || rows[0][0] != "🗑 Yes, delete" || rows[0][1] != "Cancel" {
		t.Fatalf("buttons = %v; want one row [🗑 Yes, delete | Cancel]", rows)
	}
	if len(gw.fsDeleteCallsSeen()) != 0 {
		t.Fatalf("fs.delete calls = %d; want 0 (prompt only, no delete yet)", len(gw.fsDeleteCallsSeen()))
	}

	h2, cancel2 := runReadBot(t, gw)
	defer cancel2()
	sends = sendFS(t, h2, "/fs rm -r dir")
	want = "Delete <code>/dir</code> and everything in it?"
	if len(sends) != 1 || sends[0] != want {
		t.Fatalf("sends = %q; want [%q]", sends, want)
	}

	// "-R" counts; "--recursive" does not (exact flag set).
	h3, cancel3 := runReadBot(t, gw)
	defer cancel3()
	sends = sendFS(t, h3, "/fs rm -R dir")
	if len(sends) != 1 || sends[0] != "Delete <code>/dir</code> and everything in it?" {
		t.Fatalf("sends = %q; want the recursive prompt", sends)
	}
	h4, cancel4 := runReadBot(t, gw)
	defer cancel4()
	sends = sendFS(t, h4, "/fs rm --recursive dir")
	if len(sends) != 1 || sends[0] != "Delete <code>/dir</code>?" {
		t.Fatalf("sends = %q; want the non-recursive prompt", sends)
	}
}

func TestTelegramFSRmTap(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	wb := startWiredBot(t, gw)
	defer wb.cancel()
	data := wb.bot.Registry().Register(telegram.CallbackEntry{Action: "fs_rm", FSPath: "old.txt", FSRecursive: true})
	wb.fake.setBatches([]string{callbackUpdate(9, data, 50)})
	waitFor(t, "delete edit", func() bool {
		for _, e := range wb.fake.editTexts() {
			if e == "🗑 Deleted /old.txt" {
				return true
			}
		}
		return false
	})
	wb.cancel()
	<-wb.done
	calls := gw.fsDeleteCallsSeen()
	if len(calls) != 1 || calls[0] != (fsDeleteCall{Path: "old.txt", Recursive: true}) {
		t.Fatalf("fs.delete calls = %+v; want one {old.txt, recursive=true}", calls)
	}
	edits := wb.fake.editTexts()
	if len(edits) != 1 || edits[0] != "🗑 Deleted /old.txt" {
		t.Fatalf("edits = %q; want [\"🗑 Deleted /old.txt\"]", edits)
	}
}

func TestTelegramFSRmTapNonRecursive(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	wb := startWiredBot(t, gw)
	defer wb.cancel()
	data := wb.bot.Registry().Register(telegram.CallbackEntry{Action: "fs_rm", FSPath: "f.txt"})
	wb.fake.setBatches([]string{callbackUpdate(9, data, 50)})
	waitFor(t, "delete edit", func() bool { return len(wb.fake.editTexts()) >= 1 })
	wb.cancel()
	<-wb.done
	calls := gw.fsDeleteCallsSeen()
	if len(calls) != 1 || calls[0] != (fsDeleteCall{Path: "f.txt", Recursive: false}) {
		t.Fatalf("fs.delete calls = %+v; want one {f.txt, recursive=false}", calls)
	}
}

func TestTelegramFSRmRetapRedeletes(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	wb := startWiredBot(t, gw)
	defer wb.cancel()
	data := wb.bot.Registry().Register(telegram.CallbackEntry{Action: "fs_rm", FSPath: "old.txt"})
	wb.fake.setBatches([]string{callbackUpdate(9, data, 50), callbackUpdate(10, data, 50)})
	waitFor(t, "two deletes", func() bool { return len(gw.fsDeleteCallsSeen()) >= 2 })
	wb.cancel()
	<-wb.done
	if len(gw.fsDeleteCallsSeen()) != 2 {
		t.Fatalf("fs.delete calls = %d; want 2 (entries are never consumed: re-tap re-deletes)", len(gw.fsDeleteCallsSeen()))
	}
}

func TestTelegramFSRmCancel(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	wb := startWiredBot(t, gw)
	defer wb.cancel()
	data := wb.bot.Registry().Register(telegram.CallbackEntry{Action: "noop"})
	wb.fake.setBatches([]string{callbackUpdate(9, data, 50)})
	waitFor(t, "cancel edit", func() bool { return len(wb.fake.editTexts()) >= 1 })
	wb.cancel()
	<-wb.done
	if len(gw.fsDeleteCallsSeen()) != 0 {
		t.Fatalf("fs.delete calls = %d; want 0 (Cancel deletes nothing)", len(gw.fsDeleteCallsSeen()))
	}
	edits := wb.fake.editTexts()
	if len(edits) != 1 || edits[0] != "Cancelled." {
		t.Fatalf("edits = %q; want [\"Cancelled.\"]", edits)
	}
}

func TestTelegramFSRmTapAuthError(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.fsDeleteErr = &conn.AuthError{Message: "expired"}
	wb := startWiredBot(t, gw)
	defer wb.cancel()
	data := wb.bot.Registry().Register(telegram.CallbackEntry{Action: "fs_rm", FSPath: "old.txt"})
	wb.fake.setBatches([]string{callbackUpdate(9, data, 50)})
	waitFor(t, "login-expired reply", func() bool {
		for _, s := range wb.fake.sendsSeen() {
			if s == "🔑 muse.ai login expired. Use /login." {
				return true
			}
		}
		return false
	})
	wb.cancel()
	<-wb.done
	if len(wb.fake.editTexts()) != 0 {
		t.Fatalf("edits = %q; want none (auth failure edits nothing)", wb.fake.editTexts())
	}
}

func TestTelegramFSRmTapGenericError(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.fsDeleteErr = errors.New("boom")
	wb := startWiredBot(t, gw)
	defer wb.cancel()
	data := wb.bot.Registry().Register(telegram.CallbackEntry{Action: "fs_rm", FSPath: "old.txt"})
	wb.fake.setBatches([]string{callbackUpdate(9, data, 50)})
	waitFor(t, "warning reply", func() bool {
		for _, s := range wb.fake.sendsSeen() {
			if strings.HasPrefix(s, "⚠️ ") {
				return true
			}
		}
		return false
	})
	wb.cancel()
	<-wb.done
	if len(wb.fake.editTexts()) != 0 {
		t.Fatalf("edits = %q; want none (delete failure edits nothing)", wb.fake.editTexts())
	}
}

func TestTelegramFSUsage(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	h, cancel := runReadBot(t, gw)
	defer cancel()
	texts := []string{"/fs", "/fs bogus x", "/fs stat", "/fs find", "/fs cat", "/fs get", "/fs mkdir", "/fs rm", "/fs LS --bogus"}
	batches := make([]string, len(texts))
	for i, text := range texts {
		batches[i] = telegramUpdate(int64(i+1), 111, text)
	}
	h.fake.setBatches(batches)
	sends := waitForSends(t, h, len(texts))
	if len(sends) != len(texts) {
		t.Fatalf("sends = %q; want exactly %d", sends, len(texts))
	}
	for i := 0; i < len(texts)-1; i++ {
		if sends[i] != fsUsage {
			t.Errorf("%s: send = %q; want the usage sentence", texts[i], sends[i])
		}
	}
	// "/fs LS --bogus" lowercases the op: ls runs (empty
	// listing) instead of answering usage.
	if sends[len(texts)-1] != "<pre>/\n(empty)</pre>" {
		t.Errorf("last send = %q; want the empty ls listing", sends[len(texts)-1])
	}
	if len(gw.fsListCallsSeen()) != 1 {
		t.Fatalf("fs.list calls = %d; want 1 (the lowercased LS)", len(gw.fsListCallsSeen()))
	}
}

func TestTelegramFSQuotedPaths(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.fsReadScript = map[string][]byte{
		"my file.txt": []byte("spaced"),
		"a b.txt":     []byte("single"),
	}
	h, cancel := runReadBot(t, gw)
	defer cancel()
	sends := sendFS(t, h, `/fs cat "my file.txt"`)
	want := "<b>/my file.txt</b>\n<pre>spaced</pre>"
	if len(sends) != 1 || sends[0] != want {
		t.Fatalf("sends = %q; want [%q]", sends, want)
	}
	h2, cancel2 := runReadBot(t, gw)
	defer cancel2()
	sends = sendFS(t, h2, "/fs cat 'a b.txt'")
	want = "<b>/a b.txt</b>\n<pre>single</pre>"
	if len(sends) != 1 || sends[0] != want {
		t.Fatalf("sends = %q; want [%q]", sends, want)
	}
	calls := gw.fsReadCallsSeen()
	if len(calls) != 2 || calls[0].Path != "my file.txt" || calls[1].Path != "a b.txt" {
		t.Errorf("fs.read paths = %+v; want the two quoted paths, quotes stripped", calls)
	}
}

func TestTelegramFSParseError(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	h, cancel := runReadBot(t, gw)
	defer cancel()
	sends := sendFS(t, h, `/fs ls "unterminated`)
	if len(sends) != 1 || sends[0] != "⚠️ no closing quotation" {
		t.Fatalf("sends = %q; want [\"⚠️ no closing quotation\"]", sends)
	}
	if len(gw.fsListCallsSeen()) != 0 {
		t.Fatalf("fs.list calls = %d; want 0 (parse failure never reaches the gateway)", len(gw.fsListCallsSeen()))
	}
}

func TestTelegramFSTraversalBlocked(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	h, cancel := runReadBot(t, gw)
	defer cancel()
	texts := []string{
		"/fs cat ../etc",
		"/fs ls a/../../b",
		// Quoted, so shlex keeps the backslash: the token is
		// ..\etc, which the traversal scan rejects. (An
		// UNQUOTED ..\etc is eaten by shlex itself — the
		// backslash escapes the "e" — and never reaches the
		// scan, exactly as upstream.)
		`/fs cat "..\etc"`,
		"/fs mv ../a b",
		"/fs mv a ../b",
		"/fs rm ..",
		"/fs stat ../..",
		"/fs tree a/..",
		"/fs get sandbox://../etc",
	}
	batches := make([]string, len(texts))
	for i, text := range texts {
		batches[i] = telegramUpdate(int64(i+1), 111, text)
	}
	h.fake.setBatches(batches)
	sends := waitForSends(t, h, len(texts))
	if len(sends) != len(texts) {
		t.Fatalf("sends = %q; want exactly %d", sends, len(texts))
	}
	for i, s := range sends {
		if s != "⚠️ path traversal not allowed" {
			t.Errorf("%s: send = %q; want the fixed traversal sentence", texts[i], s)
		}
	}
	if n := len(gw.fsListCallsSeen()) + len(gw.fsReadCallsSeen()) + len(gw.fsStatCallsSeen()) + len(gw.fsRenameCallsSeen()) + len(gw.fsDeleteCallsSeen()); n != 0 {
		t.Fatalf("gateway fs calls = %d; want 0 (traversal never reaches the gateway)", n)
	}
}

func TestTelegramFSTraversalFindExempt(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.fsSearchScript = []any{}
	h, cancel := runReadBot(t, gw)
	defer cancel()
	sends := sendFS(t, h, "/fs find ..")
	if len(sends) != 1 || sends[0] != "<pre>nothing found</pre>" {
		t.Fatalf("sends = %q; want the find reply (a .. fragment is a name search, not a path)", sends)
	}
	calls := gw.fsSearchCallsSeen()
	if len(calls) != 1 || calls[0].Contains != ".." {
		t.Fatalf("fs.search calls = %+v; want one {contains: \"..\"}", calls)
	}
}

func TestTelegramFSTraversalDotNamesAllowed(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.fsReadScript = map[string][]byte{"..hidden/x": []byte("ok"), "a/b": []byte("ok"), "..etc": []byte("shlex")}
	h, cancel := runReadBot(t, gw)
	defer cancel()
	sends := sendFS(t, h, "/fs cat ..hidden/x")
	if len(sends) != 1 || sends[0] != "<b>/..hidden/x</b>\n<pre>ok</pre>" {
		t.Fatalf("sends = %q; want the cat reply (..hidden is not a .. component)", sends)
	}
	// An UNQUOTED ..\etc never reaches the traversal scan:
	// shlex eats the backslash (it escapes the "e"), so the
	// token is "..etc", a plain name — exactly as upstream.
	h3, cancel3 := runReadBot(t, gw)
	defer cancel3()
	sends = sendFS(t, h3, `/fs cat ..\etc`)
	if len(sends) != 1 || sends[0] != "<b>/..etc</b>\n<pre>shlex</pre>" {
		t.Fatalf("sends = %q; want the cat reply for the shlex-escaped name", sends)
	}
	// "a/../b" DOES contain a .. component: rejected even
	// though normpath would collapse it to "b".
	h2, cancel2 := runReadBot(t, gw)
	defer cancel2()
	sends = sendFS(t, h2, "/fs cat a/../b")
	if len(sends) != 1 || sends[0] != "⚠️ path traversal not allowed" {
		t.Fatalf("sends = %q; want the traversal sentence", sends)
	}
}

func TestTelegramFSGatewayError(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.fsListErr = errors.New("boom")
	h, cancel := runReadBot(t, gw)
	defer cancel()
	sends := sendFS(t, h, "/fs ls")
	if len(sends) != 1 || sends[0] != fsGatewayError {
		t.Fatalf("sends = %q; want [%q]", sends, fsGatewayError)
	}
}

func TestTelegramFSGatewayAuthError(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.fsListErr = &conn.AuthError{Message: "expired"}
	h, cancel := runReadBot(t, gw)
	defer cancel()
	sends := sendFS(t, h, "/fs ls")
	if len(sends) != 1 || sends[0] != readLoginExpired {
		t.Fatalf("sends = %q; want [%q]", sends, readLoginExpired)
	}
}

func TestTelegramFSReplyLongDocument(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	name := strings.Repeat("x", 4000)
	gw.fsListScript = map[string][]any{
		"": {fsEntry(name, "file", fsSize(1))},
	}
	h, cancel := runReadBot(t, gw)
	defer cancel()
	docs := waitForDocs(t, h, "/fs ls", 1)
	if len(h.fake.sendsSeen()) != 0 {
		t.Fatalf("sends = %q; want none (over-long listing goes to a document)", h.fake.sendsSeen())
	}
	if len(docs) != 1 {
		t.Fatalf("documents = %+v; want exactly 1", docs)
	}
	text := "/\n📄 " + name + "  1B"
	if docs[0].Filename != "ls.txt" {
		t.Errorf("document name = %q; want \"ls.txt\"", docs[0].Filename)
	}
	wantCaption := fmt.Sprintf("ls.txt (%d chars)", utf8.RuneCountInString(text))
	if docs[0].Caption != wantCaption {
		t.Errorf("caption = %q; want %q", docs[0].Caption, wantCaption)
	}
	if docs[0].Size != int64(len(text)) {
		t.Errorf("document size = %d; want %d (the UTF-8 bytes of the listing)", docs[0].Size, len(text))
	}
}

func TestTelegramFSRmPromptEscapesPath(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	h, cancel := runReadBot(t, gw)
	defer cancel()
	sends := sendFS(t, h, "/fs rm a<b>&c")
	want := "Delete <code>/a&lt;b&gt;&amp;c</code>?"
	if len(sends) != 1 || sends[0] != want {
		t.Fatalf("sends = %q; want [%q]", sends, want)
	}
}

func TestTelegramFSStatEscapesKeys(t *testing.T) {
	t.Parallel()
	// A hostile key name must not break out of the <pre> send:
	// the dump is escaped as a whole.
	gw := newTelegramTurnFakeGateway()
	gw.fsStatScript = map[string]map[string]any{
		"x": {"</pre><b>evil</b>": "v"},
	}
	h, cancel := runReadBot(t, gw)
	defer cancel()
	sends := sendFS(t, h, "/fs stat x")
	if len(sends) != 1 {
		t.Fatalf("sends = %q; want exactly 1", sends)
	}
	if strings.Contains(sends[0], "</pre><b>") || !strings.Contains(sends[0], "&lt;/pre&gt;") {
		t.Errorf("send = %q; want the hostile key escaped inside one <pre>", sends[0])
	}
}

// TestTelegramFSStatExtraPositional pins the upstream arity
// rule (D16/F1): single-path ops guard on a nonempty path
// and IGNORE extra positionals — /fs stat a b stats a.
func TestTelegramFSStatExtraPositional(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.fsStatScript = map[string]map[string]any{
		"a.txt": {"kind": "file", "size": 12, "name": "a.txt"},
	}
	h, cancel := runReadBot(t, gw)
	defer cancel()
	sends := sendFS(t, h, "/fs stat a.txt extra junk")
	want := "<pre>{\n \"kind\": \"file\",\n \"name\": \"a.txt\",\n \"size\": 12\n}</pre>"
	if len(sends) != 1 || sends[0] != want {
		t.Fatalf("sends = %q; want [%q] (the stat dump for a.txt, not usage)", sends, want)
	}
	if calls := gw.fsStatCallsSeen(); len(calls) != 1 || calls[0] != "a.txt" {
		t.Errorf("fs.stat paths = %q; want [\"a.txt\"]", calls)
	}
}

// TestTelegramFSEmptyPathUsage pins the other half of the
// upstream rule (D16/F1): a present-but-empty path is falsy,
// so /fs cat "" and /fs rm "" answer usage and never reach
// the gateway.
func TestTelegramFSEmptyPathUsage(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	gw.fsReadScript = map[string][]byte{"x": []byte("x")}
	h, cancel := runReadBot(t, gw)
	defer cancel()
	sends := sendFS(t, h, `/fs cat ""`)
	if len(sends) != 1 || sends[0] != fsUsage {
		t.Fatalf("sends = %q; want [%q]", sends, fsUsage)
	}
	if n := len(gw.fsReadCallsSeen()); n != 0 {
		t.Fatalf("fs.read calls = %d; want 0 (empty path never reaches the gateway)", n)
	}

	h2, cancel2 := runReadBot(t, gw)
	defer cancel2()
	sends = sendFS(t, h2, `/fs rm ""`)
	if len(sends) != 1 || sends[0] != fsUsage {
		t.Fatalf("sends = %q; want [%q]", sends, fsUsage)
	}
	if n := len(gw.fsDeleteCallsSeen()); n != 0 {
		t.Fatalf("fs.delete calls = %d; want 0 (empty path never prompts)", n)
	}
}

// TestTelegramFSRmExtraPositional pins the upstream arity
// rule for rm (D16/F1): extra positionals are ignored —
// /fs rm a b prompts for a and deletes nothing yet.
func TestTelegramFSRmExtraPositional(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	h, cancel := runReadBot(t, gw)
	defer cancel()
	sends := sendFS(t, h, "/fs rm a b")
	want := "Delete <code>/a</code>?"
	if len(sends) != 1 || sends[0] != want {
		t.Fatalf("sends = %q; want [%q] (the prompt for a, not usage)", sends, want)
	}
	if n := len(gw.fsDeleteCallsSeen()); n != 0 {
		t.Fatalf("fs.delete calls = %d; want 0 (prompt only, no delete yet)", n)
	}
}

// TestTelegramFSReplyLongRuneBoundary pins the replyLong gate
// in RUNES at exactly the threshold (D17/F2, G1): a multibyte
// listing of exactly 3800 runes stays a <pre> message (0
// documents), and 3801 runes becomes a document captioned with
// the RUNE count. A byte-based gate or a >= gate would route
// the 3800-rune listing to a document.
func TestTelegramFSReplyLongRuneBoundary(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	// Text: "/\n📄 " + name + "  1B" = 1+1+1+1+3792+2+2 = 3800 runes,
	// 7592 bytes. The wrapped <pre> send is 3811 runes, so the
	// bot's splitter delivers it in two pieces; join them.
	name := strings.Repeat("é", 3792)
	gw.fsListScript = map[string][]any{
		"": {fsEntry(name, "file", fsSize(1))},
	}
	h, cancel := runReadBot(t, gw)
	defer cancel()
	h.fake.setBatches([]string{telegramUpdate(1, 111, "/fs ls")})
	waitFor(t, "2 sends", func() bool { return len(h.fake.sendsSeen()) >= 2 })
	joined := strings.Join(h.fake.sendsSeen(), "")
	text := "/\n📄 " + name + "  1B"
	if utf8.RuneCountInString(text) != 3800 {
		t.Fatalf("listing is %d runes; want exactly 3800 (test construction bug)", utf8.RuneCountInString(text))
	}
	want := "<pre>" + text + "</pre>"
	if joined != want {
		t.Fatalf("joined sends = %d runes; want the one <pre> message with 3800 runes", utf8.RuneCountInString(joined))
	}
	if n := len(h.fake.documentsSeen()); n != 0 {
		t.Fatalf("documents = %d; want 0 (exactly 3800 runes is not over the threshold)", n)
	}

	// 3801 runes: one document, caption in runes.
	name = strings.Repeat("é", 3793)
	gw2 := newTelegramTurnFakeGateway()
	gw2.fsListScript = map[string][]any{
		"": {fsEntry(name, "file", fsSize(1))},
	}
	h2, cancel2 := runReadBot(t, gw2)
	defer cancel2()
	docs := waitForDocs(t, h2, "/fs ls", 1)
	if len(h2.fake.sendsSeen()) != 0 {
		t.Fatalf("sends = %q; want none (3801 runes goes to a document)", h2.fake.sendsSeen())
	}
	if len(docs) != 1 || docs[0].Filename != "ls.txt" || docs[0].Caption != "ls.txt (3801 chars)" {
		t.Fatalf("documents = %+v; want one {ls.txt, caption \"ls.txt (3801 chars)\"}", docs)
	}
}

// TestTelegramFSMvRfNoOverwrite pins the mv overwrite gate
// (D18/G2): -rf (and -fr) are NOT -f, so the recorded rename
// call must carry overwrite=false.
func TestTelegramFSMvRfNoOverwrite(t *testing.T) {
	t.Parallel()
	for _, flag := range []string{"-rf", "-fr"} {
		gw := newTelegramTurnFakeGateway()
		h, cancel := runReadBot(t, gw)
		sends := sendFS(t, h, "/fs mv "+flag+" a b")
		want := "Moved <code>/a</code> → <code>/b</code>"
		if len(sends) != 1 || sends[0] != want {
			t.Fatalf("%s: sends = %q; want [%q]", flag, sends, want)
		}
		calls := gw.fsRenameCallsSeen()
		if len(calls) != 1 || calls[0] != (fsRenameCall{Source: "a", Destination: "b", CreateParent: true}) {
			t.Errorf("%s: fs.rename calls = %+v; want one {a→b, overwrite=false, create_parent=true}", flag, calls)
		}
		cancel()
	}
}

// TestTelegramFSCatBinaryWindowBytes pins the cat binary
// window in BYTES (D19/G3): a NUL past byte 8192 but within
// the first 8192 RUNES must NOT take the binary branch — the
// content takes the text path (over 3800 runes, so a document
// captioned /{path}, not (binary)).
func TestTelegramFSCatBinaryWindowBytes(t *testing.T) {
	t.Parallel()
	gw := newTelegramTurnFakeGateway()
	// 5000 é (10000 bytes) + NUL at byte offset 10000 + "x":
	// 5002 runes, NUL past byte 8192 but within rune 8192.
	data := append([]byte(strings.Repeat("é", 5000)), 0, 'x')
	gw.fsReadScript = map[string][]byte{"nul.bin": data}
	h, cancel := runReadBot(t, gw)
	defer cancel()
	docs := waitForDocs(t, h, "/fs cat nul.bin", 1)
	if len(h.fake.sendsSeen()) != 0 {
		t.Fatalf("sends = %q; want none (over-long text goes to a document)", h.fake.sendsSeen())
	}
	if len(docs) != 1 || docs[0].Filename != "nul.bin" || docs[0].Caption != "/nul.bin" || docs[0].Size != int64(len(data)) {
		t.Fatalf("documents = %+v; want one {nul.bin, %d bytes, caption \"/nul.bin\"} (text branch, not binary)", docs, len(data))
	}
}
