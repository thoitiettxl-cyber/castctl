// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/thoitiettxl-cyber/muse-cli/go/internal/gateway/gatewaytest"
	pb "github.com/thoitiettxl-cyber/muse-cli/go/internal/proto"
)

// fakeFS is an in-memory sandbox filesystem served over the fake
// gateway: entries, contents and write/delete/rename effects are
// all observable from the test.
type fakeFS struct {
	files map[string][]byte // path -> content; dirs are implicit
	dirs  map[string]bool
	calls []string
}

func newFakeFS() *fakeFS {
	return &fakeFS{
		files: map[string][]byte{
			"notes/hello.txt": []byte("hello world"),
			"notes/.hidden":   []byte("secret"),
			"bin/data.bin":    []byte{0x00, 0x01, 0x02},
			"a/b/c.txt":       []byte("deep"),
		},
		dirs: map[string]bool{"": true, "notes": true, "bin": true, "a": true, "a/b": true},
	}
}

func (f *fakeFS) handler() gatewaytest.Handler {
	return gatewaytest.HandlerFunc(func(req *pb.ApplicationRequest, service pb.ServiceType) gatewaytest.Response {
		path, _, _ := strings.Cut(req.GetPath(), "?")
		f.calls = append(f.calls, path)
		var body map[string]any
		dec := json.NewDecoder(strings.NewReader(string(req.GetBody())))
		dec.UseNumber()
		_ = dec.Decode(&body)
		result := f.serve(path, body)
		raw, _ := json.Marshal(map[string]any{"ok": true, "result": result})
		return gatewaytest.Response{Frames: []*pb.ServiceFrame{
			gatewaytest.ResponseFrame(0, 200, raw, true),
		}}
	})
}

func (f *fakeFS) serve(path string, body map[string]any) any {
	getStr := func(k string) string {
		s, _ := body[k].(string)
		return s
	}
	switch path {
	case "/fs/list":
		dir := strings.Trim(getStr("path"), "/")
		return map[string]any{"entries": f.entries(dir)}
	case "/fs/stat":
		p := strings.Trim(getStr("path"), "/")
		if f.dirs[p] {
			return map[string]any{"name": base(p), "type": "directory", "modifiedAt": "2026-10-29T00:00:00Z"}
		}
		if data, ok := f.files[p]; ok {
			return map[string]any{"name": base(p), "type": "file", "size": len(data), "modifiedAt": "2026-10-29T00:00:00Z"}
		}
		return map[string]any{"name": base(p), "type": "file"}
	case "/fs/read":
		p := strings.Trim(getStr("path"), "/")
		data := f.files[p]
		off := int64(0)
		if n, ok := body["offset"].(json.Number); ok {
			off, _ = n.Int64()
		}
		ln := int64(len(data))
		if n, ok := body["len"].(json.Number); ok {
			ln, _ = n.Int64()
		}
		if off > int64(len(data)) {
			off = int64(len(data))
		}
		end := off + ln
		if end > int64(len(data)) {
			end = int64(len(data))
		}
		chunk := data[off:end]
		return map[string]any{"data_base64": base64.StdEncoding.EncodeToString(chunk), "eof": end >= int64(len(data))}
	case "/fs/write":
		p := strings.Trim(getStr("path"), "/")
		enc, _ := body["data_base64"].(string)
		chunk, _ := base64.StdEncoding.DecodeString(enc)
		appendMode, _ := body["append"].(bool)
		if appendMode {
			f.files[p] = append(f.files[p], chunk...)
		} else {
			f.files[p] = chunk
		}
		f.dirs[dirOf(p)] = true
		return map[string]any{}
	case "/fs/search":
		contains := ""
		if name, ok := body["name"].(map[string]any); ok {
			contains, _ = name["contains"].(string)
		}
		var entries []any
		for p := range f.files {
			if strings.Contains(base(p), contains) {
				entries = append(entries, map[string]any{"name": base(p), "type": "file", "path": p})
			}
		}
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].(map[string]any)["path"].(string) < entries[j].(map[string]any)["path"].(string)
		})
		if entries == nil {
			entries = []any{}
		}
		return map[string]any{"entries": entries}
	case "/fs/mkdir":
		p := strings.Trim(getStr("path"), "/")
		f.dirs[p] = true
		return map[string]any{"path": "/" + p}
	case "/fs/rename":
		src := strings.Trim(getStr("source"), "/")
		dst := strings.Trim(getStr("destination"), "/")
		if data, ok := f.files[src]; ok {
			f.files[dst] = data
			delete(f.files, src)
		}
		return map[string]any{"path": "/" + dst}
	case "/fs/delete":
		p := strings.Trim(getStr("path"), "/")
		delete(f.files, p)
		delete(f.dirs, p)
		return map[string]any{"path": "/" + p}
	}
	return map[string]any{}
}

func (f *fakeFS) entries(dir string) []any {
	var out []any
	seen := map[string]bool{}
	add := func(name, typ string, size int) {
		if seen[name] {
			return
		}
		seen[name] = true
		e := map[string]any{"name": name, "type": typ, "modifiedAt": "2026-10-29T00:00:00Z"}
		if typ == "file" {
			e["size"] = size
		}
		out = append(out, e)
	}
	for p, data := range f.files {
		parent := dirOf(p)
		if parent != dir {
			continue
		}
		add(base(p), "file", len(data))
	}
	for d := range f.dirs {
		if d == "" || d == dir {
			continue
		}
		if dirOf(d) == dir {
			add(base(d), "directory", 0)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].(map[string]any)["name"].(string) < out[j].(map[string]any)["name"].(string)
	})
	if out == nil {
		out = []any{}
	}
	return out
}

func base(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func dirOf(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[:i]
	}
	return ""
}

func fsStack(t *testing.T, fs *fakeFS) *fakeStack {
	t.Helper()
	return newFakeStack(t, fs.handler(), nil)
}

func TestFSLs(t *testing.T) {
	fs := newFakeFS()
	s := fsStack(t, fs)
	if code := s.run("fs", "ls", "notes"); code != 0 {
		t.Fatalf("ls: code=%d err=%q", code, s.errb.String())
	}
	if !strings.Contains(s.out.String(), "hello.txt") || strings.Contains(s.out.String(), ".hidden") {
		t.Errorf("ls must hide dotfiles by default: %q", s.out.String())
	}
	if code := s.run("fs", "ls", "-a", "notes"); code != 0 {
		t.Fatalf("ls -a: code=%d", code)
	}
	if !strings.Contains(s.out.String(), ".hidden") {
		t.Errorf("ls -a must show dotfiles: %q", s.out.String())
	}
	if code := s.run("fs", "ls", "-l", "notes"); code != 0 {
		t.Fatalf("ls -l: code=%d", code)
	}
	if !strings.Contains(s.out.String(), "hello.txt") {
		t.Errorf("ls -l: %q", s.out.String())
	}
	if code := s.run("fs", "ls", "--json", "notes"); code != 0 {
		t.Fatalf("ls --json: code=%d", code)
	}
	var entries []map[string]any
	mustJSON(t, s.out.Bytes(), &entries)
	if len(entries) != 1 || entries[0]["name"] != "hello.txt" {
		t.Errorf("ls --json entries=%v", entries)
	}
}

func TestFSTree(t *testing.T) {
	fs := newFakeFS()
	s := fsStack(t, fs)
	if code := s.run("fs", "tree", "--depth", "3", "a"); code != 0 {
		t.Fatalf("tree: code=%d err=%q", code, s.errb.String())
	}
	if !strings.Contains(s.out.String(), "c.txt") {
		t.Errorf("tree: %q", s.out.String())
	}
	if code := s.run("fs", "tree", "--json", "a"); code != 0 {
		t.Fatalf("tree --json: code=%d", code)
	}
	if !strings.Contains(s.out.String(), `"path":"a/b/c.txt"`) {
		t.Errorf("tree --json: %q", s.out.String())
	}
	// --depth -1 is ONE level in Python (the walk guard
	// _level+1 < depth is false at level 0), never unlimited:
	// the deep file must not appear.
	if code := s.run("fs", "tree", "--depth", "-1", "a"); code != 0 {
		t.Fatalf("tree --depth -1: code=%d err=%q", code, s.errb.String())
	}
	if strings.Contains(s.out.String(), "c.txt") {
		t.Errorf("tree --depth -1 must list one level only: %q", s.out.String())
	}
	if !strings.Contains(s.out.String(), "b/") {
		t.Errorf("tree --depth -1 must still list the top level: %q", s.out.String())
	}
}

func TestFSStatCatGet(t *testing.T) {
	fs := newFakeFS()
	s := fsStack(t, fs)
	if code := s.run("fs", "stat", "notes/hello.txt"); code != 0 {
		t.Fatalf("stat: code=%d", code)
	}
	if !strings.Contains(s.out.String(), `"size": 11`) {
		t.Errorf("stat: %q", s.out.String())
	}
	if code := s.run("fs", "cat", "notes/hello.txt"); code != 0 {
		t.Fatalf("cat: code=%d", code)
	}
	if s.out.String() != "hello world" {
		t.Errorf("cat: %q", s.out.String())
	}
	if code := s.run("fs", "cat", "--max-bytes", "5", "notes/hello.txt"); code != 0 {
		t.Fatalf("cat --max-bytes: code=%d", code)
	}
	if s.out.String() != "hello" {
		t.Errorf("cat --max-bytes: %q", s.out.String())
	}
	if code := s.run("fs", "cat", "bin/data.bin"); code != 1 {
		t.Fatalf("cat binary: code=%d, want 1", code)
	}
	if code := s.run("fs", "cat", "--binary", "bin/data.bin"); code != 0 {
		t.Fatalf("cat --binary: code=%d", code)
	}
	outDir := t.TempDir()
	if code := s.run("fs", "get", "notes/hello.txt", "-o", outDir); code != 0 {
		t.Fatalf("get: code=%d err=%q", code, s.errb.String())
	}
	data, err := os.ReadFile(filepath.Join(outDir, "hello.txt"))
	if err != nil || string(data) != "hello world" {
		t.Errorf("get file: data=%q err=%v", data, err)
	}
	if !strings.Contains(s.out.String(), `"saved"`) {
		t.Errorf("get out: %q", s.out.String())
	}
}

func TestFSFindPutWrite(t *testing.T) {
	fs := newFakeFS()
	s := fsStack(t, fs)
	if code := s.run("fs", "find", "hello"); code != 0 {
		t.Fatalf("find: code=%d", code)
	}
	if !strings.Contains(s.out.String(), "hello.txt") {
		t.Errorf("find: %q", s.out.String())
	}
	// put: local file -> remote.
	local := filepath.Join(t.TempDir(), "up.txt")
	if err := os.WriteFile(local, []byte("uploaded"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := s.run("fs", "put", local, "notes/up.txt"); code != 0 {
		t.Fatalf("put: code=%d err=%q", code, s.errb.String())
	}
	if string(fs.files["notes/up.txt"]) != "uploaded" {
		t.Errorf("put content=%q", fs.files["notes/up.txt"])
	}
	if !strings.Contains(s.out.String(), `"bytes_written": 8`) {
		t.Errorf("put out: %q", s.out.String())
	}
	// write: stdin -> remote, then --append.
	s.env.Stdin = strings.NewReader("first")
	if code := s.run("fs", "write", "notes/w.txt"); code != 0 {
		t.Fatalf("write: code=%d err=%q", code, s.errb.String())
	}
	if string(fs.files["notes/w.txt"]) != "first" {
		t.Errorf("write content=%q", fs.files["notes/w.txt"])
	}
	s.env.Stdin = strings.NewReader(" second")
	if code := s.run("fs", "write", "--append", "notes/w.txt"); code != 0 {
		t.Fatalf("write --append: code=%d", code)
	}
	if string(fs.files["notes/w.txt"]) != "first second" {
		t.Errorf("append content=%q", fs.files["notes/w.txt"])
	}
}

func TestFSEdit(t *testing.T) {
	fs := newFakeFS()
	s := fsStack(t, fs)
	if code := s.run("fs", "edit", "--replace", "world", "there", "notes/hello.txt"); code != 0 {
		t.Fatalf("edit replace: code=%d err=%q", code, s.errb.String())
	}
	if string(fs.files["notes/hello.txt"]) != "hello there" {
		t.Errorf("edit content=%q", fs.files["notes/hello.txt"])
	}
	if !strings.Contains(s.out.String(), `"changed": true`) {
		t.Errorf("edit out: %q", s.out.String())
	}
	// Unchanged replacement reports changed:false and writes nothing.
	if code := s.run("fs", "edit", "--replace", "there", "there", "notes/hello.txt"); code != 0 {
		t.Fatalf("edit unchanged: code=%d", code)
	}
	if !strings.Contains(s.out.String(), `"changed": false`) {
		t.Errorf("edit unchanged out: %q", s.out.String())
	}
	// Missing OLD is a ValueError: exit 2.
	if code := s.run("fs", "edit", "--replace", "zzz", "y", "notes/hello.txt"); code != 2 {
		t.Fatalf("edit missing old: code=%d, want 2", code)
	}
	// Editor path with EDITOR=true leaves the file unchanged.
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", "true")
	if code := s.run("fs", "edit", "notes/hello.txt"); code != 0 {
		t.Fatalf("edit editor: code=%d err=%q", code, s.errb.String())
	}
	if !strings.Contains(s.out.String(), `"changed": false`) {
		t.Errorf("edit editor out: %q", s.out.String())
	}
}

func TestFSMkdirMvRm(t *testing.T) {
	fs := newFakeFS()
	s := fsStack(t, fs)
	if code := s.run("fs", "mkdir", "newdir"); code != 0 {
		t.Fatalf("mkdir: code=%d", code)
	}
	if !fs.dirs["newdir"] {
		t.Error("mkdir did not create the dir")
	}
	if code := s.run("fs", "mv", "notes/hello.txt", "notes/moved.txt"); code != 0 {
		t.Fatalf("mv: code=%d", code)
	}
	if _, ok := fs.files["notes/moved.txt"]; !ok {
		t.Error("mv did not move the file")
	}
	// rm without --yes refuses BEFORE connecting: no fs call.
	before := len(fs.calls)
	if code := s.run("fs", "rm", "notes/moved.txt"); code != 2 {
		t.Fatalf("rm without --yes: code=%d, want 2", code)
	}
	if len(fs.calls) != before {
		t.Errorf("rm without --yes connected: calls=%v", fs.calls)
	}
	if code := s.run("fs", "rm", "--yes", "notes/moved.txt"); code != 0 {
		t.Fatalf("rm --yes: code=%d", code)
	}
	if _, ok := fs.files["notes/moved.txt"]; ok {
		t.Error("rm did not delete the file")
	}
	// Unknown fs subcommand exits 2.
	if code := s.run("fs", "bogus"); code != 2 {
		t.Fatalf("fs bogus: code=%d, want 2", code)
	}
	if code := s.run("fs"); code != 2 {
		t.Fatalf("fs no args: code=%d, want 2", code)
	}
}
