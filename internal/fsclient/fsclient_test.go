// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package fsclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/thoitiettxl-cyber/muse-cli/go/internal/conn"
	"github.com/thoitiettxl-cyber/muse-cli/go/internal/gateway"
)

// fakeCall records one CallJSON invocation.
type fakeCall struct {
	method  string
	body    map[string]any
	timeout time.Duration
}

// fakeGateway is an in-memory stand-in for Gateway.CallJSON over
// fs.* routes, mirroring the FakeGW in test_fs.py. Files map a
// normalized relative path to bytes; dirs holds normalized
// directory paths ("" is the root). dirKind selects the "kind"
// string stat reports for directories ("dir" by default, so one
// test can exercise the "directory" spelling fs.get also accepts).
type fakeGateway struct {
	files   map[string][]byte
	dirs    map[string]bool
	dirKind string
	calls   []fakeCall
	// failMethod makes CallJSON return err for one method.
	failMethod string
	failErr    error
}

func newFakeGateway(files map[string][]byte) *fakeGateway {
	f := &fakeGateway{files: map[string][]byte{}, dirs: map[string]bool{"": true}}
	for p, data := range files {
		f.files[p] = append([]byte(nil), data...)
		parts := strings.Split(p, "/")[:len(strings.Split(p, "/"))-1]
		for i := 1; i <= len(parts); i++ {
			f.dirs[strings.Join(parts[:i], "/")] = true
		}
	}
	return f
}

func (f *fakeGateway) dirKindOf() string {
	if f.dirKind != "" {
		return f.dirKind
	}
	return "dir"
}

func numArg(body map[string]any, key string) int64 {
	if n, ok := numberValue(body[key]); ok {
		return n
	}
	return 0
}

func (f *fakeGateway) CallJSON(_ context.Context, method string, opts conn.RequestOptions) (any, error) {
	body, _ := opts.Body.(map[string]any)
	f.calls = append(f.calls, fakeCall{method: method, body: body, timeout: opts.Timeout})
	if method == f.failMethod {
		return nil, f.failErr
	}
	p, _ := body["path"].(string)
	switch method {
	case "fs.list":
		names := map[string]map[string]any{}
		for file, data := range f.files {
			if dirOf(file) == p {
				names[baseOf(file)] = map[string]any{"name": baseOf(file), "type": "file", "size": int64(len(data))}
			}
		}
		for d := range f.dirs {
			if d != "" && dirOf(d) == p {
				names[baseOf(d)] = map[string]any{"name": baseOf(d), "type": "directory"}
			}
		}
		keys := make([]string, 0, len(names))
		for k := range names {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		entries := make([]any, 0, len(keys))
		for _, k := range keys {
			entries = append(entries, names[k])
		}
		return map[string]any{"path": p, "entries": entries}, nil
	case "fs.stat":
		kind := "file"
		if f.dirs[p] {
			kind = f.dirKindOf()
		}
		return map[string]any{"path": "/" + p, "kind": kind}, nil
	case "fs.read":
		data := f.files[p]
		off := numArg(body, "offset")
		length := numArg(body, "len")
		if off < 0 {
			off = 0
		}
		if off > int64(len(data)) {
			off = int64(len(data))
		}
		end := off + length
		if end > int64(len(data)) {
			end = int64(len(data))
		}
		chunk := data[off:end]
		return map[string]any{
			"data_base64": base64.StdEncoding.EncodeToString(chunk),
			"eof":         end >= int64(len(data)),
		}, nil
	case "fs.write":
		data, err := base64.StdEncoding.DecodeString(body["data_base64"].(string))
		if err != nil {
			return nil, err
		}
		appendFlag, _ := body["append"].(bool)
		if appendFlag {
			f.files[p] = append(f.files[p], data...)
		} else {
			f.files[p] = append([]byte(nil), data...)
		}
		// A write implies its parent directories exist.
		for d := dirOf(p); d != ""; d = dirOf(d) {
			f.dirs[d] = true
		}
		return map[string]any{"path": "/" + p, "bytes_written": int64(len(data))}, nil
	case "fs.mkdir":
		f.dirs[p] = true
		return map[string]any{"path": "/" + p, "created": true}, nil
	case "fs.rename":
		src, _ := body["source"].(string)
		dst, _ := body["destination"].(string)
		if data, ok := f.files[src]; ok {
			f.files[dst] = data
			delete(f.files, src)
			return map[string]any{"path": "/" + dst}, nil
		}
		if f.dirs[src] {
			delete(f.dirs, src)
			f.dirs[dst] = true
			for file, data := range f.files {
				if strings.HasPrefix(file, src+"/") {
					f.files[dst+file[len(src):]] = data
					delete(f.files, file)
				}
			}
			return map[string]any{"path": "/" + dst}, nil
		}
		return nil, fmt.Errorf("no such path: %s", src)
	case "fs.delete":
		recursive, _ := body["recursive"].(bool)
		if _, ok := f.files[p]; ok {
			delete(f.files, p)
			return map[string]any{"path": "/" + p}, nil
		}
		if f.dirs[p] {
			if !recursive {
				hasChild := false
				for file := range f.files {
					if strings.HasPrefix(file, p+"/") {
						hasChild = true
					}
				}
				if hasChild {
					return nil, fmt.Errorf("directory not empty: %s", p)
				}
			}
			for file := range f.files {
				if strings.HasPrefix(file, p+"/") {
					delete(f.files, file)
				}
			}
			delete(f.dirs, p)
			return map[string]any{"path": "/" + p}, nil
		}
		return nil, fmt.Errorf("no such path: %s", p)
	case "fs.search":
		name, _ := body["name"].(map[string]any)
		contains, _ := name["contains"].(string)
		limit := numArg(body, "limit")
		var paths []string
		for file := range f.files {
			if strings.Contains(baseOf(file), contains) {
				paths = append(paths, file)
			}
		}
		for d := range f.dirs {
			if d != "" && strings.Contains(baseOf(d), contains) {
				paths = append(paths, d)
			}
		}
		sort.Strings(paths)
		if limit > 0 && int64(len(paths)) > limit {
			paths = paths[:limit]
		}
		entries := make([]any, 0, len(paths))
		for _, pth := range paths {
			typ := "file"
			if f.dirs[pth] {
				typ = "directory"
			}
			entries = append(entries, map[string]any{"name": baseOf(pth), "type": typ, "path": pth})
		}
		return map[string]any{"entries": entries}, nil
	}
	return nil, fmt.Errorf("unexpected method %s", method)
}

func dirOf(p string) string {
	i := strings.LastIndex(p, "/")
	if i < 0 {
		return ""
	}
	return p[:i]
}

func baseOf(p string) string {
	i := strings.LastIndex(p, "/")
	if i < 0 {
		return p
	}
	return p[i+1:]
}

func TestNorm(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"/", ""},
		{"", ""},
		{"/config/home.yaml", "config/home.yaml"},
		{"sandbox://workspace/a.txt", "workspace/a.txt"},
		{"a//b/./c/", "a/b/c"},
		{"  /a/b  ", "a/b"},
		{`a\b\c`, "a/b/c"},
		{`sandbox://workspace\a.txt`, "workspace/a.txt"},
		{".", ""},
		{"./a", "a"},
		{"a/./b/../c", "a/c"},
	}
	for _, tc := range cases {
		if got, err := Norm(tc.in); err != nil || got != tc.want {
			t.Errorf("Norm(%q) = %q, %v, want %q", tc.in, got, err, tc.want)
		}
	}
}

func TestNormTraversalIsClamped(t *testing.T) {
	// Port of test_fs.py NormTest.test_traversal_is_clamped:
	// normpath on a rooted path clamps ".." away, so "../etc"
	// becomes "etc" instead of erroring. The traversal error in
	// Norm is unreachable for rooted input and is kept only as a
	// fail-closed guard.
	for _, tc := range []struct {
		in, want string
	}{
		{"../etc", "etc"},
		{"a/../../etc", "etc"},
		{"..", ""},
		{"a/..", ""},
	} {
		got, err := Norm(tc.in)
		if err != nil {
			t.Errorf("Norm(%q) error = %v, want clamped %q", tc.in, err, tc.want)
		} else if got != tc.want {
			t.Errorf("Norm(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestFSMethodNamesMatchRoutes(t *testing.T) {
	// The method names FS uses must be the routes.json names:
	// fs.rename, not fs.move. Verified through the real route
	// table, not a hardcoded copy.
	tbl, err := gateway.DefaultRoutes()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][2]string{
		"fs.list":   {"POST", "/fs/list"},
		"fs.read":   {"POST", "/fs/read"},
		"fs.stat":   {"POST", "/fs/stat"},
		"fs.search": {"POST", "/fs/search"},
		"fs.write":  {"POST", "/fs/write"},
		"fs.mkdir":  {"POST", "/fs/mkdir"},
		"fs.rename": {"POST", "/fs/rename"},
		"fs.delete": {"POST", "/fs/delete"},
	}
	for method, wantRoute := range want {
		r, ok := tbl.LookupRoute(method)
		if !ok {
			t.Errorf("LookupRoute(%q) = false, want a route", method)
			continue
		}
		if r.HTTP != wantRoute[0] || r.Path != wantRoute[1] {
			t.Errorf("LookupRoute(%q) = %s %s, want %s %s", method, r.HTTP, r.Path, wantRoute[0], wantRoute[1])
		}
	}
	if _, ok := tbl.LookupRoute("fs.move"); ok {
		t.Error("LookupRoute(fs.move) = true, want false: the move operation calls fs.rename")
	}
	// And FS must actually call those names: drive each method
	// once through the fake and check the recorded methods.
	ctx := context.Background()
	gw := newFakeGateway(map[string][]byte{"a.txt": []byte("x")})
	f := New(gw)
	_, _ = f.ListDir(ctx, "")
	_, _ = f.Stat(ctx, "a.txt")
	_, _, _ = f.ReadChunk(ctx, "a.txt", 0, 1)
	_, _ = f.Search(ctx, "a", 0)
	_, _ = f.WriteFile(ctx, "b.txt", []byte("y"), true, true)
	_, _ = f.Mkdir(ctx, "d", true)
	_, _ = f.Move(ctx, "a.txt", "c.txt", false, true)
	_, _ = f.Delete(ctx, "c.txt", false)
	var methods []string
	for _, c := range gw.calls {
		methods = append(methods, c.method)
	}
	wantMethods := []string{"fs.list", "fs.stat", "fs.read", "fs.search", "fs.write", "fs.mkdir", "fs.rename", "fs.delete"}
	if !reflect.DeepEqual(methods, wantMethods) {
		t.Errorf("methods called = %v, want %v", methods, wantMethods)
	}
}

func TestFSListAndWalk(t *testing.T) {
	// Port of test_fs.py FSTest.test_list_and_walk.
	f := New(newFakeGateway(map[string][]byte{
		"config/home.yaml": []byte("x"), "memory/a/b.md": []byte("y")}))
	ctx := context.Background()
	entries, err := f.ListDir(ctx, "/")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name)
	}
	if !reflect.DeepEqual(names, []string{"config", "memory"}) {
		t.Errorf("list_dir(/) names = %v, want [config memory]", names)
	}
	all, err := f.Walk(ctx, "", -1)
	if err != nil {
		t.Fatal(err)
	}
	var rels []string
	for _, we := range all {
		rels = append(rels, we.Rel)
	}
	if !containsStr(rels, "memory/a/b.md") {
		t.Errorf("walk rels = %v, want memory/a/b.md", rels)
	}
	shallow, err := f.Walk(ctx, "", 2)
	if err != nil {
		t.Fatal(err)
	}
	var shallowRels []string
	for _, we := range shallow {
		shallowRels = append(shallowRels, we.Rel)
	}
	if containsStr(shallowRels, "memory/a/b.md") {
		t.Errorf("walk depth=2 rels = %v, want no memory/a/b.md", shallowRels)
	}
	// Depth 1 yields only top-level children.
	one, err := f.Walk(ctx, "", 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, we := range one {
		if we.Level != 0 {
			t.Errorf("walk depth=1 level = %d for %s, want 0", we.Level, we.Rel)
		}
	}
}

func containsStr(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func TestFSChunkedReadAndWrite(t *testing.T) {
	// Port of test_fs.py FSTest.test_chunked_read_and_write.
	// Chunk sizes are package variables; restore them and do not
	// run this test in parallel with other FS tests.
	oldChunk, oldWrite := ChunkSize, WriteChunkSize
	ChunkSize, WriteChunkSize = 3, 3
	defer func() { ChunkSize, WriteChunkSize = oldChunk, oldWrite }()

	gw := newFakeGateway(map[string][]byte{"f.bin": []byte("0123456789")})
	f := New(gw)
	ctx := context.Background()
	got, err := f.ReadFile(ctx, "f.bin", nil)
	if err != nil || string(got) != "0123456789" {
		t.Errorf("read_file = %q, %v, want 0123456789", got, err)
	}
	max := int64(4)
	got, err = f.ReadFile(ctx, "f.bin", &max)
	if err != nil || string(got) != "0123" {
		t.Errorf("read_file(max_bytes=4) = %q, %v, want 0123", got, err)
	}
	res, err := f.WriteFile(ctx, "g.bin", []byte("abcdefgh"), true, true)
	if err != nil {
		t.Fatal(err)
	}
	if string(gw.files["g.bin"]) != "abcdefgh" {
		t.Errorf("g.bin = %q, want abcdefgh", gw.files["g.bin"])
	}
	if res.Path != "/g.bin" || res.BytesWritten != 8 {
		t.Errorf("write result = %+v, want {/g.bin 8}", res)
	}
	var appends []bool
	var overwrites []bool
	var timeouts []time.Duration
	for _, c := range gw.calls {
		if c.method == "fs.write" {
			appendFlag, _ := c.body["append"].(bool)
			overwriteFlag, _ := c.body["overwrite"].(bool)
			appends = append(appends, appendFlag)
			overwrites = append(overwrites, overwriteFlag)
			timeouts = append(timeouts, c.timeout)
		}
	}
	if !reflect.DeepEqual(appends, []bool{false, true, true}) {
		t.Errorf("fs.write append flags = %v, want [false true true]", appends)
	}
	if !reflect.DeepEqual(overwrites, []bool{true, true, true}) {
		t.Errorf("fs.write overwrite flags = %v, want all true", overwrites)
	}
	for _, to := range timeouts {
		if to != 120*time.Second {
			t.Errorf("fs.write timeout = %v, want 120s", to)
		}
	}
	// First-chunk overwrite=false is honoured only on the first chunk.
	gw2 := newFakeGateway(nil)
	f2 := New(gw2)
	_, err = f2.WriteFile(ctx, "h.bin", []byte("abcdef"), false, false)
	if err != nil {
		t.Fatal(err)
	}
	var ow2 []bool
	var cp2 []bool
	for _, c := range gw2.calls {
		if c.method == "fs.write" {
			ow, _ := c.body["overwrite"].(bool)
			cp, _ := c.body["create_parent"].(bool)
			ow2 = append(ow2, ow)
			cp2 = append(cp2, cp)
		}
	}
	if !reflect.DeepEqual(ow2, []bool{false, true}) {
		t.Errorf("overwrite flags = %v, want [false true]", ow2)
	}
	if !reflect.DeepEqual(cp2, []bool{false, false}) {
		t.Errorf("create_parent flags = %v, want [false false]", cp2)
	}
	// Empty data still makes exactly one (empty) call.
	gw3 := newFakeGateway(nil)
	f3 := New(gw3)
	res, err = f3.WriteFile(ctx, "e.bin", nil, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.BytesWritten != 0 || res.Path != "/e.bin" {
		t.Errorf("empty write result = %+v", res)
	}
	if len(gw3.calls) != 1 {
		t.Errorf("empty write calls = %d, want 1", len(gw3.calls))
	}
	// Read timeout is 120s; other calls use 60s.
	for _, c := range gw.calls {
		if c.method == "fs.read" && c.timeout != 120*time.Second {
			t.Errorf("fs.read timeout = %v, want 120s", c.timeout)
		}
		if c.method == "fs.list" && c.timeout != 60*time.Second {
			t.Errorf("fs.list timeout = %v, want 60s", c.timeout)
		}
	}
}

func TestFSReadFileMaxBytesEdges(t *testing.T) {
	gw := newFakeGateway(map[string][]byte{"f.bin": []byte("0123")})
	f := New(gw)
	ctx := context.Background()
	zero := int64(0)
	got, err := f.ReadFile(ctx, "f.bin", &zero)
	if err != nil || len(got) != 0 {
		t.Errorf("max_bytes=0 = %q, %v, want empty", got, err)
	}
	if len(gw.calls) != 0 {
		t.Errorf("max_bytes=0 made %d calls, want 0", len(gw.calls))
	}
	neg := int64(-5)
	got, err = f.ReadFile(ctx, "f.bin", &neg)
	if err != nil || len(got) != 0 {
		t.Errorf("max_bytes=-5 = %q, %v, want empty", got, err)
	}
	if len(gw.calls) != 0 {
		t.Errorf("max_bytes=-5 made %d calls, want 0", len(gw.calls))
	}
}

func TestFSReadChunkEOFDefaultAndBadBase64(t *testing.T) {
	gw := newFakeGateway(map[string][]byte{"f.bin": []byte("abc")})
	ctx := context.Background()
	// The fake always sends eof; strip it via a wrapper gateway to
	// prove the default-true rule.
	stripping := &eofStrippingGateway{inner: gw}
	f2 := New(stripping)
	data, eof, err := f2.ReadChunk(ctx, "f.bin", 0, 3)
	if err != nil || string(data) != "abc" || !eof {
		t.Errorf("ReadChunk without eof = %q, eof=%v, %v, want abc/true", data, eof, err)
	}
	bad := &badBase64Gateway{}
	f3 := New(bad)
	if _, _, err := f3.ReadChunk(ctx, "f.bin", 0, 3); err == nil {
		t.Error("ReadChunk with invalid base64: got nil error")
	}
}

type eofStrippingGateway struct{ inner *fakeGateway }

func (g *eofStrippingGateway) CallJSON(ctx context.Context, method string, opts conn.RequestOptions) (any, error) {
	res, err := g.inner.CallJSON(ctx, method, opts)
	if err != nil {
		return nil, err
	}
	if m, ok := res.(map[string]any); ok {
		delete(m, "eof")
	}
	return res, nil
}

type badBase64Gateway struct{}

func (badBase64Gateway) CallJSON(_ context.Context, _ string, _ conn.RequestOptions) (any, error) {
	return map[string]any{"data_base64": "!!!not-base64!!!", "eof": true}, nil
}

func TestFSPutSkipsSymlinkToDir(t *testing.T) {
	// Python os.walk (followlinks=False) lists a symlink-to-dir
	// without descending into it and never uploads it: Put must
	// mirror that. A symlink-to-file still uploads the target
	// content as a file (open() follows it), like Python.
	gw := newFakeGateway(map[string][]byte{})
	f := New(gw)
	ctx := context.Background()
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.MkdirAll(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(realDir, "a.txt"), []byte("A"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "target.txt"), []byte("T"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realDir, filepath.Join(root, "linkdir")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "target.txt"), filepath.Join(root, "linkfile.txt")); err != nil {
		t.Fatal(err)
	}
	res, err := f.Put(ctx, root, "remote/up", true, true)
	if err != nil {
		t.Fatal(err)
	}
	if string(gw.files["remote/up/real/a.txt"]) != "A" {
		t.Errorf("remote/up/real/a.txt = %q, want A", gw.files["remote/up/real/a.txt"])
	}
	if _, ok := gw.files["remote/up/linkdir"]; ok {
		t.Errorf("symlink-to-dir uploaded as a file: remote/up/linkdir = %q", gw.files["remote/up/linkdir"])
	}
	if _, ok := gw.files["remote/up/linkdir/a.txt"]; ok {
		t.Error("symlink-to-dir descended: remote/up/linkdir/a.txt exists, want it skipped")
	}
	if string(gw.files["remote/up/linkfile.txt"]) != "T" {
		t.Errorf("remote/up/linkfile.txt = %q, want target content T", gw.files["remote/up/linkfile.txt"])
	}
	_ = res
}

func TestFSGetAndPutRecursive(t *testing.T) {
	// Port of test_fs.py FSTest.test_get_and_put_recursive.
	gw := newFakeGateway(map[string][]byte{"memory/a.md": []byte("A"), "memory/sub/b.md": []byte("B")})
	f := New(gw)
	ctx := context.Background()
	dir := t.TempDir()
	got, err := f.Get(ctx, "memory", dir, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("get returned %v, want 2 paths", got)
	}
	content, err := os.ReadFile(filepath.Join(dir, "memory", "sub", "b.md"))
	if err != nil || string(content) != "B" {
		t.Errorf("memory/sub/b.md = %q, %v, want B", content, err)
	}
	if _, err := f.Get(ctx, "memory", dir, false); err == nil {
		t.Error("get folder without -r: got nil error, want folder error")
	} else if !strings.Contains(err.Error(), "is a folder; use -r") {
		t.Errorf("get folder error = %q, want folder/use -r text", err)
	}
	if _, err := f.Put(ctx, filepath.Join(dir, "memory"), "data/copy", true, true); err != nil {
		t.Fatal(err)
	}
	if string(gw.files["data/copy/sub/b.md"]) != "B" {
		t.Errorf("data/copy/sub/b.md = %q, want B", gw.files["data/copy/sub/b.md"])
	}
}

func TestFSGetFileAndPutFile(t *testing.T) {
	gw := newFakeGateway(map[string][]byte{"a.txt": []byte("hello")})
	f := New(gw)
	ctx := context.Background()
	dir := t.TempDir()
	// Destination is an existing directory: file lands inside it.
	got, err := f.Get(ctx, "a.txt", dir, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != filepath.Join(dir, "a.txt") {
		t.Errorf("get file to dir = %v, want [%s]", got, filepath.Join(dir, "a.txt"))
	}
	// Destination is an exact file path.
	exact := filepath.Join(dir, "renamed.txt")
	got, err = f.Get(ctx, "a.txt", exact, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != exact {
		t.Errorf("get file to path = %v, want [%s]", got, exact)
	}
	// Put a single file; "directory" kind spelling is also accepted.
	gw.dirKind = "directory"
	res, err := f.Put(ctx, exact, "remote/copy.txt", false, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 || res[0].Path != "/remote/copy.txt" || res[0].BytesWritten != 5 {
		t.Errorf("put file = %+v, want {/remote/copy.txt 5}", res)
	}
	// Put a folder without -r errors naming the local path.
	if _, err := f.Put(ctx, dir, "remote/x", false, true); err == nil {
		t.Error("put folder without -r: got nil error")
	} else if !strings.Contains(err.Error(), "is a folder; use -r") {
		t.Errorf("put folder error = %q", err)
	}
}

func TestFSMoveDeleteMkdirStatSearch(t *testing.T) {
	gw := newFakeGateway(map[string][]byte{"a.txt": []byte("x"), "b.log": []byte("y")})
	f := New(gw)
	ctx := context.Background()
	st, err := f.Stat(ctx, "a.txt")
	if err != nil || st["kind"] != "file" {
		t.Errorf("stat = %v, %v, want kind file", st, err)
	}
	if _, err := f.Mkdir(ctx, "newdir", true); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Move(ctx, "a.txt", "newdir/a.txt", false, true); err != nil {
		t.Fatal(err)
	}
	if _, ok := gw.files["newdir/a.txt"]; !ok {
		t.Error("move did not create newdir/a.txt in fake")
	}
	if _, ok := gw.files["a.txt"]; ok {
		t.Error("move left a.txt in fake")
	}
	// Verify the move call body used fs.rename with source/destination.
	var renameBody map[string]any
	for _, c := range gw.calls {
		if c.method == "fs.rename" {
			renameBody = c.body
		}
	}
	if renameBody["source"] != "a.txt" || renameBody["destination"] != "newdir/a.txt" {
		t.Errorf("fs.rename body = %v", renameBody)
	}
	if _, err := f.Delete(ctx, "b.log", false); err != nil {
		t.Fatal(err)
	}
	if _, ok := gw.files["b.log"]; ok {
		t.Error("delete left b.log in fake")
	}
	results, err := f.Search(ctx, "a.txt", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Name != "a.txt" {
		t.Errorf("search = %+v, want one a.txt", results)
	}
	// Search limit is sent only when positive.
	gw.calls = nil
	_, _ = f.Search(ctx, "a", 1)
	if _, ok := gw.calls[0].body["limit"]; !ok {
		t.Errorf("search limit=1 body = %v, want limit key", gw.calls[0].body)
	}
	gw.calls = nil
	_, _ = f.Search(ctx, "a", 0)
	if _, ok := gw.calls[0].body["limit"]; ok {
		t.Errorf("search limit=0 body = %v, want no limit key", gw.calls[0].body)
	}
}

func TestFSGatewayErrorPropagates(t *testing.T) {
	gw := newFakeGateway(nil)
	want := errors.New("gateway down")
	gw.failMethod = "fs.list"
	gw.failErr = want
	f := New(gw)
	if _, err := f.ListDir(context.Background(), ""); !errors.Is(err, want) {
		t.Errorf("ListDir error = %v, want %v", err, want)
	}
	if _, err := New(nil).ListDir(context.Background(), ""); err == nil {
		t.Error("nil gateway ListDir: got nil error")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.ListDir(ctx, ""); err == nil {
		t.Error("cancelled ctx ListDir: got nil error")
	}
}

func TestEntryMarshalJSON(t *testing.T) {
	size := int64(12)
	e := Entry{Name: "a.txt", Type: "file", Size: &size, ModifiedAt: "2026-10-24T12:57:37",
		Extra: map[string]any{"owner": "boss"}}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"name":"a.txt","type":"file","size":12,"modifiedAt":"2026-10-24T12:57:37","owner":"boss"}`
	if string(b) != want {
		t.Errorf("Marshal(Entry) = %s, want %s", b, want)
	}
	// Absent optionals are omitted, as Python's missing keys are.
	b, err = json.Marshal(Entry{Name: "d"})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"name":"d"}` {
		t.Errorf("Marshal(minimal Entry) = %s, want {\"name\":\"d\"}", b)
	}
}

func TestWriteResultJSON(t *testing.T) {
	b, err := json.Marshal(WriteResult{Path: "/g.bin", BytesWritten: 8})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"path":"/g.bin","bytes_written":8}` {
		t.Errorf("Marshal(WriteResult) = %s", b)
	}
}
