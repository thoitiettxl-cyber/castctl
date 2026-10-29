// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package fsclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	posixpath "path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/thoitiettxl-cyber/muse-cli/go/internal/conn"
)

// ChunkSize is the fs.read window, ported from fs.py's CHUNK
// (4 MiB). A non-positive value behaves as the default, so a
// mis-set variable can never wedge ReadFile in an empty-chunk loop
// (Python would spin forever on WRITE_CHUNK=0; the Go port fails
// closed to the default instead).
var ChunkSize = 4 * 1024 * 1024

// WriteChunkSize is the raw bytes per fs.write call, ported from
// fs.py's WRITE_CHUNK (1 MiB): the base64 body must stay under the
// gateway limit.
var WriteChunkSize = 1024 * 1024

// readChunkSize returns the effective read window.
func readChunkSize() int {
	if ChunkSize <= 0 {
		return 4 * 1024 * 1024
	}
	return ChunkSize
}

// writeChunkSize returns the effective write chunk size.
func writeChunkSize() int {
	if WriteChunkSize <= 0 {
		return 1024 * 1024
	}
	return WriteChunkSize
}

// readTimeout bounds one fs.read call (fs.py: timeout=120).
const readTimeout = 120 * time.Second

// writeTimeout bounds one fs.write call (fs.py: timeout=120).
const writeTimeout = 120 * time.Second

// callTimeout bounds the remaining fs.* calls (fs.py: _call
// default timeout=60).
const callTimeout = 60 * time.Second

// Gateway is the narrow gateway contract FS needs: one unary JSON
// call. It deliberately carries only CallJSON: FS never opens a
// stream, subscribes, or downloads, so Request and DownloadFile
// are not part of this contract even though conn.Gateway offers
// them. Defining the interface where it is consumed keeps fakes
// to one method and keeps this package independent of the wire
// gateway. conn.Gateway satisfies it; see the compile-time check
// below.
type Gateway interface {
	CallJSON(ctx context.Context, method string, opts conn.RequestOptions) (any, error)
}

var _ Gateway = (conn.Gateway)(nil)

// FS is the System Files client, ported from fs.py's FS class. An
// FS is safe for concurrent use when its Gateway is. Construct it
// with New; the zero value has no gateway and every method fails.
type FS struct {
	gw Gateway
}

// New builds an FS over gw. A nil gw is accepted and makes every
// method return an error instead of panicking.
func New(gw Gateway) *FS {
	return &FS{gw: gw}
}

// Norm normalizes a remote path, ported verbatim from fs.py:6-15
// (norm). It strips surrounding whitespace, maps backslashes to
// slashes, strips one leading "sandbox://" prefix, and resolves
// "." and duplicate slashes against the root, so "/" and "" both
// become "" and "/config/home.yaml" becomes "config/home.yaml".
// A ".." segment that survives rooting is a traversal error; for
// rooted input normpath clamps ".." away (norm("../etc") is
// "etc"), so the error is unreachable in practice but is kept, as
// in Python, so the check fails closed if the rooting ever
// changes. The path package (POSIX) is used, never filepath:
// remote paths are always POSIX, even on non-POSIX hosts.
func Norm(p string) (string, error) {
	s := strings.TrimSpace(p)
	s = strings.ReplaceAll(s, "\\", "/")
	s = strings.TrimPrefix(s, "sandbox://")
	s = strings.TrimLeft(posixpath.Clean("/"+s), "/")
	if s == "." {
		s = ""
	}
	for _, part := range strings.Split(s, "/") {
		if part == ".." {
			return "", fmt.Errorf("path traversal not allowed: %s", pythonRepr(p))
		}
	}
	return s, nil
}

// pythonRepr renders s the way Python's repr() renders a str for
// the common cases: single quotes, with backslash, single-quote,
// newline, carriage-return and tab escaped. Error messages in this
// package quote user input Python-style (e.g. norm's traversal
// error) so stderr text matches Python's for ordinary paths.
func pythonRepr(s string) string {
	var b strings.Builder
	b.WriteByte('\'')
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString("\\\\")
		case '\'':
			b.WriteString("\\'")
		case '\n':
			b.WriteString("\\n")
		case '\r':
			b.WriteString("\\r")
		case '\t':
			b.WriteString("\\t")
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('\'')
	return b.String()
}

// Entry is one fs.list / fs.search entry. Name, Type, Size and
// ModifiedAt are the fields the fs commands read (ls -l uses type,
// size and modifiedAt; tree uses name and type); every other
// server field is preserved verbatim in Extra so --json output
// keeps it. JSON field order is name, type, size, modifiedAt,
// then Extra keys in sorted order.
type Entry struct {
	// Name is the entry's file name (never a path).
	Name string `json:"name"`
	// Type is the entry's type ("file", "directory", ...), or ""
	// when the server sent none.
	Type string `json:"type,omitempty"`
	// Size is the entry's size in bytes, or nil when the server
	// sent none.
	Size *int64 `json:"size,omitempty"`
	// ModifiedAt is the entry's modification timestamp string,
	// or "" when the server sent none.
	ModifiedAt string `json:"modifiedAt,omitempty"`
	// Extra holds every server field beyond the four above,
	// decoded verbatim.
	Extra map[string]any `json:"-"`
}

// MarshalJSON renders an Entry with the known fields first (in
// struct order) and Extra keys after, sorted. This keeps unknown
// server fields in --json output without letting a hand-built
// Extra shadow a known field.
func (e Entry) MarshalJSON() ([]byte, error) {
	var b strings.Builder
	b.WriteString(`{"name":`)
	name, err := json.Marshal(e.Name)
	if err != nil {
		return nil, err
	}
	b.Write(name)
	if e.Type != "" {
		b.WriteString(`,"type":`)
		v, err := json.Marshal(e.Type)
		if err != nil {
			return nil, err
		}
		b.Write(v)
	}
	if e.Size != nil {
		b.WriteString(`,"size":`)
		v, err := json.Marshal(*e.Size)
		if err != nil {
			return nil, err
		}
		b.Write(v)
	}
	if e.ModifiedAt != "" {
		b.WriteString(`,"modifiedAt":`)
		v, err := json.Marshal(e.ModifiedAt)
		if err != nil {
			return nil, err
		}
		b.Write(v)
	}
	keys := make([]string, 0, len(e.Extra))
	for k := range e.Extra {
		switch k {
		case "name", "type", "size", "modifiedAt":
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.WriteString(",")
		kb, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		b.Write(kb)
		b.WriteString(":")
		vb, err := json.Marshal(e.Extra[k])
		if err != nil {
			return nil, err
		}
		b.Write(vb)
	}
	b.WriteString("}")
	return []byte(b.String()), nil
}

// decodeEntry converts one decoded entry object into an Entry,
// keeping unknown fields in Extra.
func decodeEntry(v any) (Entry, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return Entry{}, fmt.Errorf("fsclient: entry is %T, want object", v)
	}
	var e Entry
	if s, ok := m["name"].(string); ok {
		e.Name = s
	}
	if s, ok := m["type"].(string); ok {
		e.Type = s
	}
	if n, ok := numberValue(m["size"]); ok {
		e.Size = &n
	}
	if s, ok := m["modifiedAt"].(string); ok {
		e.ModifiedAt = s
	}
	for k, val := range m {
		switch k {
		case "name", "type", "size", "modifiedAt":
			continue
		}
		if e.Extra == nil {
			e.Extra = map[string]any{}
		}
		e.Extra[k] = val
	}
	return e, nil
}

// numberValue converts a decoded JSON number (json.Number, int64,
// int, float64) to int64, truncating a fractional part toward
// zero. Non-numbers report false.
func numberValue(v any) (int64, bool) {
	switch n := v.(type) {
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return i, true
		}
		f, err := n.Float64()
		if err != nil {
			return 0, false
		}
		return int64(f), true
	case int64:
		return n, true
	case int:
		return int64(n), true
	case float64:
		return int64(n), true
	default:
		return 0, false
	}
}

// decodeEntries extracts the "entries" list of an fs.list /
// fs.search result. A missing entries key yields no entries, as
// Python's .get("entries", []) does; a non-object result or a
// non-object entry is an error.
func decodeEntries(result any, method string) ([]Entry, error) {
	m, ok := result.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("fsclient: %s: response is %T, want object", method, result)
	}
	raw, present := m["entries"]
	if !present || raw == nil {
		return nil, nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("fsclient: %s: entries is %T, want array", method, raw)
	}
	entries := make([]Entry, 0, len(list))
	for i, item := range list {
		e, err := decodeEntry(item)
		if err != nil {
			return nil, fmt.Errorf("fsclient: %s: entry %d: %w", method, i, err)
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// call performs one fs.* call and returns its decoded object
// result. A nil gateway, a non-object result, and a gateway error
// are all errors.
func (f *FS) call(ctx context.Context, method string, body map[string]any, timeout time.Duration) (map[string]any, error) {
	if f == nil || f.gw == nil {
		return nil, fmt.Errorf("fsclient: nil gateway")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result, err := f.gw.CallJSON(ctx, method, conn.RequestOptions{Body: body, Timeout: timeout})
	if err != nil {
		return nil, err
	}
	m, ok := result.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("fsclient: %s: response is %T, want object", method, result)
	}
	return m, nil
}

// ListDir lists a remote directory, ported from fs.py (list_dir):
// fs.list with the normalized path, returning the entries list
// (empty when the server sends none).
func (f *FS) ListDir(ctx context.Context, path string) ([]Entry, error) {
	p, err := Norm(path)
	if err != nil {
		return nil, err
	}
	result, err := f.call(ctx, "fs.list", map[string]any{"path": p}, callTimeout)
	if err != nil {
		return nil, err
	}
	return decodeEntries(result, "fs.list")
}

// Stat stats a remote path, ported from fs.py (stat): fs.stat
// with the normalized path, returning the server's result object
// verbatim. The shape is server-defined, so the result passes
// through as a decoded object rather than a fixed struct.
func (f *FS) Stat(ctx context.Context, path string) (map[string]any, error) {
	p, err := Norm(path)
	if err != nil {
		return nil, err
	}
	return f.call(ctx, "fs.stat", map[string]any{"path": p}, callTimeout)
}

// ReadChunk reads one window of a remote file, ported from fs.py
// (read_chunk): fs.read with offset/len, a 120s timeout, and a
// base64-decoded body. It returns the bytes and whether the server
// reported end-of-file (defaulting to true when the server sends
// no eof flag, as Python's r.get("eof", True) does).
func (f *FS) ReadChunk(ctx context.Context, path string, offset, length int64) ([]byte, bool, error) {
	p, err := Norm(path)
	if err != nil {
		return nil, false, err
	}
	result, err := f.call(ctx, "fs.read", map[string]any{
		"path": p, "offset": offset, "len": length,
	}, readTimeout)
	if err != nil {
		return nil, false, err
	}
	encoded, _ := result["data_base64"].(string)
	encoded = strings.Map(func(r rune) rune {
		// Python's b64decode (validate=False) ignores
		// whitespace; strip it so wrapped base64 decodes.
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '\f' || r == '\v' {
			return -1
		}
		return r
	}, encoded)
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, false, fmt.Errorf("fsclient: fs.read: decode data_base64: %w", err)
	}
	eof := true
	if v, present := result["eof"]; present {
		eof = truthyValue(v)
	}
	return data, eof, nil
}

// truthyValue mirrors Python's bool() for the values a server
// flag may carry: nil/false/0/"" are false, everything else true.
func truthyValue(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	case []any:
		return len(t) > 0
	case map[string]any:
		return len(t) > 0
	default:
		if n, ok := numberValue(v); ok {
			return n != 0
		}
		return v != nil
	}
}

// ReadFile reads a whole remote file, ported from fs.py
// (read_file): it loops ReadChunk windows to EOF or an empty
// chunk, stopping early once maxBytes bytes have been read. A nil
// maxBytes reads to EOF; a non-positive maxBytes reads nothing
// and makes no call, exactly as Python's `if n <= 0: break`
// before the first chunk does.
func (f *FS) ReadFile(ctx context.Context, path string, maxBytes *int64) ([]byte, error) {
	var out []byte
	var off int64
	for {
		var n int64
		if maxBytes == nil {
			n = int64(readChunkSize())
		} else {
			n = min(int64(readChunkSize()), *maxBytes-off)
		}
		if n <= 0 {
			break
		}
		data, eof, err := f.ReadChunk(ctx, path, off, n)
		if err != nil {
			return nil, err
		}
		out = append(out, data...)
		off += int64(len(data))
		if eof || len(data) == 0 {
			break
		}
	}
	return out, nil
}

// Search searches remote file names, ported from fs.py (search):
// fs.search with {name: {contains}}, plus "limit" only when limit
// is positive (Python's `if limit:` omits 0 and negatives too).
func (f *FS) Search(ctx context.Context, contains string, limit int64) ([]Entry, error) {
	body := map[string]any{"name": map[string]any{"contains": contains}}
	if limit > 0 {
		body["limit"] = limit
	}
	result, err := f.call(ctx, "fs.search", body, callTimeout)
	if err != nil {
		return nil, err
	}
	return decodeEntries(result, "fs.search")
}

// WalkEntry is one step of a depth-first walk: the entry's path
// relative to the System Files root, the entry itself, and its
// depth level (0 for the top directory's children).
type WalkEntry struct {
	// Rel is the entry path relative to the root, e.g.
	// "memory/a/b.md".
	Rel string
	// Entry is the listed entry.
	Entry Entry
	// Level is 0 for children of the walked path, 1 for their
	// children, and so on.
	Level int
}

// unlimitedDepth is the Walk depth sentinel for "no cap": only
// internal callers (Get) may pass it. CLI depths are clamped by
// the command layer before they reach Walk.
const unlimitedDepth = -1

// Walk lists a subtree depth-first, ported from fs.py (walk).
// depth caps recursion: a directory at level L is descended into
// only when depth is negative (unlimited, the internal sentinel)
// or L+1 < depth, so depth 1 yields only the top directory's
// children and depth 2 yields two levels, exactly as Python's
// `_level + 1 < depth` guard does. A negative depth is unlimited
// ONLY as the internal sentinel: Python's tree command passes
// its CLI depth (where -1 means one level) through the same
// guard, so the command layer must clamp negative CLI depths to
// 0 before calling Walk.
func (f *FS) Walk(ctx context.Context, path string, depth int) ([]WalkEntry, error) {
	base, err := Norm(path)
	if err != nil {
		return nil, err
	}
	var out []WalkEntry
	if err := f.walkInto(ctx, base, 0, depth, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (f *FS) walkInto(ctx context.Context, base string, level, depth int, out *[]WalkEntry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	entries, err := f.ListDir(ctx, base)
	if err != nil {
		return err
	}
	for _, e := range entries {
		rel := e.Name
		if base != "" {
			rel = base + "/" + e.Name
		}
		*out = append(*out, WalkEntry{Rel: rel, Entry: e, Level: level})
		if e.Type == "directory" && (depth < 0 || level+1 < depth) {
			if err := f.walkInto(ctx, rel, level+1, depth, out); err != nil {
				return err
			}
		}
	}
	return nil
}

// WriteResult is the result of WriteFile, ported from fs.py
// (write_file's return): the written path with a leading slash and
// the number of bytes written.
type WriteResult struct {
	Path         string `json:"path"`
	BytesWritten int64  `json:"bytes_written"`
}

// WriteFile writes data to a remote path, ported verbatim from
// fs.py (write_file). Data is sent in WriteChunkSize raw-byte
// chunks, each base64-encoded with a 120s timeout. The first chunk
// carries the caller's overwrite flag and create_parent; later
// chunks carry overwrite=true and append=true. Empty data still
// makes one (empty) call, as Python's `while first or off <
// len(data)` loop does. The server's per-chunk replies are
// discarded; the returned result is built locally, as in Python.
func (f *FS) WriteFile(ctx context.Context, path string, data []byte, overwrite, createParent bool) (WriteResult, error) {
	p, err := Norm(path)
	if err != nil {
		return WriteResult{}, err
	}
	off := 0
	first := true
	for first || off < len(data) {
		end := off + writeChunkSize()
		if end > len(data) {
			end = len(data)
		}
		part := data[off:end]
		chunkOverwrite := overwrite
		if !first {
			chunkOverwrite = true
		}
		_, err := f.call(ctx, "fs.write", map[string]any{
			"path": p, "overwrite": chunkOverwrite, "append": !first,
			"create_parent": createParent,
			"data_base64":   base64.StdEncoding.EncodeToString(part),
		}, writeTimeout)
		if err != nil {
			return WriteResult{}, err
		}
		off = end
		first = false
	}
	return WriteResult{Path: "/" + p, BytesWritten: int64(len(data))}, nil
}

// Mkdir creates a remote directory, ported from fs.py (mkdir):
// fs.mkdir with the normalized path and the recursive flag. The
// server's result object passes through verbatim.
func (f *FS) Mkdir(ctx context.Context, path string, parents bool) (map[string]any, error) {
	p, err := Norm(path)
	if err != nil {
		return nil, err
	}
	return f.call(ctx, "fs.mkdir", map[string]any{"path": p, "recursive": parents}, callTimeout)
}

// Move renames a remote path, ported from fs.py (move). The
// method is "fs.rename" — routes.json has no "fs.move" — with
// source, destination, overwrite and create_parent, all paths
// normalized. The server's result object passes through verbatim.
func (f *FS) Move(ctx context.Context, src, dst string, overwrite, createParent bool) (map[string]any, error) {
	source, err := Norm(src)
	if err != nil {
		return nil, err
	}
	destination, err := Norm(dst)
	if err != nil {
		return nil, err
	}
	return f.call(ctx, "fs.rename", map[string]any{
		"source": source, "destination": destination,
		"overwrite": overwrite, "create_parent": createParent,
	}, callTimeout)
}

// Delete deletes a remote path, ported from fs.py (delete):
// fs.delete with the normalized path and the recursive flag. The
// server's result object passes through verbatim.
func (f *FS) Delete(ctx context.Context, path string, recursive bool) (map[string]any, error) {
	p, err := Norm(path)
	if err != nil {
		return nil, err
	}
	return f.call(ctx, "fs.delete", map[string]any{"path": p, "recursive": recursive}, callTimeout)
}

// Get downloads a remote file (or, with recursive, a folder) into
// a local destination, ported verbatim from fs.py (get). It
// returns the local paths written. For a folder, the destination
// gains a subdirectory named after the folder ("system-files"
// for the root) and the folder structure is kept; for a file, the
// destination is a directory to place the file in, or the exact
// file path when it is not an existing directory. Files are
// written directly, with no ".part" staging, no skip-if-exists
// and no byte_len warning — that staging belongs to
// shared.SaveResources. A folder without recursive is an error
// naming the original path argument, as in Python.
func (f *FS) Get(ctx context.Context, path, dest string, recursive bool) ([]string, error) {
	p, err := Norm(path)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat(ctx, p)
	if err != nil {
		return nil, err
	}
	name := "system-files"
	if p != "" {
		name = posixpath.Base(p)
	}
	kind, _ := st["kind"].(string)
	if kind == "dir" || kind == "directory" {
		if !recursive {
			return nil, fmt.Errorf("%s is a folder; use -r", path)
		}
		root := filepath.Join(dest, name)
		if err := os.MkdirAll(root, 0o777); err != nil {
			return nil, err
		}
		entries, err := f.Walk(ctx, p, unlimitedDepth)
		if err != nil {
			return nil, err
		}
		var got []string
		for _, we := range entries {
			suffix := strings.TrimLeft(we.Rel[len(p):], "/")
			parts := strings.Split(suffix, "/")
			local := filepath.Join(append([]string{root}, parts...)...)
			if we.Entry.Type == "directory" {
				if err := os.MkdirAll(local, 0o777); err != nil {
					return nil, err
				}
				continue
			}
			if err := os.MkdirAll(filepath.Dir(local), 0o777); err != nil {
				return nil, err
			}
			data, err := f.ReadFile(ctx, we.Rel, nil)
			if err != nil {
				return nil, err
			}
			if err := os.WriteFile(local, data, 0o666); err != nil {
				return nil, err
			}
			got = append(got, local)
		}
		return got, nil
	}
	local := dest
	if fi, err := os.Stat(dest); err == nil && fi.IsDir() {
		local = filepath.Join(dest, name)
	}
	data, err := f.ReadFile(ctx, p, nil)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(local, data, 0o666); err != nil {
		return nil, err
	}
	return []string{local}, nil
}

// Put uploads a local file (or, with recursive, a folder) to a
// remote path, ported verbatim from fs.py (put). For a folder,
// every local directory is created remotely (parents included)
// and every file is written under the matching remote directory;
// for a file, the single file is written to the normalized remote
// path. It returns one WriteResult per file written. A folder
// without recursive is an error naming the local path, as in
// Python. A symlink to a directory inside the walked folder is
// skipped silently, as Python's os.walk does (it lists the link
// without descending); a symlink to a file uploads the target
// content as a file.
func (f *FS) Put(ctx context.Context, local, remote string, recursive, overwrite bool) ([]WriteResult, error) {
	r, err := Norm(remote)
	if err != nil {
		return nil, err
	}
	fi, err := os.Stat(local)
	if err != nil {
		return nil, err
	}
	if fi.IsDir() {
		if !recursive {
			return nil, fmt.Errorf("%s is a folder; use -r", local)
		}
		var done []WriteResult
		walkErr := filepath.WalkDir(local, func(dpath string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.Type()&fs.ModeSymlink != 0 {
				if info, serr := os.Stat(dpath); serr == nil && info.IsDir() {
					// A symlink to a directory: Python
					// os.walk (followlinks=False) lists
					// it without descending and never
					// uploads it. Skip it silently —
					// no mkdir, no upload — mirroring
					// Python. (WalkDir would not descend
					// into it anyway: IsDir is false for
					// a symlink entry.)
					return nil
				}
				// A broken symlink, or a symlink to a
				// file: fall through. ReadFile follows
				// the link for a file and errors for a
				// broken one, as Python's open() does.
			}
			rel, err := filepath.Rel(local, dpath)
			if err != nil {
				return err
			}
			relSlash := filepath.ToSlash(rel)
			rd := r
			if relSlash != "." {
				rd = posixpath.Join(r, relSlash)
			}
			if d.IsDir() {
				_, err := f.Mkdir(ctx, rd, true)
				return err
			}
			// Files arrive one by one from WalkDir, not grouped
			// by directory as os.walk groups them: the remote
			// directory is the file's parent relative path, and
			// the file name is the entry's own name.
			dirRel := ""
			if i := strings.LastIndex(relSlash, "/"); i >= 0 {
				dirRel = relSlash[:i]
			}
			fileDir := r
			if dirRel != "" {
				fileDir = posixpath.Join(r, dirRel)
			}
			data, err := os.ReadFile(dpath)
			if err != nil {
				return err
			}
			res, err := f.WriteFile(ctx, posixpath.Join(fileDir, d.Name()), data, overwrite, true)
			if err != nil {
				return err
			}
			done = append(done, res)
			return nil
		})
		if walkErr != nil {
			return nil, walkErr
		}
		return done, nil
	}
	data, err := os.ReadFile(local)
	if err != nil {
		return nil, err
	}
	res, err := f.WriteFile(ctx, r, data, overwrite, true)
	if err != nil {
		return nil, err
	}
	return []WriteResult{res}, nil
}
