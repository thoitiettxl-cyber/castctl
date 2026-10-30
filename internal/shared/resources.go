// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package shared

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/logging"
)

// sandboxRe matches a sandbox:// link inside free text, ported
// verbatim from cli.py:800 (_SANDBOX_RE). The link runs to the first
// whitespace, ')', ']', '"' , '\” or '>' character.
var sandboxRe = regexp.MustCompile(`sandbox://[^\s)\]"'>]+`)

// Resource is one downloadable file referenced by a history event,
// ported from cli.py:803-842 (event_resources). Field order is the
// Python dict order: path, kind, then mime, byte_len, label and
// variants in that fixed order, each present only when the source
// entry carried a non-null value for it.
type Resource struct {
	// Path is the sandbox:// path or /media/raw/ URL, resolved
	// through variants.original when the entry has one.
	Path string `json:"path"`
	// Kind is the data key with trailing "s" stripped ("video",
	// "image"), "resource" for resources lists, or "link" for a
	// sandbox:// link found in text. The first kind seen for a
	// path wins; later entries for the same path keep it.
	Kind string `json:"kind"`
	// MIME is the entry's mime, when present and non-null.
	MIME *string `json:"mime,omitempty"`
	// ByteLen is the entry's byte_len, when present and non-null.
	ByteLen *int64 `json:"byte_len,omitempty"`
	// Label is the entry's label, when present and non-null.
	Label *string `json:"label,omitempty"`
	// Variants is the entry's variants object, kept verbatim when
	// present and non-null (usually a map of variant name to URL).
	Variants any `json:"variants,omitempty"`
}

// FileRow is one row of the `files` command output, ported from
// cli.py:880-891 (file_rows): the event's seq and message_id plus
// the resource fields, in that order.
type FileRow struct {
	// Seq is the event's seq, or nil when it carries no numeric seq.
	Seq *int64 `json:"seq"`
	// MessageID is the payload message_id, falling back to the
	// event's message_id.
	MessageID *string `json:"message_id"`
	// Resource holds the path/kind/mime/byte_len/label/variants
	// fields, flattened in JSON output after seq and message_id.
	Resource
}

// EventResources lists the downloadable files referenced by one
// history event, ported verbatim from cli.py:803-842
// (event_resources), with one documented ordering difference (see
// below). Sources are visited in Python's order:
//
//  1. every list under payload.data, keyed by the data key with
//     trailing "s" characters stripped (Python's key.rstrip("s"));
//  2. the event's "resources" list, then the payload's, kind
//     "resource";
//  3. sandbox:// links in payload fallback_text, payload.data
//     fallback_text, payload display_text and payload content, kind
//     "link".
//
// An entry is dropped when it has no usable path, when the path is
// neither a sandbox:// path nor contains "/media/raw/", or when its
// "missing" flag is truthy. The path resolves through
// variants.original when the entry has one. Entries are deduplicated
// by path in first-seen order: the first kind wins, but later
// entries for the same path overwrite mime, byte_len, label and
// variants when they carry a non-null value.
//
// Ordering difference: Python iterates payload.data in wire order.
// Decoded Go maps have no wire order, so this port visits data keys
// in sorted order. The result is deterministic, but for a payload
// whose data keys are not already sorted it may order rows
// differently from Python. This is a differential item for PR5, not
// something the decoded-value API can recover.
func EventResources(ev map[string]any) []Resource {
	p := payloadOf(ev)
	found := map[string]*Resource{}
	var order []string

	add := func(item any, kind string) {
		if s, ok := asString(item); ok {
			item = map[string]any{"path": s}
		}
		m, ok := asMap(item)
		if !ok {
			return
		}
		resolvedPath := resourcePath(m)
		if resolvedPath == "" {
			return
		}
		if truthy(m["missing"]) {
			return
		}
		r, seen := found[resolvedPath]
		if !seen {
			r = &Resource{Path: resolvedPath, Kind: kind}
			found[resolvedPath] = r
			order = append(order, resolvedPath)
		}
		if v := stringPtrField(m, "mime"); v != nil {
			r.MIME = v
		}
		if v := intPtrField(m, "byte_len"); v != nil {
			r.ByteLen = v
		}
		if v := stringPtrField(m, "label"); v != nil {
			r.Label = v
		}
		if v, present := m["variants"]; present && v != nil {
			r.Variants = v
		}
	}

	data, _ := asMap(p["data"])
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		items, ok := asList(data[key])
		if !ok {
			continue
		}
		kind := strings.TrimRight(key, "s")
		for _, item := range items {
			add(item, kind)
		}
	}
	for _, src := range []any{ev["resources"], p["resources"]} {
		items, ok := asList(src)
		if !ok {
			continue
		}
		for _, item := range items {
			add(item, "resource")
		}
	}
	for _, text := range []any{p["fallback_text"], data["fallback_text"], p["display_text"], p["content"]} {
		s, ok := asString(text)
		if !ok {
			continue
		}
		for _, m := range sandboxRe.FindAllString(s, -1) {
			add(m, "link")
		}
	}

	out := make([]Resource, 0, len(order))
	for _, k := range order {
		out = append(out, *found[k])
	}
	return out
}

// resourcePath resolves an entry's downloadable path: its "path"
// wins when non-empty, else its variants.original (Python's
// `item.get("path") or variants.original`). It returns ""
// when there is no path or the path is neither a sandbox:// path
// nor contains "/media/raw/", mirroring event_resources' add()
// guard. Unlike the gateway's media_path, this does not validate
// traversal: it only filters by prefix, exactly as Python does.
func resourcePath(item map[string]any) string {
	resolvedPath := stringField(item, "path")
	if resolvedPath == "" {
		if variants, ok := asMap(item["variants"]); ok {
			resolvedPath = stringField(variants, "original")
		}
	}
	if strings.HasPrefix(resolvedPath, "sandbox://") || strings.Contains(resolvedPath, "/media/raw/") {
		return resolvedPath
	}
	return ""
}

// FileRows returns one row per file referenced by these history
// events, ported from cli.py:880-891 (file_rows). Non-object events
// are skipped (lenient shaping; Python would raise on them).
func FileRows(events []any) []FileRow {
	var rows []FileRow
	for _, e := range events {
		ev, ok := asMap(e)
		if !ok {
			continue
		}
		p := payloadOf(ev)
		for _, r := range EventResources(ev) {
			rows = append(rows, FileRow{
				Seq:       intPtrField(ev, "seq"),
				MessageID: firstStringPtr(p["message_id"], ev["message_id"]),
				Resource:  r,
			})
		}
	}
	return rows
}

// Downloader is the narrow download contract SaveResources needs:
// the DownloadFile method of conn.Gateway. It is defined here, in
// the consuming package, so this package depends only on the
// interface, never on a concrete gateway. A conn.Gateway satisfies
// it, as does any fake with the same method.
type Downloader interface {
	DownloadFile(ctx context.Context, ref any, opts conn.DownloadOptions) ([]byte, error)
}

var _ Downloader = (conn.Gateway)(nil)

// SaveRow is one result row of SaveResources, ported from
// cli.py:845-878 (save_resources). Field order is the Python dict
// order: path, file, then skipped/bytes for a skipped download,
// error for a failed one, or bytes/warning for a saved one.
type SaveRow struct {
	// Path is the resource path that was downloaded.
	Path string `json:"path"`
	// File is the absolute local path the resource was saved to
	// (or would have been saved to, for a failed download).
	File string `json:"file"`
	// Skipped is "exists" when the destination already existed and
	// overwrite was false.
	Skipped string `json:"skipped,omitempty"`
	// Bytes is the existing file's size for a skipped download, or
	// the downloaded size for a saved one. It is nil for a failed
	// download (Python emits no bytes key there).
	Bytes *int64 `json:"bytes,omitempty"`
	// Error is the download failure, when the download failed.
	Error string `json:"error,omitempty"`
	// Warning names an expected size that did not match the
	// downloaded size, e.g. "expected 5 bytes".
	Warning string `json:"warning,omitempty"`
}

// SaveResources downloads each resource into directory and returns
// one result row each, ported verbatim from cli.py:845-878
// (save_resources). The directory is created when needed. A
// destination that already exists is skipped unless overwrite is
// true, reporting the existing size. Each download is written to a
// ".part" file and renamed into place; a byte_len mismatch is
// reported as a warning, not an error.
//
// A download failure is captured in the row's error field, exactly
// for the failures Python catches (GatewayError, TimeoutError and
// ValueError, i.e. every failure that is not an auth failure or a
// cancelled context). An *AuthError or a cancelled context
// propagates as a returned error instead, as does any local
// filesystem failure (creating the directory, writing or renaming
// the file), which Python would raise.
func SaveResources(ctx context.Context, dl Downloader, resources []Resource, directory string, overwrite bool) ([]SaveRow, error) {
	if err := os.MkdirAll(directory, 0o777); err != nil {
		return nil, fmt.Errorf("save resources: create directory: %w", err)
	}
	rows := make([]SaveRow, 0, len(resources))
	for _, r := range resources {
		dest := LocalName(r.Path, directory)
		abs, err := filepath.Abs(dest)
		if err != nil {
			return nil, fmt.Errorf("save resources: absolute path: %w", err)
		}
		row := SaveRow{Path: r.Path, File: abs}
		if fi, err := os.Stat(dest); err == nil && !overwrite {
			size := fi.Size()
			row.Skipped = "exists"
			row.Bytes = &size
			rows = append(rows, row)
			continue
		}
		data, err := dl.DownloadFile(ctx, downloadRef(r), conn.DownloadOptions{})
		if err != nil {
			if ctx.Err() != nil {
				return nil, err
			}
			var authErr *conn.AuthError
			if errors.As(err, &authErr) {
				return nil, err
			}
			// The row's error field is an ERROR rendering
			// (loop 6, item 4): the allowlist summary only,
			// never the untrusted ref or body bytes. A
			// MediaPath ValidationError already carries
			// kind + length; a GatewayError renders as its
			// summary through SummarizeErr.
			row.Error = logging.SummarizeErr(err)
			rows = append(rows, row)
			continue
		}
		tmp := dest + ".part"
		if err := os.WriteFile(tmp, data, 0o666); err != nil {
			return nil, fmt.Errorf("save resources: write %s: %w", tmp, err)
		}
		if err := os.Rename(tmp, dest); err != nil {
			return nil, fmt.Errorf("save resources: rename %s: %w", tmp, err)
		}
		size := int64(len(data))
		row.Bytes = &size
		if r.ByteLen != nil && *r.ByteLen != size {
			row.Warning = fmt.Sprintf("expected %d bytes", *r.ByteLen)
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// downloadRef builds the ref SaveResources passes to DownloadFile:
// the resource dict Python passes to gw.download_file, so the
// gateway's variants.original preference applies. When the resource
// carries no variants, the bare path string is equivalent and is
// passed instead.
func downloadRef(r Resource) any {
	if r.Variants != nil {
		return map[string]any{"path": r.Path, "variants": r.Variants}
	}
	return r.Path
}

// LocalName returns the local file name for a resource path inside
// directory, ported from cli.py's _local_name: the basename of the
// path with any "?..." query stripped and trailing slashes removed,
// or "download" when nothing remains.
func LocalName(resourcePath, directory string) string {
	s := strings.SplitN(resourcePath, "?", 2)[0]
	s = strings.TrimRight(s, "/")
	name := path.Base(s)
	if name == "" || name == "." || name == "/" {
		name = "download"
	}
	return filepath.Join(directory, name)
}
