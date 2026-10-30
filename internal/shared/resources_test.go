// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package shared

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
)

// Port of test_media.py EventResourcesTest, plus the resource-list,
// variants and dedup rules of cli.py event_resources.

func TestEventResourcesVideosAndLinksDedupe(t *testing.T) {
	t.Parallel()
	p := "sandbox://workspace/imagine_media/cat-1.mp4"
	ev := map[string]any{"seq": int64(1), "payload": map[string]any{
		"fallback_text": "![v](" + p + ")",
		"data": map[string]any{
			"videos": []any{map[string]any{"path": p, "mime": "video/mp4", "byte_len": int64(5)}},
			"images": []any{map[string]any{"path": "sandbox://workspace/x.png", "missing": true}},
		}}}
	res := EventResources(ev)
	if len(res) != 1 {
		t.Fatalf("len(EventResources) = %d, want 1: %+v", len(res), res)
	}
	if res[0].Kind != "video" {
		t.Errorf("kind = %q, want %q", res[0].Kind, "video")
	}
	if res[0].ByteLen == nil || *res[0].ByteLen != 5 {
		t.Errorf("byte_len = %v, want 5", res[0].ByteLen)
	}
	if res[0].Path != p {
		t.Errorf("path = %q, want %q", res[0].Path, p)
	}
}

func TestEventResourcesNoFiles(t *testing.T) {
	t.Parallel()
	if got := EventResources(map[string]any{"payload": map[string]any{"display_text": "hi"}}); len(got) != 0 {
		t.Errorf("EventResources = %+v, want empty", got)
	}
}

func TestEventResourcesRules(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		ev   map[string]any
		want []Resource
	}{
		{
			name: "resources lists use kind resource",
			ev: map[string]any{"resources": []any{
				map[string]any{"path": "sandbox://workspace/a.bin", "label": "A"}}},
			want: []Resource{{Path: "sandbox://workspace/a.bin", Kind: "resource", Label: strPtr("A")}},
		},
		{
			name: "payload resources after event resources",
			ev: map[string]any{
				"resources": []any{map[string]any{"path": "sandbox://workspace/a.bin"}},
				"payload":   map[string]any{"resources": []any{map[string]any{"path": "sandbox://workspace/b.bin"}}}},
			want: []Resource{
				{Path: "sandbox://workspace/a.bin", Kind: "resource"},
				{Path: "sandbox://workspace/b.bin", Kind: "resource"},
			},
		},
		{
			name: "string item becomes path dict",
			ev: map[string]any{"payload": map[string]any{
				"data": map[string]any{"files": []any{"sandbox://workspace/s.txt"}}}},
			want: []Resource{{Path: "sandbox://workspace/s.txt", Kind: "file"}},
		},
		{
			name: "non sandbox path dropped",
			ev: map[string]any{"payload": map[string]any{
				"data": map[string]any{"files": []any{map[string]any{"path": "https://example.com/x.png"}}}}},
			want: []Resource{},
		},
		{
			name: "media raw url kept",
			ev: map[string]any{"payload": map[string]any{
				"data": map[string]any{"files": []any{map[string]any{"path": "https://abc.metaaivm.com/media/raw/workspace/x.png"}}}}},
			want: []Resource{{Path: "https://abc.metaaivm.com/media/raw/workspace/x.png", Kind: "file"}},
		},
		{
			name: "variants original resolves path when path empty",
			ev: map[string]any{"payload": map[string]any{
				"data": map[string]any{"images": []any{map[string]any{
					"variants": map[string]any{"original": "sandbox://workspace/v.png"}}}}}},
			want: []Resource{{
				Path: "sandbox://workspace/v.png",
				Kind: "image",
				// variants is kept verbatim on the resource, as
				// Python's add() sets it from the entry.
				Variants: map[string]any{"original": "sandbox://workspace/v.png"},
			}},
		},
		{
			name: "first kind wins later fields overwrite",
			ev: map[string]any{"payload": map[string]any{
				"data": map[string]any{
					"videos": []any{map[string]any{"path": "sandbox://workspace/d.mp4", "mime": "video/mp4"}},
					"files":  []any{map[string]any{"path": "sandbox://workspace/d.mp4", "mime": "video/other", "label": "L"}},
				}}},
			// Sorted data keys visit "files" before "videos", so
			// the deterministic Go order makes kind "file" here
			// where Python's wire order would make it "video".
			// The pinned rule is first-kind-wins plus field
			// overwrite, whatever the visit order.
			want: []Resource{{Path: "sandbox://workspace/d.mp4", Kind: "file", MIME: strPtr("video/mp4"), Label: strPtr("L")}},
		},
		{
			name: "key rstrip s verbatim",
			ev: map[string]any{"payload": map[string]any{
				"data": map[string]any{"class": []any{map[string]any{"path": "sandbox://workspace/c.bin"}}}}},
			want: []Resource{{Path: "sandbox://workspace/c.bin", Kind: "cla"}},
		},
		{
			name: "non-list data value skipped",
			ev: map[string]any{"payload": map[string]any{
				"data": map[string]any{"video": map[string]any{"path": "sandbox://workspace/d.mp4"}}}},
			want: []Resource{},
		},
		{
			name: "link in display text",
			ev: map[string]any{"payload": map[string]any{
				"display_text": "see sandbox://workspace/doc.pdf ok"}},
			want: []Resource{{Path: "sandbox://workspace/doc.pdf", Kind: "link"}},
		},
		{
			name: "link stops at closing paren",
			ev: map[string]any{"payload": map[string]any{
				"display_text": "![v](sandbox://workspace/a.mp4) tail"}},
			want: []Resource{{Path: "sandbox://workspace/a.mp4", Kind: "link"}},
		},
		{
			name: "missing false is kept",
			ev: map[string]any{"payload": map[string]any{
				"data": map[string]any{"files": []any{map[string]any{"path": "sandbox://workspace/k.bin", "missing": false}}}}},
			want: []Resource{{Path: "sandbox://workspace/k.bin", Kind: "file"}},
		},
		{
			name: "variants kept verbatim",
			ev: map[string]any{"payload": map[string]any{
				"data": map[string]any{"images": []any{map[string]any{
					"path":     "sandbox://workspace/i.png",
					"variants": map[string]any{"original": "https://x/media/raw/workspace/i.png", "thumb": "https://x/t.png"},
				}}}}},
			want: []Resource{{
				Path:     "sandbox://workspace/i.png",
				Kind:     "image",
				Variants: map[string]any{"original": "https://x/media/raw/workspace/i.png", "thumb": "https://x/t.png"},
			}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := EventResources(tc.ev)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("EventResources = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestFileRows(t *testing.T) {
	t.Parallel()
	events := []any{
		map[string]any{"seq": int64(9), "payload": map[string]any{
			"message_id": "m9",
			"data":       map[string]any{"videos": []any{map[string]any{"path": "sandbox://workspace/v.mp4"}}}}},
		map[string]any{"seq": int64(10), "payload": map[string]any{"display_text": "no files"}},
		"not an event",
	}
	rows := FileRows(events)
	if len(rows) != 1 {
		t.Fatalf("len(FileRows) = %d, want 1", len(rows))
	}
	want := FileRow{Seq: intPtr(9), MessageID: strPtr("m9"), Resource: Resource{Path: "sandbox://workspace/v.mp4", Kind: "video"}}
	if !reflect.DeepEqual(rows[0], want) {
		t.Errorf("FileRows[0] = %+v, want %+v", rows[0], want)
	}
}

func TestFileRowJSONOrder(t *testing.T) {
	t.Parallel()
	row := FileRow{Seq: intPtr(9), MessageID: strPtr("m9"), Resource: Resource{
		Path: "sandbox://workspace/v.mp4", Kind: "video", MIME: strPtr("video/mp4"), ByteLen: intPtr(5)}}
	b, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"seq":9,"message_id":"m9","path":"sandbox://workspace/v.mp4","kind":"video","mime":"video/mp4","byte_len":5}`
	if string(b) != want {
		t.Errorf("Marshal(FileRow) = %s, want %s", b, want)
	}
}

func TestLocalName(t *testing.T) {
	t.Parallel()
	cases := []struct{ in, want string }{
		{"sandbox://workspace/a/b.png", "b.png"},
		{"https://h/media/raw/workspace/cat%201.mp4?x=1", "cat%201.mp4"},
		{"sandbox://workspace/", "workspace"},
		{"", "download"},
		{"/", "download"},
		{"sandbox://workspace/a/", "a"},
	}
	for _, tc := range cases {
		got := LocalName(tc.in, "/tmp/d")
		if filepath.Base(got) != tc.want {
			t.Errorf("LocalName(%q) = %q, want basename %q", tc.in, got, tc.want)
		}
	}
}

// fakeDownloader is an in-memory Downloader for SaveResources tests.
type fakeDownloader struct {
	files map[string][]byte
	err   map[string]error
	refs  []any
}

func (f *fakeDownloader) DownloadFile(_ context.Context, ref any, _ conn.DownloadOptions) ([]byte, error) {
	f.refs = append(f.refs, ref)
	var path string
	switch r := ref.(type) {
	case string:
		path = r
	case map[string]any:
		path, _ = r["path"].(string)
	}
	if err, ok := f.err[path]; ok {
		return nil, err
	}
	data, ok := f.files[path]
	if !ok {
		return nil, &conn.GatewayError{Status: 404, Payload: "not found"}
	}
	return data, nil
}

func TestSaveResources(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dl := &fakeDownloader{files: map[string][]byte{
		"sandbox://workspace/a.txt": []byte("hello"),
		"sandbox://workspace/b.bin": []byte("0123456789"),
	}}
	resources := []Resource{
		{Path: "sandbox://workspace/a.txt", Kind: "video"},
		{Path: "sandbox://workspace/b.bin", Kind: "video", ByteLen: intPtr(5)},
		{Path: "sandbox://workspace/missing.txt", Kind: "video"},
	}
	rows, err := SaveResources(context.Background(), dl, resources, dir, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("len(rows) = %d, want 3", len(rows))
	}
	if rows[0].Error != "" || rows[0].Bytes == nil || *rows[0].Bytes != 5 {
		t.Errorf("row 0 = %+v, want saved 5 bytes", rows[0])
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "a.txt")); string(got) != "hello" {
		t.Errorf("a.txt = %q, want hello", got)
	}
	if rows[1].Warning != "expected 5 bytes" {
		t.Errorf("row 1 warning = %q, want %q", rows[1].Warning, "expected 5 bytes")
	}
	if rows[2].Error == "" || rows[2].Bytes != nil {
		t.Errorf("row 2 = %+v, want error row with no bytes", rows[2])
	}
	// No .part files remain.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".part" {
			t.Errorf("leftover .part file: %s", e.Name())
		}
	}
	// Second run skips existing files.
	rows2, err := SaveResources(context.Background(), dl, resources[:2], dir, false)
	if err != nil {
		t.Fatal(err)
	}
	if rows2[0].Skipped != "exists" || rows2[0].Bytes == nil || *rows2[0].Bytes != 5 {
		t.Errorf("skipped row = %+v, want skipped/exists 5 bytes", rows2[0])
	}
	// Overwrite re-downloads.
	rows3, err := SaveResources(context.Background(), dl, resources[:1], dir, true)
	if err != nil {
		t.Fatal(err)
	}
	if rows3[0].Skipped != "" {
		t.Errorf("overwrite row skipped = %q, want empty", rows3[0].Skipped)
	}
}

func TestSaveResourcesAuthErrorPropagates(t *testing.T) {
	t.Parallel()
	dl := &fakeDownloader{err: map[string]error{
		"sandbox://workspace/a.txt": conn.NewAuthError("bad cookies"),
	}}
	_, err := SaveResources(context.Background(), dl,
		[]Resource{{Path: "sandbox://workspace/a.txt"}}, t.TempDir(), false)
	var authErr *conn.AuthError
	if !errors.As(err, &authErr) {
		t.Errorf("SaveResources error = %v, want *AuthError propagation", err)
	}
}

func TestSaveResourcesCancelledContextPropagates(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dl := &fakeDownloader{err: map[string]error{
		"sandbox://workspace/a.txt": errors.New("boom"),
	}}
	_, err := SaveResources(ctx, dl,
		[]Resource{{Path: "sandbox://workspace/a.txt"}}, t.TempDir(), false)
	if err == nil {
		t.Error("SaveResources with cancelled ctx: got nil error, want propagation")
	}
}

func TestSaveResourcesVariantsRef(t *testing.T) {
	t.Parallel()
	dl := &fakeDownloader{files: map[string][]byte{
		"sandbox://workspace/i.png": []byte("png"),
	}}
	_, err := SaveResources(context.Background(), dl,
		[]Resource{{Path: "sandbox://workspace/i.png", Variants: map[string]any{"original": "https://x/media/raw/i.png"}}},
		t.TempDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(dl.refs) != 1 {
		t.Fatalf("refs = %v, want 1", dl.refs)
	}
	m, ok := dl.refs[0].(map[string]any)
	if !ok || m["path"] != "sandbox://workspace/i.png" {
		t.Errorf("ref = %#v, want dict with path (variants preference applies at the gateway)", dl.refs[0])
	}
}
