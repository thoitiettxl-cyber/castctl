// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package shared

// Loop-6 tests (item 4): a download-row Error is an error
// rendering, so it must carry the allowlist summary only —
// never the untrusted ref or body bytes — whether the failure
// is a GatewayError or a MediaPath ValidationError.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/gateway"
)

const loop6Marker = "LOOP6MARKER7f3a91"

type loop6Downloader struct {
	err error
}

func (d *loop6Downloader) DownloadFile(_ context.Context, _ any, _ conn.DownloadOptions) ([]byte, error) {
	return nil, d.err
}

func TestLoop6SaveResourcesRowError(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// (a) A GatewayError carrying body bytes in its Payload:
	// the row renders the allowlist summary only.
	dl := &loop6Downloader{err: &conn.GatewayError{Status: 500, Payload: "plain body words " + loop6Marker, BodyLength: 52, BodyLengthKnown: true}}
	rows, err := SaveResources(context.Background(), dl, []Resource{{Path: "sandbox://workspace/a.txt", Kind: "video"}}, dir, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("len(rows) = %d, want 1", len(rows))
	}
	if rows[0].Error == "" {
		t.Fatal("row.Error is empty: positive control failed")
	}
	if strings.Contains(rows[0].Error, loop6Marker) {
		t.Errorf("row.Error = %q, carries body bytes", rows[0].Error)
	}
	if !strings.Contains(rows[0].Error, "status=500") || !strings.Contains(rows[0].Error, "body_length=52") {
		t.Errorf("row.Error = %q, want the allowlist summary fields", rows[0].Error)
	}
	// (b) A MediaPath ValidationError for a marker ref, as
	// Gateway.DownloadFile produces it: kind + length only.
	_, mediaErr := gateway.MediaPath("sandbox://../" + loop6Marker)
	if mediaErr == nil {
		t.Fatal("gateway.MediaPath(marker ref): nil error")
	}
	dl2 := &loop6Downloader{err: mediaErr}
	rows2, err := SaveResources(context.Background(), dl2, []Resource{{Path: "sandbox://workspace/b.txt", Kind: "video"}}, dir, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rows2[0].Error, loop6Marker) {
		t.Errorf("row.Error = %q, carries the untrusted ref", rows2[0].Error)
	}
	if !strings.Contains(rows2[0].Error, "bad sandbox path") || !strings.Contains(rows2[0].Error, "ref_length=") {
		t.Errorf("row.Error = %q, want kind + ref length", rows2[0].Error)
	}
	// (c) downloadRef passes the resource dict through, so the
	// MediaPath preference applies to the ref the downloader
	// sees; the ref itself is never rendered.
	ref := downloadRef(Resource{Path: "sandbox://workspace/c.txt", Kind: "video", Variants: map[string]any{"original": "orig/path"}})
	m, ok := ref.(map[string]any)
	if !ok || m["path"] != "sandbox://workspace/c.txt" {
		t.Errorf("downloadRef = %#v, want the resource dict", ref)
	}
	// (d) Loop 7 (V1, distinguishing case): a ConnectionError
	// wrapping PLAIN prose. GatewayError.Error() and the
	// MediaPath ValidationError are already summaries, so
	// (a) and (b) pass even if the row rendered
	// err.Error() directly — they cannot distinguish the
	// SummarizeErr rendering from a neutered one. This case
	// can: SummarizeErr renders error_length only, while
	// err.Error() would carry the prose verbatim.
	prose := "plain prose " + loop6Marker
	dl3 := &loop6Downloader{err: &conn.ConnectionError{Err: errors.New(prose)}}
	rows3, err := SaveResources(context.Background(), dl3, []Resource{{Path: "sandbox://workspace/d.txt", Kind: "video"}}, dir, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows3) != 1 {
		t.Fatalf("len(rows3) = %d, want 1", len(rows3))
	}
	if rows3[0].Error == "" {
		t.Fatal("row.Error is empty: positive control failed")
	}
	if strings.Contains(rows3[0].Error, loop6Marker) || strings.Contains(rows3[0].Error, "plain prose") {
		t.Errorf("row.Error = %q, carries the wrapped prose", rows3[0].Error)
	}
	if !strings.Contains(rows3[0].Error, fmt.Sprintf("error_length=%d", len(prose))) {
		t.Errorf("row.Error = %q, want error_length=%d", rows3[0].Error, len(prose))
	}
}
