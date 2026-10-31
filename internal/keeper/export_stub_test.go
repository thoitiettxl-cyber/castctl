// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build !with_chromedp

package keeper

import (
	"context"
	"errors"
	"testing"
)

// Tag-off: the exporter reports unavailable, and the build
// carries no chromedp import (proven by `go list` in the
// final matrix, not by this test).
func TestStubExporterUnavailable(t *testing.T) {
	if CDPAvailable() {
		t.Fatal("CDPAvailable() true in a tag-off build")
	}
	_, err := NewCDPExporter("http://127.0.0.1:9226/").Export(context.Background())
	if !errors.Is(err, ErrReexportUnavailable) {
		t.Fatalf("stub Export error = %v; want ErrReexportUnavailable", err)
	}
}
