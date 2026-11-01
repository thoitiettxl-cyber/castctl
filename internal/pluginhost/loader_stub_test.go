// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build (!cgo && !windows) || android

package pluginhost_test

import (
	"context"
	"strings"
	"testing"

	"github.com/thoitiettxl-cyber/castctl/internal/pluginhost"
)

func TestStubLoaderRefuses(t *testing.T) {
	if pluginhost.SupportPlugins() {
		t.Fatal("SupportPlugins = true on a stub build, want false")
	}
	if got := pluginhost.SupportValue(); got != "0" {
		t.Fatalf("SupportValue = %q, want 0", got)
	}
	h := pluginhost.New(pluginhost.Options{})
	defer h.Close()
	report := h.ApplyConfig(context.Background(), []pluginhost.Desired{{Tag: "echo", Type: "echo", Path: "/plugins/echo.so"}})
	if len(report.Skipped) != 1 || !strings.Contains(report.Skipped[0].Reason, "requires cgo") {
		t.Fatalf("skipped = %+v, want cgo refusal", report.Skipped)
	}
}
