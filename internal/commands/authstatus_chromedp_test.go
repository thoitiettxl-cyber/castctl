// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build with_chromedp

package commands

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestAuthStatusHeadlessObservedAvailable (D3) pins the
// real wiring in a chromedp build: keeper entry +
// credentials present, driver available, and the embedded
// contract observed (2026-11-03 observation leg), so auth
// status must report headless available with no reason.
func TestAuthStatusHeadlessObservedAvailable(t *testing.T) {
	t.Parallel()
	exp := time.Now().Add(30 * 24 * time.Hour).Unix()
	home, configFile := testHome(t, `{"default_profile":"muse01","profiles":{"muse01":{}},`+
		`"credentials":[{"tag":"c1","profile":"muse01","username":"u","password":"p"}],`+
		`"keeper":[{"tag":"k1","profile":"muse01","interval":"1h","credentials":"c1"}]}`)
	dir := filepath.Join(home, "profiles", "muse01")
	_ = os.MkdirAll(dir, 0o700)
	_ = os.WriteFile(filepath.Join(dir, "cookies.txt"), []byte(jarCookies(exp)), 0o600)
	var outBuf, errBuf strings.Builder
	env := &Env{Stdout: stringWriter{&outBuf}, Stderr: stringWriter{&errBuf},
		Getenv: mapGetenv(map[string]string{"CASTCTL_CONFIG": configFile})}
	if code := Run(context.Background(), []string{"auth", "status"}, env); code != 0 {
		t.Fatalf("status: code=%d stderr=%q", code, errBuf.String())
	}
	var res authStatusJSON
	if err := json.Unmarshal([]byte(outBuf.String()), &res); err != nil {
		t.Fatalf("status output: %v (%q)", err, outBuf.String())
	}
	if !res.HeadlessAvailable || res.HeadlessReason != "" {
		t.Fatalf("headless = %v/%q; want true/\"\" (contract observed)", res.HeadlessAvailable, res.HeadlessReason)
	}
}
