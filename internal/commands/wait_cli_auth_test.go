// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

import (
	"strings"
	"testing"
)

// T15 (auth, CLI level): an auth failure anywhere on the wait
// path must surface as exit 2 with a typed JSON line — never
// masked as 124. The fake auth endpoint answers 401, so Connect
// fails as a typed auth_check_failed error before any
// subscription starts. (The Runner-level *conn.AuthError →
// "auth_failed" mapping is pinned by classify_redact_test.go;
// this test pins the CLI wiring end to end.)
func TestWaitAuthErrorExits2(t *testing.T) {
	s := newFakeStack(t, nil, nil)
	s.auth.AuthCheckStatus = 401
	code := s.run("wait", "--timeout", "5")
	if code != 2 {
		t.Fatalf("wait with expired auth: code=%d, want 2; err=%q", code, s.errb.String())
	}
	if !strings.Contains(s.errb.String(), `"auth_check_failed"`) {
		t.Errorf("stderr = %q, want the typed auth_check_failed JSON line", s.errb.String())
	}
}
