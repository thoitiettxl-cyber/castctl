// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/thoitiettxl-cyber/muse-cli/go/internal/conn"
)

// The connector must surface cookies-file failures as *conn.AuthError
// (the conn pass-through contract: connectors return AuthError for
// auth failures, never a plain transport/profile error). The wait
// Runner treats only AuthError as fatal; a plain I/O error is
// retried until the deadline and reported as a timeout (124),
// where Python exits 2. LoadCookies itself keeps its own contract
// (plain error for a missing file); the typing happens here, at the
// point the failure enters the connection machinery.
func TestConnectorCookiesFileFailuresAreAuthErrors(t *testing.T) {
	connect := NewConnector(nil)
	t.Run("missing file", func(t *testing.T) {
		_, err := connect(context.Background(), conn.Config{CookiesFile: filepath.Join(t.TempDir(), "nope.txt")})
		if err == nil {
			t.Fatal("missing cookies file: nil error")
		}
		var authErr *conn.AuthError
		if !errors.As(err, &authErr) {
			t.Fatalf("missing cookies file: err=%v (%T), want *conn.AuthError", err, err)
		}
	})
	t.Run("unparseable file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "cookies.txt")
		if err := os.WriteFile(path, []byte("not\tvalid\tcookies\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := connect(context.Background(), conn.Config{CookiesFile: path})
		if err == nil {
			t.Fatal("unparseable cookies file: nil error")
		}
		var authErr *conn.AuthError
		if !errors.As(err, &authErr) {
			t.Fatalf("unparseable cookies file: err=%v (%T), want *conn.AuthError", err, err)
		}
	})
}
