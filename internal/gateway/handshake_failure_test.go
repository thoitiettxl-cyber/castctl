// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

// Loop-5 handshake-failure tests: a WebSocket handshake
// failure's rendered error must carry only the validated
// status token (or a fixed message) — never peer status-line
// text — while the original error chain stays reachable for
// classification (errors.As / IsTransient).

import (
	"errors"
	"net/http"
	"strings"
	"syscall"
	"testing"
)

const handshakeMarker = "ALLOW5HS-9d2e41"

func TestHandshakeFailureErrorAllowlist(t *testing.T) {
	t.Parallel()
	// Malformed status line carrying marker prose: the
	// rendering must not contain it.
	raw := errors.New(`websocket: malformed HTTP status code "` + handshakeMarker + ` with spaces"`)
	err := newHandshakeFailureError(nil, raw)
	if err == nil {
		t.Fatal("newHandshakeFailureError returned nil")
	}
	got := err.Error()
	if got == "" {
		t.Fatal("Error() empty: positive control failed")
	}
	if strings.Contains(got, handshakeMarker) || strings.Contains(got, "with spaces") {
		t.Errorf("handshake error %q carries peer status-line text", got)
	}
	if !strings.Contains(got, "handshake") {
		t.Errorf("handshake error %q, want the handshake class", got)
	}
	// The chain is preserved: the original error is reachable.
	if !errors.Is(err, raw) {
		t.Errorf("handshake error does not unwrap to the original error")
	}
	// A validated token IS emitted.
	tokErr := errors.New(`websocket: malformed HTTP status code "error"`)
	tok := newHandshakeFailureError(nil, tokErr)
	if !strings.Contains(tok.Error(), "error") {
		t.Errorf("handshake error %q, want the validated status token", tok.Error())
	}
	// A numeric response status is emitted as a code.
	resp := &http.Response{StatusCode: 403}
	num := newHandshakeFailureError(resp, errors.New("bad handshake"))
	if !strings.Contains(num.Error(), "403") {
		t.Errorf("handshake error %q, want status_code=403", num.Error())
	}
	// An errno cause stays reachable through the wrapper, so
	// IsTransient classification is unchanged.
	errno := newHandshakeFailureError(nil, syscall.ECONNRESET)
	if !errors.Is(errno, syscall.ECONNRESET) {
		t.Errorf("handshake error does not unwrap to its errno cause")
	}
}
