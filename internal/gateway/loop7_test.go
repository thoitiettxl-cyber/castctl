// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

// Loop-7 RED tests (T1): callAction must return the wire byte
// length on the non-200 / non-x-component branch, not 0.

import (
	"context"
	"net/http"
	"testing"
)

func TestLoop7CallActionNon200ReturnsWireLength(t *testing.T) {
	cases := []struct {
		name        string
		status      int
		contentType string
		body        string
	}{
		{name: "500", status: 500, contentType: "text/plain", body: "gateway exploded; try again later"},
		{name: "200-html", status: 200, contentType: "text/html", body: "<html>stale</html>"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/settings", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tc.contentType)
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			})
			r, n, known, err := callAction(context.Background(), muxClient(mux), fakeCookie, "actionid12345678901234", nil, "https://muse.ai/settings")
			if err != nil {
				t.Fatalf("callAction: %v", err)
			}
			if r != nil {
				t.Fatalf("callAction result = %#v, want nil", r)
			}
			if n != len(tc.body) {
				t.Errorf("callAction length = %d, want the wire length %d", n, len(tc.body))
			}
			if !known {
				t.Errorf("callAction known = false, want true: the %d-byte body was read", n)
			}
		})
	}
}
