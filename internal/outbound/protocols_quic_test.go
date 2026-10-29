//go:build with_quic

// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package outbound

import (
	"context"
	"fmt"
	"testing"
)

// With with_quic, hysteria2/tuic build and start. Peer dials need a real
// QUIC peer and are [UNVERIFIED] in PR1.

func TestProtocolQUICBuildAndStart(t *testing.T) {
	cases := []string{
		`{"type":"hysteria2","tag":"h2","server":"127.0.0.1","server_port":443,"password":"FAKE","tls":{"enabled":true,"insecure":true,"server_name":"127.0.0.1"}}`,
		`{"type":"tuic","tag":"tuic","server":"127.0.0.1","server_port":443,"uuid":"123e4567-e89b-12d3-a456-426614174000","password":"FAKE","tls":{"enabled":true,"insecure":true,"server_name":"127.0.0.1"}}`,
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			m := newTestManager(t)
			out := parseOutbound(t, m, raw)
			if err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options); err != nil {
				t.Fatalf("CreateOutbound %s: %v", out.Type, err)
			}
			if err := m.Start(); err != nil {
				t.Fatalf("Start %s: %v", out.Type, err)
			}
			if _, err := m.Dialer(out.Tag); err != nil {
				t.Fatal(err)
			}
		})
	}
}

var _ = fmt.Sprintf
