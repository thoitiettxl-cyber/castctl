// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package outbound

import "testing"

func TestSocksaddr(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		port     uint16
		wantAddr string
		wantFqdn string
		wantPort uint16
	}{
		{name: "ipv4", host: "127.0.0.1", port: 443, wantAddr: "127.0.0.1", wantPort: 443},
		{name: "ipv6", host: "::1", port: 80, wantAddr: "::1", wantPort: 80},
		{name: "domain", host: "gateway.test", port: 443, wantFqdn: "gateway.test", wantPort: 443},
		{name: "domain with port zero", host: "example.test", port: 0, wantFqdn: "example.test", wantPort: 0},
		{name: "empty host", host: "", port: 80, wantPort: 80},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Socksaddr(tt.host, tt.port)
			if got.Port != tt.wantPort {
				t.Errorf("Socksaddr(%q, %d).Port = %d, want %d", tt.host, tt.port, got.Port, tt.wantPort)
			}
			if tt.wantAddr != "" && got.Addr.String() != tt.wantAddr {
				t.Errorf("Socksaddr(%q, %d).Addr = %v, want %s", tt.host, tt.port, got.Addr, tt.wantAddr)
			}
			if tt.wantFqdn != "" && got.Fqdn != tt.wantFqdn {
				t.Errorf("Socksaddr(%q, %d).Fqdn = %q, want %q", tt.host, tt.port, got.Fqdn, tt.wantFqdn)
			}
			if tt.wantFqdn != "" && got.Addr.IsValid() {
				t.Errorf("Socksaddr(%q, %d).Addr = %v, want invalid for a domain", tt.host, tt.port, got.Addr)
			}
			if tt.wantAddr != "" && got.Fqdn != "" {
				t.Errorf("Socksaddr(%q, %d).Fqdn = %q, want empty for an IP literal", tt.host, tt.port, got.Fqdn)
			}
		})
	}
}
