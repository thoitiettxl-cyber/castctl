// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package outbound

// WireGuard DNS= capture (per-profile DNS PR, precedence branch
// (ii)): the wg-quick parser must no longer silently drop DNS=.
// All key material below is the literal placeholder "<redacted>".

import (
	"strings"
	"testing"
)

func TestParseWireGuardConfCapturesDNS(t *testing.T) {
	parsed, err := ParseWireGuardConfWithDNS([]byte(redactedWGConf))
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.DNSServers) != 1 || parsed.DNSServers[0] != "10.8.0.1" {
		t.Fatalf("DNSServers = %v, want [10.8.0.1]", parsed.DNSServers)
	}
	// The endpoint itself is unchanged by the capture.
	if parsed.Endpoint.PrivateKey != "<redacted>" {
		t.Errorf("PrivateKey = %q, want placeholder", parsed.Endpoint.PrivateKey)
	}
	// The legacy entry point keeps its signature and still parses.
	if _, err := ParseWireGuardConf([]byte(redactedWGConf)); err != nil {
		t.Fatalf("ParseWireGuardConf (legacy form) must keep working, got: %v", err)
	}
}

func TestParseWireGuardConfCapturesMultipleDNS(t *testing.T) {
	conf := strings.Replace(redactedWGConf, "DNS = 10.8.0.1", "DNS = 10.8.0.1, 10.8.0.2", 1)
	parsed, err := ParseWireGuardConfWithDNS([]byte(conf))
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.DNSServers) != 2 || parsed.DNSServers[0] != "10.8.0.1" || parsed.DNSServers[1] != "10.8.0.2" {
		t.Fatalf("DNSServers = %v, want [10.8.0.1 10.8.0.2]", parsed.DNSServers)
	}
}

func TestParseWireGuardConfNoDNSIsEmpty(t *testing.T) {
	parsed, err := ParseWireGuardConfWithDNS([]byte(redactedWGConfIPv6Endpoint))
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.DNSServers) != 0 {
		t.Fatalf("DNSServers = %v, want empty when no DNS= line exists", parsed.DNSServers)
	}
}
