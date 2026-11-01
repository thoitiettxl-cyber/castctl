// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package pluginhost

import "testing"

func TestPluginIdentitySecretBlind(t *testing.T) {
	// Synthetic secrets only.
	a := []byte(`{"type":"wireguard","tag":"wg1","private_key":"AAAA1111","server":"1.2.3.4","server_port":51820}`)
	b := []byte(`{"type":"wireguard","tag":"wg1","private_key":"ZZZZ9999","server":"1.2.3.4","server_port":51820}`)
	ia, err := NewPluginIdentity("wg1", a)
	if err != nil {
		t.Fatal(err)
	}
	ib, err := NewPluginIdentity("wg1", b)
	if err != nil {
		t.Fatal(err)
	}
	if ia.OutboundHash != ib.OutboundHash {
		t.Fatalf("identity hash changed on secret rotation: %q vs %q", ia.OutboundHash, ib.OutboundHash)
	}
	if ia.OutboundTag != "wg1" {
		t.Fatalf("identity tag = %q, want wg1", ia.OutboundTag)
	}
	c := []byte(`{"type":"wireguard","tag":"wg1","private_key":"AAAA1111","server":"5.6.7.8","server_port":51820}`)
	ic, err := NewPluginIdentity("wg1", c)
	if err != nil {
		t.Fatal(err)
	}
	if ic.OutboundHash == ia.OutboundHash {
		t.Fatal("identity hash did not change when a non-secret field changed")
	}
	if _, err := NewPluginIdentity("", a); err == nil {
		t.Fatal("empty tag: want error")
	}
	if _, err := NewPluginIdentity("wg1", []byte(`not json`)); err == nil {
		t.Fatal("invalid json: want error")
	}
}
