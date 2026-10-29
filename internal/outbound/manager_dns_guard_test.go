// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package outbound

import (
	"context"
	"strings"
	"testing"
	"time"
)

// F3 nil-router guard tests. sing-box's resolve dialer captures the
// DNS router from the registry context at outbound construction
// time (common/dialer/resolve.go: NewResolveDialer) and dereferences
// it on the first domain dial (resolve.go:103). A Manager without a
// registered DNS router must therefore refuse a domain-server
// outbound at CreateOutbound time — cleanly, with an error, never a
// panic — and registering a router AFTER CreateOutbound must not
// resurrect the refused outbound. IP-server outbounds and IP
// destinations are unaffected: they never touch the resolve dialer.

// TestCreateOutboundDomainServerWithoutDNSRouter is Case A: a
// domain-server http outbound with no DNS router registered must
// error at CreateOutbound (no panic, no outbound created).
func TestCreateOutboundDomainServerWithoutDNSRouter(t *testing.T) {
	m := newTestManager(t)
	out := parseOutbound(t, m, `{"type":"http","tag":"proxy","server":"proxy.invalid","server_port":8080}`)
	err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options)
	if err == nil {
		t.Fatal("CreateOutbound(domain server, no DNS router) = nil, want error")
	}
	if !strings.Contains(err.Error(), "DNS router") {
		t.Errorf("CreateOutbound error = %v, want it to name the missing DNS router", err)
	}
	if _, ok := m.Outbound("proxy"); ok {
		t.Error("domain-server outbound exists after refused CreateOutbound")
	}
	if _, err := m.Dialer("proxy"); err == nil {
		t.Error("Dialer(proxy) = nil after refused CreateOutbound, want error")
	}
}

// TestCreateOutboundDomainServerRouterRegisteredAfter is Case C:
// registering a DNS router AFTER the (refused) CreateOutbound does
// not repair anything — the outbound still does not exist and
// dialling still errors cleanly — but creating it again AFTER
// registration succeeds (the PR3 wiring rule: RegisterDNS BEFORE
// CreateOutbound).
func TestCreateOutboundDomainServerRouterRegisteredAfter(t *testing.T) {
	m := newTestManager(t)
	raw := `{"type":"http","tag":"proxy","server":"proxy.invalid","server_port":8080}`
	out := parseOutbound(t, m, raw)
	if err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options); err == nil {
		t.Fatal("CreateOutbound before RegisterDNSRouter = nil, want error")
	}
	m.RegisterDNSRouter(failClosedDNSRouter{})
	if _, ok := m.Outbound("proxy"); ok {
		t.Error("outbound exists after late router registration: the refused creation must not be repaired retroactively")
	}
	if _, err := m.Dialer("proxy"); err == nil {
		t.Error("Dialer(proxy) = nil after late router registration, want error (no outbound was created)")
	}
	out2 := parseOutbound(t, m, raw)
	if err := m.CreateOutbound(context.Background(), out2.Tag, out2.Type, out2.Options); err != nil {
		t.Fatalf("CreateOutbound after RegisterDNSRouter = %v, want nil", err)
	}
}

// TestCreateOutboundDomainServerWithDNSRouterFirst is the positive
// control for Cases A/C: a router registered BEFORE CreateOutbound
// lets a domain-server outbound be created (dialling it then fails
// through the router, with the router's error — no panic).
func TestCreateOutboundDomainServerWithDNSRouterFirst(t *testing.T) {
	m := newTestManager(t)
	m.RegisterDNSRouter(failClosedDNSRouter{})
	out := parseOutbound(t, m, `{"type":"http","tag":"proxy","server":"proxy.invalid","server_port":8080}`)
	if err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options); err != nil {
		t.Fatalf("CreateOutbound(domain server, router first) = %v, want nil", err)
	}
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	d, err := m.Dialer("proxy")
	if err != nil {
		t.Fatalf("Dialer: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// The dial must return the router's refusal as an error, never panic.
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("dial through domain-server outbound panicked: %v", r)
			}
		}()
		conn, err := d.DialContext(ctx, "tcp", "127.0.0.1", 1)
		if err == nil {
			conn.Close()
			t.Fatal("dial = nil, want the DNS router's refusal")
		}
		if !strings.Contains(err.Error(), "lookup refused") {
			t.Errorf("dial error = %v, want the DNS router's refusal", err)
		}
	}()
}

// TestCreateOutboundIPServerWithoutDNSRouter is Case D: an
// IP-literal server needs no resolution, so no DNS router is
// required and creation succeeds.
func TestCreateOutboundIPServerWithoutDNSRouter(t *testing.T) {
	m := newTestManager(t)
	out := parseOutbound(t, m, `{"type":"http","tag":"proxy","server":"127.0.0.1","server_port":1}`)
	if err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options); err != nil {
		t.Fatalf("CreateOutbound(IP server, no DNS router) = %v, want nil", err)
	}
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, err := m.Dialer("proxy"); err != nil {
		t.Fatalf("Dialer: %v", err)
	}
}

// TestDirectDialIPTargetWithoutDNSRouter is Case E: an IP
// destination through a direct outbound works with no DNS router
// at all.
func TestDirectDialIPTargetWithoutDNSRouter(t *testing.T) {
	_, tcpPort := startFakeTCP(t)
	m := newTestManager(t)
	out := parseOutbound(t, m, `{"type":"direct","tag":"direct"}`)
	if err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options); err != nil {
		t.Fatalf("CreateOutbound direct = %v", err)
	}
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	d, err := m.Dialer("direct")
	if err != nil {
		t.Fatalf("Dialer: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", "127.0.0.1", uint16(tcpPort))
	if err != nil {
		t.Fatalf("direct IP dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := conn.Read(buf); err != nil {
		t.Fatal(err)
	}
	if string(buf[:2]) != "ok" {
		t.Errorf("echo = %q, want ok", buf)
	}
}
