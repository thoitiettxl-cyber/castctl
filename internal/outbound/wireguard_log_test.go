//go:build with_wireguard && with_gvisor

// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package outbound

// WireGuard endpoint log tests: sing-box's device logs reach
// castctl's factory (through the redacting writer), and key
// material must never appear in full.
//
// IpcSet-failure scope, stated honestly: the IpcSet-failure
// error path itself is NOT exercised here. Bad key material is
// rejected by sing-box's option decode ("decode private key")
// BEFORE any device exists, so no options shape reaches
// IpcSet with bad material; valid material starts cleanly.
// What IS exercised: (a) the decode-error path through the
// manager's WrapErr boundary (error text + capture carry no
// key), and (b) a valid Start, whose device lines flow through
// the factory. The WrapErr boundary itself is what would
// redact an IpcSet error's IPC text if one ever surfaced.
// These tests run only under with_wireguard+with_gvisor; the
// CI legs (untagged, with_utls) do not run them.

import (
	"bytes"
	"context"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	badoption "github.com/sagernet/sing/common/json/badoption"

	"github.com/thoitiettxl-cyber/castctl/internal/logging"
)

// syncCapture is a mutex-guarded capture buffer. Sing-box
// device goroutines write through the factory writer
// concurrently with the test's reads; a plain bytes.Buffer
// races there (loop-2 verifier: DATA RACE in
// safeWriter.Write vs Buffer.String under -race). Every
// access here is serialised, so a read always sees a
// consistent snapshot and -race stays clean.
type syncCapture struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *syncCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}

func (c *syncCapture) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

// drainCapture waits until the capture is quiescent — two
// successive snapshots 50ms apart identical — up to 2s, and
// returns the final snapshot. Device goroutines emit
// asynchronously after Start returns and after Close, so a
// read taken immediately after Close can miss trailing
// lines; quiescence (not a fixed sleep, and never an
// unsynchronised read) is what makes the snapshot complete.
func drainCapture(t *testing.T, c *syncCapture) string {
	t.Helper()
	prev := c.String()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
		cur := c.String()
		if cur == prev {
			return cur
		}
		prev = cur
	}
	return c.String()
}

func wgWiredManager(t *testing.T) (*Manager, *logging.Handle, *syncCapture) {
	t.Helper()
	cap := &syncCapture{}
	h, err := logging.NewFactory(context.Background(), logging.Settings{Level: "trace"}, cap)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	m, err := NewManager(context.Background(), h.Logger("castctl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	out := parseOutbound(t, m, `{"type":"direct","tag":"direct"}`)
	if err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options); err != nil {
		t.Fatal(err)
	}
	return m, h, cap
}

// TestWireGuardInvalidKeyErrorCarriesNoKey: an invalid private
// key (a fixture string, not valid base64) fails endpoint
// creation at decode. The error text and the factory capture
// must carry no key material — the decode error passes through
// the manager's WrapErr boundary on its way out.
func TestWireGuardInvalidKeyErrorCarriesNoKey(t *testing.T) {
	m, h, cap := wgWiredManager(t)
	opts := &option.WireGuardEndpointOptions{
		PrivateKey: "LOGFIX-WGPRIV-6e19d0",
		Address: badoption.Listable[netip.Prefix]{
			netip.MustParsePrefix("10.0.0.2/32"),
		},
		MTU: 1280,
		Peers: []option.WireGuardPeer{
			{
				Address:   "127.0.0.1",
				Port:      51820,
				PublicKey: generateWGKey(t),
				AllowedIPs: badoption.Listable[netip.Prefix]{
					netip.MustParsePrefix("0.0.0.0/0"),
				},
			},
		},
	}
	err := m.CreateEndpoint(context.Background(), "wg", "wireguard", opts)
	if err == nil {
		t.Fatal("CreateEndpoint(invalid private key) = nil, want a decode error")
	}
	if !strings.Contains(err.Error(), "decode private key") {
		t.Errorf("error %q, want the sing-box decode error (wrong failure point)", err.Error())
	}
	if strings.Contains(err.Error(), "LOGFIX-WGPRIV-6e19d0") {
		t.Errorf("error contains the fixture private key: %v", err)
	}
	// The decode failure emits NOTHING through the factory
	// (measured: capture length 0 after Close) — scanning an
	// empty capture for the key would pass vacuously. A probe
	// line through the same factory proves the capture is
	// live, so the scan below examines real bytes; the decode
	// assertions above (not the probe) are the evidence about
	// the key rejection itself.
	logging.Emit(h.Logger("castctl"), context.Background(), log.LevelInfo, "invalid-key-capture-probe")
	got := drainCapture(t, cap)
	if got == "" {
		t.Fatal("capture empty after the probe line: positive control failed (suppression, not redaction)")
	}
	if !strings.Contains(got, "invalid-key-capture-probe") {
		t.Errorf("capture %q, want the probe line (proves the capture path was exercised)", got)
	}
	if strings.Contains(got, "LOGFIX-WGPRIV-6e19d0") {
		t.Errorf("capture contains the fixture private key:\n%s", got)
	}
}

// TestWireGuardDeviceLinesCarryNoFullKey: a valid endpoint
// Start emits wireguard-go device lines through the factory.
// No full key (private or public) may appear; the peer line
// the device itself emits carries only its own 4-char
// abbreviation (peer(ABCD…)), within Boss's at-most-8-chars
// rule. Keys here are freshly generated per test run, never
// fixtures and never secrets.
func TestWireGuardDeviceLinesCarryNoFullKey(t *testing.T) {
	m, _, cap := wgWiredManager(t)
	priv := generateWGKey(t)
	pub := generateWGKey(t)
	opts := &option.WireGuardEndpointOptions{
		PrivateKey: priv,
		Address: badoption.Listable[netip.Prefix]{
			netip.MustParsePrefix("10.0.0.2/32"),
		},
		MTU: 1280,
		Peers: []option.WireGuardPeer{
			{
				Address:   "127.0.0.1",
				Port:      51820,
				PublicKey: pub,
				AllowedIPs: badoption.Listable[netip.Prefix]{
					netip.MustParsePrefix("0.0.0.0/0"),
				},
			},
		},
	}
	if err := m.CreateEndpoint(context.Background(), "wg", "wireguard", opts); err != nil {
		t.Fatalf("CreateEndpoint: %v", err)
	}
	if err := m.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	_ = m.Close()
	got := drainCapture(t, cap)
	if got == "" {
		t.Fatal("capture empty: the device lines never reached the factory (positive control failed)")
	}
	for _, v := range []string{priv, pub} {
		if strings.Contains(got, v) {
			t.Errorf("capture contains a full key")
		}
	}
	if !strings.Contains(got, "peer(") {
		t.Errorf("capture %q, want a device peer line (proves the WG emission path was exercised)", got)
	}
	// The device's own abbreviation is 4 chars + ellipsis:
	// assert exactly that, and that no longer prefix of the
	// public key survives anywhere in the capture.
	if !strings.Contains(got, "peer("+pub[:4]+"…)") {
		t.Errorf("capture %q, want peer(<first 4 chars>…) for the fixture peer", got)
	}
	if strings.Contains(got, pub[:8]) {
		t.Errorf("capture contains an 8-char public-key prefix; the device emits 4, want no longer form")
	}
}
