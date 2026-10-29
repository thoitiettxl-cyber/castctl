package outbound

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	m, err := NewManager(context.Background(), log.NewNOPFactory().NewLogger("test"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

// parseOutbound parses one option.Outbound JSON object through sing-box's
// own UnmarshalJSONContext, using the manager's registry context.
func parseOutbound(t *testing.T, m *Manager, raw string) option.Outbound {
	t.Helper()
	var out option.Outbound
	if err := json.UnmarshalContext(m.Context(), []byte(raw), &out); err != nil {
		t.Fatalf("parse outbound %s: %v", raw, err)
	}
	return out
}

func TestManagerCreateAndLifecycle(t *testing.T) {
	t.Run("direct build start dial close", func(t *testing.T) {
		_, tcpPort := startFakeTCP(t)
		m := newTestManager(t)
		out := parseOutbound(t, m, `{"type":"direct","tag":"direct"}`)
		if err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options); err != nil {
			t.Fatalf("CreateOutbound direct: %v", err)
		}
		if err := m.Start(); err != nil {
			t.Fatalf("Start: %v", err)
		}
		d, err := m.Dialer("direct")
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := d.DialContext(ctx, "tcp", "127.0.0.1", uint16(tcpPort))
		if err != nil {
			t.Fatalf("DialContext direct: %v", err)
		}
		defer conn.Close()
		if _, err := conn.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 16)
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		if string(buf[:n]) != "ok" {
			t.Errorf("direct echo = %q, want %q", string(buf[:n]), "ok")
		}
		if err := m.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	})

	t.Run("duplicate tag is an error", func(t *testing.T) {
		m := newTestManager(t)
		out := parseOutbound(t, m, `{"type":"direct","tag":"direct"}`)
		if err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options); err != nil {
			t.Fatal(err)
		}
		if err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options); err == nil {
			t.Fatal("duplicate tag CreateOutbound = nil, want error")
		}
	})

	t.Run("unknown type is an error", func(t *testing.T) {
		m := newTestManager(t)
		err := m.CreateOutbound(context.Background(), "nope", "bogus-type", nil)
		if err == nil {
			t.Fatal("unknown type CreateOutbound = nil, want error")
		}
		if !strings.Contains(err.Error(), "bogus-type") {
			t.Errorf("error = %v, want it to name the unknown type", err)
		}
	})

	t.Run("empty tag is an error", func(t *testing.T) {
		m := newTestManager(t)
		if err := m.CreateOutbound(context.Background(), "", "direct", &option.DirectOutboundOptions{}); err == nil {
			t.Fatal("empty tag CreateOutbound = nil, want error")
		}
	})

	t.Run("wireguard as outbound names the endpoint form", func(t *testing.T) {
		m := newTestManager(t)
		err := m.CreateOutbound(context.Background(), "wg", "wireguard", &option.StubOptions{})
		if err == nil {
			t.Fatal("wireguard-as-outbound = nil, want error")
		}
		if !strings.Contains(strings.ToLower(err.Error()), "endpoint") {
			t.Errorf("error = %v, want it to name the endpoint form", err)
		}
	})

	t.Run("double start is an error", func(t *testing.T) {
		m := newTestManager(t)
		out := parseOutbound(t, m, `{"type":"direct","tag":"direct"}`)
		if err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options); err != nil {
			t.Fatal(err)
		}
		if err := m.Start(); err != nil {
			t.Fatalf("first Start: %v", err)
		}
		if err := m.Start(); err == nil {
			t.Fatal("second Start = nil, want error")
		}
	})

	t.Run("close without start and double close are nil", func(t *testing.T) {
		m := newTestManager(t)
		if err := m.Close(); err != nil {
			t.Fatalf("Close without Start: %v", err)
		}
		if err := m.Close(); err != nil {
			t.Fatalf("second Close: %v", err)
		}
	})

	t.Run("dialer for unknown tag is an error", func(t *testing.T) {
		m := newTestManager(t)
		if _, err := m.Dialer("missing"); err == nil {
			t.Fatal("Dialer(missing) = nil, want error")
		}
	})

	t.Run("failed start does not mark the manager started", func(t *testing.T) {
		m := newTestManager(t)
		out := parseOutbound(t, m, `{"type":"direct","tag":"direct"}`)
		if err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options); err != nil {
			t.Fatal(err)
		}
		// Simulate a stage failure the way a racing Close causes one:
		// closing the lifecycle scope cancels its context, so every
		// Scope.Start stage returns an error.
		if err := m.scope.Close(); err != nil {
			t.Fatalf("closing scope: %v", err)
		}
		if err := m.Start(); err == nil {
			t.Fatal("Start with a closed scope = nil, want error")
		}
		if m.started {
			t.Error("Start failed but started is true: the flag must be set only after all start stages succeed")
		}
	})

	t.Run("default is the first outbound created", func(t *testing.T) {
		m := newTestManager(t)
		out := parseOutbound(t, m, `{"type":"direct","tag":"direct"}`)
		if err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options); err != nil {
			t.Fatal(err)
		}
		if m.Default() == nil || m.Default().Tag() != "direct" {
			t.Errorf("Default() = %v, want direct", m.Default())
		}
	})

	t.Run("manager satisfies outbound manager access", func(t *testing.T) {
		m := newTestManager(t)
		var _ adapter.OutboundManager = m.OutboundManager()
	})
}

func TestManagerConcurrentStartClose(t *testing.T) {
	// NB10: Start, Close and Dialer racing must leave the manager in a
	// terminal state — the started flag must reflect the actual Start
	// outcome, never "started" when Start failed or Close won the race.
	// Run with -race: the flag is guarded by the same mutex that
	// serializes Start/Close.
	for iter := 0; iter < 16; iter++ {
		m, err := NewManager(context.Background(), log.NewNOPFactory().NewLogger("test"))
		if err != nil {
			t.Fatal(err)
		}
		out := parseOutbound(t, m, `{"type":"direct","tag":"direct"}`)
		if err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		var startErr error
		wg.Add(1)
		go func() {
			defer wg.Done()
			startErr = m.Start()
		}()
		for j := 0; j < 4; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = m.Close()
			}()
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = m.Dialer("direct")
			}()
		}
		wg.Wait()
		if startErr == nil && !m.started {
			t.Errorf("iter %d: Start returned nil but started is false", iter)
		}
		if startErr != nil && m.started {
			t.Errorf("iter %d: Start returned %v but started is true: a failed or pre-empted Start must not leave the manager started", iter, startErr)
		}
		if err := m.Start(); err == nil {
			t.Fatalf("iter %d: Start after concurrent Start/Close = nil, want error", iter)
		} else if !strings.Contains(err.Error(), "Start called") {
			t.Errorf("iter %d: second Start error = %v, want a Start-called error", iter, err)
		}
		_ = m.Close()
	}
}

func TestManagerConcurrentNewContext(t *testing.T) {
	// include.Context() races on a package-global assignment; NewManager
	// must be safe to call concurrently (registries built once, service
	// registry cloned per manager). Run with -race.
	for i := 0; i < 8; i++ {
		t.Run("parallel manager", func(t *testing.T) {
			t.Parallel()
			m, err := NewManager(context.Background(), log.NewNOPFactory().NewLogger("test"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = m.Close() }()
			out := parseOutbound(t, m, `{"type":"direct","tag":"direct"}`)
			if err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options); err != nil {
				t.Fatal(err)
			}
			if err := m.Start(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestManagerNoSecretsInErrors(t *testing.T) {
	// A fixture password must never surface in an error string.
	_, tcpPort := startFakeTCP(t)
	m := newTestManager(t)
	_ = tcpPort
	raw := `{"type":"socks","tag":"proxy","server":"127.0.0.1","server_port":1,"version":"5","username":"user","password":"FAKE"}`
	out := parseOutbound(t, m, raw)
	if err := m.CreateOutbound(context.Background(), out.Tag, out.Type, out.Options); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	d, err := m.Dialer("proxy")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = d.DialContext(ctx, "tcp", "127.0.0.1", 80)
	if err == nil {
		t.Fatal("dial through refusing proxy = nil, want error")
	}
	if strings.Contains(err.Error(), "FAKE") {
		t.Errorf("dial error leaks fixture password: %v", err)
	}
	var _ = errors.Is
}
