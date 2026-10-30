// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package deliver_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/thoitiettxl-cyber/castctl/internal/deliver"
	"github.com/thoitiettxl-cyber/castctl/internal/gateway"
)

const fakeCookies = "hatch_sess=FAKE; datr=FAKE"

func TestWakeFuncMatchesGatewayWakeVM(t *testing.T) {
	// Compile-time wiring proof: the frozen gateway.WakeVM
	// signature must be assignable to deliver.WakeFunc, so the
	// commands layer can pass gateway.WakeVM as WakeDeps.WakeVM
	// with no adapter.
	var _ deliver.WakeFunc = gateway.WakeVM
}

func TestWakeTimeoutValue(t *testing.T) {
	if deliver.WakeTimeout != 15*time.Second {
		t.Errorf("WakeTimeout = %v, want 15s", deliver.WakeTimeout)
	}
}

func TestWake(t *testing.T) {
	t.Run("profile vm id, fake wake helper", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"wake":"ok"}`))
		}))
		defer server.Close()
		client := server.Client()

		var seenClient *http.Client
		var seenCookies, seenToken, seenVMID string
		wakeFn := func(ctx context.Context, c *http.Client, cookies, accessToken, vmID string) (int, any, error) {
			seenClient, seenCookies, seenToken, seenVMID = c, cookies, accessToken, vmID
			// Prove the passed-in client is usable: it reaches
			// the fake server. No live host is involved.
			resp, err := c.Get(server.URL)
			if err != nil {
				return 0, nil, err
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return 0, nil, fmt.Errorf("fake server status %d", resp.StatusCode)
			}
			return 202, map[string]any{"woken": true}, nil
		}

		got, err := deliver.Wake(context.Background(), deliver.WakeDeps{
			Client:  client,
			Cookies: fakeCookies,
			VMID:    "fake-vm-1",
			FetchAccessToken: func(context.Context, *http.Client, string) (string, error) {
				return "fake-access-token", nil
			},
			FetchSessionInfo: func(context.Context, *http.Client, string) (gateway.SessionInfo, error) {
				t.Error("FetchSessionInfo must not be called when VMID is set")
				return gateway.SessionInfo{}, nil
			},
			WakeVM: wakeFn,
		})
		if err != nil {
			t.Fatalf("Wake: %v", err)
		}
		if seenClient != client {
			t.Error("wake helper received a different client than the one passed in")
		}
		if seenCookies != fakeCookies || seenToken != "fake-access-token" || seenVMID != "fake-vm-1" {
			t.Errorf("wake helper args = cookies %q token %q vmID %q", seenCookies, seenToken, seenVMID)
		}
		if got.Status != 202 {
			t.Errorf("Status = %d, want 202", got.Status)
		}
		if m, ok := got.Body.(map[string]any); !ok || m["woken"] != true {
			t.Errorf("Body = %#v, want the helper reply verbatim", got.Body)
		}
	})

	t.Run("empty vm id resolves via session info", func(t *testing.T) {
		var seenVMID string
		_, err := deliver.Wake(context.Background(), deliver.WakeDeps{
			Client:  httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).Client(),
			Cookies: fakeCookies,
			FetchAccessToken: func(context.Context, *http.Client, string) (string, error) {
				return "fake-access-token", nil
			},
			FetchSessionInfo: func(_ context.Context, _ *http.Client, cookies string) (gateway.SessionInfo, error) {
				if cookies != fakeCookies {
					t.Errorf("FetchSessionInfo cookies = %q, want fake cookies", cookies)
				}
				return gateway.SessionInfo{VMID: "resolved-vm-9"}, nil
			},
			WakeVM: func(_ context.Context, _ *http.Client, _, _, vmID string) (int, any, error) {
				seenVMID = vmID
				return 200, nil, nil
			},
		})
		if err != nil {
			t.Fatalf("Wake: %v", err)
		}
		if seenVMID != "resolved-vm-9" {
			t.Errorf("vmID passed to wake helper = %q, want resolved-vm-9", seenVMID)
		}
	})

	t.Run("nil client fails before network", func(t *testing.T) {
		called := false
		_, err := deliver.Wake(context.Background(), deliver.WakeDeps{
			Cookies: fakeCookies,
			WakeVM: func(context.Context, *http.Client, string, string, string) (int, any, error) {
				called = true
				return 0, nil, nil
			},
		})
		if err == nil {
			t.Fatal("Wake(nil client): got nil error")
		}
		if called {
			t.Error("wake helper was called despite a nil client")
		}
	})

	t.Run("missing wake helper fails before network", func(t *testing.T) {
		fetchCalled := false
		_, err := deliver.Wake(context.Background(), deliver.WakeDeps{
			Client:  httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).Client(),
			Cookies: fakeCookies,
			FetchAccessToken: func(context.Context, *http.Client, string) (string, error) {
				fetchCalled = true
				return "", nil
			},
		})
		if !errors.Is(err, deliver.ErrWakeUnavailable) {
			t.Fatalf("Wake(nil WakeVM): err = %v, want ErrWakeUnavailable", err)
		}
		if fetchCalled {
			t.Error("token fetch ran despite a missing wake helper")
		}
	})

	t.Run("token failure surfaces before session info, empty vm id", func(t *testing.T) {
		// Python wake_vm fetches the access token FIRST, then
		// session info for the vm_id: when both fail, the token
		// error surfaces, and a token failure makes no
		// session-info call at all.
		tokenErr := errors.New("fake token failure")
		sessionErr := errors.New("fake session failure")
		sessionCalled := false
		_, err := deliver.Wake(context.Background(), deliver.WakeDeps{
			Client:  httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).Client(),
			Cookies: fakeCookies,
			FetchAccessToken: func(context.Context, *http.Client, string) (string, error) {
				return "", tokenErr
			},
			FetchSessionInfo: func(context.Context, *http.Client, string) (gateway.SessionInfo, error) {
				sessionCalled = true
				return gateway.SessionInfo{}, sessionErr
			},
			WakeVM: func(context.Context, *http.Client, string, string, string) (int, any, error) {
				return 200, nil, nil
			},
		})
		if !errors.Is(err, tokenErr) {
			t.Fatalf("Wake: err = %v, want the token error %v", err, tokenErr)
		}
		if sessionCalled {
			t.Error("FetchSessionInfo was called despite the token fetch failing")
		}
	})

	t.Run("both fetches fail, token error surfaces", func(t *testing.T) {
		tokenErr := errors.New("fake token failure")
		sessionErr := errors.New("fake session failure")
		_, err := deliver.Wake(context.Background(), deliver.WakeDeps{
			Client:  httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).Client(),
			Cookies: fakeCookies,
			FetchAccessToken: func(context.Context, *http.Client, string) (string, error) {
				return "", tokenErr
			},
			FetchSessionInfo: func(context.Context, *http.Client, string) (gateway.SessionInfo, error) {
				return gateway.SessionInfo{}, sessionErr
			},
			WakeVM: func(context.Context, *http.Client, string, string, string) (int, any, error) {
				return 200, nil, nil
			},
		})
		if !errors.Is(err, tokenErr) {
			t.Fatalf("Wake: err = %v, want the token error %v", err, tokenErr)
		}
		if errors.Is(err, sessionErr) {
			t.Errorf("Wake: err wraps the session error too: %v", err)
		}
	})

	t.Run("token fetch error is wrapped", func(t *testing.T) {
		sentinel := errors.New("fake auth failure")
		_, err := deliver.Wake(context.Background(), deliver.WakeDeps{
			Client:  httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).Client(),
			Cookies: fakeCookies,
			VMID:    "fake-vm-1",
			FetchAccessToken: func(context.Context, *http.Client, string) (string, error) {
				return "", sentinel
			},
			WakeVM: func(context.Context, *http.Client, string, string, string) (int, any, error) {
				return 200, nil, nil
			},
		})
		if !errors.Is(err, sentinel) {
			t.Fatalf("Wake: err = %v, want it to wrap the fetch error", err)
		}
	})

	t.Run("wake helper error is wrapped", func(t *testing.T) {
		sentinel := errors.New("fake wake failure")
		_, err := deliver.Wake(context.Background(), deliver.WakeDeps{
			Client:  httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).Client(),
			Cookies: fakeCookies,
			VMID:    "fake-vm-1",
			FetchAccessToken: func(context.Context, *http.Client, string) (string, error) {
				return "fake-access-token", nil
			},
			WakeVM: func(context.Context, *http.Client, string, string, string) (int, any, error) {
				return 0, nil, sentinel
			},
		})
		if !errors.Is(err, sentinel) {
			t.Fatalf("Wake: err = %v, want it to wrap the helper error", err)
		}
	})

	t.Run("context cancellation reaches the wake helper", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		start := time.Now()
		_, err := deliver.Wake(ctx, deliver.WakeDeps{
			Client:  httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).Client(),
			Cookies: fakeCookies,
			VMID:    "fake-vm-1",
			FetchAccessToken: func(context.Context, *http.Client, string) (string, error) {
				return "fake-access-token", nil
			},
			WakeVM: func(ctx context.Context, _ *http.Client, _, _, _ string) (int, any, error) {
				<-ctx.Done()
				return 0, nil, ctx.Err()
			},
		})
		if err == nil {
			t.Fatal("Wake: got nil error, want a context error")
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Errorf("Wake took %v, want it to end promptly on cancellation", elapsed)
		}
	})
}
