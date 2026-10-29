package outbound

import (
	"context"
	"testing"
	"time"
)

// BootstrapLookup is the single system-resolver call site in the Go port.
// It exists only to resolve a DNS server's own hostname before that
// server can be used. These tests use localhost only: no network, no
// fallback behaviour is exercised here.

func TestBootstrapLookup(t *testing.T) {
	t.Run("localhost resolves to loopback", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		addrs, err := BootstrapLookup(ctx, "localhost")
		if err != nil {
			t.Fatalf("BootstrapLookup(localhost) = %v", err)
		}
		if len(addrs) == 0 {
			t.Fatal("BootstrapLookup(localhost) returned no addresses")
		}
		foundLoopback := false
		for _, addr := range addrs {
			if addr.IsLoopback() {
				foundLoopback = true
			}
		}
		if !foundLoopback {
			t.Errorf("BootstrapLookup(localhost) = %v, want at least one loopback address", addrs)
		}
	})

	// NOTE: negative DNS tests are intentionally absent. This VM's
	// egress resolver answers wildcard-style (PR0: getent returned
	// 198.18.8.226/227 for arbitrary names) and the cgo resolver
	// ignores Go context cancellation for hosts-file hits, so
	// "unresolvable host" and "cancelled context" outcomes are
	// environment-dependent, not product behaviour. The bootstrap
	// failure path is covered at the DNS layer with an injected
	// fake (TestClientBootstrapFailureIsError).

	t.Run("empty host is an error", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := BootstrapLookup(ctx, "")
		if err == nil {
			t.Fatal("BootstrapLookup(\"\") = nil, want error")
		}
	})
}
