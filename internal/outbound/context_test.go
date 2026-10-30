// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package outbound

import (
	"context"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"
)

func TestNewContext(t *testing.T) {
	t.Run("registers registries", func(t *testing.T) {
		ctx := NewContext(context.Background())
		if service.FromContext[adapter.OutboundRegistry](ctx) == nil {
			t.Fatal("outbound registry missing from context")
		}
		if service.FromContext[adapter.EndpointRegistry](ctx) == nil {
			t.Fatal("endpoint registry missing from context")
		}
		if service.FromContext[adapter.DNSTransportRegistry](ctx) == nil {
			t.Fatal("dns transport registry missing from context")
		}
	})

	t.Run("keeps an existing registry", func(t *testing.T) {
		first := NewContext(context.Background())
		second := NewContext(first)
		if service.RegistryFromContext(first) != service.RegistryFromContext(second) {
			t.Fatal("NewContext replaced an existing registry instead of keeping it")
		}
	})

	t.Run("concurrent calls are race free and independent", func(t *testing.T) {
		t.Parallel()
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ctx := NewContext(context.Background())
				if service.FromContext[adapter.OutboundRegistry](ctx) == nil {
					t.Error("outbound registry missing from concurrent context")
				}
			}()
		}
		wg.Wait()
	})
}

// TestGlobalRegistryContextSingleInstance pins NB9 within this package:
// the process-global registry context is built exactly once, behind the
// single registryOnce in context.go, so repeated and concurrent access
// always returns the same registry. NewContext clones that registry per
// caller by design, so per-caller registries deliberately differ; only
// the global one is pinned here. internal/profile derives from the
// same global via outbound.RegistryContext (see singContext in
// profile/outbound.go and TestRegistryContextSharedWithProfile in
// context_shared_test.go); there is no second sync.Once.
func TestGlobalRegistryContextSingleInstance(t *testing.T) {
	first := RegistryContext()
	if first == nil {
		t.Fatal("RegistryContext() = nil")
	}
	base := service.RegistryFromContext(first)
	if base == nil {
		t.Fatal("global registry context carries no registry")
	}
	if second := RegistryContext(); service.RegistryFromContext(second) != base {
		t.Fatal("RegistryContext() built the registry twice: repeated calls return different registries")
	}

	const goroutines = 32
	regs := make([]service.Registry, goroutines)
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			regs[i] = service.RegistryFromContext(RegistryContext())
		}(i)
	}
	wg.Wait()
	for i, reg := range regs {
		if reg != base {
			t.Errorf("concurrent RegistryContext()[%d] registry = %v, want the single shared registry %v", i, reg, base)
		}
	}
}
