// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package outbound_test

import (
	"context"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/service"

	"github.com/thoitiettxl-cyber/muse-cli/go/internal/outbound"
	"github.com/thoitiettxl-cyber/muse-cli/go/internal/profile"
)

// TestRegistryContextSharedWithProfile pins the NB9 unification from
// outside both packages: outbound.RegistryContext is the single
// process-global registry, and profile parsing (which delegates to it
// via singContext) exercises the same global. profile exposes no
// accessor returning its registry context, so pointer identity across
// packages cannot be asserted directly; instead this test pins (a)
// the global is a single instance under repeated and concurrent
// access, (b) concurrent access through BOTH entry points —
// outbound.NewContext/RegistryContext and profile.ParseSingleConfig —
// succeeds under -race with identical parse outcomes, and (c) the
// outbound registry rejects the same unknown type through the
// outbound construction path that profile parsing rejects through
// its parse path. The delegation itself is visible in
// profile/outbound.go: singContext returns outbound.RegistryContext(),
// and profile no longer imports sing-box/include (verify with
// grep -rn "sing-box/include" internal/profile/).
func TestRegistryContextSharedWithProfile(t *testing.T) {
	first := outbound.RegistryContext()
	if first == nil {
		t.Fatal("RegistryContext() = nil")
	}
	base := service.RegistryFromContext(first)
	if base == nil {
		t.Fatal("RegistryContext() carries no service registry")
	}
	if got := service.RegistryFromContext(outbound.RegistryContext()); got != base {
		t.Fatal("RegistryContext() returned a different registry on a repeated call")
	}

	const goroutines = 16
	errs := make([]string, goroutines)
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				ctx := outbound.NewContext(context.Background())
				if service.RegistryFromContext(ctx) == nil {
					errs[i] = "NewContext carries no registry"
				}
				return
			}
			cfg, err := profile.ParseSingleConfig([]byte(`{"profiles":{"p":{"outbound":{"type":"direct"}}}}`), "/base")
			if err != nil {
				errs[i] = "ParseSingleConfig: " + err.Error()
				return
			}
			ref, ok := cfg.Profiles["p"]
			if !ok {
				errs[i] = "parsed config has no profile p"
				return
			}
			ob, err := ref.Outbound.InlineOutbound()
			if err != nil || ob == nil || ob.Type != "direct" {
				errs[i] = "InlineOutbound did not parse the direct outbound through the shared registry"
			}
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != "" {
			t.Errorf("concurrent shared-registry access [%d]: %s", i, err)
		}
	}
	// The global must still be the same single instance after the
	// concurrent exercise through both packages.
	if got := service.RegistryFromContext(outbound.RegistryContext()); got != base {
		t.Error("RegistryContext() registry changed after concurrent access through outbound and profile")
	}

	// Profile parsing rejects an unknown outbound type through the
	// shared registry; the outbound construction path rejects it too.
	cfg, err := profile.ParseSingleConfig([]byte(`{"profiles":{"p":{"outbound":{"type":"bogus-type"}}}}`), "/base")
	if err == nil && cfg != nil {
		if _, ok := cfg.Profiles["p"]; ok {
			_, err = cfg.Profiles["p"].Outbound.InlineOutbound()
		}
	}
	if err == nil {
		t.Fatal("profile parse of unknown outbound type = nil, want error through the shared registry")
	}

	m, err := outbound.NewManager(context.Background(), log.NewNOPFactory().NewLogger("test"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	if err := m.CreateOutbound(context.Background(), "bad", "bogus-type", nil); err == nil {
		t.Fatal("CreateOutbound bogus-type = nil, want error through the shared registry")
	}
}
