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
