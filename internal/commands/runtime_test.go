// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

import (
	"testing"

	"github.com/sagernet/sing-box/option"
)

func topoOutbound(tag, detour string) option.Outbound {
	opts := &option.DirectOutboundOptions{}
	opts.Detour = detour
	return option.Outbound{Tag: tag, Type: "direct", Options: opts}
}

func topoTags(obs []option.Outbound) []string {
	tags := make([]string, 0, len(obs))
	for _, ob := range obs {
		tags = append(tags, ob.Tag)
	}
	return tags
}

func TestTopoOrderOutbounds(t *testing.T) {
	t.Run("detour before outer, file order otherwise", func(t *testing.T) {
		ordered, err := topoOrderOutbounds([]option.Outbound{
			topoOutbound("outer", "inner"),
			topoOutbound("inner", ""),
			topoOutbound("plain", ""),
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := topoTags(ordered); len(got) != 3 || got[0] != "inner" || got[1] != "outer" || got[2] != "plain" {
			t.Errorf("order = %v, want [inner outer plain]", got)
		}
	})

	t.Run("endpoint detour target is a leaf", func(t *testing.T) {
		ordered, err := topoOrderOutbounds([]option.Outbound{
			topoOutbound("px", "wg1"),
		}, map[string]bool{"wg1": true})
		if err != nil {
			t.Fatalf("endpoint detour = %v, want nil", err)
		}
		if got := topoTags(ordered); len(got) != 1 || got[0] != "px" {
			t.Errorf("order = %v, want [px]", got)
		}
	})

	t.Run("missing detour errors", func(t *testing.T) {
		if _, err := topoOrderOutbounds([]option.Outbound{topoOutbound("px", "nope")}, nil); err == nil {
			t.Error("missing detour = nil error, want error")
		}
	})

	t.Run("detour to unknown tag errors even with endpoints present", func(t *testing.T) {
		if _, err := topoOrderOutbounds([]option.Outbound{topoOutbound("px", "nope")}, map[string]bool{"wg1": true}); err == nil {
			t.Error("missing detour = nil error, want error")
		}
	})

	t.Run("cycle errors", func(t *testing.T) {
		if _, err := topoOrderOutbounds([]option.Outbound{
			topoOutbound("a", "b"),
			topoOutbound("b", "a"),
		}, nil); err == nil {
			t.Error("cycle = nil error, want error")
		}
	})

	t.Run("cycle through endpoint-named tag is not a cycle", func(t *testing.T) {
		// An outbound detouring to an endpoint tag never
		// recurses, so it cannot form a cycle through it.
		if _, err := topoOrderOutbounds([]option.Outbound{
			topoOutbound("px", "wg1"),
		}, map[string]bool{"wg1": true}); err != nil {
			t.Errorf("endpoint detour = %v, want nil", err)
		}
	})
}
