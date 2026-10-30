// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package outbound

import (
	"context"
	"errors"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	N "github.com/sagernet/sing/common/network"
)

// stubRouter is the minimal adapter.Router for outbound-only operation.
//
// Measured (PR1 router probe, ~/workspace/tmp/pr1-router-probe/
// router-probe.log): on the direct, socks, and DNS-transport
// construction/start/dial paths, NO Router method was ever called
// (call count 0 after every phase, both with full tags and with
// with_utls alone). WireGuard-endpoint construction/start is covered
// separately by tagged tests (TestWireGuardEndpointBuildStartClose);
// dial/handshake through a WireGuard endpoint was NOT probed and
// remains unverified. The stub therefore exists only to satisfy
// constructors that read a Router from the service context. The
// routing methods return clear errors because inbound routing is never
// used by outbound-only code; if a future sing-box path calls one, the
// error names the stub instead of failing silently. Decision: build on
// registry-only managers + this stub (Gate 2 option B); do NOT use
// full box.Box. Fallback condition (a called method whose error breaks
// construction/start/dial) was never met in the probe.
type stubRouter struct{}

var _ adapter.Router = stubRouter{}

var errNoRouter = errors.New("outbound: no router: outbound-only mode has no inbound routing")

func (stubRouter) Start(stage adapter.StartStage, scope *adapter.Scope) error { return nil }

func (stubRouter) PreMatch(metadata adapter.InboundContext, firstPacket []byte) adapter.PreMatchResult {
	return adapter.PreMatchResult{Action: adapter.PreMatchContinue}
}

func (stubRouter) HijackDNSPacket(ctx context.Context, payload []byte, writer N.PacketWriter, metadata adapter.InboundContext) {
}

func (stubRouter) RouteConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	return errNoRouter
}

func (stubRouter) RoutePacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	return errNoRouter
}

func (stubRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
}

func (stubRouter) RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
}

func (stubRouter) RuleSet(tag string) (adapter.RuleSet, bool) { return nil, false }

func (stubRouter) Rules() []adapter.Rule { return nil }

func (stubRouter) NeedFindProcess() bool { return false }

func (stubRouter) NeedFindNeighbor() bool { return false }

func (stubRouter) NeighborResolver() adapter.NeighborResolver { return nil }

func (stubRouter) AppendTracker(tracker adapter.ConnectionTracker) {}

func (stubRouter) ResetNetwork() {}

// stubNetworkManager is the minimal adapter.NetworkManager for
// outbound-only operation. Two constructors dereference it:
//
//   - WireGuard endpoint construction calls
//     networkManager.InterfaceFinder() unconditionally.
//   - dialer.NewDNSQueryOptions calls DefaultOptions() when two or more
//     DNS transports exist without a domain_resolver.
//
// Both return benign zero values: the default interface finder (nil
// monitor, no interface watching) and empty network options. No
// interface monitoring, no WIFI state, no DNS-cache flushing.
type stubNetworkManager struct{}

var _ adapter.NetworkManager = stubNetworkManager{}

func (stubNetworkManager) Start(stage adapter.StartStage, scope *adapter.Scope) error { return nil }

func (stubNetworkManager) Initialize(ruleSets []adapter.RuleSet) {}

func (stubNetworkManager) InterfaceFinder() control.InterfaceFinder {
	return control.NewDefaultInterfaceFinder()
}

func (stubNetworkManager) UpdateInterfaces() error { return nil }

func (stubNetworkManager) DefaultNetworkInterface() *adapter.NetworkInterface { return nil }

func (stubNetworkManager) NetworkInterfaces() []adapter.NetworkInterface { return nil }

func (stubNetworkManager) NetworkEnvironment() uint64 { return 0 }

func (stubNetworkManager) AutoDetectInterface() bool { return false }

func (stubNetworkManager) AutoDetectInterfaceFunc() control.Func { return nil }

func (stubNetworkManager) ProtectFunc() control.Func { return nil }

func (stubNetworkManager) DefaultOptions() adapter.NetworkOptions { return adapter.NetworkOptions{} }

func (stubNetworkManager) RegisterAutoRedirectOutputMark(mark uint32) error { return nil }

func (stubNetworkManager) AutoRedirectOutputMark() uint32 { return 0 }

func (stubNetworkManager) AutoRedirectOutputMarkFunc() control.Func { return nil }

func (stubNetworkManager) NetworkMonitor() tun.NetworkUpdateMonitor { return nil }

func (stubNetworkManager) InterfaceMonitor() tun.DefaultInterfaceMonitor { return nil }

func (stubNetworkManager) PackageManager() tun.PackageManager { return nil }

func (stubNetworkManager) NeedWIFIState() bool { return false }

func (stubNetworkManager) WIFIState() adapter.WIFIState { return adapter.WIFIState{} }

func (stubNetworkManager) UpdateWIFIState(ctx context.Context) {}

func (stubNetworkManager) ResetNetwork(ctx context.Context) {}

func (stubNetworkManager) FlushSystemDNSCache() {}
