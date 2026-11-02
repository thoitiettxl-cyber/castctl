// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package pluginhost

import (
	"sync"
	"sync/atomic"
)

// hostCallbackEntry is one registered reverse-callback target:
// the host that owns the plugin plus the plugin's tag. The
// registry is keyed by the callback ID stored in the plugin's
// host context (see the unix/windows loaders). It exists so a
// plugin calling host.log reaches the right Host without the
// loader passing Go pointers through C (which cgo forbids).
type hostCallbackEntry struct {
	host *Host
	tag  string
}

var (
	hostCallbackSeq atomic.Uint64
	hostCallbacks   sync.Map // uint64 -> hostCallbackEntry
)

func registerHostCallback(host *Host, tag string) uint64 {
	id := hostCallbackSeq.Add(1)
	hostCallbacks.Store(id, hostCallbackEntry{host: host, tag: tag})
	return id
}

func unregisterHostCallback(id uint64) {
	hostCallbacks.Delete(id)
}

func lookupHostCallback(id uint64) (hostCallbackEntry, bool) {
	raw, ok := hostCallbacks.Load(id)
	if !ok {
		return hostCallbackEntry{}, false
	}
	entry, ok := raw.(hostCallbackEntry)
	return entry, ok
}
