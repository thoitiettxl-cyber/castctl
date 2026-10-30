// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/thoitiettxl-cyber/muse-cli/go/internal/conn"
	pb "github.com/thoitiettxl-cyber/muse-cli/go/internal/proto"
)

// serviceID maps a route's service name to its ServiceType value.
// Unknown or absent names map to daemon (0), exactly as
// SERVICE_IDS.get(route.get("service", "daemon"), 0) does.
func serviceID(name string) pb.ServiceType {
	switch name {
	case "sentinel":
		return pb.ServiceType_SERVICE_SENTINEL
	case "vault":
		return pb.ServiceType_SERVICE_VAULT
	case "authd":
		return pb.ServiceType_SERVICE_AUTHD
	default:
		return pb.ServiceType_SERVICE_DAEMON
	}
}

// routeEntry is the wire shape of one routes.json entry. Only
// method, http, path and service are ever used; the auxiliary
// fields (aliases, noiseOnly, streamMode, channel,
// connectionClass, responseType, requestBody) are preserved in the
// embedded file but ignored here, as in Python.
type routeEntry struct {
	Method  string `json:"method"`
	HTTP    string `json:"http"`
	Path    string `json:"path"`
	Service string `json:"service"`
}

// RouteTable is the parsed routes.json: 258 methods. It is built
// once per process from the verbatim embedded bytes in
// internal/proto; parsing errors are construction errors, never
// per-call errors.
type RouteTable struct {
	mu     sync.RWMutex
	routes map[string]conn.Route
	// counts records the embedded table's shape for tests.
	counts map[string]int
	total  int
}

var (
	defaultTable     *RouteTable
	defaultTableOnce sync.Once
	defaultTableErr  error
)

// DefaultRoutes returns the process-wide route table parsed from the
// embedded routes.json.
func DefaultRoutes() (*RouteTable, error) {
	defaultTableOnce.Do(func() {
		defaultTable, defaultTableErr = ParseRoutes(pb.RoutesJSON())
	})
	return defaultTable, defaultTableErr
}

// ParseRoutes parses routes.json bytes into a RouteTable. Duplicate
// method names keep the first entry; entries without a method are
// skipped.
func ParseRoutes(data []byte) (*RouteTable, error) {
	var entries []routeEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("gateway: parse routes: %w", err)
	}
	t := &RouteTable{routes: make(map[string]conn.Route, len(entries)), counts: map[string]int{}}
	for _, e := range entries {
		if e.Method == "" {
			continue
		}
		t.counts[e.HTTP]++
		t.total++
		if _, ok := t.routes[e.Method]; ok {
			continue
		}
		t.routes[e.Method] = conn.Route{Method: e.Method, HTTP: e.HTTP, Path: e.Path, Service: e.Service}
	}
	return t, nil
}

// LookupRoute returns the route for a method, or false when the
// method is unknown. Unknown HTTP methods are never routes: only
// entries present in routes.json answer true, so LookupRoute
// returns false for unknown methods (the `raw` rejection lives in
// commands, in PR3).
func (t *RouteTable) LookupRoute(method string) (conn.Route, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	r, ok := t.routes[method]
	return r, ok
}

// Total returns the number of route entries in the table.
func (t *RouteTable) Total() int { return t.total }

// CountHTTP returns how many entries use the given HTTP verb.
func (t *RouteTable) CountHTTP(verb string) int { return t.counts[verb] }
