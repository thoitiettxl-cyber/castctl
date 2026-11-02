// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package webui

import (
	"net"
	"net/http"
	"net/url"
	"strings"
)

// Origin allowlist for mutating API requests (Design A): the
// server sends no CORS headers and accepts no cross-origin
// browser request, without relying on the browser to enforce
// anything. The check runs after auth and before the timeout
// (pinned order: rate-limit → auth → Origin → timeout), and
// only on POST/PUT/PATCH/DELETE: reads (GET/HEAD) carry no
// mutation and are safe to serve to any loopback caller.
//
//   - No Origin header: a non-browser client (curl, the CLI's
//     own tooling). Allowed: browsers always send Origin on
//     credentialed cross-origin POSTs, so absence is the
//     non-browser signal.
//   - Origin with a loopback host (127.0.0.0/8, ::1, localhost,
//     any port): the server is loopback-only, so a loopback
//     origin is the operator's own browser on this machine.
//     Allowed. The loopback test reuses the screencast
//     helpers (originHost/isLoopbackHost).
//   - Origin whose host equals the request Host (same-host,
//     any port): the UI served from this server calling back
//     to it. Allowed.
//   - Anything else — a remote origin, an opaque "null"
//     origin, a malformed Origin, or an Origin carrying
//     userinfo (browsers never emit userinfo in Origin) —
//     gets a fixed 403 with no value echo. The Bearer token is still required first:
//     the 403 only ever replaces a response an authenticated
//     request would have received, so it leaks nothing about
//     whether the token was valid to an unauthenticated
//     caller (auth runs first and 401s them instead).
//
// This is a defence-in-depth check on top of the Bearer token
// and the loopback bind, not a replacement for either: a
// loopback attacker with the token is already the operator's
// own machine, and the token remains the gate.
func (s *Server) requireSameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		default:
			next.ServeHTTP(w, r)
			return
		}
		origin := r.Header.Get("Origin")
		if origin == "" {
			next.ServeHTTP(w, r)
			return
		}
		if allowedOrigin(origin, r.Host) {
			next.ServeHTTP(w, r)
			return
		}
		writeError(w, http.StatusForbidden, "forbidden", "cross-origin request rejected")
	})
}

// allowedOrigin reports whether an Origin header value is a
// loopback or same-host origin for a request addressed to
// requestHost. A malformed Origin is never allowed.
func allowedOrigin(origin, requestHost string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || u.User != nil {
		return false
	}
	if isLoopbackHost(originHost(origin)) {
		return true
	}
	host := u.Hostname()
	if host == "" {
		return false
	}
	reqHost := requestHost
	if h, _, err := net.SplitHostPort(reqHost); err == nil {
		reqHost = h
	}
	reqHost = strings.Trim(reqHost, "[]")
	return strings.EqualFold(host, reqHost)
}
