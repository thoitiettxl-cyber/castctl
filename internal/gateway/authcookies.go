// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

import (
	"context"
	"fmt"
	"net/http"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
)

// Cookie-returning variants of the cheap auth chain, for the
// session keeper.
//
// The keeper must observe Set-Cookie renewal on the cheap chain
// (GET /api/session -> POST /api/auth/check) without changing the
// behaviour of the seven existing doHatch call sites, so doHatch
// itself is untouched: these variants share the same request and
// error mapping as FetchSessionInfo/FetchAccessToken and add
// only the parsed Set-Cookie values.
//
// Parsing uses http.ParseSetCookie, one call per Set-Cookie
// header value, exactly as the stdlib would parse a response.
// Unparseable values are skipped and counted; the count is for
// diagnostics only (a count, never the line). Cookies are
// returned alongside errors whenever a response header was
// received, so a tick can persist a server-issued deletion even
// when the step then reports AuthError. On a transport error no
// header exists and no cookies are returned.
//
// The returned cookies are SECRET MATERIAL (cookie values).
// Callers must never log, print, or copy them outside the
// merge/write path. Only the cookie *names*, counts, and expiry
// dates may reach logs or state.

// ParseSetCookieHeader parses every Set-Cookie value in hdr with
// http.ParseSetCookie. Unparseable values are skipped; the second
// return value counts them. It never hand-splits a header line:
// the stdlib parser owns the grammar.
func ParseSetCookieHeader(hdr http.Header) (cookies []*http.Cookie, skipped int) {
	if hdr == nil {
		return nil, 0
	}
	for _, value := range hdr.Values("Set-Cookie") {
		c, err := http.ParseSetCookie(value)
		if err != nil {
			skipped++
			continue
		}
		cookies = append(cookies, c)
	}
	return cookies, skipped
}

func fetchSessionInfoRaw(ctx context.Context, client *http.Client, cookies string) (SessionInfo, http.Header, error) {
	status, data, hdr, err := doHatch(ctx, client, http.MethodGet, "https://muse.ai/api/session", hatchHeaders(cookies, ""), nil)
	if err != nil {
		return SessionInfo{}, nil, err
	}
	if status != 200 {
		return SessionInfo{}, hdr, conn.NewAuthError(fmt.Sprintf("api/session -> %d (cookies expired? re-export)", status))
	}
	raw, err := decodeJSONValue(data)
	if err != nil {
		sum := summarizeBody("api/session returned non-JSON", data, hdr.Get("Content-Type"), nil)
		return SessionInfo{}, hdr, conn.NewAuthError(sum.text)
	}
	info, ok := raw.(map[string]any)
	if !ok {
		// Python: "vm_id" not in a non-dict body is also the
		// VM-unavailable case, not an auth failure.
		sum := summarizeBody(vmUnavailableLabel, data, hdr.Get("Content-Type"), nil)
		return SessionInfo{}, hdr, gatewayErrorFromSummary(-1, sum)
	}
	rawVM, ok := info["vm_id"]
	if !ok {
		sum := summarizeBody(vmUnavailableLabel, data, hdr.Get("Content-Type"), info, "status")
		return SessionInfo{}, hdr, gatewayErrorFromSummary(-1, sum)
	}
	vmID, ok := rawVM.(string)
	if !ok {
		// JSON null (or any non-string) vm_id is the missing-VM
		// case, not a string: Python's `"vm_id" not in info`
		// branch is about absence, and a null vm_id means the
		// same thing — the VM is down/restarting. Formatting
		// it with %v would yield "<nil>" as a bogus VM id.
		sum := summarizeBody(vmUnavailableLabel, data, hdr.Get("Content-Type"), info, "status")
		return SessionInfo{}, hdr, gatewayErrorFromSummary(-1, sum)
	}
	return SessionInfo{VMID: vmID, Raw: info}, hdr, nil
}

// FetchSessionInfoWithCookies is FetchSessionInfo plus the
// response's parsed Set-Cookie values (and the skipped-value
// count). Error mapping is identical to FetchSessionInfo.
func FetchSessionInfoWithCookies(ctx context.Context, client *http.Client, cookies string) (SessionInfo, []*http.Cookie, int, error) {
	info, hdr, err := fetchSessionInfoRaw(ctx, client, cookies)
	parsed, skipped := ParseSetCookieHeader(hdr)
	return info, parsed, skipped, err
}

func fetchAccessTokenRaw(ctx context.Context, client *http.Client, cookies string) (string, http.Header, error) {
	status, data, hdr, err := doHatch(ctx, client, http.MethodPost, "https://muse.ai/api/auth/check", hatchHeaders(cookies, ""), []byte{})
	if err != nil {
		return "", nil, err
	}
	if status != 200 {
		sum := summarizeBody(fmt.Sprintf("auth/check -> %d (cookies expired? re-export)", status), data, hdr.Get("Content-Type"), nil)
		return "", hdr, conn.NewAuthError(sum.text)
	}
	d, err := decodeJSONObject(data)
	if err != nil {
		return "", hdr, conn.NewAuthError("auth/check returned non-JSON or missing access_token")
	}
	token, _ := d["access_token"].(string)
	if token == "" {
		return "", hdr, conn.NewAuthError("auth/check response missing access_token")
	}
	return token, hdr, nil
}

// FetchAccessTokenWithCookies is FetchAccessToken plus the
// response's parsed Set-Cookie values (and the skipped-value
// count). Error mapping is identical to FetchAccessToken.
func FetchAccessTokenWithCookies(ctx context.Context, client *http.Client, cookies string) (string, []*http.Cookie, int, error) {
	token, hdr, err := fetchAccessTokenRaw(ctx, client, cookies)
	parsed, skipped := ParseSetCookieHeader(hdr)
	return token, parsed, skipped, err
}
