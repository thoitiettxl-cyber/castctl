// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
)

// UserAgent is the Chrome/153 Mac user agent Python sends on every
// HTTPS call (gateway.py UA).
const UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36"

// GatewayHost is the shared WebSocket gateway host.
const GatewayHost = "hatch.metaaivm.com"

// AuthTimeout bounds each HTTPS auth call (20s in Python).
const AuthTimeout = 20 * time.Second

// hatchHeaders builds the headers for muse.ai HTTPS calls: Chrome
// UA, Referer/Origin, Sec-Fetch-*, Accept/Content-Type
// application/json, Cookie, and Authorization: Bearer when a token
// is present. The Cookie value is never copied anywhere else.
func hatchHeaders(cookies, accessToken string) http.Header {
	h := http.Header{}
	h.Set("User-Agent", UserAgent)
	h.Set("Referer", "https://muse.ai/")
	h.Set("Origin", "https://muse.ai")
	h.Set("Sec-Fetch-Site", "same-origin")
	h.Set("Sec-Fetch-Mode", "cors")
	h.Set("Sec-Fetch-Dest", "empty")
	h.Set("Accept", "application/json")
	h.Set("Content-Type", "application/json")
	h.Set("Cookie", cookies)
	if accessToken != "" {
		h.Set("Authorization", "Bearer "+accessToken)
	}
	return h
}

// doHatch performs one muse.ai HTTPS request with an AuthTimeout
// bound (the caller's earlier deadline still wins) and returns the
// status code and body bytes. Transport errors are returned as a
// typed summary (transport.go): operation, error class, and
// net-error kind only — Go's HTTP stack embeds wire bytes in its
// error text, so the old redactErr fallback leaked peer bytes
// into output. The original error chain is preserved for
// errors.As/Is classification, but the printed text is the
// summary. The callers classify
// them (auth helpers map them to AuthError only where Python
// would fail the same way — a network failure reaching
// fetch_session_info in Python raises the raw curl error, but
// the Connector treats any non-AuthError connect failure as a
// failed connect; mapping transport errors to AuthError here
// would wrongly mark them unretryable, so they are left for the
// caller).
func doHatch(ctx context.Context, client *http.Client, method, url string, headers http.Header, body []byte) (int, []byte, http.Header, error) {
	ctx, cancel := context.WithTimeout(ctx, AuthTimeout)
	defer cancel()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return 0, nil, nil, redactErr(err)
	}
	req.Header = headers
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, wrapTransportError(transportOp(method, url), err)
	}
	defer resp.Body.Close()
	// Responses are small JSON/RSC bodies; cap the read so a
	// hostile server cannot grow memory without bound.
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return 0, nil, nil, wrapTransportError(transportOp(method, url), err)
	}
	return resp.StatusCode, data, resp.Header, nil
}

// SessionInfo is the decoded /api/session response. VMID is the
// assigned personal VM id.
type SessionInfo struct {
	VMID string
	Raw  map[string]any
}

// vmUnavailableLabel is the class label for a session response
// that carries no usable vm_id. The wake guidance is a CONSTANT
// (never body-derived): loop 5 dropped it with the raw body
// text, but the ruling did not require dropping it, so it is
// restored here (loop 6, item 6c). The CLI's
// session_unavailable classification keys on the "VM
// unavailable" prefix.
const vmUnavailableLabel = "VM unavailable; retry shortly or `MUSE_VM_ID=<id> castctl wake`"

// FetchSessionInfo discovers the assigned personal VM: GET
// /api/session. A non-200 status is an AuthError (cookies
// expired). A missing vm_id is a retryable *conn.GatewayError, NOT
// an AuthError: the VM is down/restarting
// ({"status":"unavailable",...}), exactly as in Python.
// Loop 5: no error from this function carries body bytes —
// non-JSON and missing-vm_id failures carry the allowlist
// summary only (status enum parsed by key, body length,
// content-type). The "VM unavailable" class label in the
// GatewayError payload is a constant, not body text: the
// CLI's session_unavailable classification keys on it.
func FetchSessionInfo(ctx context.Context, client *http.Client, cookies string) (SessionInfo, error) {
	info, _, err := fetchSessionInfoRaw(ctx, client, cookies)
	return info, err
}

// FetchAccessToken exchanges cookies for an access token: POST
// /api/auth/check with an empty body. Non-200 is an AuthError.
// Loop 5: the AuthError carries the allowlist summary only,
// never body bytes.
func FetchAccessToken(ctx context.Context, client *http.Client, cookies string) (string, error) {
	token, _, err := fetchAccessTokenRaw(ctx, client, cookies)
	return token, err
}

// FetchHatchToken exchanges an access token for a hatch token:
// POST /api/hatch/token {vmAddress, vmName}. Non-200 is an
// AuthError. Loop 5: the AuthError carries the allowlist
// summary only, never body bytes.
func FetchHatchToken(ctx context.Context, client *http.Client, cookies, accessToken, vmID string) (string, error) {
	payload, err := json.Marshal(map[string]string{
		"vmAddress": fmt.Sprintf("wss://%s.metaaivm.com/", vmID),
		"vmName":    vmID,
	})
	if err != nil {
		return "", err
	}
	status, data, hdr, err := doHatch(ctx, client, http.MethodPost, "https://muse.ai/api/hatch/token", hatchHeaders(cookies, accessToken), payload)
	if err != nil {
		return "", err
	}
	if status != 200 {
		sum := summarizeBody(fmt.Sprintf("hatch/token -> %d", status), data, hdr.Get("Content-Type"), nil)
		return "", conn.NewAuthError(sum.text)
	}
	d, err := decodeJSONObject(data)
	if err != nil {
		return "", conn.NewAuthError("hatch/token returned non-JSON or missing token")
	}
	token, _ := d["token"].(string)
	if token == "" {
		return "", conn.NewAuthError("hatch/token response missing token")
	}
	return token, nil
}
