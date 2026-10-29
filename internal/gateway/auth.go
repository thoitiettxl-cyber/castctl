package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/thoitiettxl-cyber/muse-cli/go/internal/conn"
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
// status code and body bytes. Transport errors are returned
// wrapped in a redaction wrapper (redactErr): the original error
// chain is preserved for errors.As/Is classification, but the
// printed text has credentials stripped. The callers classify
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
		return 0, nil, nil, redactErr(err)
	}
	defer resp.Body.Close()
	// Responses are small JSON/RSC bodies; cap the read so a
	// hostile server cannot grow memory without bound.
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return 0, nil, nil, redactErr(err)
	}
	return resp.StatusCode, data, resp.Header, nil
}

// SessionInfo is the decoded /api/session response. VMID is the
// assigned personal VM id.
type SessionInfo struct {
	VMID string
	Raw  map[string]any
}

// FetchSessionInfo discovers the assigned personal VM: GET
// /api/session. A non-200 status is an AuthError (cookies
// expired). A missing vm_id is a retryable *conn.GatewayError, NOT
// an AuthError: the VM is down/restarting
// ({"status":"unavailable",...}), exactly as in Python.
func FetchSessionInfo(ctx context.Context, client *http.Client, cookies string) (SessionInfo, error) {
	status, data, _, err := doHatch(ctx, client, http.MethodGet, "https://muse.ai/api/session", hatchHeaders(cookies, ""), nil)
	if err != nil {
		return SessionInfo{}, err
	}
	if status != 200 {
		return SessionInfo{}, conn.NewAuthError(fmt.Sprintf("api/session -> %d (cookies expired? re-export)", status))
	}
	raw, err := decodeJSONValue(data)
	if err != nil {
		return SessionInfo{}, conn.NewAuthError(redactErrorString(fmt.Sprintf("api/session returned non-JSON (%q)", truncateText(string(data), 80))))
	}
	info, ok := raw.(map[string]any)
	if !ok {
		// Python: "vm_id" not in a non-dict body is also the
		// VM-unavailable case, not an auth failure.
		return SessionInfo{}, &conn.GatewayError{Status: -1, Payload: redactErrorString(fmt.Sprintf("VM unavailable (%v); retry shortly or `MUSE_VM_ID=<id> muse-cli wake`", raw))}
	}
	rawVM, ok := info["vm_id"]
	if !ok {
		return SessionInfo{}, &conn.GatewayError{Status: -1, Payload: redactErrorString(fmt.Sprintf("VM unavailable (%v); retry shortly or `MUSE_VM_ID=<id> muse-cli wake`", info))}
	}
	return SessionInfo{VMID: fmt.Sprintf("%v", rawVM), Raw: info}, nil
}

// FetchAccessToken exchanges cookies for an access token: POST
// /api/auth/check with an empty body. Non-200 is an AuthError.
func FetchAccessToken(ctx context.Context, client *http.Client, cookies string) (string, error) {
	status, data, _, err := doHatch(ctx, client, http.MethodPost, "https://muse.ai/api/auth/check", hatchHeaders(cookies, ""), []byte{})
	if err != nil {
		return "", err
	}
	if status != 200 {
		return "", conn.NewAuthError(redactErrorString(fmt.Sprintf("auth/check -> %d %s (cookies expired? re-export)", status, truncateText(string(data), 120))))
	}
	d, err := decodeJSONObject(data)
	if err != nil {
		return "", conn.NewAuthError("auth/check returned non-JSON or missing access_token")
	}
	token, _ := d["access_token"].(string)
	if token == "" {
		return "", conn.NewAuthError("auth/check response missing access_token")
	}
	return token, nil
}

// FetchHatchToken exchanges an access token for a hatch token:
// POST /api/hatch/token {vmAddress, vmName}. Non-200 is an
// AuthError.
func FetchHatchToken(ctx context.Context, client *http.Client, cookies, accessToken, vmID string) (string, error) {
	payload, err := json.Marshal(map[string]string{
		"vmAddress": fmt.Sprintf("wss://%s.metaaivm.com/", vmID),
		"vmName":    vmID,
	})
	if err != nil {
		return "", err
	}
	status, data, _, err := doHatch(ctx, client, http.MethodPost, "https://muse.ai/api/hatch/token", hatchHeaders(cookies, accessToken), payload)
	if err != nil {
		return "", err
	}
	if status != 200 {
		return "", conn.NewAuthError(redactErrorString(fmt.Sprintf("hatch/token -> %d %s", status, truncateText(string(data), 160))))
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
