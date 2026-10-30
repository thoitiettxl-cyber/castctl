// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package deliver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/thoitiettxl-cyber/castctl/internal/gateway"
)

// WakeTimeout bounds the wake POST itself: 15s in Python
// (cli.py:2128-2146, wake_vm). It does not bound the token and
// session-info fetches that precede it; those carry the auth
// helpers' own timeout. The timeout applies to the WakeVM call
// only, via a derived context whose earlier deadline still wins.
const WakeTimeout = 15 * time.Second

// WakeFunc is the signature of the gateway wake helper:
//
//	func WakeVM(ctx context.Context, client *http.Client, cookies, accessToken, vmID string) (status int, body any, err error)
//
// It POSTs https://muse.ai/api/hatch/vm/wake with JSON
// {"vm_id", "retry_count": 0}, builds headers via the gateway's
// unexported hatchHeaders, and returns the HTTP status plus the
// body parsed as JSON, or the body text truncated to 300 bytes
// when it is not JSON.
//
// The helper exists in the tree (internal/gateway/wake.go,
// gateway.WakeVM). Wake takes it as an injected WakeDeps.WakeVM
// value so tests can substitute a fake; the commands layer passes
// gateway.WakeVM directly. A nil WakeVM means no helper was
// injected, and Wake returns ErrWakeUnavailable before doing any
// network work.
type WakeFunc func(ctx context.Context, client *http.Client, cookies, accessToken, vmID string) (status int, body any, err error)

// ErrWakeUnavailable reports that no wake helper was injected.
// It is returned before any network work, so callers can
// distinguish "helper missing" from an auth or transport failure.
var ErrWakeUnavailable = errors.New("deliver: wake helper not available")

// WakeResult is the `wake` output shape, ported from wake_vm
// (cli.py:2128-2146): {"status": http_status, "body": ...}.
// Field order is the Python dict order. Body is the server reply
// verbatim (parsed JSON, or text truncated to 300 bytes by the
// wake helper); the server defines its shape. Status is int64,
// per the JSON invariant.
type WakeResult struct {
	Status int64 `json:"status"`
	Body   any   `json:"body"`
}

// WakeDeps carries Wake's explicit dependencies. Client is the
// *http.Client from the dialer's HTTPClient, passed in — never
// a shared package-level default client. Cookies is the Cookie
// header value resolved by the caller (the commands layer passes
// rt.Cookies(), which parses the cookies file through the
// gateway); Wake never parses a cookies file itself. VMID is the
// profile's vm_id, or empty to resolve it via FetchSessionInfo,
// as Python does (cfg vm_id, else fetch_session_info).
//
// FetchAccessToken and FetchSessionInfo default to the exported
// gateway helpers when nil; tests inject fakes. WakeVM is
// gateway.WakeVM (see WakeFunc); nil means no helper was injected
// and Wake returns ErrWakeUnavailable.
type WakeDeps struct {
	Client           *http.Client
	Cookies          string
	VMID             string
	FetchAccessToken func(ctx context.Context, client *http.Client, cookies string) (string, error)
	FetchSessionInfo func(ctx context.Context, client *http.Client, cookies string) (gateway.SessionInfo, error)
	WakeVM           WakeFunc
}

// Wake asks muse.ai to wake the VM and returns {status, body},
// ported from wake_vm (cli.py:2128-2146). Resolution order is
// Python's: cookies (already resolved by the caller), access
// token via FetchAccessToken, vm_id from the profile or from
// FetchSessionInfo when empty, then the wake POST via WakeVM
// bounded by WakeTimeout. Errors from the fetch helpers are
// returned wrapped, preserving their chain for errors.As
// classification by the caller; a nil client or a missing wake
// helper fails before any network work.
func Wake(ctx context.Context, deps WakeDeps) (WakeResult, error) {
	if deps.Client == nil {
		return WakeResult{}, fmt.Errorf("deliver: wake: nil http client")
	}
	if deps.WakeVM == nil {
		return WakeResult{}, ErrWakeUnavailable
	}
	fetchAccessToken := deps.FetchAccessToken
	if fetchAccessToken == nil {
		fetchAccessToken = gateway.FetchAccessToken
	}
	fetchSessionInfo := deps.FetchSessionInfo
	if fetchSessionInfo == nil {
		fetchSessionInfo = gateway.FetchSessionInfo
	}
	// Python's order (wake_vm): the access token is fetched
	// FIRST, then the vm_id is resolved from the profile or from
	// session info when empty. A token failure therefore
	// surfaces before any session-info error and makes no
	// session-info call at all.
	accessToken, err := fetchAccessToken(ctx, deps.Client, deps.Cookies)
	if err != nil {
		return WakeResult{}, fmt.Errorf("deliver: wake: fetch access token: %w", err)
	}
	vmID := deps.VMID
	if vmID == "" {
		info, err := fetchSessionInfo(ctx, deps.Client, deps.Cookies)
		if err != nil {
			return WakeResult{}, fmt.Errorf("deliver: wake: fetch session info: %w", err)
		}
		vmID = info.VMID
	}
	wakeCtx, cancel := context.WithTimeout(ctx, WakeTimeout)
	defer cancel()
	status, body, err := deps.WakeVM(wakeCtx, deps.Client, deps.Cookies, accessToken, vmID)
	if err != nil {
		return WakeResult{}, fmt.Errorf("deliver: wake: %w", err)
	}
	return WakeResult{Status: int64(status), Body: body}, nil
}
