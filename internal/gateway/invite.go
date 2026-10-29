// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/thoitiettxl-cyber/muse-cli/go/internal/conn"
)

// Invite endpoints (gateway.py fetch_invite / create_invite /
// redeem_invite_code). All calls go through the outbound HTTP
// client supplied by the caller; cookies travel only in the Cookie
// header.

var inviteCodePattern = regexp.MustCompile(`^[A-Z0-9]{6,16}$`)

// FetchInvite returns the invite-friends sheet data: GET
// /api/hatch/invite. 401/403 is an AuthError; any other non-200 is
// a GatewayError; a non-JSON or non-dict body is a GatewayError.
// Read-only: it never POSTs (the POST creates a code, which is
// account-state-changing).
func FetchInvite(ctx context.Context, client *http.Client, cookies string) (map[string]any, error) {
	status, data, _, err := doHatch(ctx, client, http.MethodGet, "https://muse.ai/api/hatch/invite", hatchHeaders(cookies, ""), nil)
	if err != nil {
		return nil, err
	}
	if status == 401 || status == 403 {
		return nil, conn.NewAuthError(fmt.Sprintf("api/hatch/invite -> %d (cookies expired? re-export)", status))
	}
	if status != 200 {
		return nil, &conn.GatewayError{Status: status, Payload: redactErrorString(truncateText(string(data), 200))}
	}
	d, err := decodeJSONObject(data)
	if err != nil {
		// Distinguish non-JSON from a JSON non-dict, as Python
		// does (different messages, both GatewayError -1).
		if _, jerr := decodeJSONValue(data); jerr != nil {
			return nil, &conn.GatewayError{Status: -1, Payload: redactErrorString(fmt.Sprintf("api/hatch/invite returned non-JSON (%q)", truncateText(string(data), 80)))}
		}
		v, _ := decodeJSONValue(data)
		return nil, &conn.GatewayError{Status: -1, Payload: fmt.Sprintf("api/hatch/invite returned %T", v)}
	}
	return d, nil
}

// CreateInvite creates this account's invite code: POST
// /api/hatch/invite with no body (30s timeout). This WRITES
// account state — it is what opening Invite friends does. Error
// mapping matches FetchInvite, with the POST status in the
// AuthError message.
func CreateInvite(ctx context.Context, client *http.Client, cookies string) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	status, data, _, err := doHatch(ctx, client, http.MethodPost, "https://muse.ai/api/hatch/invite", hatchHeaders(cookies, ""), []byte{})
	if err != nil {
		return nil, err
	}
	if status == 401 || status == 403 {
		return nil, conn.NewAuthError(fmt.Sprintf("api/hatch/invite POST -> %d (cookies expired? re-export)", status))
	}
	if status != 200 {
		return nil, &conn.GatewayError{Status: status, Payload: redactErrorString(truncateText(string(data), 200))}
	}
	d, err := decodeJSONObject(data)
	if err != nil {
		return nil, &conn.GatewayError{Status: -1, Payload: redactErrorString(fmt.Sprintf("api/hatch/invite POST returned non-JSON (%q)", truncateText(string(data), 80)))}
	}
	return d, nil
}

// RedeemInviteCode redeems a friend's invite code: POST
// /api/hatch/invite-code/redeem {code,
// supportsRedemptionStatus:true}. The code is stripped and
// uppercased; anything outside ^[A-Z0-9]{6,16}$ is a
// *ValidationError. 401/403 is an AuthError; every other status
// is returned with its body, exactly as Python returns
// (http_status, body). A non-JSON body becomes
// {"success":false,"reason":"unknown","detail":...}.
func RedeemInviteCode(ctx context.Context, client *http.Client, cookies, code string) (int, any, error) {
	// strings.TrimSpace + ToUpper over ASCII letters: TrimSpace
	// strips Unicode whitespace as Python's strip() does for the
	// cases that matter (spaces/newlines around a pasted code).
	code = upperASCII(trimSpaceASCII(code))
	if !inviteCodePattern.MatchString(code) {
		return 0, nil, &ValidationError{Message: fmt.Sprintf("not an invite code: %q", code)}
	}
	payload, err := json.Marshal(map[string]any{"code": code, "supportsRedemptionStatus": true})
	if err != nil {
		return 0, nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	status, data, _, err := doHatch(ctx, client, http.MethodPost, "https://muse.ai/api/hatch/invite-code/redeem", hatchHeaders(cookies, ""), payload)
	if err != nil {
		return 0, nil, err
	}
	if status == 401 || status == 403 {
		return 0, nil, conn.NewAuthError(fmt.Sprintf("invite-code/redeem -> %d (cookies expired? re-export)", status))
	}
	body, jerr := decodeJSONValue(data)
	if jerr != nil {
		body = map[string]any{"success": false, "reason": "unknown", "detail": truncateText(string(data), 200)}
	}
	return status, body, nil
}

func trimSpaceASCII(s string) string {
	start := 0
	for start < len(s) && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r' || s[start] == '\v' || s[start] == '\f') {
		start++
	}
	end := len(s)
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r' || s[end-1] == '\v' || s[end-1] == '\f') {
		end--
	}
	return s[start:end]
}

func upperASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 'a' + 'A'
		}
	}
	return string(b)
}
