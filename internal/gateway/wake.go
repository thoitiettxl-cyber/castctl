// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// wakeURL is the muse.ai VM wake endpoint. It is a package-level
// variable only so tests can point it at an httptest server;
// production code must never reassign it. Tests that override it
// must restore the previous value via t.Cleanup.
var wakeURL = "https://muse.ai/api/hatch/vm/wake"

// wakeTimeout bounds each wake call (15s, matching Python
// wake_vm's timeout=15).
const wakeTimeout = 15 * time.Second

// WakeVM asks muse.ai to wake the VM with vmID and returns the
// HTTP status and the response body, mirroring Python wake_vm in
// cli.py: POST wakeURL with {"vm_id": vmID, "retry_count": 0} and
// the hatch headers for cookies/accessToken.
//
// A non-2xx status is NOT an error: status and the parsed body are
// returned and err is nil. Only transport errors (including the
// timeout below) are returned as err, wrapped for safe printing
// by doHatch (redactErr), with the original chain preserved for
// errors.Is/errors.As.
//
// The body is the parsed JSON value (object, array, or scalar;
// numbers decode as json.Number, per decodeJSONValue) when the
// response parses as JSON, nil when the response body is empty
// (Python wake_vm: `resp.json() if resp.text else None`, so an
// empty body is JSON null, not ""), and otherwise the raw
// response text truncated to 300 bytes. The truncation is in bytes, not runes
// or characters, matching Python's resp.text[:300] as specified
// for this port, so it may split a multi-byte rune.
//
// The call is bounded by wakeTimeout via context.WithTimeout.
// WithTimeout never extends a caller deadline: an earlier caller
// deadline still fires first, and doHatch's longer AuthTimeout
// bound inside the call cannot extend the 15s cap either — the
// earliest deadline wins.
func WakeVM(ctx context.Context, client *http.Client, cookies, accessToken, vmID string) (status int, body any, err error) {
	if client == nil {
		return 0, nil, errors.New("wake: nil http client")
	}
	payload, err := json.Marshal(map[string]any{"vm_id": vmID, "retry_count": 0})
	if err != nil {
		return 0, nil, fmt.Errorf("wake: encode body: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, wakeTimeout)
	defer cancel()
	status, data, _, err := doHatch(ctx, client, http.MethodPost, wakeURL, hatchHeaders(cookies, accessToken), payload)
	if err != nil {
		return 0, nil, err
	}
	if len(data) == 0 {
		// Python: empty body -> None (JSON null), not "".
		return status, nil, nil
	}
	v, jerr := decodeJSONValue(data)
	if jerr != nil {
		// Redact the full body first, then truncate to 300
		// bytes: truncating the raw body first can leave a
		// secret fragment too short for the redaction
		// floors. The byte cut (which may split a multi-byte
		// rune, as documented above) is unchanged.
		text := redactFreeText(string(data))
		if len(text) > 300 {
			text = text[:300]
		}
		return status, text, nil
	}
	return status, v, nil
}
