// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package deliver

import (
	"context"
	"fmt"

	"github.com/thoitiettxl-cyber/muse-cli/go/internal/conn"
)

// stopThreadBody is the chat.cancel body for a side chat
// (cli.py:2093-2106): {"session_id": thread}.
type stopThreadBody struct {
	SessionID string `json:"session_id"`
}

// StopTurn stops Muse's current turn (the web app's Stop
// button), ported from cancel_turn (cli.py:2093-2106). The body
// is {} for the main chat (empty thread) or {"session_id":
// thread} for a side chat, as the web client sends it. The
// server reply is returned verbatim (parsed JSON), e.g.
// {"cancelled": true}.
func StopTurn(ctx context.Context, gw Gateway, thread string) (any, error) {
	if gw == nil {
		return nil, fmt.Errorf("deliver: stop: nil gateway")
	}
	var body any = struct{}{}
	if thread != "" {
		body = stopThreadBody{SessionID: thread}
	}
	return gw.CallJSON(ctx, "chat.cancel", conn.RequestOptions{Body: body})
}
