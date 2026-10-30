// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package deliver

import (
	"context"
	"fmt"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
)

// SessionOpKind is one session operation, named after the
// subcommand suffix in the argparse loop (cli.py:2474-2483):
// session-rename, session-pin, session-unpin, session-archive,
// session-unarchive, session-delete.
type SessionOpKind string

// Session operation kinds. The string value is the gateway method
// suffix: the method is "session." + kind.
const (
	SessionOpRename    SessionOpKind = "rename"
	SessionOpPin       SessionOpKind = "pin"
	SessionOpUnpin     SessionOpKind = "unpin"
	SessionOpArchive   SessionOpKind = "archive"
	SessionOpUnarchive SessionOpKind = "unarchive"
	SessionOpDelete    SessionOpKind = "delete"
)

// validSessionOpKinds is the exact kind list from the argparse
// loop, in argparse order.
var validSessionOpKinds = []SessionOpKind{
	SessionOpRename,
	SessionOpPin,
	SessionOpUnpin,
	SessionOpArchive,
	SessionOpUnarchive,
	SessionOpDelete,
}

// sessionStartParams is the "params" object of the session.start
// body (cli.py:2076-2081). Field order is the Python dict order:
// origin, lifecycle, title. Title is omitted when empty, as
// Python adds it only when truthy.
type sessionStartParams struct {
	Origin    string `json:"origin"`
	Lifecycle string `json:"lifecycle"`
	Title     string `json:"title,omitempty"`
}

// sessionStartBody is the session.start request body.
type sessionStartBody struct {
	Method string             `json:"method"`
	Params sessionStartParams `json:"params"`
}

// sessionRenameBody is the session.rename request body
// (cli.py:2086-2087). Field order is the Python dict order:
// session_id, title.
type sessionRenameBody struct {
	SessionID string `json:"session_id"`
	Title     string `json:"title"`
}

// sessionMethodBody is the request body for every session
// operation except rename (cli.py:2089): the method path plus
// the session id. Field order is the Python dict order: method,
// session_id.
type sessionMethodBody struct {
	Method    string `json:"method"`
	SessionID string `json:"session_id"`
}

// SessionStart starts a new side chat and returns the server
// reply verbatim (parsed JSON), ported from session_start
// (cli.py:2076-2081). The reply is returned as-is: the server
// defines its shape, matching Python's out() passthrough. An
// empty title is omitted from the params, exactly as in Python.
func SessionStart(ctx context.Context, gw Gateway, title string) (any, error) {
	if gw == nil {
		return nil, fmt.Errorf("deliver: session start: nil gateway")
	}
	body := sessionStartBody{
		Method: "/api/session/start",
		Params: sessionStartParams{
			Origin:    "fresh",
			Lifecycle: "persistent",
			Title:     title,
		},
	}
	return gw.CallJSON(ctx, "session.start", conn.RequestOptions{Body: body})
}

// SessionOp renames, pins, unpins, archives, unarchives, or
// deletes one session and returns the server reply verbatim
// (parsed JSON), ported from session_op (cli.py:2084-2091).
// Rename sends {"session_id", "title"}; every other kind sends
// {"method": "/api/session/<kind>", "session_id"}. The title
// argument is ignored for kinds other than rename, as in Python.
// An unknown kind is an error: the argparse loop only ever
// produces the six kinds above, so an unknown kind is a caller
// bug, not a server round trip.
func SessionOp(ctx context.Context, gw Gateway, kind SessionOpKind, sessionID, title string) (any, error) {
	if gw == nil {
		return nil, fmt.Errorf("deliver: session %s: nil gateway", kind)
	}
	valid := false
	for _, k := range validSessionOpKinds {
		if k == kind {
			valid = true
			break
		}
	}
	if !valid {
		return nil, fmt.Errorf("deliver: unknown session operation %q", kind)
	}
	method := "session." + string(kind)
	if kind == SessionOpRename {
		return gw.CallJSON(ctx, method, conn.RequestOptions{
			Body: sessionRenameBody{SessionID: sessionID, Title: title},
		})
	}
	return gw.CallJSON(ctx, method, conn.RequestOptions{
		Body: sessionMethodBody{Method: "/api/session/" + string(kind), SessionID: sessionID},
	})
}
