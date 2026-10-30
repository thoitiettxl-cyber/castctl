// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package shared

// StatusSummary is the `status` command output shape, ported from
// cli.py:529-536 (status_data). Field order is the Python dict
// order: vm_id, sessions, unread, identity. The three gateway calls
// themselves (sessions.list, chat.unread_count, identity) belong to
// command wiring (Phase 2); this package owns only the shape, so
// the summary stays a pure function of already-fetched values and
// never touches a gateway.
type StatusSummary struct {
	// VMID is the gateway's VM id.
	VMID string `json:"vm_id"`
	// Sessions is the number of sessions in the sessions.list
	// result (0 when the result carries no sessions list).
	Sessions int `json:"sessions"`
	// Unread is the chat.unread_count result, kept verbatim.
	Unread any `json:"unread"`
	// Identity is the identity result, kept verbatim.
	Identity any `json:"identity"`
}

// SummarizeStatus builds a StatusSummary from the three values
// status_data reads, ported from cli.py:529-536 (status_data):
// sessions counts the "sessions" list of the sessions.list result,
// and unread and identity pass through untouched.
func SummarizeStatus(vmID string, sessionsResult map[string]any, unread any, identity any) StatusSummary {
	sessions, _ := asList(sessionsResult["sessions"])
	return StatusSummary{
		VMID:     vmID,
		Sessions: len(sessions),
		Unread:   unread,
		Identity: identity,
	}
}
