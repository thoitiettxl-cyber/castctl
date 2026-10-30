// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package shared

// InviteReward is the reward block of an invite summary: the
// reward's title and body, or absent entirely when the server
// carries no reward object.
type InviteReward struct {
	Title *string `json:"title"`
	Body  *string `json:"body"`
}

// InviteSummary is the invite summary, ported from cli.py:659-681
// (summarize_invite). Field order is the Python dict order: state,
// code, link, max_uses, used, uses_remaining, reward, offer,
// share_text, redeemed_someone_elses_code.
type InviteSummary struct {
	State                    *string       `json:"state"`
	Code                     *string       `json:"code"`
	Link                     *string       `json:"link"`
	MaxUses                  *int64        `json:"max_uses"`
	Used                     *int64        `json:"used"`
	UsesRemaining            *int64        `json:"uses_remaining"`
	Reward                   *InviteReward `json:"reward"`
	Offer                    *string       `json:"offer"`
	ShareText                *string       `json:"share_text"`
	RedeemedSomeonesElseCode *bool         `json:"redeemed_someone_elses_code"`
}

// SummarizeInvite extracts the invite fields that matter from a
// GET /api/hatch/invite result, ported verbatim from
// cli.py:659-681 (summarize_invite). uses_remaining is computed as
// max(max_uses - use_count, 0) only when the server left it null
// and both max_uses and use_count are present; a server-provided
// value (including 0) always wins. A non-object reward yields a
// nil reward, exactly as Python's isinstance check does.
func SummarizeInvite(d map[string]any) InviteSummary {
	var reward *InviteReward
	if rm, ok := asMap(d["reward"]); ok {
		reward = &InviteReward{
			Title: stringPtrField(rm, "title"),
			Body:  stringPtrField(rm, "body"),
		}
	}
	remaining := intPtrField(d, "uses_remaining")
	if remaining == nil {
		maxUses := intPtrField(d, "max_uses")
		used := intPtrField(d, "use_count")
		if maxUses != nil && used != nil {
			r := *maxUses - *used
			if r < 0 {
				r = 0
			}
			remaining = &r
		}
	}
	return InviteSummary{
		State:                    stringPtrField(d, "invite_state"),
		Code:                     stringPtrField(d, "code"),
		Link:                     stringPtrField(d, "invite_link"),
		MaxUses:                  intPtrField(d, "max_uses"),
		Used:                     intPtrField(d, "use_count"),
		UsesRemaining:            remaining,
		Reward:                   reward,
		Offer:                    stringPtrField(d, "subtitle"),
		ShareText:                stringPtrField(d, "share_text"),
		RedeemedSomeonesElseCode: boolPtrField(d, "has_redeemed_invite_code"),
	}
}
