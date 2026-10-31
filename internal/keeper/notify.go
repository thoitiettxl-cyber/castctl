// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package keeper

import (
	"context"
	"fmt"
)

// Telegram notices: fixed content, no secrets, no error text,
// no cookie names, no values, no token URLs. The profile name
// is configuration, not a secret, and is the only variable
// content. Every notice ends with the no-automatic-action line
// so a reader never mistakes a notice for an action taken.

// NoticeKind is the closed set of keeper notice kinds.
type NoticeKind string

const (
	// NoticeLoggedOut: the cheap chain proved the session dead
	// and the keeper stopped for this entry.
	NoticeLoggedOut NoticeKind = "logged_out"
	// NoticeReexported: a CDP re-export recovered the session.
	NoticeReexported NoticeKind = "re-exported"
	// NoticeFailed: the keeper stopped for a reason other than
	// a proven-dead session (e.g. the cookies file is missing
	// and no export could recover it).
	NoticeFailed NoticeKind = "failed"
)

// Notifier sends one fixed-content notice. Implementations live
// in the command layer (Telegram); the core never imports a
// transport. Notify is best-effort: a failure never fails the
// tick, it only leaves the warn marker pending.
type Notifier interface {
	Notify(ctx context.Context, kind NoticeKind, profileName string) error
}

// NoticeText renders the fixed notice body for a kind and
// profile. The re-login path names the two working remedies:
// screencast login and auth import.
func NoticeText(kind NoticeKind, profileName string) string {
	switch kind {
	case NoticeReexported:
		return fmt.Sprintf("castctl keeper: profile %s session re-exported from the browser and verified. No action was taken automatically.", profileName)
	case NoticeFailed:
		return fmt.Sprintf("castctl keeper: profile %s keeper stopped (session could not be verified). Re-login with `castctl auth login --profile %s` or re-import with `castctl auth import --profile %s`. No action was taken automatically.", profileName, profileName, profileName)
	default: // NoticeLoggedOut and any unknown kind degrade to logged_out.
		return fmt.Sprintf("castctl keeper: profile %s is logged out (cookies expired or revoked). Re-login with `castctl auth login --profile %s` or re-import with `castctl auth import --profile %s`. No action was taken automatically.", profileName, profileName, profileName)
	}
}
