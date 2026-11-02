// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package keeper

import (
	"context"
	"fmt"
	"strings"
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
	// NoticeCaptcha: headless re-login stopped because the
	// login page presented a captcha. Never bypassed.
	NoticeCaptcha NoticeKind = "captcha"
	// NoticeTwoFactor: headless re-login stopped because the
	// login page demanded a second factor or checkpoint.
	NoticeTwoFactor NoticeKind = "two_factor"
	// NoticeCheckpoint: headless re-login stopped because the
	// login page presented an account checkpoint / review.
	NoticeCheckpoint NoticeKind = "checkpoint"
	// NoticeLocked: headless re-login stopped because the
	// account or login form is locked.
	NoticeLocked NoticeKind = "locked"
	// NoticeBlocked: headless re-login stopped because the
	// login page did not match the recorded contract, or the
	// re-login driver is unavailable in this build.
	NoticeBlocked NoticeKind = "blocked"
	// NoticeReloginFailed: headless re-login exhausted its
	// per-incident attempts without recovering the session
	// and without a specific blocker kind.
	NoticeReloginFailed NoticeKind = "relogin_failed"
)

// AllNoticeKinds is the closed set, for validation and tests:
// a kind outside it must never be emitted.
var AllNoticeKinds = []NoticeKind{
	NoticeLoggedOut, NoticeReexported, NoticeFailed,
	NoticeCaptcha, NoticeTwoFactor, NoticeCheckpoint,
	NoticeLocked, NoticeBlocked, NoticeReloginFailed,
}

// ValidNoticeKind reports whether kind is in the closed set.
func ValidNoticeKind(kind NoticeKind) bool {
	for _, k := range AllNoticeKinds {
		if k == kind {
			return true
		}
	}
	return false
}

// Notifier sends one fixed-content notice. Implementations live
// in the command layer (Telegram); the core never imports a
// transport. Notify is best-effort: a failure never fails the
// tick, it only leaves the warn marker pending.
type Notifier interface {
	Notify(ctx context.Context, kind NoticeKind, profileName string) error
}

// SanitizeDisplay strips line/field breaks from a name
// before it is embedded in a notice or a stdout summary line:
// a newline in a profile or tag name must never forge a
// second output line. Profile names are charset-validated at
// parse time and keeper tags at parse time too; this is
// defence at the emission point for hand-built values.
func SanitizeDisplay(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		return r
	}, s)
}

// NoticeText renders the fixed notice body for a kind and
// profile. The re-login path names the two working remedies:
// screencast login and auth import. Blocker kinds name the
// blocker and state that automation stopped rather than
// bypassing it; the text is fixed — no error text, no values,
// no page content.
func NoticeText(kind NoticeKind, profileName string) string {
	profileName = SanitizeDisplay(profileName)
	switch kind {
	case NoticeReexported:
		return fmt.Sprintf("castctl keeper: profile %s session re-exported from the browser and verified. No action was taken automatically.", profileName)
	case NoticeFailed:
		return fmt.Sprintf("castctl keeper: profile %s keeper stopped (session could not be verified). Re-login with `castctl auth login --profile %s` or re-import with `castctl auth import --profile %s`. No action was taken automatically.", profileName, profileName, profileName)
	case NoticeCaptcha:
		return fmt.Sprintf("castctl keeper: profile %s automatic re-login stopped: the login page presented a captcha. Automation never bypasses captchas. Re-login with `castctl auth login --profile %s` or re-import with `castctl auth import --profile %s`. No action was taken automatically.", profileName, profileName, profileName)
	case NoticeTwoFactor:
		return fmt.Sprintf("castctl keeper: profile %s automatic re-login stopped: the login page demanded a second factor. Automation never answers second-factor prompts. Re-login with `castctl auth login --profile %s` or re-import with `castctl auth import --profile %s`. No action was taken automatically.", profileName, profileName, profileName)
	case NoticeCheckpoint:
		return fmt.Sprintf("castctl keeper: profile %s automatic re-login stopped: the login page presented an account checkpoint. Re-login with `castctl auth login --profile %s` or re-import with `castctl auth import --profile %s`. No action was taken automatically.", profileName, profileName, profileName)
	case NoticeLocked:
		return fmt.Sprintf("castctl keeper: profile %s automatic re-login stopped: the login page is locked. Re-login with `castctl auth login --profile %s` or re-import with `castctl auth import --profile %s`. No action was taken automatically.", profileName, profileName, profileName)
	case NoticeBlocked:
		return fmt.Sprintf("castctl keeper: profile %s automatic re-login stopped: the login page did not match the expected form, or re-login is unavailable in this build. Re-login with `castctl auth login --profile %s` or re-import with `castctl auth import --profile %s`. No action was taken automatically.", profileName, profileName, profileName)
	case NoticeReloginFailed:
		return fmt.Sprintf("castctl keeper: profile %s automatic re-login failed after its attempts and the keeper stopped. Re-login with `castctl auth login --profile %s` or re-import with `castctl auth import --profile %s`. No action was taken automatically.", profileName, profileName, profileName)
	default: // NoticeLoggedOut and any unknown kind degrade to logged_out.
		return fmt.Sprintf("castctl keeper: profile %s is logged out (cookies expired or revoked). Re-login with `castctl auth login --profile %s` or re-import with `castctl auth import --profile %s`. No action was taken automatically.", profileName, profileName, profileName)
	}
}
