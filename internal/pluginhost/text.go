// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package pluginhost

import (
	"strings"

	"github.com/thoitiettxl-cyber/castctl/internal/logging"
)

// maxPluginTextLen is THE cap for plugin-chosen text that
// reaches output: envelope error messages, loader error
// strings, skip reasons, and plugin check output. It matches
// the host.log message cap (4096) already in host.go, so
// every plugin-text surface truncates at the same length,
// with an explicit "…" marker. A plugin returning a 5 MB
// payload can therefore never make host output 5 MB.
const maxPluginTextLen = 4096

// maxHostMethodLen bounds the host-callback method name a
// plugin passes to the host (the C ABI carries no length
// for it). A method with no NUL within this bound is
// rejected instead of being read unbounded (which could
// segfault the host on an unterminated pointer).
const maxHostMethodLen = 256

// capPluginText truncates s to maxPluginTextLen runes with
// an explicit marker. It never invents content: over-long
// text is cut, not summarised.
func capPluginText(s string) string {
	if len(s) > maxPluginTextLen {
		return s[:maxPluginTextLen] + "…"
	}
	return s
}

// safePluginText redacts plugin-chosen free-form text for
// output (SafeString strips secret-keyed shapes, cookie
// fragments, Bearer tokens, and URL userinfo) and caps it
// at maxPluginTextLen. Every loader/host/plugin-check
// error path that can carry plugin text goes through it.
func safePluginText(s string) string {
	return capPluginText(logging.SafeString(s))
}

// scrubShadowPath replaces occurrences of the shadow path
// in loader error text with the operator-supplied source
// path, so user-facing errors never leak the shadow
// directory layout or pid.
func scrubShadowPath(text, shadowPath, displayPath string) string {
	if shadowPath == "" || displayPath == "" || shadowPath == displayPath {
		return text
	}
	return strings.ReplaceAll(text, shadowPath, displayPath)
}
