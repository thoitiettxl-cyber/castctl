//go:build with_utls

// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package outbound

import "testing"

// skipUnlessUTLS is a no-op when uTLS is compiled in; see
// utls_skip_disabled_test.go for the untagged form.
func skipUnlessUTLS(t *testing.T) {
	t.Helper()
}
