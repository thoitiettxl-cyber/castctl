//go:build !with_utls

// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package outbound

import "testing"

// skipUnlessUTLS skips the calling subtest when the build has no
// uTLS support (sing-box's utls_stub rejects every uTLS client
// build with "uTLS is not included in this build"). It is the
// Shape S helper: exactly the 6 subtests that construct a uTLS
// client call it (see dialer_test.go and tls_test.go); the
// error-expecting TLS subtests that pass untagged do NOT call
// it, because the stub error is the behaviour they pin.
func skipUnlessUTLS(t *testing.T) {
	t.Helper()
	t.Skip("uTLS is not included in this build (rebuild with -tags with_utls)")
}
