//go:build !with_utls

// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

import "testing"

// skipUnlessUTLS skips the calling test when the build has no
// uTLS support: the production gateway dial path defaults to the
// uTLS chrome fingerprint (GatewayTLSOptions), and sing-box's
// utls_stub rejects every uTLS client build without it. This
// mirrors internal/outbound's Shape S helper.
func skipUnlessUTLS(t *testing.T) {
	t.Helper()
	t.Skip("uTLS is not included in this build (rebuild with -tags with_utls)")
}
