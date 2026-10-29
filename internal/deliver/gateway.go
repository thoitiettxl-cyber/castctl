// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package deliver

import (
	"context"

	"github.com/thoitiettxl-cyber/muse-cli/go/internal/conn"
)

// Gateway is the minimal gateway surface this package needs: one
// unary JSON call. conn.Gateway satisfies it (see the compile-time
// assertion below, matching the fsclient pattern); tests inject
// fakes that record the method and body.
type Gateway interface {
	CallJSON(ctx context.Context, method string, opts conn.RequestOptions) (any, error)
}

var _ Gateway = (conn.Gateway)(nil)
