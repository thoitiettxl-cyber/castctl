// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build (!cgo && !windows) || android

package pluginhost

import "fmt"

// Stub loader: dynamic plugin loading is unavailable. On
// no-cgo builds there is no dlopen; on GOOS=android builds
// there is deliberately no android loader file — the phone
// path is the GOOS=linux/arm64 glibc build run inside
// Droidspaces (see docs/plugins.md), and GOOS=android is
// fallback-only, so an android GOOS binary refuses loads
// with this clear error instead of silently stubbing. This
// mirrors upstream loader_unsupported.go at pin 250d5981.
type stubLoader struct{}

const supportValue = "0"

func defaultLoader() Loader { return stubLoader{} }

func (stubLoader) Open(file File, host *Host) (Client, error) {
	return nil, fmt.Errorf("standard dynamic library plugin loading requires cgo on this platform: %s", file.Path)
}
