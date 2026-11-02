// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package pluginhost

// SupportValue reports whether the current binary can load
// dynamic plugins: "1" for cgo builds (and windows), "0"
// otherwise. It mirrors upstream support_cgo.go /
// support_nocgo.go (supportPluginValue) at pin 250d5981.
func SupportValue() string { return supportValue }

// SupportPlugins reports whether dynamic plugin loading is
// available in this binary.
func SupportPlugins() bool { return supportValue == "1" }
