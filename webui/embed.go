// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

// Package webui embeds the committed single-file frontend build
// (webui/dist/index.html) for the Go server in
// internal/webui. Go embed patterns cannot leave the package
// directory, so the embed lives here, next to the committed
// build it serves. The build is the production build (mocks
// off); the screencast flag state of the committed dist is
// recorded in docs/development.md and the PR body. This package
// contains no frontend source and no server logic: it only
// exposes the embedded bytes.
package webui

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
)

//go:embed dist/index.html
var distFS embed.FS

// FS returns the embedded frontend filesystem (dist/ with
// index.html) for the server.
func FS() fs.FS {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		// The embed pattern guarantees "dist" exists; a
		// failure here is a build bug, not a runtime one.
		panic(err)
	}
	return sub
}

// BundleSHA256 returns the lowercase hex SHA-256 of the
// embedded dist/index.html: the StatusInfo bundle hash. It is
// computed from the embedded bytes, never hardcoded.
func BundleSHA256() string {
	data, err := fs.ReadFile(distFS, "dist/index.html")
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
