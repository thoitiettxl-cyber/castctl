// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package webui

import (
	"net/http"
)

// Plugins in this build: gated unavailable (Boss decision D1,
// option (b)). There is no plugin loader, no `plugins` config
// key or schema, and no plugin config pass-through to the
// browser in this build — the plugin-core work lands
// separately (PR #30), and a follow-up wires the real
// list/enable/disable surface onto the page structure this
// endpoint and the frontend Plugins page establish. Until
// then the backend advertises unsupported explicitly,
// following the screencast-availability pattern (a 200 status
// body reporting available:false with a reason) rather than
// a 404 or an empty list that could be mistaken for "no
// plugins installed". The frontend renders the reason and
// offers no enable/disable control. No fake data is served:
// `plugins` is an empty list because the build lists nothing,
// and `available` is false.
//
// The follow-up must NOT reuse this shape for real data
// without versioning the contract: when the loader lands,
// this endpoint gains the list and the controls, and the
// frontend's unavailable branch becomes the
// loader-absent branch.

func (s *Server) handleGetPlugins(w http.ResponseWriter, r *http.Request) {
	writeEnvelope(w, http.StatusOK, map[string]any{
		"available": false,
		"reason":    "plugin support is not available in this build (plugin core lands separately; a follow-up wires list/enable/disable)",
		"plugins":   []any{},
	})
}
