// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package webui

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/thoitiettxl-cyber/castctl/internal/outbound"
)

// WireGuard endpoint import: parse a wg-quick .conf, preview the
// redacted endpoint object, and optionally save it. The parser
// is the shared outbound.ParseWireGuardConfWithDNS converter
// (never a second parser): it starts no device, dials nothing,
// and never validates key material, so the fixture placeholder
// "<redacted>" parses. On save, the endpoint object is appended
// to "endpoints" and a captured DNS= list is stored as
// wireguard_dns[tag] (the precedence branch ResolveProfileDNS
// reads); the full merged document is validated before any
// write, like every other config save.

type importEndpointBody struct {
	Tag      string `json:"tag"`
	ConfText string `json:"conf_text"`
	Save     bool   `json:"save"`
}

func (s *Server) handleImportEndpoint(w http.ResponseWriter, r *http.Request) {
	var body importEndpointBody
	if err := decodeBody(w, r, 64<<10, &body); err != nil {
		writeAPIError(w, err)
		return
	}
	if strings.TrimSpace(body.Tag) == "" {
		writeAPIError(w, errValidation("endpoint tag is required"))
		return
	}
	if strings.TrimSpace(body.Tag) != body.Tag {
		writeAPIError(w, errValidation("endpoint tag must not have surrounding whitespace"))
		return
	}
	parsed, err := outbound.ParseWireGuardConfWithDNS([]byte(body.ConfText))
	if err != nil {
		writeAPIError(w, errValidation("wireguard conf is invalid: "+safeMessage(err)))
		return
	}
	raw, err := json.Marshal(parsed.Endpoint)
	if err != nil {
		writeAPIError(w, errInternal())
		return
	}
	obj, err := decodeGeneric(raw)
	if err != nil {
		writeAPIError(w, errInternal())
		return
	}
	endpoint, ok := obj.(map[string]any)
	if !ok {
		writeAPIError(w, errInternal())
		return
	}
	// option.Endpoint is flat: type + tag alongside the
	// WireGuardEndpointOptions fields.
	endpoint["type"] = "wireguard"
	endpoint["tag"] = body.Tag
	if !body.Save {
		// Preview: the redacted endpoint object as JSON text.
		// The frontend renders it verbatim; no value in it is
		// real beyond what the user pasted (the pasted conf
		// itself is the user's own input, redacted here like
		// every other endpoint view).
		preview, err := json.MarshalIndent(redactGeneric(endpoint), "", "  ")
		if err != nil {
			writeAPIError(w, errInternal())
			return
		}
		writeEnvelope(w, http.StatusOK, map[string]any{"preview": string(preview)})
		return
	}
	load, err := s.loadConfig()
	if err != nil {
		writeAPIError(w, err)
		return
	}
	if _, err := s.saveDirect(load, func(doc map[string]any) error {
		arr, _ := doc["endpoints"].([]any)
		for _, elem := range arr {
			if obj, ok := elem.(map[string]any); ok {
				if t, _ := obj["tag"].(string); t == body.Tag {
					return errValidation("endpoint already exists")
				}
			}
		}
		doc["endpoints"] = append(arr, endpoint)
		if len(parsed.DNSServers) > 0 {
			wgDNS, _ := doc["wireguard_dns"].(map[string]any)
			if wgDNS == nil {
				wgDNS = map[string]any{}
			}
			servers := make([]any, 0, len(parsed.DNSServers))
			for _, dns := range parsed.DNSServers {
				servers = append(servers, dns)
			}
			wgDNS[body.Tag] = servers
			doc["wireguard_dns"] = wgDNS
		}
		return nil
	}); err != nil {
		writeAPIError(w, err)
		return
	}
	writeEnvelope(w, http.StatusOK, s.endpointSummaryAfter(body.Tag))
}
