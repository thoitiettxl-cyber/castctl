// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package webui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/thoitiettxl-cyber/castctl/internal/profile"
	"github.com/thoitiettxl-cyber/castctl/internal/redact"
)

// Section editors for the `keeper` and `webui` blocks: GET/PUT
// pairs mirroring the DNS and Telegram section saves. Every
// mutation funnels through saveGuarded (full-document parse,
// sentinel assertion, hash-on-save, flock + atomic 0600 write,
// 409 on a stale base_sha256): there is no second save path.
// The whole-document JSON editor on the Config page is kept
// alongside these editors; there is no visual block editor and
// no draft persistence (a draft would persist config including
// secret markers, violating the secrets contract).
//
// The keeper editor edits configuration only: it never ticks
// the keeper, writes cookies, or contacts a browser. Keeper
// status is read-only on GET /keeper (handleGetKeeper), which
// reports exactly the fields keeper.ReadStatus returns at this
// head — no keep-alive/auto-wake/auto-re-login field exists
// there, and none is invented here.
//
// The `webui` editor's token field is write-only, like
// Telegram's: empty means unchanged, a placeholder is rejected,
// and a new plaintext token is hashed on save by saveGuarded.
// Editing `listen` takes effect on restart (the running server
// keeps its bound address); editing the idle timeout or rate
// limit takes effect immediately, because the server re-reads
// the stored block per request.

// --- keeper settings ------------------------------------------

// keeperSettingsEntry is one `keeper` entry as the settings
// editor shows it: the config fields plus the interval in
// seconds (the keeper status view's unit), so the editor can
// show both the duration string and its magnitude.
type keeperSettingsEntry struct {
	Tag             string `json:"tag"`
	Profile         string `json:"profile"`
	Browser         string `json:"browser"`
	Interval        string `json:"interval"`
	IntervalSeconds int64  `json:"interval_seconds"`
	Notify          string `json:"notify"`
}

func (s *Server) handleGetKeeperSettings(w http.ResponseWriter, r *http.Request) {
	load, err := s.loadConfig()
	if err != nil {
		writeAPIError(w, err)
		return
	}
	cfg, err := s.parseLoaded(load)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	entries := []keeperSettingsEntry{}
	if cfg.Keeper != nil {
		for _, e := range cfg.Keeper.Entries {
			interval := ""
			if e.IntervalSet && e.Interval > 0 {
				interval = e.Interval.String()
			}
			entries = append(entries, keeperSettingsEntry{
				Tag:             e.Tag,
				Profile:         e.Profile,
				Browser:         e.Browser,
				Interval:        interval,
				IntervalSeconds: int64(e.EffectiveInterval() / time.Second),
				Notify:          e.Notify,
			})
		}
	}
	writeEnvelope(w, http.StatusOK, map[string]any{
		"entries": entries,
		"sha256":  load.hash,
	})
}

type putKeeperEntryBody struct {
	Tag      string  `json:"tag"`
	Profile  string  `json:"profile"`
	Browser  string  `json:"browser"`
	Interval *string `json:"interval"`
	Notify   *string `json:"notify"`
}

type putKeeperSettingsBody struct {
	// Entries is a value RawMessage (not a pointer) so `null`
	// (delete the block) stays distinguishable from a missing
	// key (validation error): a null unmarshals a *RawMessage
	// field to nil, but a value field to the bytes "null".
	Entries    json.RawMessage `json:"entries"`
	BaseSHA256 string          `json:"base_sha256"`
}

func (s *Server) handlePutKeeperSettings(w http.ResponseWriter, r *http.Request) {
	var body putKeeperSettingsBody
	if err := decodeBody(w, r, 1<<20, &body); err != nil {
		writeAPIError(w, err)
		return
	}
	if body.Entries == nil {
		writeAPIError(w, errValidation("entries is required"))
		return
	}
	if strings.TrimSpace(body.BaseSHA256) == "" {
		writeAPIError(w, errValidation("base_sha256 is required"))
		return
	}
	var submitted []any
	deleteBlock := false
	if strings.TrimSpace(string(body.Entries)) == "null" {
		deleteBlock = true
	} else {
		var entries []putKeeperEntryBody
		dec := json.NewDecoder(bytes.NewReader(body.Entries))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&entries); err != nil {
			writeAPIError(w, errValidation("entries must be an array of keeper entries"))
			return
		}
		if entries == nil {
			entries = []putKeeperEntryBody{}
		}
		for _, e := range entries {
			// Canonical key order tag, profile, browser,
			// interval, notify, rendered via orderedObject:
			// a plain map would re-encode with sorted keys
			// (encoding/json) for entries the stored
			// document does not already carry, so a new
			// entry saved through this editor would come
			// back alphabetised instead of canonical.
			entry := &orderedObject{vals: map[string]any{}}
			entry.set("tag", e.Tag)
			entry.set("profile", e.Profile)
			entry.set("browser", e.Browser)
			if e.Interval != nil && strings.TrimSpace(*e.Interval) != "" {
				entry.set("interval", *e.Interval)
			}
			if e.Notify != nil && *e.Notify != "" {
				entry.set("notify", *e.Notify)
			}
			submitted = append(submitted, entry)
		}
	}
	load, err := s.loadConfig()
	if err != nil {
		writeAPIError(w, err)
		return
	}
	newHash, err := s.saveMerged(load, body.BaseSHA256, func(doc map[string]any) error {
		if deleteBlock {
			delete(doc, "keeper")
		} else {
			doc["keeper"] = submitted
		}
		return nil
	})
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeEnvelope(w, http.StatusOK, map[string]any{"sha256": newHash})
}

// --- webui settings -------------------------------------------

// webUISettingsView is the GET /settings/webui view: every
// field except the token, which is write-only (token_set +
// masked only, the Telegram pattern). Duration and limit
// values are the EFFECTIVE values (defaults applied), so the
// editor shows the live behaviour even when the keys are
// absent; the duration string form is what PUT accepts.
type webUISettingsView struct {
	Listen                    string                 `json:"listen"`
	UIDir                     string                 `json:"ui_dir"`
	TokenSet                  bool                   `json:"token_set"`
	Masked                    string                 `json:"masked"`
	SessionIdleTimeout        string                 `json:"session_idle_timeout"`
	SessionIdleTimeoutSeconds int64                  `json:"session_idle_timeout_seconds"`
	LoginRateLimit            loginRateLimitSettings `json:"login_rate_limit"`
}

type loginRateLimitSettings struct {
	Attempts      int    `json:"attempts"`
	Window        string `json:"window"`
	WindowSeconds int64  `json:"window_seconds"`
}

// webUISettingsResponse is the GET /settings/webui envelope
// payload: the view fields FLAT in `data` alongside sha256,
// the same shape as the keeper and telegram GETs and the
// shape the frontend WebUISettings type declares
// (webui/src/types/api.ts:273-281). A nested "settings" key
// here broke the section editor (D-WEBUI-GET): loadWebUI
// reads result.login_rate_limit.attempts off `data` directly.
// The flat shape is pinned by TestSettingsGETShapesMatchFrontend
// (settings_shape_test.go) and the dev-mock shape check in
// webui/tests/mockServer.test.ts.
type webUISettingsResponse struct {
	webUISettingsView
	SHA256 string `json:"sha256"`
}

func (s *Server) handleGetWebUISettings(w http.ResponseWriter, r *http.Request) {
	load, err := s.loadConfig()
	if err != nil {
		writeAPIError(w, err)
		return
	}
	cfg, err := s.parseLoaded(load)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	view := webUISettingsView{
		SessionIdleTimeout:        profile.EffectiveSessionIdleTimeout(nil).String(),
		SessionIdleTimeoutSeconds: int64(profile.EffectiveSessionIdleTimeout(nil) / time.Second),
	}
	attempts, window := profile.EffectiveLoginRateLimit(nil)
	view.LoginRateLimit = loginRateLimitSettings{Attempts: attempts, Window: window.String(), WindowSeconds: int64(window / time.Second)}
	if cfg.WebUI != nil {
		view.Listen = profile.EffectiveListen(cfg.WebUI)
		view.UIDir = cfg.WebUI.UIDir
		view.TokenSet = cfg.WebUI.Token != ""
		if view.TokenSet {
			view.Masked = "***"
		}
		idle := profile.EffectiveSessionIdleTimeout(cfg.WebUI)
		view.SessionIdleTimeout = idle.String()
		view.SessionIdleTimeoutSeconds = int64(idle / time.Second)
		attempts, window = profile.EffectiveLoginRateLimit(cfg.WebUI)
		view.LoginRateLimit = loginRateLimitSettings{Attempts: attempts, Window: window.String(), WindowSeconds: int64(window / time.Second)}
	}
	writeEnvelope(w, http.StatusOK, webUISettingsResponse{webUISettingsView: view, SHA256: load.hash})
}

type putLoginRateLimitBody struct {
	Attempts *int    `json:"attempts"`
	Window   *string `json:"window"`
}

type putWebUISettingsBody struct {
	Listen             *string `json:"listen"`
	Token              *string `json:"token"`
	UIDir              *string `json:"ui_dir"`
	SessionIdleTimeout *string `json:"session_idle_timeout"`
	// LoginRateLimit is a value RawMessage (not a pointer) so
	// `null` (delete the key) stays distinguishable from a
	// missing key (unchanged): see putKeeperSettingsBody.
	LoginRateLimit json.RawMessage `json:"login_rate_limit"`
	BaseSHA256     string          `json:"base_sha256"`
}

func (s *Server) handlePutWebUISettings(w http.ResponseWriter, r *http.Request) {
	var body putWebUISettingsBody
	if err := decodeBody(w, r, 64<<10, &body); err != nil {
		writeAPIError(w, err)
		return
	}
	if strings.TrimSpace(body.BaseSHA256) == "" {
		writeAPIError(w, errValidation("base_sha256 is required"))
		return
	}
	// Decode the nested limit object when present: `null`
	// deletes the key, an object merges per field. Unknown
	// nested keys are rejected.
	var limit *putLoginRateLimitBody
	limitDelete := false
	if body.LoginRateLimit != nil {
		if strings.TrimSpace(string(body.LoginRateLimit)) == "null" {
			limitDelete = true
		} else {
			var decoded putLoginRateLimitBody
			dec := json.NewDecoder(bytes.NewReader(body.LoginRateLimit))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&decoded); err != nil {
				writeAPIError(w, errValidation("login_rate_limit must be an object"))
				return
			}
			limit = &decoded
		}
	}
	load, err := s.loadConfig()
	if err != nil {
		writeAPIError(w, err)
		return
	}
	newHash, err := s.saveMerged(load, body.BaseSHA256, func(doc map[string]any) error {
		section, _ := doc["webui"].(map[string]any)
		if section == nil {
			section = map[string]any{}
		}
		if body.Listen != nil {
			// Empty restores the default by deleting the key:
			// a present-but-empty listen is a parse error.
			if strings.TrimSpace(*body.Listen) == "" {
				delete(section, "listen")
			} else {
				section["listen"] = strings.TrimSpace(*body.Listen)
			}
		}
		if body.Token != nil {
			// Empty token = unchanged (write-only field). A
			// non-empty token replaces the stored one; a
			// placeholder is never a token. Whitespace
			// anywhere is rejected, matching parse: a stored
			// token with whitespace can never authenticate
			// (authorized() rejects it before bcrypt) and
			// would lock the server out.
			if strings.TrimSpace(*body.Token) != "" {
				token := *body.Token
				if token == "***" || token == redact.Marker {
					return errValidation("webui.token must be a real token, not a placeholder")
				}
				if strings.ContainsAny(token, " \t\r\n") {
					return errValidation("webui.token must not contain whitespace")
				}
				section["token"] = token
			}
		}
		if body.UIDir != nil {
			if strings.TrimSpace(*body.UIDir) == "" {
				delete(section, "ui_dir")
			} else {
				section["ui_dir"] = strings.TrimSpace(*body.UIDir)
			}
		}
		if body.SessionIdleTimeout != nil {
			if strings.TrimSpace(*body.SessionIdleTimeout) == "" {
				delete(section, "session_idle_timeout")
			} else {
				// Enforced here, not only by the full-document
				// parse in saveMerged: sub-floor values are
				// rejected with a fixed message, never
				// silently clamped.
				d, err := time.ParseDuration(strings.TrimSpace(*body.SessionIdleTimeout))
				if err != nil || d < profile.MinSessionIdleTimeout || d > profile.MaxSessionIdleTimeout {
					return errValidation("session_idle_timeout must be a duration string from 1m to 720h")
				}
				section["session_idle_timeout"] = *body.SessionIdleTimeout
			}
		}
		if limitDelete {
			delete(section, "login_rate_limit")
		} else if limit != nil {
			nested, _ := section["login_rate_limit"].(map[string]any)
			if nested == nil {
				nested = map[string]any{}
			}
			if limit.Attempts != nil {
				if *limit.Attempts < 1 || *limit.Attempts > profile.MaxLoginRateLimitAttempts {
					return errValidation(fmt.Sprintf("login_rate_limit.attempts must be an integer from 1 to %d", profile.MaxLoginRateLimitAttempts))
				}
				nested["attempts"] = json.Number(strconv.Itoa(*limit.Attempts))
			}
			if limit.Window != nil {
				if strings.TrimSpace(*limit.Window) == "" {
					return errValidation("login_rate_limit.window must not be empty")
				}
				d, err := time.ParseDuration(strings.TrimSpace(*limit.Window))
				if err != nil || d < profile.MinLoginRateLimitWindow || d > profile.MaxLoginRateLimitWindow {
					return errValidation("login_rate_limit.window must be a duration string from 1s to 24h")
				}
				nested["window"] = *limit.Window
			}
			section["login_rate_limit"] = nested
		}
		doc["webui"] = section
		return nil
	})
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeEnvelope(w, http.StatusOK, map[string]any{"sha256": newHash})
}
