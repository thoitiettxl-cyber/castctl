// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package webui

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/thoitiettxl-cyber/castctl/internal/gateway"
	"github.com/thoitiettxl-cyber/castctl/internal/keeper"
	"github.com/thoitiettxl-cyber/castctl/internal/profile"
	"github.com/thoitiettxl-cyber/castctl/internal/redact"
)

// singboxVersion reports the sing-box module version from the
// build info, or "unknown" when the module is absent (tests
// built without it). No version is hardcoded: the module line
// in go.mod is the source of truth.
func singboxVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, dep := range info.Deps {
		if dep.Path == "github.com/sagernet/sing-box" {
			return dep.Version
		}
	}
	return "unknown"
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	load, err := s.loadConfig()
	if err != nil {
		writeAPIError(w, err)
		return
	}
	source := "none"
	defaultProfile := ""
	profileCount, outboundCount, endpointCount := 0, 0, 0
	if load.state.Found {
		if cfg, perr := profile.ParseSingleConfig(load.raw, s.deps.ConfigDir); perr == nil {
			source = s.configSource(load, cfg)
			defaultProfile = cfg.DefaultProfile
			profileCount = len(cfg.Profiles)
			outboundCount = len(cfg.Outbounds)
			endpointCount = len(cfg.Endpoints)
		} else {
			source = "invalid"
		}
	} else if load.state.Exists {
		source = s.configSource(load, nil)
	}
	writeEnvelope(w, http.StatusOK, map[string]any{
		"version":         s.deps.Version,
		"go_version":      runtime.Version(),
		"singbox_version": singboxVersion(),
		"listen_addr":     s.deps.ListenAddr,
		"remote_exposure": false,
		"config_path":     s.configPath(),
		"config_source":   source,
		"default_profile": defaultProfile,
		"profile_count":   profileCount,
		"outbound_count":  outboundCount,
		"endpoint_count":  endpointCount,
		"bundle_sha256":   s.deps.BundleSHA256,
	})
}

func (s *Server) configPath() string {
	return s.deps.ConfigDir + "/config.json"
}

// --- profiles --------------------------------------------------

func (s *Server) handleListProfiles(w http.ResponseWriter, r *http.Request) {
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
	writeEnvelope(w, http.StatusOK, s.profileSummaries(cfg, s.legacyProfileNames(cfg)))
}

// profileDetail is the frozen ProfileDetail shape.
type profileDetail struct {
	Name        string            `json:"name"`
	Default     bool              `json:"default"`
	Source      string            `json:"source"`
	HasCookies  bool              `json:"has_cookies"`
	OutboundTag any               `json:"outbound_tag"`
	Fingerprint string            `json:"fingerprint"`
	Dir         string            `json:"dir"`
	Entry       map[string]any    `json:"entry"`
	Paths       map[string]string `json:"paths"`
	Warnings    []string          `json:"warnings"`
}

func (s *Server) loadDetail(name string) (*profileDetail, error) {
	load, err := s.loadConfig()
	if err != nil {
		return nil, err
	}
	cfg, err := s.parseLoaded(load)
	if err != nil {
		return nil, err
	}
	p, ok := cfg.Profiles[name]
	if !ok {
		return nil, errNotFound("profile not found")
	}
	return s.detailFor(cfg, p, load), nil
}

func (s *Server) detailFor(cfg *profile.SingleConfig, p *profile.Profile, load *configLoad) *profileDetail {
	var tag any
	switch p.Outbound.Kind {
	case profile.OutboundDirect:
		tag = nil
	case profile.OutboundTag, profile.OutboundInline:
		tag = p.Outbound.Tag
	default:
		tag = nil
	}
	fingerprint := p.Fingerprint
	if fingerprint == "" {
		fingerprint = "chrome"
	}
	entry := map[string]any{}
	if load != nil && len(load.raw) > 0 {
		if doc, err := decodeGeneric(load.raw); err == nil {
			if obj, ok := doc.(map[string]any); ok {
				if profiles, ok := obj["profiles"].(map[string]any); ok {
					if rawEntry, ok := profiles[p.Name].(map[string]any); ok {
						if redacted, ok := redactGeneric(rawEntry).(map[string]any); ok {
							entry = redacted
						}
					}
				}
			}
		}
	}
	return &profileDetail{
		Name:        p.Name,
		Default:     p.Name == cfg.DefaultProfile,
		Source:      "single-file",
		HasCookies:  cookiesPresent(p.CookiesFile),
		OutboundTag: tag,
		Fingerprint: fingerprint,
		Dir:         p.Dir,
		Entry:       entry,
		Paths: map[string]string{
			"dir":          p.Dir,
			"config_file":  p.ConfigFile,
			"cookies_file": p.CookiesFile,
			"chat_file":    p.ChatFile,
		},
		Warnings: profileWarnings(s.deps.ConfigDir, cfg, p),
	}
}

// profileWarnings mirrors internal/commands profileWarnings
// (same messages, same checks): cookies-file presence/mode,
// config-file mode, dangling outbound tag. Paths are the
// operator's own local paths.
func profileWarnings(_ string, single *profile.SingleConfig, prof *profile.Profile) []string {
	warnings := []string{}
	if st, err := os.Stat(prof.CookiesFile); err != nil {
		if os.IsNotExist(err) {
			warnings = append(warnings, fmt.Sprintf("cookies file %s does not exist", prof.CookiesFile))
		}
	} else if st.Mode().Perm() != 0o600 {
		warnings = append(warnings, fmt.Sprintf("cookies file %s has mode %04o, expected 0600", prof.CookiesFile, st.Mode().Perm()))
	}
	if prof.ConfigFile != "" {
		if info, err := os.Stat(prof.ConfigFile); err == nil {
			if info.Mode().Perm() != 0o600 {
				warnings = append(warnings, fmt.Sprintf("config file %s has mode %04o, expected 0600", prof.ConfigFile, info.Mode().Perm()))
			}
		}
	}
	if prof.Outbound.Kind == profile.OutboundTag && prof.Outbound.Tag != "" && prof.Outbound.Tag != "direct" {
		if single != nil && !tagDefined(single, prof.Outbound.Tag) {
			warnings = append(warnings, fmt.Sprintf("outbound tag %q is not defined in the config", prof.Outbound.Tag))
		}
	}
	return warnings
}

func tagDefined(single *profile.SingleConfig, tag string) bool {
	if obs, err := single.ParsedOutbounds(); err == nil {
		for _, ob := range obs {
			if ob.Tag == tag {
				return true
			}
		}
	}
	if eps, err := single.ParsedEndpoints(); err == nil {
		for _, ep := range eps {
			if ep.Tag == tag {
				return true
			}
		}
	}
	return false
}

func (s *Server) handleGetProfile(w http.ResponseWriter, r *http.Request) {
	detail, err := s.loadDetail(chi.URLParam(r, "name"))
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeEnvelope(w, http.StatusOK, detail)
}

type createProfileBody struct {
	Name        string  `json:"name"`
	CookiesFile *string `json:"cookies_file"`
	Outbound    *string `json:"outbound"`
	SetDefault  *bool   `json:"set_default"`
}

func (s *Server) handleCreateProfile(w http.ResponseWriter, r *http.Request) {
	var body createProfileBody
	if err := decodeBody(w, r, 64<<10, &body); err != nil {
		writeAPIError(w, err)
		return
	}
	if _, err := profile.ValidateProfileName(body.Name); err != nil {
		writeAPIError(w, errValidation("invalid profile name: "+safeMessage(err)))
		return
	}
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
	if _, exists := cfg.Profiles[body.Name]; exists {
		writeAPIError(w, errValidation("profile already exists"))
		return
	}
	if _, err := s.saveDirect(load, func(doc map[string]any) error {
		profiles, err := profilesObject(doc)
		if err != nil {
			return err
		}
		entry := map[string]any{}
		if body.CookiesFile != nil && *body.CookiesFile != "" {
			entry["cookies_file"] = *body.CookiesFile
		}
		if body.Outbound != nil && *body.Outbound != "" && *body.Outbound != "direct" {
			entry["outbound"] = *body.Outbound
		}
		profiles[body.Name] = entry
		if body.SetDefault != nil && *body.SetDefault {
			doc["default_profile"] = body.Name
		}
		return nil
	}); err != nil {
		writeAPIError(w, err)
		return
	}
	detail, err := s.loadDetail(body.Name)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	// The frozen create response is a ProfileSummary.
	writeEnvelope(w, http.StatusOK, profileSummary{
		Name:        detail.Name,
		Default:     detail.Default,
		Source:      detail.Source,
		HasCookies:  detail.HasCookies,
		OutboundTag: detail.OutboundTag,
		Fingerprint: detail.Fingerprint,
		Dir:         detail.Dir,
	})
}

type patchProfileBody struct {
	AutoApprove   *bool   `json:"auto_approve"`
	AutoAllowOnce *bool   `json:"auto_allow_once"`
	Outbound      *string `json:"outbound"`
	Fingerprint   *string `json:"fingerprint"`
}

func (s *Server) handlePatchProfile(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	var body patchProfileBody
	if err := decodeBody(w, r, 64<<10, &body); err != nil {
		writeAPIError(w, err)
		return
	}
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
	if _, exists := cfg.Profiles[name]; !exists {
		writeAPIError(w, errNotFound("profile not found"))
		return
	}
	if _, err := s.saveDirect(load, func(doc map[string]any) error {
		profiles, err := profilesObject(doc)
		if err != nil {
			return err
		}
		entry, ok := profiles[name].(map[string]any)
		if !ok {
			return errValidation("profile entry is invalid")
		}
		if body.AutoApprove != nil {
			if *body.AutoApprove {
				entry["auto_approve"] = "always"
			} else {
				entry["auto_approve"] = "off"
			}
		}
		if body.AutoAllowOnce != nil {
			entry["auto_allow_once"] = *body.AutoAllowOnce
		}
		if body.Outbound != nil {
			if *body.Outbound == "" || *body.Outbound == "direct" {
				delete(entry, "outbound")
			} else {
				entry["outbound"] = *body.Outbound
			}
		}
		if body.Fingerprint != nil {
			if *body.Fingerprint == "" {
				delete(entry, "fingerprint")
			} else {
				entry["fingerprint"] = *body.Fingerprint
			}
		}
		profiles[name] = entry
		return nil
	}); err != nil {
		writeAPIError(w, err)
		return
	}
	detail, err := s.loadDetail(name)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeEnvelope(w, http.StatusOK, detail)
}

type deleteProfileBody struct {
	Confirm *bool  `json:"confirm"`
	Name    string `json:"name"`
}

func (s *Server) handleDeleteProfile(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	var body deleteProfileBody
	if err := decodeBody(w, r, 64<<10, &body); err != nil {
		writeAPIError(w, err)
		return
	}
	if body.Confirm == nil || !*body.Confirm || body.Name != name {
		writeAPIError(w, errValidation("delete requires {confirm: true, name}"))
		return
	}
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
	if _, exists := cfg.Profiles[name]; !exists {
		writeAPIError(w, errNotFound("profile not found"))
		return
	}
	if _, err := s.saveDirect(load, func(doc map[string]any) error {
		profiles, err := profilesObject(doc)
		if err != nil {
			return err
		}
		delete(profiles, name)
		if def, _ := doc["default_profile"].(string); def == name {
			delete(doc, "default_profile")
		}
		return nil
	}); err != nil {
		writeAPIError(w, err)
		return
	}
	writeEnvelope(w, http.StatusOK, map[string]any{"deleted": true})
}

func (s *Server) handleRenameProfile(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	var body struct {
		To string `json:"to"`
	}
	if err := decodeBody(w, r, 64<<10, &body); err != nil {
		writeAPIError(w, err)
		return
	}
	if _, err := profile.ValidateProfileName(body.To); err != nil {
		writeAPIError(w, errValidation("invalid profile name: "+safeMessage(err)))
		return
	}
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
	if _, exists := cfg.Profiles[name]; !exists {
		writeAPIError(w, errNotFound("profile not found"))
		return
	}
	if _, exists := cfg.Profiles[body.To]; exists {
		writeAPIError(w, errValidation("profile already exists"))
		return
	}
	if _, err := s.saveDirect(load, func(doc map[string]any) error {
		profiles, err := profilesObject(doc)
		if err != nil {
			return err
		}
		entry, ok := profiles[name]
		if !ok {
			return errValidation("profile entry is invalid")
		}
		delete(profiles, name)
		profiles[body.To] = entry
		if def, _ := doc["default_profile"].(string); def == name {
			doc["default_profile"] = body.To
		}
		return nil
	}); err != nil {
		writeAPIError(w, err)
		return
	}
	detail, err := s.loadDetail(body.To)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeEnvelope(w, http.StatusOK, profileSummary{
		Name:        detail.Name,
		Default:     detail.Default,
		Source:      detail.Source,
		HasCookies:  detail.HasCookies,
		OutboundTag: detail.OutboundTag,
		Fingerprint: detail.Fingerprint,
		Dir:         detail.Dir,
	})
}

func (s *Server) handleSetDefaultProfile(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
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
	if _, exists := cfg.Profiles[name]; !exists {
		writeAPIError(w, errNotFound("profile not found"))
		return
	}
	if _, err := s.saveDirect(load, func(doc map[string]any) error {
		doc["default_profile"] = name
		return nil
	}); err != nil {
		writeAPIError(w, err)
		return
	}
	writeEnvelope(w, http.StatusOK, map[string]any{"default_profile": name})
}

// handleUnavailableTest is the explicit answer for profile and
// outbound test endpoints in this build: the phased test runner
// is CLI-shaped (stdout/Env-bound) and extracting it is a
// follow-up, not silently faked here. The frontend surfaces
// this error through its existing notification path.
func handleUnavailableProfileTest(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "unavailable", "profile test is available only via the castctl CLI in this build")
}

func handleUnavailableOutboundTest(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "unavailable", "outbound test is available only via the castctl CLI in this build")
}

// profilesObject returns the doc's "profiles" object, creating
// it when absent (create path on a fresh file).
func profilesObject(doc map[string]any) (map[string]any, error) {
	if v, ok := doc["profiles"]; ok {
		obj, ok := v.(map[string]any)
		if !ok {
			return nil, errValidation(`"profiles" must be an object`)
		}
		return obj, nil
	}
	obj := map[string]any{}
	doc["profiles"] = obj
	return obj, nil
}

// --- login status / import / restore ---------------------------

// ErrNoBackup reports that a profile has no .bak cookies file to
// restore. The command layer returns it (possibly wrapped) from
// its RestoreCookies seam; the handler maps it to 404.
var ErrNoBackup = errors.New("no backup cookies file")

func (s *Server) resolveCookiesFile(name string) (cookiesFile string, legacy bool, err error) {
	load, lerr := s.loadConfig()
	if lerr != nil {
		return "", false, lerr
	}
	if load.state.Found {
		cfg, perr := profile.ParseSingleConfig(load.raw, s.deps.ConfigDir)
		if perr != nil {
			return "", false, errValidation("stored config is invalid: " + safeMessage(perr))
		}
		if p, ok := cfg.Profiles[name]; ok {
			return p.CookiesFile, false, nil
		}
	}
	paths, perr := profile.ProfilePaths(s.deps.ConfigDir, name)
	if perr != nil {
		return "", false, errValidation("invalid profile name: " + safeMessage(perr))
	}
	if _, serr := os.Stat(filepath.Join(paths.Dir, "config.json")); serr == nil {
		return paths.Cookies, true, nil
	}
	return "", false, errNotFound("profile not found")
}

// cookiesFormat detects the cookies-file form structurally, the
// same dispatch ParseCookies uses, without returning any value:
// "json" for a leading '{', "header" for the one-line form,
// "netscape" for the jar form. It returns "" when the content
// does not parse as any form.
func cookiesFormat(content []byte) string {
	trimmed := strings.TrimSpace(string(content))
	if trimmed == "" {
		return ""
	}
	if _, err := gateway.ParseCookies(string(content), "cookies"); err != nil {
		return ""
	}
	if strings.HasPrefix(trimmed, "{") {
		return "json"
	}
	if strings.Contains(trimmed, "hatch_sess=") || strings.Contains(trimmed, "datr=") {
		return "header"
	}
	return "netscape"
}

func (s *Server) handleLoginStatus(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	cookiesFile, _, err := s.resolveCookiesFile(name)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	present := cookiesPresent(cookiesFile)
	var format any
	var parseOK bool
	if present {
		if data, rerr := os.ReadFile(cookiesFile); rerr == nil {
			// Values stay in-process: only the detected form
			// and the parse verdict leave this handler.
			if f := cookiesFormat(data); f != "" {
				format = f
				parseOK = true
			}
		}
	}
	// Keeper state (no network): the logged-out flag and the
	// recorded expiries are metadata by name only, never values.
	var earliestExpiry, lastCheckedAt any
	loggedOut := false
	if load, lerr := s.loadConfig(); lerr == nil && load.state.Found {
		if cfg, perr := profile.ParseSingleConfig(load.raw, s.deps.ConfigDir); perr == nil && cfg.Keeper != nil {
			if entry := cfg.Keeper.KeeperEntryForProfile(name); entry != nil {
				if st, serr := keeper.ReadStatus(s.deps.ConfigDir, entry); serr == nil {
					loggedOut = st.LoggedOut
					if st.EarliestExpiry != nil {
						earliestExpiry = st.EarliestExpiry.Format(time.RFC3339)
					}
					if st.LastCheckedAt != nil {
						lastCheckedAt = st.LastCheckedAt.Format(time.RFC3339)
					}
				}
			}
		}
	}
	writeEnvelope(w, http.StatusOK, map[string]any{
		"logged_in":       present && parseOK && !loggedOut,
		"vm_id_prefix":    nil,
		"expiry":          earliestExpiry,
		"cookies_present": present,
		"cookies_format":  format,
		"last_checked_at": lastCheckedAt,
	})
}

type loginImportBody struct {
	Format  string `json:"format"`
	Content string `json:"content"`
}

func (s *Server) handleLoginImport(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	var body loginImportBody
	if err := decodeBody(w, r, 1<<20, &body); err != nil {
		writeAPIError(w, err)
		return
	}
	if body.Format != "text" && body.Format != "file" {
		writeAPIError(w, errValidation("format must be text or file"))
		return
	}
	if cookiesFile, _, err := s.resolveCookiesFile(name); err != nil {
		writeAPIError(w, err)
		return
	} else if !containedInDir(s.deps.ConfigDir, cookiesFile) {
		// Web UI containment (Boss ruling 2026-10-31): the
		// import seam never writes outside the config dir,
		// even when the stored cookies_file (CLI-created)
		// points elsewhere. The seam is not called, so no
		// file is written and no .bak is created.
		writeAPIError(w, errValidation("cookies file is outside the config directory"))
		return
	}
	if s.deps.ImportCookies == nil {
		writeError(w, http.StatusNotImplemented, "unavailable", "cookie import is unavailable in this build")
		return
	}
	if _, err := s.deps.ImportCookies(r.Context(), name, body.Content); err != nil {
		writeAPIError(w, errValidation(safeMessage(err)))
		return
	}
	// verified:false — this build performs no live verification
	// after import; claiming otherwise would be a false pass.
	writeEnvelope(w, http.StatusOK, map[string]any{"saved": true, "verified": false})
}

func (s *Server) handleLoginRestore(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if cookiesFile, _, err := s.resolveCookiesFile(name); err != nil {
		writeAPIError(w, err)
		return
	} else if !containedInDir(s.deps.ConfigDir, cookiesFile) {
		// Same containment as login import: restore never
		// touches a cookies file outside the config dir.
		writeAPIError(w, errValidation("cookies file is outside the config directory"))
		return
	}
	if s.deps.RestoreCookies == nil {
		writeError(w, http.StatusNotImplemented, "unavailable", "cookie restore is unavailable in this build")
		return
	}
	restored, err := s.deps.RestoreCookies(r.Context(), name)
	if err != nil {
		if errors.Is(err, ErrNoBackup) {
			writeAPIError(w, errNotFound("no backup cookies file"))
			return
		}
		writeAPIError(w, errValidation(safeMessage(err)))
		return
	}
	writeEnvelope(w, http.StatusOK, map[string]any{"restored": restored})
}

// --- outbounds / endpoints ------------------------------------

func (s *Server) handleListOutbounds(w http.ResponseWriter, r *http.Request) {
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
	rawOutbounds, _, err := rawSections(load)
	if err != nil {
		writeAPIError(w, errValidation("stored config is invalid: "+safeMessage(err)))
		return
	}
	byTag := map[string]map[string]any{}
	for _, obj := range rawOutbounds {
		if tag, ok := obj["tag"].(string); ok {
			byTag[tag] = obj
		}
	}
	out := make([]outboundSummary, 0, len(cfg.Outbounds))
	for _, ob := range cfg.Outbounds {
		summary := ob.Type
		if obj, ok := byTag[ob.Tag]; ok {
			summary = summarizeObject(obj)
		}
		out = append(out, outboundSummary{
			Tag:     ob.Tag,
			Type:    ob.Type,
			Summary: summary,
			UsedBy:  usedByOutbound(cfg, ob.Tag),
		})
	}
	writeEnvelope(w, http.StatusOK, out)
}

func (s *Server) handleGetOutbound(w http.ResponseWriter, r *http.Request) {
	tag := chi.URLParam(r, "tag")
	load, err := s.loadConfig()
	if err != nil {
		writeAPIError(w, err)
		return
	}
	if _, err := s.parseLoaded(load); err != nil {
		writeAPIError(w, err)
		return
	}
	rawOutbounds, _, err := rawSections(load)
	if err != nil {
		writeAPIError(w, errValidation("stored config is invalid: "+safeMessage(err)))
		return
	}
	for _, obj := range rawOutbounds {
		if t, ok := obj["tag"].(string); ok && t == tag {
			writeEnvelope(w, http.StatusOK, redactGeneric(obj))
			return
		}
	}
	writeAPIError(w, errNotFound("outbound not found"))
}

type outboundBody struct {
	Outbound map[string]any `json:"outbound"`
}

func (s *Server) handleCreateOutbound(w http.ResponseWriter, r *http.Request) {
	var body outboundBody
	if err := decodeBody(w, r, 1<<20, &body); err != nil {
		writeAPIError(w, err)
		return
	}
	if body.Outbound == nil {
		writeAPIError(w, errValidation("outbound must be an object"))
		return
	}
	tag, _ := body.Outbound["tag"].(string)
	if strings.TrimSpace(tag) == "" {
		writeAPIError(w, errValidation("outbound requires a tag"))
		return
	}
	load, err := s.loadConfig()
	if err != nil {
		writeAPIError(w, err)
		return
	}
	if _, err := s.saveDirect(load, func(doc map[string]any) error {
		arr, _ := doc["outbounds"].([]any)
		for _, elem := range arr {
			if obj, ok := elem.(map[string]any); ok {
				if t, _ := obj["tag"].(string); t == tag {
					return errValidation("outbound already exists")
				}
			}
		}
		// A new element has no stored counterpart: any sentinel
		// inside it rejects (adoptNew semantics).
		if _, _, err := mergeNode(nil, false, body.Outbound, "outbounds", false); err != nil {
			var rej *sentinelRejection
			if errors.As(err, &rej) {
				return errValidation("redacted value at " + rej.path + " has no stored value to keep")
			}
			return err
		}
		doc["outbounds"] = append(arr, body.Outbound)
		return nil
	}); err != nil {
		writeAPIError(w, err)
		return
	}
	writeEnvelope(w, http.StatusOK, s.outboundSummaryAfter(tag))
}

func (s *Server) outboundSummaryAfter(tag string) outboundSummary {
	load, err := s.loadConfig()
	if err != nil {
		return outboundSummary{Tag: tag}
	}
	cfg, err := s.parseLoaded(load)
	if err != nil {
		return outboundSummary{Tag: tag}
	}
	rawOutbounds, _, _ := rawSections(load)
	for _, ob := range cfg.Outbounds {
		if ob.Tag == tag {
			summary := ob.Type
			for _, obj := range rawOutbounds {
				if t, _ := obj["tag"].(string); t == tag {
					summary = summarizeObject(obj)
				}
			}
			return outboundSummary{Tag: tag, Type: ob.Type, Summary: summary, UsedBy: usedByOutbound(cfg, tag)}
		}
	}
	return outboundSummary{Tag: tag}
}

func (s *Server) handlePatchOutbound(w http.ResponseWriter, r *http.Request) {
	tag := chi.URLParam(r, "tag")
	var body outboundBody
	if err := decodeBody(w, r, 1<<20, &body); err != nil {
		writeAPIError(w, err)
		return
	}
	if body.Outbound == nil {
		writeAPIError(w, errValidation("outbound must be an object"))
		return
	}
	// PATCH is a full-object replacement with the sentinel
	// merge: the client sends the complete redacted object from
	// the detail view. Partial objects would delete absent keys
	// (R9) and must not be sent; the tag must stay identical.
	if newTag, _ := body.Outbound["tag"].(string); newTag != tag {
		writeAPIError(w, errValidation("outbound tag must not change; delete and recreate to rename"))
		return
	}
	load, err := s.loadConfig()
	if err != nil {
		writeAPIError(w, err)
		return
	}
	if _, err := s.saveDirect(load, func(doc map[string]any) error {
		arr, _ := doc["outbounds"].([]any)
		for i, elem := range arr {
			obj, ok := elem.(map[string]any)
			if !ok {
				continue
			}
			if t, _ := obj["tag"].(string); t == tag {
				merged, _, err := mergeNode(obj, true, body.Outbound, "outbounds["+strconv.Itoa(i)+"]", false)
				if err != nil {
					var rej *sentinelRejection
					if errors.As(err, &rej) {
						return errValidation("redacted value at " + rej.path + " has no stored value to keep")
					}
					return err
				}
				arr[i] = merged
				doc["outbounds"] = arr
				return nil
			}
		}
		return errNotFound("outbound not found")
	}); err != nil {
		writeAPIError(w, err)
		return
	}
	writeEnvelope(w, http.StatusOK, s.outboundSummaryAfter(tag))
}

func (s *Server) handleDeleteOutbound(w http.ResponseWriter, r *http.Request) {
	tag := chi.URLParam(r, "tag")
	load, err := s.loadConfig()
	if err != nil {
		writeAPIError(w, err)
		return
	}
	if _, err := s.saveDirect(load, func(doc map[string]any) error {
		arr, _ := doc["outbounds"].([]any)
		kept := make([]any, 0, len(arr))
		found := false
		for _, elem := range arr {
			if obj, ok := elem.(map[string]any); ok {
				if t, _ := obj["tag"].(string); t == tag {
					found = true
					continue
				}
			}
			kept = append(kept, elem)
		}
		if !found {
			return errNotFound("outbound not found")
		}
		doc["outbounds"] = kept
		return nil
	}); err != nil {
		writeAPIError(w, err)
		return
	}
	writeEnvelope(w, http.StatusOK, map[string]any{"deleted": true})
}

func (s *Server) handleValidateOutbound(w http.ResponseWriter, r *http.Request) {
	var body outboundBody
	if err := decodeBody(w, r, 1<<20, &body); err != nil {
		writeAPIError(w, err)
		return
	}
	if body.Outbound == nil {
		writeAPIError(w, errValidation("outbound must be an object"))
		return
	}
	load, err := s.loadConfig()
	if err != nil {
		writeAPIError(w, err)
		return
	}
	// Validate by appending to a COPY of the stored document
	// and parsing the whole: no write happens on any path.
	var stored any = map[string]any{}
	if len(load.raw) > 0 {
		doc, derr := decodeGeneric(load.raw)
		if derr != nil {
			writeAPIError(w, errValidation("stored config is invalid: "+safeMessage(derr)))
			return
		}
		stored = doc
	}
	storedObj, ok := stored.(map[string]any)
	if !ok {
		writeAPIError(w, errValidation("config document must be a JSON object"))
		return
	}
	if _, _, err := mergeNode(nil, false, body.Outbound, "outbounds", false); err != nil {
		var rej *sentinelRejection
		if errors.As(err, &rej) {
			writeEnvelope(w, http.StatusOK, map[string]any{"valid": false, "errors": []string{"redacted value at " + rej.path + " has no stored value to keep"}})
			return
		}
		writeAPIError(w, err)
		return
	}
	arr, _ := storedObj["outbounds"].([]any)
	storedObj["outbounds"] = append(arr, body.Outbound)
	merged, merr := json.Marshal(storedObj)
	if merr != nil {
		writeAPIError(w, errInternal())
		return
	}
	if _, verr := profile.ParseSingleConfig(merged, s.deps.ConfigDir); verr != nil {
		writeEnvelope(w, http.StatusOK, map[string]any{"valid": false, "errors": []string{safeMessage(verr)}})
		return
	}
	writeEnvelope(w, http.StatusOK, map[string]any{"valid": true, "errors": []string{}})
}

func (s *Server) handleListEndpoints(w http.ResponseWriter, r *http.Request) {
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
	rawOutbounds, rawEndpoints, err := rawSections(load)
	if err != nil {
		writeAPIError(w, errValidation("stored config is invalid: "+safeMessage(err)))
		return
	}
	byTag := map[string]map[string]any{}
	for _, obj := range rawEndpoints {
		if tag, ok := obj["tag"].(string); ok {
			byTag[tag] = obj
		}
	}
	out := make([]endpointSummary, 0, len(cfg.Endpoints))
	for _, ep := range cfg.Endpoints {
		summary := ep.Type
		if obj, ok := byTag[ep.Tag]; ok {
			summary = summarizeObject(obj)
		}
		out = append(out, endpointSummary{
			Tag:     ep.Tag,
			Type:    ep.Type,
			Summary: summary,
			UsedBy:  usedByEndpoint(cfg, rawOutbounds, ep.Tag),
		})
	}
	writeEnvelope(w, http.StatusOK, out)
}

func (s *Server) handleGetEndpoint(w http.ResponseWriter, r *http.Request) {
	tag := chi.URLParam(r, "tag")
	load, err := s.loadConfig()
	if err != nil {
		writeAPIError(w, err)
		return
	}
	if _, err := s.parseLoaded(load); err != nil {
		writeAPIError(w, err)
		return
	}
	_, rawEndpoints, err := rawSections(load)
	if err != nil {
		writeAPIError(w, errValidation("stored config is invalid: "+safeMessage(err)))
		return
	}
	for _, obj := range rawEndpoints {
		if t, ok := obj["tag"].(string); ok && t == tag {
			writeEnvelope(w, http.StatusOK, redactGeneric(obj))
			return
		}
	}
	writeAPIError(w, errNotFound("endpoint not found"))
}

type endpointBody struct {
	Endpoint map[string]any `json:"endpoint"`
}

func (s *Server) endpointSummaryAfter(tag string) endpointSummary {
	load, err := s.loadConfig()
	if err != nil {
		return endpointSummary{Tag: tag}
	}
	cfg, err := s.parseLoaded(load)
	if err != nil {
		return endpointSummary{Tag: tag}
	}
	rawOutbounds, rawEndpoints, _ := rawSections(load)
	for _, ep := range cfg.Endpoints {
		if ep.Tag == tag {
			summary := ep.Type
			for _, obj := range rawEndpoints {
				if t, _ := obj["tag"].(string); t == tag {
					summary = summarizeObject(obj)
				}
			}
			return endpointSummary{Tag: tag, Type: ep.Type, Summary: summary, UsedBy: usedByEndpoint(cfg, rawOutbounds, tag)}
		}
	}
	return endpointSummary{Tag: tag}
}

func (s *Server) handleCreateEndpoint(w http.ResponseWriter, r *http.Request) {
	var body endpointBody
	if err := decodeBody(w, r, 1<<20, &body); err != nil {
		writeAPIError(w, err)
		return
	}
	if body.Endpoint == nil {
		writeAPIError(w, errValidation("endpoint must be an object"))
		return
	}
	tag, _ := body.Endpoint["tag"].(string)
	if strings.TrimSpace(tag) == "" {
		writeAPIError(w, errValidation("endpoint requires a tag"))
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
				if t, _ := obj["tag"].(string); t == tag {
					return errValidation("endpoint already exists")
				}
			}
		}
		if _, _, err := mergeNode(nil, false, body.Endpoint, "endpoints", false); err != nil {
			var rej *sentinelRejection
			if errors.As(err, &rej) {
				return errValidation("redacted value at " + rej.path + " has no stored value to keep")
			}
			return err
		}
		doc["endpoints"] = append(arr, body.Endpoint)
		return nil
	}); err != nil {
		writeAPIError(w, err)
		return
	}
	writeEnvelope(w, http.StatusOK, s.endpointSummaryAfter(tag))
}

func (s *Server) handlePatchEndpoint(w http.ResponseWriter, r *http.Request) {
	tag := chi.URLParam(r, "tag")
	var body endpointBody
	if err := decodeBody(w, r, 1<<20, &body); err != nil {
		writeAPIError(w, err)
		return
	}
	if body.Endpoint == nil {
		writeAPIError(w, errValidation("endpoint must be an object"))
		return
	}
	if newTag, _ := body.Endpoint["tag"].(string); newTag != tag {
		writeAPIError(w, errValidation("endpoint tag must not change; delete and recreate to rename"))
		return
	}
	load, err := s.loadConfig()
	if err != nil {
		writeAPIError(w, err)
		return
	}
	if _, err := s.saveDirect(load, func(doc map[string]any) error {
		arr, _ := doc["endpoints"].([]any)
		for i, elem := range arr {
			obj, ok := elem.(map[string]any)
			if !ok {
				continue
			}
			if t, _ := obj["tag"].(string); t == tag {
				merged, _, err := mergeNode(obj, true, body.Endpoint, "endpoints["+strconv.Itoa(i)+"]", false)
				if err != nil {
					var rej *sentinelRejection
					if errors.As(err, &rej) {
						return errValidation("redacted value at " + rej.path + " has no stored value to keep")
					}
					return err
				}
				arr[i] = merged
				doc["endpoints"] = arr
				return nil
			}
		}
		return errNotFound("endpoint not found")
	}); err != nil {
		writeAPIError(w, err)
		return
	}
	writeEnvelope(w, http.StatusOK, s.endpointSummaryAfter(tag))
}

func (s *Server) handleDeleteEndpoint(w http.ResponseWriter, r *http.Request) {
	tag := chi.URLParam(r, "tag")
	load, err := s.loadConfig()
	if err != nil {
		writeAPIError(w, err)
		return
	}
	if _, err := s.saveDirect(load, func(doc map[string]any) error {
		arr, _ := doc["endpoints"].([]any)
		kept := make([]any, 0, len(arr))
		found := false
		for _, elem := range arr {
			if obj, ok := elem.(map[string]any); ok {
				if t, _ := obj["tag"].(string); t == tag {
					found = true
					continue
				}
			}
			kept = append(kept, elem)
		}
		if !found {
			return errNotFound("endpoint not found")
		}
		doc["endpoints"] = kept
		return nil
	}); err != nil {
		writeAPIError(w, err)
		return
	}
	writeEnvelope(w, http.StatusOK, map[string]any{"deleted": true})
}

// --- config / dns ----------------------------------------------

func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	load, err := s.loadConfig()
	if err != nil {
		writeAPIError(w, err)
		return
	}
	if load.state.Exists && !load.state.Found {
		writeAPIError(w, errValidation("legacy layout: run castctl config migrate in the CLI; the web UI does not migrate"))
		return
	}
	if !load.state.Found {
		writeAPIError(w, errNotFound("no config file"))
		return
	}
	cfg, err := s.parseLoaded(load)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	redacted, err := profile.RedactJSON(load.raw)
	if err != nil {
		writeAPIError(w, errValidation("stored config is invalid: "+safeMessage(err)))
		return
	}
	writeEnvelope(w, http.StatusOK, map[string]any{
		"content": string(redacted),
		"sha256":  load.hash,
		"source":  s.configSource(load, cfg),
	})
}

type putConfigBody struct {
	Content    string `json:"content"`
	BaseSHA256 string `json:"base_sha256"`
}

func (s *Server) handlePutConfig(w http.ResponseWriter, r *http.Request) {
	var body putConfigBody
	if err := decodeBody(w, r, 1<<20, &body); err != nil {
		writeAPIError(w, err)
		return
	}
	submitted, err := decodeGeneric([]byte(body.Content))
	if err != nil {
		writeAPIError(w, errValidation("config content is not valid JSON"))
		return
	}
	load, err := s.loadConfig()
	if err != nil {
		writeAPIError(w, err)
		return
	}
	newHash, err := s.saveSubmitted(load, body.BaseSHA256, submitted)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeEnvelope(w, http.StatusOK, map[string]any{"sha256": newHash})
}

type validateConfigBody struct {
	Content string `json:"content"`
}

func (s *Server) handleValidateConfig(w http.ResponseWriter, r *http.Request) {
	var body validateConfigBody
	if err := decodeBody(w, r, 1<<20, &body); err != nil {
		writeAPIError(w, err)
		return
	}
	if _, err := profile.ParseSingleConfig([]byte(body.Content), s.deps.ConfigDir); err != nil {
		writeEnvelope(w, http.StatusOK, map[string]any{"valid": false, "errors": []string{safeMessage(err)}})
		return
	}
	writeEnvelope(w, http.StatusOK, map[string]any{"valid": true, "errors": []string{}})
}

func (s *Server) handleGetDNS(w http.ResponseWriter, r *http.Request) {
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
	_ = cfg
	dns := map[string]any{}
	if len(load.raw) > 0 {
		if doc, derr := decodeGeneric(load.raw); derr == nil {
			if obj, ok := doc.(map[string]any); ok {
				if section, ok := obj["dns"].(map[string]any); ok {
					dns = section
				}
			}
		}
	}
	writeEnvelope(w, http.StatusOK, map[string]any{
		"dns":    redactGeneric(dns),
		"sha256": load.hash,
	})
}

type putDNSBody struct {
	DNS        any    `json:"dns"`
	BaseSHA256 string `json:"base_sha256"`
}

func (s *Server) handlePutDNS(w http.ResponseWriter, r *http.Request) {
	// decodeBody with DisallowUnknownFields would reject the
	// open-ended dns object, so decode generically here.
	v, err := bodyJSON(w, r, 1<<20)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	obj, ok := v.(map[string]any)
	if !ok {
		writeAPIError(w, errValidation("request body must be a JSON object"))
		return
	}
	baseSHA, _ := obj["base_sha256"].(string)
	submitted, hasDNS := obj["dns"]
	if !hasDNS {
		writeAPIError(w, errValidation("dns is required"))
		return
	}
	if submitted != nil {
		if _, ok := submitted.(map[string]any); !ok {
			writeAPIError(w, errValidation("dns must be an object or null"))
			return
		}
	}
	load, err := s.loadConfig()
	if err != nil {
		writeAPIError(w, err)
		return
	}
	if load.hash != baseSHA {
		writeAPIError(w, errConfigChanged())
		return
	}
	var storedSection any
	storedPresent := false
	if len(load.raw) > 0 {
		if doc, derr := decodeGeneric(load.raw); derr == nil {
			if docObj, ok := doc.(map[string]any); ok {
				if section, ok := docObj["dns"]; ok {
					storedSection, storedPresent = section, true
				}
			}
		}
	}
	var mergedSection any
	if submitted == nil {
		mergedSection = nil
	} else {
		merged, _, merr := mergeNode(storedSection, storedPresent, submitted, "dns", false)
		if merr != nil {
			var rej *sentinelRejection
			if errors.As(merr, &rej) {
				writeAPIError(w, errValidation("redacted value at "+rej.path+" has no stored value to keep"))
				return
			}
			writeAPIError(w, err)
			return
		}
		mergedSection = merged
	}
	newHash, err := s.saveMerged(load, baseSHA, func(doc map[string]any) error {
		if mergedSection == nil {
			delete(doc, "dns")
		} else {
			doc["dns"] = mergedSection
		}
		return nil
	})
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeEnvelope(w, http.StatusOK, map[string]any{"sha256": newHash})
}

// --- telegram ---------------------------------------------------

type telegramView struct {
	Configured     bool    `json:"configured"`
	Masked         string  `json:"masked"`
	Profile        string  `json:"profile"`
	AllowedUserIDs []int64 `json:"allowed_user_ids"`
	AutoApprove    bool    `json:"auto_approve"`
	AutoAllowOnce  bool    `json:"auto_allow_once"`
}

func (s *Server) handleGetTelegram(w http.ResponseWriter, r *http.Request) {
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
	view := telegramView{AllowedUserIDs: []int64{}}
	if cfg.Telegram != nil {
		view.Configured = true
		// Masked display only: exactly "***" when a token is
		// stored, never any part of the token.
		view.Masked = "***"
		view.Profile = cfg.Telegram.Profile
		view.AllowedUserIDs = cfg.Telegram.AllowedUserIDs
		view.AutoApprove = cfg.Telegram.AutoApprove
		view.AutoAllowOnce = cfg.Telegram.AutoAllowOnce
	}
	writeEnvelope(w, http.StatusOK, view)
}

type putTelegramBody struct {
	Profile        *string       `json:"profile"`
	Token          *string       `json:"token"`
	AllowedUserIDs []json.Number `json:"allowed_user_ids"`
	AutoApprove    *bool         `json:"auto_approve"`
	AutoAllowOnce  *bool         `json:"auto_allow_once"`
}

func (s *Server) handlePutTelegram(w http.ResponseWriter, r *http.Request) {
	var body putTelegramBody
	if err := decodeBody(w, r, 64<<10, &body); err != nil {
		writeAPIError(w, err)
		return
	}
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
	var ids []int64
	idsSet := body.AllowedUserIDs != nil
	if idsSet {
		for _, n := range body.AllowedUserIDs {
			id, cerr := n.Int64()
			if cerr != nil || id <= 0 {
				writeAPIError(w, errValidation("telegram.allowed_user_ids must contain positive integers only"))
				return
			}
			ids = append(ids, id)
		}
		if len(ids) == 0 {
			writeAPIError(w, errValidation("telegram.allowed_user_ids must not be empty"))
			return
		}
	}
	if _, err := s.saveDirect(load, func(doc map[string]any) error {
		section, _ := doc["telegram"].(map[string]any)
		creating := section == nil
		if creating {
			section = map[string]any{}
		}
		if body.Profile != nil {
			if strings.TrimSpace(*body.Profile) == "" {
				return errValidation("telegram.profile must not be empty")
			}
			section["profile"] = *body.Profile
		} else if creating {
			// Documented zero-value: a created block links
			// the default profile when the body names none.
			if cfg.DefaultProfile == "" {
				return errValidation("telegram.profile is required when no default profile exists")
			}
			section["profile"] = cfg.DefaultProfile
		}
		if body.Token != nil {
			// Empty token = unchanged (write-only field).
			// A non-empty token replaces the stored one; its
			// shape is validated by the full-config parse.
			if strings.TrimSpace(*body.Token) != "" {
				token := strings.TrimSpace(*body.Token)
				// A placeholder is never a token: accepting
				// one would lock the bot out with the
				// redaction marker as its credential.
				if token == "***" || token == redact.Marker {
					return errValidation("telegram.token must be a real bot token, not a placeholder")
				}
				section["token"] = token
			} else if creating {
				return errValidation("telegram.token is required")
			}
		} else if creating {
			return errValidation("telegram.token is required")
		}
		if idsSet {
			arr := make([]any, 0, len(ids))
			for _, id := range ids {
				arr = append(arr, json.Number(strconv.FormatInt(id, 10)))
			}
			section["allowed_user_ids"] = arr
		} else if creating {
			return errValidation("telegram.allowed_user_ids is required")
		}
		if body.AutoApprove != nil {
			section["auto_approve"] = *body.AutoApprove
		}
		if body.AutoAllowOnce != nil {
			section["auto_allow_once"] = *body.AutoAllowOnce
		}
		doc["telegram"] = section
		return nil
	}); err != nil {
		writeAPIError(w, err)
		return
	}
	// Re-read for the response view (masked only, never the token).
	load2, err := s.loadConfig()
	if err != nil {
		writeAPIError(w, err)
		return
	}
	cfg2, err := s.parseLoaded(load2)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	view := telegramView{AllowedUserIDs: []int64{}}
	if cfg2.Telegram != nil {
		view.Configured = true
		view.Masked = "***"
		view.Profile = cfg2.Telegram.Profile
		view.AllowedUserIDs = cfg2.Telegram.AllowedUserIDs
		view.AutoApprove = cfg2.Telegram.AutoApprove
		view.AutoAllowOnce = cfg2.Telegram.AutoAllowOnce
	}
	writeEnvelope(w, http.StatusOK, view)
}

// --- keeper -----------------------------------------------------

func (s *Server) handleGetKeeper(w http.ResponseWriter, r *http.Request) {
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
	type keeperEntryView struct {
		Tag             string        `json:"tag"`
		Profile         string        `json:"profile"`
		Browser         string        `json:"browser"`
		IntervalSeconds int64         `json:"interval_seconds"`
		Notify          string        `json:"notify"`
		Status          keeper.Status `json:"status"`
	}
	entries := []keeperEntryView{}
	if cfg.Keeper != nil {
		for _, e := range cfg.Keeper.Entries {
			st, serr := keeper.ReadStatus(s.deps.ConfigDir, e)
			if serr != nil {
				writeAPIError(w, errInternal())
				return
			}
			entries = append(entries, keeperEntryView{
				Tag:             e.Tag,
				Profile:         e.Profile,
				Browser:         e.Browser,
				IntervalSeconds: int64(e.EffectiveInterval() / time.Second),
				Notify:          e.Notify,
				Status:          st,
			})
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Tag < entries[j].Tag })
	writeEnvelope(w, http.StatusOK, entries)
}
