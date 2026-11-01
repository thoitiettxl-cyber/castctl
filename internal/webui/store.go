// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package webui

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/thoitiettxl-cyber/castctl/internal/logging"
	"github.com/thoitiettxl-cyber/castctl/internal/profile"
	"github.com/thoitiettxl-cyber/castctl/internal/redact"
)

// safeMessage renders an internal error's text for an API error
// body: SafeString is the second redaction boundary (the first
// is never emitting untrusted text). Parse/validation errors
// name paths and keys only by the base rules; SafeString strips
// any secret-keyed shape that slips through, so a marker value
// can never appear in an error body.
func safeMessage(err error) string {
	if err == nil {
		return ""
	}
	return logging.SafeString(err.Error())
}

// configLoad is one load of config.json: the raw bytes, their
// SHA-256, and the guarded-write state. raw is nil when the file
// is absent; state.Found is false for an absent file and for a
// legacy-flat file (state.Exists distinguishes those two).
type configLoad struct {
	raw   []byte
	hash  string
	state *profile.ConfigState
}

func (s *Server) loadConfig() (*configLoad, error) {
	state, err := profile.LoadConfigState(s.deps.ConfigDir)
	if err != nil {
		return nil, errValidation("stored config is invalid: " + safeMessage(err))
	}
	var raw []byte
	if state.Exists {
		data, err := os.ReadFile(filepath.Join(s.deps.ConfigDir, "config.json"))
		if err != nil {
			if os.IsNotExist(err) {
				// Raced with a delete between the state
				// load and the read: report as changed.
				return nil, errConfigChanged()
			}
			return nil, errInternal()
		}
		raw = data
	}
	return &configLoad{raw: raw, hash: state.SHA256, state: state}, nil
}

// parseLoaded parses a loaded config, refusing legacy-only and
// absent layouts with explicit errors (no silent fallback, no
// overwrite of a legacy file).
func (s *Server) parseLoaded(load *configLoad) (*profile.SingleConfig, error) {
	if load.state.Exists && !load.state.Found {
		return nil, errValidation("legacy layout: run castctl config migrate in the CLI; the web UI does not migrate")
	}
	if !load.state.Found {
		return nil, errNotFound("no config file")
	}
	cfg, err := profile.ParseSingleConfig(load.raw, s.deps.ConfigDir)
	if err != nil {
		return nil, errValidation("stored config is invalid: " + safeMessage(err))
	}
	return cfg, nil
}

// decodeGeneric decodes JSON bytes into a generic document with
// UseNumber (integer fidelity for ids/ports).
func decodeGeneric(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

// docObject returns the document as an object, or a validation
// error when it is not one.
func docObject(doc any) (map[string]any, error) {
	obj, ok := doc.(map[string]any)
	if !ok {
		return nil, errValidation("config document must be a JSON object")
	}
	return obj, nil
}

// saveMerged applies mutate to a generic copy of the stored
// document, validates the FULL merged document (parse + tag
// cross-references) before any write, asserts the merged
// document holds no sentinel at a secret position (R8), hashes
// a plaintext webui.token before persisting (hash-on-save),
// and writes through the guarded path. baseSHA is the client's
// base_sha256: a mismatch is 409 config_changed with no write,
// no merge. An invalid merged document leaves the file
// byte-identical. The intermediate marshal preserves the stored
// document's key order inside raw blocks (see marshalOrdered);
// the canonical encoder then preserves raw sections verbatim
// on later CLI saves, so a web UI save does not reorder keys.
func (s *Server) saveMerged(load *configLoad, baseSHA string, mutate func(doc map[string]any) error) (string, error) {
	return s.saveGuarded(load, baseSHA, true, mutate)
}

// saveDirect is saveMerged for endpoints without a client hash
// (profile/outbound/endpoint/telegram saves, whose frozen
// request bodies carry no base_sha256): the expected hash is
// the freshly loaded one, and ConfigState.Save still refuses a
// concurrent change under the lock with 409.
func (s *Server) saveDirect(load *configLoad, mutate func(doc map[string]any) error) (string, error) {
	return s.saveGuarded(load, load.hash, false, mutate)
}

func (s *Server) saveGuarded(load *configLoad, expectedSHA string, checkExpected bool, mutate func(doc map[string]any) error) (string, error) {
	if load.state.Exists && !load.state.Found {
		return "", errValidation("legacy layout: run castctl config migrate in the CLI; the web UI does not migrate")
	}
	if checkExpected && load.hash != expectedSHA {
		return "", errConfigChanged()
	}
	var stored any = map[string]any{}
	if len(load.raw) > 0 {
		doc, err := decodeGeneric(load.raw)
		if err != nil {
			return "", errValidation("stored config is invalid: " + safeMessage(err))
		}
		stored = doc
	}
	doc, err := docObject(stored)
	if err != nil {
		return "", err
	}
	// Snapshot the stored cookies_file values before mutate:
	// doc aliases stored, so the comparison below needs the
	// pre-mutation strings.
	storedCookies := profileCookiesFiles(stored)
	// Snapshot the stored ui_dir the same way: only a new or
	// changed value is re-checked below.
	storedUIDir, storedUIDirHas := webUIUIDirValue(stored)
	// Snapshot whether the stored document carries a token:
	// refreshTokenHash needs it after the save to tell a
	// removal (stored token gone) from a document that never
	// carried one (startup comparator untouched).
	storedHadToken := storedWebUIToken(stored)
	if err := mutate(doc); err != nil {
		return "", err
	}
	// Web UI containment (Boss ruling 2026-10-31): a save may
	// only INTRODUCE a cookies_file value that is relative and
	// resolves inside the config dir (symlink- and ".."-aware).
	// Values already present anywhere in the stored document
	// pass through unchanged, so a CLI-created absolute path
	// keeps round-tripping — including across a profile rename,
	// which moves the value to a new key without changing it.
	// Only values new to the document are checked. This covers
	// every web UI write path that funnels through
	// saveGuarded: profile-create, PUT /config, and the
	// section saves (whose cookies_file values are unchanged).
	// Login import/restore check the resolved path separately,
	// at the seam that writes it.
	storedValues := map[string]bool{}
	for _, value := range storedCookies {
		storedValues[value] = true
	}
	for _, value := range profileCookiesFiles(doc) {
		if !storedValues[value] {
			if err := rejectNewCookiesFile(s.deps.ConfigDir, value); err != nil {
				return "", err
			}
		}
	}
	// B-1 save-time guard (same "only new or changed values"
	// pattern): a ui_dir the save introduces must not overlap
	// the config directory or contain a cookies file. An
	// unchanged stored value passes through here, but the
	// full-document parse below rejects a lexically
	// overlapping value, and serve-time resolution rejects
	// any overlapping value (including symlink-only ones)
	// before a file is served — so a dangerous stored value
	// can never reach the static shell through the API.
	if mergedUIDir, ok := webUIUIDirValue(doc); ok && mergedUIDir != "" && (!storedUIDirHas || storedUIDir != mergedUIDir) {
		if err := rejectNewUIDir(s.deps.ConfigDir, mergedUIDir, profileCookiesFiles(doc)); err != nil {
			return "", err
		}
	}
	if err := checkWhitespaceKeys(doc, ""); err != nil {
		var rej *sentinelRejection
		if errors.As(err, &rej) {
			return "", errValidation("invalid key at " + rej.path)
		}
		return "", err
	}
	// Order-preserving intermediate marshal: the re-parse
	// below captures raw blocks, so this order is the order
	// the canonical encoder re-emits on save.
	merged, err := marshalOrdered(load.raw, doc)
	if err != nil {
		return "", errInternal()
	}
	parsed, err := profile.ParseSingleConfig(merged, s.deps.ConfigDir)
	if err != nil {
		return "", errValidation("merged config is invalid: " + safeMessage(err))
	}
	// R8 assertion on the merged document as written.
	mergedDoc, err := decodeGeneric(merged)
	if err != nil {
		return "", errInternal()
	}
	if path := findSentinelAtSecretPosition(mergedDoc, false, ""); path != "" {
		return "", errValidation("redacted value at " + path + " has no stored value to keep")
	}
	// Hash-on-save: a plaintext webui.token in the merged
	// document is hashed with bcrypt before persisting, via
	// the same helper as serve-start hashing; an
	// already-hashed token passes through untouched. The
	// sentinel can never reach here at this position: the
	// merge keeps the stored value for a sentinel at a
	// secret position (R1) and R8 above rejects a sentinel
	// with no stored value, so a Marker here is an internal
	// error, never a value to hash. A token over bcrypt's
	// 72-byte limit fails the save (400) with a rule-only
	// message; nothing is written.
	if parsed.WebUI != nil && parsed.WebUI.Token != "" && !profile.LooksLikeBcryptHash(parsed.WebUI.Token) {
		if parsed.WebUI.Token == redact.Marker {
			return "", errInternal()
		}
		hash, err := profile.HashWebUIToken(parsed.WebUI.Token)
		if err != nil {
			return "", errValidation("webui token is invalid: " + safeMessage(err))
		}
		if err := parsed.ReplaceWebUIToken(hash); err != nil {
			return "", errInternal()
		}
	}
	if err := load.state.Save(parsed); err != nil {
		if errors.Is(err, profile.ErrConcurrentChange) {
			return "", errConfigChanged()
		}
		return "", errInternal()
	}
	// The save persisted: refresh the live comparator from
	// the saved document (rotation takes effect without
	// restart; a removal clears it — see refreshTokenHash).
	// hadToken is snapshotted from the stored document
	// before mutation: only a token the stored document
	// carried can be removed by this save. This is the only
	// in-process save funnel — every API save path
	// (saveMerged, saveDirect, saveSubmitted) runs through
	// saveGuarded — so no save path can persist a token
	// without refreshing the comparator. CLI saves run in
	// another process and take effect on restart, as before.
	s.refreshTokenHash(parsed, storedHadToken)
	return load.state.SHA256, nil
}

// saveSubmitted merges a full submitted document (the redacted
// view the user edited) against the stored document with the
// sentinel merge, then saves through saveMerged's validation +
// guarded write. It is PUT /config's path; the section saves
// (DNS, telegram) merge a section and delegate here via mutate.
func (s *Server) saveSubmitted(load *configLoad, baseSHA string, submitted any) (string, error) {
	submittedObj, err := docObject(submitted)
	if err != nil {
		return "", err
	}
	if err := checkWhitespaceKeys(submittedObj, ""); err != nil {
		var rej *sentinelRejection
		if errors.As(err, &rej) {
			return "", errValidation("invalid key at " + rej.path)
		}
		return "", err
	}
	var stored any = map[string]any{}
	if len(load.raw) > 0 {
		doc, err := decodeGeneric(load.raw)
		if err != nil {
			return "", errValidation("stored config is invalid: " + safeMessage(err))
		}
		stored = doc
	}
	merged, err := mergeConfig(stored, submittedObj)
	if err != nil {
		var rej *sentinelRejection
		if errors.As(err, &rej) {
			return "", errValidation("redacted value at " + rej.path + " has no stored value to keep")
		}
		return "", err
	}
	mergedObj, err := docObject(merged)
	if err != nil {
		return "", err
	}
	return s.saveMerged(load, baseSHA, func(doc map[string]any) error {
		for k := range doc {
			delete(doc, k)
		}
		for k, v := range mergedObj {
			doc[k] = v
		}
		return nil
	})
}

// configSource derives the layout label the frontend shows:
// "single-file" (only the single file), "legacy" (only legacy
// profile directories), "mixed" (both), or "none" (no config).
// Legacy detection is a stat-only scan of profiles/*/config.json
// whose name is not a key of the single file's profiles; no
// legacy file is read.
func (s *Server) configSource(load *configLoad, cfg *profile.SingleConfig) string {
	// Display-only: an enumeration error degrades to no
	// legacy profiles shown; only the log gate fails closed
	// on it (see legacyProfileNames).
	legacyNames, _ := s.legacyProfileNames(cfg)
	if !load.state.Found {
		if len(legacyNames) > 0 {
			return "legacy"
		}
		return "none"
	}
	if len(legacyNames) > 0 {
		return "mixed"
	}
	return "single-file"
}

// legacyProfileNames lists the names of legacy profile
// directories under profiles/ that are not keys of the
// single-file document: a directory carrying a config.json.
// A symlink to a directory IS followed, mirroring
// DiscoverProfileNames exactly for the symlink treatment
// (DirEntry.IsDir is false for a symlink to a directory, so
// a bare IsDir check would silently drop every symlinked
// legacy profile from the log gate's refused set). Name
// validation is deliberately NOT mirrored here: this
// enumeration is a guard scan, not migration discovery, so
// an invalid-name directory carrying a config.json is still
// listed — but listing alone refuses nothing: logGate fails
// the whole gate closed when the listed entry's refused set
// cannot be computed (its paths reject the name; see
// logGate). An error is returned when the profiles
// directory cannot be listed (other than not existing,
// which means no legacy profile can exist), when a symlink
// entry's target cannot be stat'ed (any error, including a
// dangling target: an unresolvable symlink holds no
// enumerable config), or when a candidate entry's
// config.json cannot be stat'ed (other than not existing,
// which means the entry holds no legacy config): the
// refused set cannot be enumerated then, so the caller
// that guards secrets (logGate) must fail closed.
// Display-only callers treat an error as no legacy
// profiles, as before.
func (s *Server) legacyProfileNames(cfg *profile.SingleConfig) ([]string, error) {
	profilesDir := filepath.Join(s.deps.ConfigDir, "profiles")
	entries, err := os.ReadDir(profilesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		// Names already defined in the single-file document
		// are never legacy profiles, whatever the
		// filesystem entry looks like: exclude them before
		// any probe, so an unresolvable symlink carrying a
		// single-file profile's name cannot fail the gate
		// closed for a shape that holds no legacy profile.
		if cfg != nil {
			if _, ok := cfg.Profiles[e.Name()]; ok {
				continue
			}
		}
		isDir := e.IsDir()
		if !isDir && e.Type()&os.ModeSymlink != 0 {
			// A symlink whose target cannot be stat'ed
			// (loop, dangling) is an enumeration failure,
			// not a skip: the entry's config is
			// unreachable, so its refused set is
			// unknowable. There is deliberately NO
			// IsNotExist carve-out here — a dangling
			// symlink's ENOENT means the target does not
			// resolve, unlike a missing config.json,
			// which means the entry holds no legacy
			// profile. A stat that succeeds but names a
			// non-directory is still skipped, as in
			// DiscoverProfileNames.
			st, serr := os.Stat(filepath.Join(profilesDir, e.Name()))
			if serr != nil {
				return nil, serr
			}
			isDir = st.IsDir()
		}
		if !isDir {
			continue
		}
		if _, err := os.Stat(filepath.Join(profilesDir, e.Name(), "config.json")); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names, nil
}

// redactGeneric redacts a generic document for a GET response:
// secret keys wholesale, header maps wholesale, URL userinfo
// scrub only. It never mutates its input.
func redactGeneric(v any) any {
	return redact.Value(v)
}

// sha256Hex is the lowercase hex SHA-256 of data.
func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// --- summaries -------------------------------------------------

// profileSummary is the frozen ProfileSummary shape.
type profileSummary struct {
	Name        string `json:"name"`
	Default     bool   `json:"default"`
	Source      string `json:"source"`
	HasCookies  bool   `json:"has_cookies"`
	OutboundTag any    `json:"outbound_tag"`
	Fingerprint string `json:"fingerprint"`
	Dir         string `json:"dir"`
}

func (s *Server) profileSummaries(cfg *profile.SingleConfig, legacyNames []string) []profileSummary {
	out := make([]profileSummary, 0, len(cfg.Profiles)+len(legacyNames))
	for _, name := range cfg.ProfileNames() {
		p := cfg.Profiles[name]
		var tag any
		switch p.Outbound.Kind {
		case profile.OutboundDirect:
			tag = nil
		case profile.OutboundTag:
			tag = p.Outbound.Tag
		case profile.OutboundInline:
			tag = p.Outbound.Tag
		default:
			tag = nil
		}
		fingerprint := p.Fingerprint
		if fingerprint == "" {
			fingerprint = "chrome"
		}
		hasCookies := cookiesPresent(p.CookiesFile)
		out = append(out, profileSummary{
			Name:        name,
			Default:     name == cfg.DefaultProfile,
			Source:      "single-file",
			HasCookies:  hasCookies,
			OutboundTag: tag,
			Fingerprint: fingerprint,
			Dir:         p.Dir,
		})
	}
	for _, name := range legacyNames {
		paths, err := profile.ProfilePaths(s.deps.ConfigDir, name)
		dir := ""
		hasCookies := false
		if err == nil {
			dir = paths.Dir
			hasCookies = cookiesPresent(paths.Cookies)
		}
		out = append(out, profileSummary{
			Name:        name,
			Default:     false,
			Source:      "legacy",
			HasCookies:  hasCookies,
			OutboundTag: nil,
			Fingerprint: "",
			Dir:         dir,
		})
	}
	return out
}

// cookiesPresent stats a cookies file: presence only, never a
// read (values stay on disk).
func cookiesPresent(path string) bool {
	if path == "" {
		return false
	}
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

// outboundSummary is the frozen OutboundSummary shape.
type outboundSummary struct {
	Tag     string   `json:"tag"`
	Type    string   `json:"type"`
	Summary string   `json:"summary"`
	UsedBy  []string `json:"used_by"`
}

// endpointSummary is the frozen EndpointSummary shape.
type endpointSummary struct {
	Tag     string   `json:"tag"`
	Type    string   `json:"type"`
	Summary string   `json:"summary"`
	UsedBy  []string `json:"used_by"`
}

// rawSections decodes the stored document's outbounds/endpoints
// arrays as generic objects for summary derivation and detail
// views. A decode failure here means the stored file failed
// parse already; callers surface the parse error instead.
func rawSections(load *configLoad) (outbounds, endpoints []map[string]any, err error) {
	if len(load.raw) == 0 {
		return nil, nil, nil
	}
	doc, err := decodeGeneric(load.raw)
	if err != nil {
		return nil, nil, err
	}
	obj, ok := doc.(map[string]any)
	if !ok {
		return nil, nil, fmt.Errorf("config document must be an object")
	}
	outbounds = genericObjectArray(obj["outbounds"])
	endpoints = genericObjectArray(obj["endpoints"])
	return outbounds, endpoints, nil
}

func genericObjectArray(v any) []map[string]any {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(arr))
	for _, elem := range arr {
		if obj, ok := elem.(map[string]any); ok {
			out = append(out, obj)
		}
	}
	return out
}

// summarizeObject derives a display summary from a generic
// outbound/endpoint object: "<type> <host>:<port>" when a host
// and port are present, "<type> <address>" for WireGuard-style
// address lists, else just the type. Display-only: hostnames
// and addresses are not secrets; secret keys are never read
// here (values pass through redactGeneric on detail views).
func summarizeObject(obj map[string]any) string {
	typ, _ := obj["type"].(string)
	host := firstString(obj, "server", "address", "host")
	if host == "" {
		if arr, ok := obj["address"].([]any); ok && len(arr) > 0 {
			if s, ok := arr[0].(string); ok {
				host = s
			}
		}
	}
	port := firstPort(obj)
	switch {
	case typ != "" && host != "" && port != "":
		return typ + " " + host + ":" + port
	case typ != "" && host != "":
		return typ + " " + host
	case typ != "":
		return typ
	default:
		return ""
	}
}

func firstString(obj map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := obj[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func firstPort(obj map[string]any) string {
	for _, k := range []string{"server_port", "port"} {
		switch v := obj[k].(type) {
		case json.Number:
			return v.String()
		case float64:
			return strings.TrimSuffix(fmt.Sprintf("%v", v), ".0")
		}
	}
	return ""
}

// usedByOutbound returns the profile names whose outbound tag
// (tag reference or inline auto-tag) equals tag.
func usedByOutbound(cfg *profile.SingleConfig, tag string) []string {
	var names []string
	for _, name := range cfg.ProfileNames() {
		p := cfg.Profiles[name]
		if p.Outbound.Tag == tag && p.Outbound.Kind != profile.OutboundDirect {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// usedByEndpoint returns the names that reference an endpoint
// tag: profiles whose outbound tag equals it, and outbounds
// whose detour/endpoint field names it. Best-effort display
// derivation from the stored document; the parse validation is
// the real cross-reference control.
func usedByEndpoint(cfg *profile.SingleConfig, rawOutbounds []map[string]any, tag string) []string {
	seen := map[string]bool{}
	var names []string
	add := func(name string) {
		if name != "" && !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	for _, name := range cfg.ProfileNames() {
		p := cfg.Profiles[name]
		if p.Outbound.Tag == tag {
			add(name)
		}
	}
	for _, obj := range rawOutbounds {
		for _, k := range []string{"detour", "endpoint"} {
			if s, ok := obj[k].(string); ok && s == tag {
				if t, ok := obj["tag"].(string); ok {
					add(t)
				}
			}
		}
	}
	sort.Strings(names)
	return names
}
