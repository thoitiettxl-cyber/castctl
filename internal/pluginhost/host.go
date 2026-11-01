// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package pluginhost

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/thoitiettxl-cyber/castctl/internal/pluginabi"
)

// Package pluginhost is the plugin host: discovery, shadow copy,
// dynamic loading, lifecycle (ApplyConfig), the host.log-only
// reverse callback, panic/timeout isolation at the host
// boundary, the glibc compatibility gate, and the per-session
// loopback egress proxy.
//
// The loader and lifecycle mirror CLIProxyAPI's pluginhost at
// pin 250d5981 (loader_unix.go, loader_windows.go, shadow.go,
// platform.go, host.go ApplyConfig, client_guard.go, abi.go,
// rpc_client.go schema gate, host_callbacks.go host.log
// dispatch), renamed into the castctl namespace and cut down
// to the approved v1 design. Per-file citations are in
// docs/plugins.md References and in the comments on each
// mirrored piece. What was deliberately NOT copied is listed
// in docs/plugins.md: host.auth.*, the store/registry,
// min_version/allow_downgrade, random shadow names, load-time
// signature checks, and any sandbox promise.
//
// Trust boundary (BQ1, closed): plugins are trusted,
// first-party, in-process, with no sandbox. A native crash
// (segfault, Go runtime crash, os.Exit, memory corruption) in
// plugin code cannot be contained by this host; only
// host-adapter panics (recovered in the guarded call) and
// plugin-returned envelope errors are isolated. See
// docs/plugins.md "Native-panic limit".

// Client is one loaded plugin image. Call exchanges one JSON
// envelope (see CallEnvelope). Shutdown detaches the client
// logically; the image is never unloaded.
type Client interface {
	Call(ctx context.Context, method string, request []byte) ([]byte, error)
	Shutdown()
}

// Loader opens a plugin file into a Client. The default loader
// is the dynamic-library loader (cgo unix / windows) or the
// stub that refuses loads (no-cgo / GOOS=android builds).
type Loader interface {
	Open(file File, host *Host) (Client, error)
}

// Desired is one plugin the caller wants loaded: a config
// entry (tag/type/fragment) plus the binary path resolved by
// discovery and the per-session handoff (identity/egress).
// Two Desired entries may share one Path (BQ2(A) logical
// instances): each gets its own registration and its own
// host-side state. Whether two Hosts share one loaded image
// for the same tag+path is a loader property (see
// docs/plugins.md "Image sharing"), not a Desired property.
type Desired struct {
	Tag  string
	Type string
	// Path is the plugin binary to load.
	Path string
	// Fragment is the config fragment verbatim (entry object
	// minus tag/type).
	Fragment []byte
	// Identity is the secret-stripped outbound identity, or
	// nil when the caller supplies none.
	Identity *pluginabi.Identity
	// Egress is the per-session loopback proxy description, or
	// nil when the caller supplies none.
	Egress *pluginabi.Egress
	// EgressProxy, when set, is the loopback proxy this
	// plugin's traffic goes through, owned by the wiring
	// that built it. The host adopts it (AdoptEgress) so
	// its credentials die with the host, and applies the
	// plugin's declared cookie_hosts to it after each
	// registration. Nil means no proxy is handed over.
	// Ownership: the host adopts the proxy only when a
	// registration succeeds (applyRegistration). If a
	// fresh load fails (Open or register), the proxy is
	// never adopted and stays caller-owned: the caller
	// must close it. The host never closes a proxy it
	// did not adopt.
	EgressProxy *EgressProxy
	// ManifestPath, when set, names a checksums.txt manifest the
	// binary must verify against before it is loaded.
	ManifestPath string
}

// Options configures a Host.
type Options struct {
	// Loader overrides the default dynamic loader (tests use a
	// fake). Nil means the default loader.
	Loader Loader
	// Log receives host.log callback entries and lifecycle
	// warnings. It must not block: it may be called from a
	// plugin thread. Nil discards.
	Log func(level, message string)
}

// Host owns loaded plugins and applies desired configurations
// to them. A Host is safe for concurrent use: ApplyConfig calls
// serialize, and Call may run concurrently with ApplyConfig
// for a different tag.
type Host struct {
	loader Loader
	log    func(level, message string)

	applyMu sync.Mutex
	mu      sync.Mutex
	loaded  map[string]*loadedPlugin
	fused   map[string]fusedEntry
	// egresses are loopback proxies handed to the host by
	// the wiring (AdoptEgress) so their credentials die
	// with the host. The host never creates a proxy: the
	// upstream transport and dial function belong to the
	// wiring that owns the profile.
	egressMu sync.Mutex
	egresses []*EgressProxy
}

// fusedEntry records why a plugin is fused and WHICH image
// path was fused. A fuse is per-path: reconfiguring to a
// different path clears it, while the same path stays fused.
type fusedEntry struct {
	reason string
	path   string
}

// LoadedPlugin is the host-side view of a registered plugin.
type LoadedPlugin struct {
	Tag           string
	Type          string
	Metadata      pluginabi.Metadata
	Capabilities  pluginabi.Capabilities
	SchemaVersion uint32
	Commands      []pluginabi.Command
	Path          string
}

// Skipped is one desired plugin ApplyConfig did not load, with
// the reason (a warn-and-skip record, never a secret value).
type Skipped struct {
	Tag    string
	Reason string
}

// ApplyReport is the result of ApplyConfig: the tags that are
// loaded AND callable afterwards, and the desired entries
// that were skipped. A tag is never in Loaded for a path
// it is fused for, even when its image is still resident:
// fused calls fail fast for that path until a
// different-path ApplyConfig clears the fuse.
type ApplyReport struct {
	Loaded  []string
	Skipped []Skipped
}

type loadedPlugin struct {
	desired      Desired
	client       Client
	registered   bool
	metadata     pluginabi.Metadata
	capabilities pluginabi.Capabilities
	schema       uint32
	commands     []pluginabi.Command
	path         string
	egress       *EgressProxy
}

// New builds a Host. No plugin is loaded until ApplyConfig.
// Constructing a host sweeps stale shadow directories left
// by dead processes (best-effort; see shadow.go).
func New(opts Options) *Host {
	loader := opts.Loader
	if loader == nil {
		loader = defaultLoader()
	}
	logFn := opts.Log
	if logFn == nil {
		logFn = func(string, string) {}
	}
	sweepStaleShadowDirs()
	return &Host{
		loader: loader,
		log:    logFn,
		loaded: make(map[string]*loadedPlugin),
		fused:  make(map[string]fusedEntry),
	}
}

func (h *Host) logf(level, message string) {
	if h == nil || h.log == nil {
		return
	}
	h.log(level, message)
}

// Fused reports whether tag is fused (skipped until replaced),
// and the fuse reason.
func (h *Host) Fused(tag string) (string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	entry, ok := h.fused[tag]
	return entry.reason, ok
}

// Loaded reports the registered plugin for tag, if any.
// A fuse is per-path: only a fuse recorded for the loaded
// image's own path hides it — a call for that path
// fail-fasts (see Call), so Loaded means callable for
// that path. A fuse recorded for a different path (a
// failed replacement, rolled back to this image) does
// not hide the loaded image. Registration fields are
// read under h.mu, the same mutex applyRegistration
// writes them under.
func (h *Host) Loaded(tag string) (LoadedPlugin, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	lp, ok := h.loaded[tag]
	if !ok || !lp.registered {
		return LoadedPlugin{}, false
	}
	if entry, fused := h.fused[tag]; fused && entry.path == lp.path {
		return LoadedPlugin{}, false
	}
	return LoadedPlugin{
		Tag:           lp.desired.Tag,
		Type:          lp.desired.Type,
		Metadata:      lp.metadata,
		Capabilities:  lp.capabilities,
		SchemaVersion: lp.schema,
		Commands:      append([]pluginabi.Command(nil), lp.commands...),
		Path:          lp.path,
	}, true
}

// AdoptEgress registers a loopback proxy with the host so
// Host.Close closes it (revoking its credentials). The host
// never creates proxies and never adopts the same proxy
// twice. Adoption is reference-counted by pointer across
// loaded tags: superseding a plugin's proxy (reconfigure
// with a different EgressProxy) or detaching the last tag
// that references a proxy closes it immediately — a
// superseded proxy's credentials and cookie scope must not
// outlive the plugin image that used them. Two tags sharing
// one proxy pointer keep it alive until the last tag
// leaves. Callers that create a proxy per plugin session
// adopt it here; callers that keep a proxy alive past the
// host must not adopt it. A nil EgressProxy in a later
// Desired keeps the existing proxy (see applyRegistration).
func (h *Host) AdoptEgress(p *EgressProxy) {
	if h == nil || p == nil {
		return
	}
	h.egressMu.Lock()
	defer h.egressMu.Unlock()
	for _, existing := range h.egresses {
		if existing == p {
			return
		}
	}
	h.egresses = append(h.egresses, p)
}

// maybeCloseEgress closes p when no loaded tag references
// it anymore (reference-counted by pointer: AdoptEgress
// dedups by pointer, and tags may share one proxy). It is
// called when a tag's egress pointer is superseded or the
// tag is detached/deleted. ApplyConfig serialises these
// calls (applyMu), so the scan-then-close sequence cannot
// interleave with another ApplyConfig; Host.Close closes
// every adopted proxy regardless and is idempotent via the
// proxy's closeOnce.
func (h *Host) maybeCloseEgress(p *EgressProxy) {
	if h == nil || p == nil {
		return
	}
	h.mu.Lock()
	refs := 0
	for _, lp := range h.loaded {
		if lp != nil && lp.egress == p {
			refs++
		}
	}
	h.mu.Unlock()
	if refs == 0 {
		_ = p.Close()
	}
}

// Close shuts down every loaded plugin (detach only; images
// stay mapped), closes adopted egress proxies (revoking
// their credentials), removes this process's shadow
// directory, and clears host state. It is idempotent.
// Close serialises against ApplyConfig via applyMu: an
// ApplyConfig racing Close can no longer install a plugin
// after Close snapshot the state (a client Close would
// never shut down and a proxy Close would never revoke).
// Client Shutdown calls run OUTSIDE h.mu: a client may block
// on an in-flight native call, and holding the host lock
// across that would stall every other host operation.
func (h *Host) Close() {
	if h == nil {
		return
	}
	h.applyMu.Lock()
	defer h.applyMu.Unlock()
	h.mu.Lock()
	var clients []Client
	for tag, lp := range h.loaded {
		if lp != nil && lp.client != nil {
			clients = append(clients, lp.client)
		}
		delete(h.loaded, tag)
	}
	h.fused = make(map[string]fusedEntry)
	h.mu.Unlock()
	h.egressMu.Lock()
	proxies := h.egresses
	h.egresses = nil
	h.egressMu.Unlock()
	for _, c := range clients {
		c.Shutdown()
	}
	for _, p := range proxies {
		_ = p.Close()
	}
	// Best-effort: a shadow-cleanup failure must never
	// fail shutdown.
	CleanupShadowDir()
}

// ApplyConfig loads, reconfigures, replaces, and detaches
// plugins to match desired, mirroring upstream ApplyConfig
// (internal/pluginhost/host.go:213 at pin 250d5981): quiesce
// before replace, rollback on new-image failure, never unload,
// fuse on host-side panic, warn-and-skip per plugin. A
// per-plugin failure never fails the whole call: it is
// recorded in the report and the previously loaded plugin (if
// any) keeps running. ApplyConfig returns only when every
// desired entry has been attempted.
func (h *Host) ApplyConfig(ctx context.Context, desired []Desired) ApplyReport {
	if h == nil {
		return ApplyReport{}
	}
	h.applyMu.Lock()
	defer h.applyMu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	report := ApplyReport{}
	seen := make(map[string]bool)
	desiredByTag := make(map[string]Desired)
	ordered := make([]Desired, 0, len(desired))
	for _, d := range desired {
		if seen[d.Tag] {
			report.Skipped = append(report.Skipped, Skipped{Tag: d.Tag, Reason: "duplicate plugin tag in desired config"})
			continue
		}
		seen[d.Tag] = true
		desiredByTag[d.Tag] = d
		ordered = append(ordered, d)
	}

	// Detach unselected plugins. Shutdown calls run
	// outside h.mu (a client may block on an in-flight
	// native call); detached egress proxies are released
	// after the map update, once no loaded tag references
	// them.
	h.mu.Lock()
	var detached []Client
	var detachedEgress []*EgressProxy
	for tag, lp := range h.loaded {
		if _, ok := desiredByTag[tag]; !ok {
			if lp != nil && lp.client != nil {
				detached = append(detached, lp.client)
			}
			if lp != nil && lp.egress != nil {
				detachedEgress = append(detachedEgress, lp.egress)
			}
			delete(h.loaded, tag)
			delete(h.fused, tag)
		}
	}
	h.mu.Unlock()
	for _, c := range detached {
		c.Shutdown()
	}
	for _, p := range detachedEgress {
		h.maybeCloseEgress(p)
	}

	for _, d := range ordered {
		// A fuse is per-path: the same path stays fused
		// (skipped), a different path replaces and clears
		// the fuse. A fused tag with no loaded entry and
		// the same path stays skipped.
		h.mu.Lock()
		fuseEntry, isFused := h.fused[d.Tag]
		existing := h.loaded[d.Tag]
		h.mu.Unlock()
		if isFused && fuseEntry.path == d.Path {
			report.Skipped = append(report.Skipped, Skipped{Tag: d.Tag, Reason: "fused: " + fuseEntry.reason})
			// A tag fused for this path is never reported
			// Loaded, even when its image is still
			// resident: Loaded means callable for that
			// path, and fused calls fail fast.
			continue
		}
		if isFused {
			h.mu.Lock()
			delete(h.fused, d.Tag)
			h.mu.Unlock()
		}
		if existing != nil && existing.path == d.Path {
			// Same image: reconfigure in place.
			if err := h.reconfigure(ctx, existing, d); err != nil {
				// Rollback: re-register with the old fragment.
				if rerr := h.register(ctx, existing, existing.desired); rerr != nil {
					h.fuse(d.Tag, "reconfigure failed and rollback failed: "+shortErr(rerr), existing.path)
					h.mu.Lock()
					delete(h.loaded, d.Tag)
					h.mu.Unlock()
					existing.client.Shutdown()
					h.maybeCloseEgress(existing.egress)
					report.Skipped = append(report.Skipped, Skipped{Tag: d.Tag, Reason: "reconfigure failed and rollback failed"})
				} else {
					report.Skipped = append(report.Skipped, Skipped{Tag: d.Tag, Reason: "reconfigure failed, rolled back to previous config"})
					report.Loaded = append(report.Loaded, d.Tag)
				}
				continue
			}
			report.Loaded = append(report.Loaded, d.Tag)
			continue
		}
		if existing != nil {
			// Different image: quiesce before replace. A
			// quiesce failure is logged, never fatal
			// (upstream callQuiesce / logQuiesceError).
			if err := h.quiesce(ctx, existing); err != nil {
				h.logf("warn", "plugin quiesce failed for tag "+d.Tag)
			}
			replacement, err := h.loadOne(ctx, d)
			if err != nil {
				// Rollback: re-register the old image with
				// its old fragment.
				if rerr := h.register(ctx, existing, existing.desired); rerr != nil {
					h.fuse(d.Tag, "replacement failed and rollback failed: "+shortErr(rerr), existing.path)
					h.mu.Lock()
					delete(h.loaded, d.Tag)
					h.mu.Unlock()
					existing.client.Shutdown()
					h.maybeCloseEgress(existing.egress)
					report.Skipped = append(report.Skipped, Skipped{Tag: d.Tag, Reason: "replacement failed and rollback failed"})
				} else {
					report.Skipped = append(report.Skipped, Skipped{Tag: d.Tag, Reason: "replacement failed, rolled back to previous image"})
					report.Loaded = append(report.Loaded, d.Tag)
				}
				continue
			}
			// Shut the old image down before installing
			// the replacement, outside h.mu. The old
			// image's egress proxy is released once the
			// replacement is installed (kept when the
			// replacement shares the pointer).
			existing.client.Shutdown()
			h.mu.Lock()
			h.loaded[d.Tag] = replacement
			delete(h.fused, d.Tag)
			h.mu.Unlock()
			h.maybeCloseEgress(existing.egress)
			report.Loaded = append(report.Loaded, d.Tag)
			continue
		}
		// Fresh load.
		lp, err := h.loadOne(ctx, d)
		if err != nil {
			report.Skipped = append(report.Skipped, Skipped{Tag: d.Tag, Reason: shortErr(err)})
			continue
		}
		h.mu.Lock()
		h.loaded[d.Tag] = lp
		delete(h.fused, d.Tag)
		h.mu.Unlock()
		report.Loaded = append(report.Loaded, d.Tag)
	}
	return report
}

func shortErr(err error) string {
	if err == nil {
		return ""
	}
	// Skip reasons are rendered output: strip control
	// characters (including C1) BEFORE the cap/redact
	// path, so a plugin-chosen newline or escape in a
	// loader error can never forge a second output line
	// or inject a terminal sequence downstream. The cap
	// and redaction in safePluginText reintroduce no
	// control characters.
	return safePluginText(stripControlChars(err.Error()))
}

func (h *Host) fuse(tag, reason, path string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.fused == nil {
		h.fused = make(map[string]fusedEntry)
	}
	h.fused[tag] = fusedEntry{reason: reason, path: path}
}

// loadOne opens (the loader shadow-copies and compat-gates)
// and registers one desired plugin. On any failure the client
// is detached and the error returned.
//
// The glibc compat gate deliberately lives in the real
// loader, not here: it must run on the shadow-copy bytes
// about to be dlopened, and the host must stay usable with
// injected loaders whose paths are not files on disk. The
// unix loader checks CheckPluginCompat on the shadow path
// before dlopen, so every real load is gated exactly once,
// on the exact bytes loaded.
func (h *Host) loadOne(ctx context.Context, d Desired) (*loadedPlugin, error) {
	// Tag and type are validated at the Host layer with the
	// same regex as config/discovery BEFORE any filename
	// use: a tag like "../../evil" must never reach
	// ShadowCopy, and a path-like type must never be
	// trusted as a type name.
	if !validPluginID(d.Tag) {
		return nil, fmt.Errorf("invalid plugin tag %q", d.Tag)
	}
	if !validPluginID(d.Type) {
		return nil, fmt.Errorf("invalid plugin type %q", d.Type)
	}
	if d.Path == "" {
		return nil, fmt.Errorf("plugin %q has no binary path", d.Tag)
	}
	if d.ManifestPath != "" {
		if err := VerifyFileChecksum(d.Path, d.ManifestPath); err != nil {
			return nil, err
		}
	}
	file := File{ID: d.Tag, Path: d.Path, ManifestPath: d.ManifestPath}
	client, err := h.loader.Open(file, h)
	if err != nil {
		return nil, err
	}
	lp := &loadedPlugin{desired: d, client: client, path: d.Path}
	if err := h.register(ctx, lp, d); err != nil {
		client.Shutdown()
		return nil, err
	}
	return lp, nil
}

// sendRegistration marshals one register/reconfigure request
// (the fragment is sent verbatim; an empty fragment is sent
// as {} so the plugin never sees a JSON null) and returns
// the validated registration. register and reconfigure
// differ only in the method name and the error noun.
func (h *Host) sendRegistration(ctx context.Context, lp *loadedPlugin, method string, d Desired) (pluginabi.Registration, uint32, error) {
	fragment := cloneBytes(d.Fragment)
	if len(fragment) == 0 {
		fragment = []byte(`{}`)
	}
	req, err := json.Marshal(pluginabi.RegisterRequest{
		ConfigJSON:    json.RawMessage(fragment),
		SchemaVersion: pluginabi.SchemaVersion,
		Tag:           d.Tag,
		Type:          d.Type,
		Identity:      d.Identity,
		Egress:        d.Egress,
	})
	if err != nil {
		return pluginabi.Registration{}, 0, err
	}
	result, err := h.callEnvelope(ctx, lp, method, req, d.Tag)
	if err != nil {
		return pluginabi.Registration{}, 0, err
	}
	var reg pluginabi.Registration
	if err := json.Unmarshal(result, &reg); err != nil {
		return pluginabi.Registration{}, 0, fmt.Errorf("plugin %q registration is not valid json: %v", d.Tag, err)
	}
	schema, err := pluginabi.ValidateRegistration(reg)
	if err != nil {
		return pluginabi.Registration{}, 0, fmt.Errorf("plugin %q: %w", d.Tag, err)
	}
	return reg, schema, nil
}

// applyRegistration stores a validated registration on lp
// and applies its declared cookie hosts to the plugin's
// egress proxy, if any. Cookie scoping is fail-closed: no
// declaration means no injection. Registration fields are
// written under h.mu — the same mutex Loaded() reads them
// under and maybeCloseEgress scans lp.egress under — so a
// reconfigure cannot race a concurrent Loaded() or Call.
// The egress side effects (adoption, scope update, release
// of a superseded proxy) run after the lock is released:
// AdoptEgress and maybeCloseEgress take their own locks,
// and holding h.mu across them would deadlock.
func (h *Host) applyRegistration(lp *loadedPlugin, d Desired, reg pluginabi.Registration, schema uint32) {
	h.mu.Lock()
	lp.metadata = reg.Metadata
	lp.capabilities = reg.Capabilities
	lp.schema = schema
	lp.commands = append([]pluginabi.Command(nil), reg.Commands...)
	lp.desired = d
	lp.registered = true
	oldEgress := lp.egress
	if d.EgressProxy != nil {
		lp.egress = d.EgressProxy
	}
	egress := lp.egress
	h.mu.Unlock()
	if d.EgressProxy != nil {
		h.AdoptEgress(d.EgressProxy)
	}
	// Nil EgressProxy keeps the existing proxy (documented):
	// the new registration's cookie scope still applies to
	// it below.
	if egress != nil {
		egress.SetCookieHosts(reg.CookieHosts)
	}
	if oldEgress != nil && oldEgress != egress {
		h.maybeCloseEgress(oldEgress)
	}
}

// register sends plugin.register with the lifecycle request
// and applies the schema/metadata/capability gate (mirroring
// upstream registerRPCPlugin, rpc_client.go:100-118: request
// carries the host schema version; higher plugin schema
// rejected; missing schema becomes 1).
func (h *Host) register(ctx context.Context, lp *loadedPlugin, d Desired) error {
	reg, schema, err := h.sendRegistration(ctx, lp, pluginabi.MethodPluginRegister, d)
	if err != nil {
		return err
	}
	h.applyRegistration(lp, d, reg, schema)
	return nil
}

func (h *Host) reconfigure(ctx context.Context, lp *loadedPlugin, d Desired) error {
	reg, schema, err := h.sendRegistration(ctx, lp, pluginabi.MethodPluginReconfigure, d)
	if err != nil {
		return err
	}
	h.applyRegistration(lp, d, reg, schema)
	return nil
}

func (h *Host) quiesce(ctx context.Context, lp *loadedPlugin) error {
	_, err := h.callEnvelope(ctx, lp, pluginabi.MethodPluginQuiesce, []byte(`{}`), lp.desired.Tag)
	return err
}

func cloneBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// Call sends one envelope method call to a loaded plugin and
// returns the envelope Result on success. An envelope error
// becomes a Go error ("<code>: <message>"); a transport error,
// a host-adapter panic (recovered, plugin fused), or a context
// deadline (plugin fused, call abandoned) also becomes a Go
// error. The plugin never picks an exit code and its raw
// server bodies never reach output: only the envelope result
// or the envelope error is returned.
func (h *Host) Call(ctx context.Context, tag, method string, request []byte) ([]byte, error) {
	h.mu.Lock()
	lp, ok := h.loaded[tag]
	fuseEntry, isFused := h.fused[tag]
	var client Client
	var path string
	if ok && lp != nil {
		// Snapshot the client and path under h.mu: they
		// are immutable after loadOne, but no loadedPlugin
		// field is read outside the lock.
		client = lp.client
		path = lp.path
	}
	h.mu.Unlock()
	// A fused plugin is never re-called: fail fast with the
	// stored fuse reason instead of invoking the plugin
	// again. The fuse lasts until a different-path
	// ApplyConfig clears it — not until a deadline. A fused
	// tag with no loaded entry (rollback-failure deletion)
	// reports fused, not "not loaded": the distinction
	// matters, because a same-path load will skip.
	if isFused && (!ok || fuseEntry.path == path) {
		return nil, fmt.Errorf("plugin %q is fused: %s", tag, fuseEntry.reason)
	}
	if !ok || lp == nil || client == nil {
		return nil, fmt.Errorf("plugin %q is not loaded", tag)
	}
	return h.callEnvelopeClient(ctx, client, method, request, tag, path)
}

// callEnvelope is the guarded call for a loadedPlugin
// (registration, reconfigure, quiesce): lp.client and
// lp.path are immutable after loadOne, so reading them
// here cannot race applyRegistration's h.mu-guarded
// writes. Call uses callEnvelopeClient with a snapshot
// taken under h.mu instead.
func (h *Host) callEnvelope(ctx context.Context, lp *loadedPlugin, method string, request []byte, tag string) ([]byte, error) {
	return h.callEnvelopeClient(ctx, lp.client, method, request, tag, lp.path)
}

// callEnvelopeClient is the guarded call (mirroring upstream
// client_guard.go:80-115: the call runs in a goroutine, a
// recovered panic re-surfaces to the caller after the finish
// hook, and ctx cancellation abandons the call without killing
// the plugin thread). Here a recovered host-adapter panic
// fuses the plugin instead of re-panicking: the host boundary,
// not the CLI boundary, owns plugin panics.
func (h *Host) callEnvelopeClient(ctx context.Context, client Client, method string, request []byte, tag, path string) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	type callResult struct {
		response  []byte
		err       error
		recovered any
	}
	result := make(chan callResult, 1)
	go func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				result <- callResult{recovered: recovered}
			}
		}()
		response, err := client.Call(ctx, method, request)
		result <- callResult{response: response, err: err}
	}()
	select {
	case res := <-result:
		if res.recovered != nil {
			reason := fmt.Sprintf("%s panic: %T", method, res.recovered)
			h.fuse(tag, reason, path)
			return nil, fmt.Errorf("plugin %q: %s", tag, reason)
		}
		if res.err != nil {
			return nil, res.err
		}
		return parseEnvelope(res.response, tag)
	case <-ctx.Done():
		// The call is abandoned, not killed: the plugin
		// thread keeps running until it notices ctx. The
		// plugin is fused so no further call is attempted
		// on a hung image.
		h.fuse(tag, "call timed out or cancelled: "+method, path)
		return nil, ctx.Err()
	}
}

// parseEnvelope decodes one response envelope. A non-JSON or
// error envelope is an error; an ok envelope yields Result
// (nil when absent).
func parseEnvelope(response []byte, tag string) ([]byte, error) {
	var env pluginabi.Envelope
	if err := json.Unmarshal(response, &env); err != nil {
		return nil, fmt.Errorf("plugin %q returned invalid envelope: %v", tag, err)
	}
	if !env.OK {
		if env.Error != nil {
			// Both the code and the message are
			// plugin-chosen: strip controls from both
			// (safety N1) before the cap/redact path,
			// so a forged newline cannot create a
			// second output line downstream.
			return nil, fmt.Errorf("plugin %q: %s: %s", tag, stripControlChars(env.Error.Code), safePluginText(stripControlChars(env.Error.Message)))
		}
		return nil, fmt.Errorf("plugin %q returned a failed envelope without an error", tag)
	}
	return env.Result, nil
}

// isErrorEnvelope reports whether bytes decode as a failed
// envelope. The loader uses it to distinguish a plugin error
// envelope (rc != 0 with envelope bytes) from a transport
// failure, mirroring upstream isPluginErrorEnvelope.
func isErrorEnvelope(response []byte) bool {
	var env pluginabi.Envelope
	if err := json.Unmarshal(response, &env); err != nil {
		return false
	}
	return !env.OK && env.Error != nil
}

// --- Host reverse callbacks: host.log ONLY ---

// hostLogRequest is the JSON a plugin sends to host.log.
type hostLogRequest struct {
	Level   string `json:"level"`
	Message string `json:"message"`
}

// dispatchHostCall handles one reverse callback from a plugin.
// The allowlist has exactly one method, host.log. Everything
// else — including host.auth.*, host.http.*, host.model.* —
// is rejected with an error envelope. There is deliberately no
// host.auth.* surface: it would read the whole credential file
// (upstream auth_callbacks.go at pin 250d5981). The returned
// bytes are always an envelope.
func (h *Host) dispatchHostCall(method string, request []byte) []byte {
	if method != pluginabi.MethodHostLog {
		env := pluginabi.NewErrorEnvelope("unsupported_host_callback", "unsupported host callback "+method)
		raw, _ := json.Marshal(env)
		return raw
	}
	var req hostLogRequest
	if err := json.Unmarshal(request, &req); err != nil {
		env := pluginabi.NewErrorEnvelope("invalid_host_log_request", "decode host log request: "+err.Error())
		raw, _ := json.Marshal(env)
		return raw
	}
	message := strings.TrimSpace(req.Message)
	if message == "" {
		message = "plugin log"
	}
	// Strip control characters so a plugin log line cannot
	// inject terminal control sequences or forge a second
	// log line in host output: newline/CR/tab become a
	// space, other C0 controls and DEL are dropped. Then
	// the message goes through the same cap-before-redact
	// path as every other plugin-text surface (4096 with
	// marker, secret-keyed shapes redacted).
	message = stripControlChars(message)
	message = safePluginText(message)
	// The level is an allowlist, not free text: plugincheck
	// prints it raw, so a level carrying a newline or ESC
	// must never reach output as-is. Unknown levels become
	// "info".
	level := strings.ToLower(strings.TrimSpace(req.Level))
	switch level {
	case "info", "warn", "warning", "error", "debug":
		// Keep, normalising "warning" to "warn" below.
	default:
		level = "info"
	}
	if level == "warning" {
		level = "warn"
	}
	h.logf(level, message)
	raw, _ := json.Marshal(pluginabi.Envelope{OK: true, Result: json.RawMessage(`{}`)})
	return raw
}
