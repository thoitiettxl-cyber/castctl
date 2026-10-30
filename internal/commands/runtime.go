// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"reflect"
	"sort"
	"strings"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/dns"
	"github.com/thoitiettxl-cyber/castctl/internal/gateway"
	"github.com/thoitiettxl-cyber/castctl/internal/logging"
	"github.com/thoitiettxl-cyber/castctl/internal/outbound"
	"github.com/thoitiettxl-cyber/castctl/internal/profile"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

// Runtime is the single wired path for every network-touching
// command: outbound manager + DNS client + dialer + gateway
// connector + conn.Muse, closed in reverse order. It is built once
// per invocation by defaultBuildRuntime and closed by the caller via
// Close, even on failure.
type Runtime struct {
	Profile  *profile.Profile
	Location *profile.ConfigLocation
	Single   *profile.SingleConfig // nil when no single config file exists
	Manager  *outbound.Manager
	DNS      *dns.Client // nil when no single config file exists (no resolver); with a single config file a resolver is always built (own, WireGuard, global-compat, or synthesised default)
	Dialer   *outbound.Dialer
	Muse     *conn.Muse

	// resolveFn, when non-nil, replaces Dialer.Resolve. It is a
	// test seam: tests inject a fake resolver through a
	// BuildRuntime override instead of standing up DNS.
	resolveFn func(ctx context.Context, domain string) ([]netip.Addr, error)
	// httpClientOverride, when non-nil, replaces
	// Dialer.HTTPClient(). Tests inject an httptest-backed client
	// through a BuildRuntime override or the Env hook.
	httpClientOverride *http.Client

	closeFuncs []func() error
}

// Resolve resolves a domain through the outbound's DNS router
// (Dialer.Resolve), or the injected test resolver when set.
func (r *Runtime) Resolve(ctx context.Context, domain string) ([]netip.Addr, error) {
	if r.resolveFn != nil {
		return r.resolveFn(ctx, domain)
	}
	return r.Dialer.Resolve(ctx, domain)
}

// Close releases resources in reverse build order: Muse, DNS client,
// manager (which closes outbounds/endpoints). Errors are joined;
// Close is idempotent.
func (r *Runtime) Close() error {
	var errs []error
	for i := len(r.closeFuncs) - 1; i >= 0; i-- {
		if err := r.closeFuncs[i](); err != nil {
			errs = append(errs, err)
		}
	}
	r.closeFuncs = nil
	return errors.Join(errs...)
}

// HTTPClient returns the outbound dialer's HTTP client, or the
// injected test client when set. All HTTPS in commands goes
// through it; http.DefaultClient is never used.
func (r *Runtime) HTTPClient() *http.Client {
	if r.httpClientOverride != nil {
		return r.httpClientOverride
	}
	return r.Dialer.HTTPClient()
}

// Cookies loads the profile's cookie header, requiring the file to
// exist and be non-empty first. Failures are typed auth errors
// (cookies_missing, exit 2) so dispatch never prints a cookie value
// and never exits 0 on failed auth.
func (r *Runtime) Cookies() (string, error) {
	if err := requireCookiesFile(r.Profile); err != nil {
		return "", err
	}
	cookies, err := gateway.LoadCookies(r.Profile.CookiesFile)
	if err != nil {
		var auth *conn.AuthError
		if errors.As(err, &auth) {
			return "", classifyAuthMessage(auth)
		}
		// LoadCookies returns *AuthError for unparseable cookies and
		// a plain error for a missing file; the file was just
		// checked, so treat any other failure as cookies_missing
		// rather than leaking internals.
		return "", &typedAuthError{Code: 2, Type: "cookies_missing", Err: err}
	}
	if strings.TrimSpace(cookies) == "" {
		return "", &typedAuthError{Code: 2, Type: "cookies_missing", Err: fmt.Errorf("cookies file %s is empty", r.Profile.CookiesFile)}
	}
	return cookies, nil
}

func requireCookiesFile(p *profile.Profile) error {
	info, err := os.Stat(p.CookiesFile)
	if err != nil {
		if os.IsNotExist(err) {
			return &typedAuthError{Code: 2, Type: "cookies_missing", Err: fmt.Errorf("no cookies at %s (run `castctl auth export` for guidance)", p.CookiesFile)}
		}
		return &typedAuthError{Code: 2, Type: "cookies_missing", Err: err}
	}
	if info.Size() == 0 {
		return &typedAuthError{Code: 2, Type: "cookies_missing", Err: fmt.Errorf("cookies file %s is empty", p.CookiesFile)}
	}
	return nil
}

// connectorConfig builds the conn.Config for the profile. (tag, hash)
// come from profile.OutboundIdentityForConfig when a single config
// exists, so edits to the referenced object change the identity;
// OutboundIdentity (fixed-shape hash) is only the fallback for
// invocations without a single config file (SourceNone profile).
func connectorConfig(prof *profile.Profile, single *profile.SingleConfig) (conn.Config, error) {
	tag, hash, err := identityForProfile(prof, single)
	if err != nil {
		return conn.Config{}, err
	}
	return conn.Config{
		CookiesFile:  prof.CookiesFile,
		VMID:         prof.VMID,
		NodeID:       prof.NodeID,
		OutboundTag:  tag,
		OutboundHash: hash,
	}, nil
}

func identityForProfile(prof *profile.Profile, single *profile.SingleConfig) (string, string, error) {
	if single != nil {
		tag, hash, err := profile.OutboundIdentityForConfig(single, prof.Name)
		if err != nil {
			return "", "", errCode(2, err)
		}
		return tag, hash, nil
	}
	tag, hash, err := profile.OutboundIdentity(prof)
	if err != nil {
		return "", "", errCode(2, err)
	}
	return tag, hash, nil
}

// defaultBuildRuntime wires manager + DNS + dialer + connector +
// conn.Muse for one invocation. Order is inviolable: DNS is
// registered before any outbound is created (F3 nil-router guard),
// detour chains are created before the outbounds that reference
// them (topological order over Detour fields), DNS Start runs before
// Manager.Start, and Manager.Start runs before any dial. No heartbeat
// is started: Python starts its heartbeat only on the wait/send/
// Telegram paths, never on the unary read commands this package
// implements, and conn.Muse.Close stops the heartbeat when it is
// running. Sing-box internal logs and castctl's own events go
// through the one resolved log factory (config `log` block,
// overridden by --log-level); sing-box failures also surface as
// returned errors.
func defaultBuildRuntime(ctx context.Context, loc *profile.ConfigLocation, prof *profile.Profile, env *Env) (*Runtime, error) {
	single, found, err := profile.LoadSingleConfig(loc.ConfigDir)
	if err != nil {
		return nil, errCode(2, err)
	}
	if !found {
		single = nil
	}

	rt := &Runtime{Profile: prof, Location: loc, Single: single}
	fail := func(err error) (*Runtime, error) {
		_ = rt.Close()
		return nil, err
	}

	// Logging: resolve the level once (CLI override > config >
	// warn) and build the single factory that governs every
	// emission below — sing-box's and castctl's. The factory is
	// closed last (prepended to closeFuncs, which run in
	// reverse order), so log lines emitted during shutdown of
	// the other components are not lost.
	var cliLevel string
	var cliSet bool
	var stderrWriter io.Writer
	if env != nil {
		cliLevel, cliSet = env.LogLevelOverride, env.LogLevelSet
		stderrWriter = env.stderr()
	}
	settings, err := profile.ResolveLogSettings(single, cliLevel, cliSet)
	if err != nil {
		return nil, errCode(2, err)
	}
	logHandle, err := logging.NewFactory(ctx, logging.Settings{
		Disabled:  settings.Disabled,
		Level:     settings.Level,
		Output:    settings.Output,
		Timestamp: settings.Timestamp,
	}, stderrWriter)
	if err != nil {
		return nil, errCode(2, err)
	}
	rt.closeFuncs = append([]func() error{func() error { return logHandle.Close() }}, rt.closeFuncs...)

	mgr, err := outbound.NewManager(ctx, logHandle.Logger("castctl"))
	if err != nil {
		return fail(errCode(2, err))
	}
	rt.Manager = mgr
	rt.closeFuncs = append(rt.closeFuncs, func() error { return mgr.Close() })

	// DNS: build and register BEFORE creating outbounds.
	// The resolver is per-profile (profile.ResolveProfileDNS):
	// own block, WireGuard-imported servers, global-compat
	// fallback, or the synthesised DoH default. Synthesised
	// runtime defaults are never written into the config file.
	// The synthesised direct tag (direct profiles' default, or
	// an own block detouring to it) is created in
	// createOutbounds below, before dnsClient.Start(), so the
	// detour resolves by Start time (detour init is lazy).
	var dnsClient *dns.Client
	var synthDirectTag string
	if single != nil {
		resolved, err := profile.ResolveProfileDNS(prof, single)
		if err != nil {
			return fail(errCode(2, err))
		}
		synthDirectTag = resolved.SynthesizedDirectTag
		if resolved.Warning != "" && env != nil {
			fmt.Fprintln(env.stderr(), resolved.Warning)
		}
		if resolved.Options != nil {
			dnsClient, err = dns.New(mgr.Context(), *resolved.Options, mgr.OutboundManager(), dns.WithLogFactory(logHandle.Factory))
			if err != nil {
				return fail(errCode(2, err))
			}
			rt.DNS = dnsClient
			rt.closeFuncs = append(rt.closeFuncs, func() error { return dnsClient.Close() })
			mgr.RegisterDNS(dnsClient.Router(), dnsClient.TransportManager())
			// DNS source chosen, at debug: the resolved source
			// and the first server's tag only — never the raw
			// options (which may carry credentials/detours).
			serverTag := "none"
			if len(resolved.Options.Servers) > 0 {
				serverTag = resolved.Options.Servers[0].Tag
				if serverTag == "" {
					serverTag = "unnamed"
				}
			}
			logging.Emit(logHandle.Logger("castctl"), context.Background(), log.LevelDebug,
				"event=dns_source source="+string(resolved.Source)+" server="+serverTag)
		}
	}

	// Endpoints and outbounds, detour-first (topological order).
	if err := createOutbounds(ctx, mgr, single, prof, synthDirectTag); err != nil {
		return fail(err)
	}

	// Outbound chain, at debug: the resolved detour chain for
	// the active profile, tags only (the same shape `profile
	// test` prints). Emitted only when the identity resolves;
	// a failure here is reported by the dialer setup below.
	if tag, _, err := identityForProfile(prof, single); err == nil {
		logging.Emit(logHandle.Logger("castctl"), context.Background(), log.LevelDebug,
			"event=outbound_chain profile="+prof.Name+" chain="+strings.Join(detourChain(single, tag), ","))
	}

	// DNS lifecycle before the manager lifecycle (the order used by
	// dns/client_test.go; Manager.Start runs the outbound stages).
	if dnsClient != nil {
		if err := dnsClient.Start(); err != nil {
			return fail(errCode(2, err))
		}
	}
	if err := mgr.Start(); err != nil {
		return fail(errCode(3, err))
	}

	// Dialer for the active profile's outbound (or the synthetic
	// direct outbound when the profile references an endpoint tag
	// directly: Manager.Dialer only resolves outbound tags, and the
	// synthetic outbound is created in createOutbounds, before
	// Start).
	tag, _, err := identityForProfile(prof, single)
	if err != nil {
		return fail(err)
	}
	dialTag := tag
	if _, ok := mgr.Outbound(dialTag); !ok {
		if _, ok := mgr.Endpoint(dialTag); ok {
			dialTag = dialerOutboundTag
		}
	}
	dialer, err := mgr.Dialer(dialTag)
	if err != nil {
		return fail(errCode(2, err))
	}
	rt.Dialer = dialer

	cfg, err := connectorConfig(prof, single)
	if err != nil {
		return fail(err)
	}
	if env.HTTPClient != nil {
		rt.httpClientOverride = env.HTTPClient()
	}
	connector := env.newConnector(dialer, gateway.WithLogger(logHandle.Logger("gateway")))
	var muse *conn.Muse
	if env.Logger != nil {
		muse = conn.New(connector, conn.WithConfig(cfg), conn.WithLogger(env.Logger))
	} else {
		// The slog world is bridged through the same factory:
		// conn's debug/info lines are filtered by the one
		// resolved level, and every line passes the SafeString
		// boundary in the bridge handler.
		muse = conn.New(connector, conn.WithConfig(cfg), conn.WithLogger(logHandle.SlogLogger("castctl")))
	}
	rt.Muse = muse
	rt.closeFuncs = append(rt.closeFuncs, func() error { muse.Close(); return nil })
	return rt, nil
}

// dialerOutboundTag is the tag of the synthetic direct outbound
// created when a profile's outbound reference is an endpoint tag
// (e.g. wireguard): endpoints cannot be dialled directly, only via
// an outbound that detours to them.
const dialerOutboundTag = "castctl-dialer"

// createOutbounds creates endpoints first, then outbounds in
// detour-first topological order. The guard rejection from
// CreateOutbound (domain-server outbound without a DNS router, or a
// detour cycle/missing detour) surfaces as exit 2 with a clear
// message; this wiring never silently reorders past the guard, it
// only orders creation so a well-formed chain succeeds. When no
// outbound carries the "direct" tag, an explicit direct outbound is
// created: the manager refuses an implicit direct fallback, but an
// explicit one created here is deliberate and visible.
// SynthesizedDirectOutbound builds the runtime-only direct
// outbound used as a DNS detour target for a direct profile.
// Gate-2 clearance (NOT a guard weakening): sing-box rejects a
// detour to an EMPTY direct outbound at transport Start
// (common/dialer/detour.go:69-76, sing-box v1.14.4: IsEmpty is
// computed in protocol/direct/outbound.go:75-77 as
// DeepEqual(DialerOptions, {UDPFragmentDefault: true})), and no
// DNS transport dialer sets DisableEmptyDirectCheck, so the only
// in-API clearance is a non-empty direct target. This outbound
// is made non-empty by exactly one explicit field,
// UDPFragment=false. That field affects only UDP packet dialing
// through this outbound; the outbound carries DNS-detour traffic
// only (never profile traffic, which dials through "direct"),
// and for the DoH default (TCP/TLS) it changes no dialing
// behaviour at all. The plain "direct" outbound is left empty,
// so a detour naming "direct" still fails exactly as before
// (pinned by internal/dns/gate2_test.go). The tag is
// per-profile (profile.SynthesizedDirectTag), created only in
// the active profile's own manager, so it cannot leak DNS
// between profiles.
func SynthesizedDirectOutbound() *option.DirectOutboundOptions {
	udpFragment := false
	opts := &option.DirectOutboundOptions{}
	opts.UDPFragment = &udpFragment
	return opts
}

func createOutbounds(ctx context.Context, mgr *outbound.Manager, single *profile.SingleConfig, prof *profile.Profile, synthDirectTag string) error {
	created := map[string]bool{}
	if single != nil {
		endpoints, err := single.ParsedEndpoints()
		if err != nil {
			return errCode(2, err)
		}
		for _, ep := range endpoints {
			if err := mgr.CreateEndpoint(ctx, ep.Tag, ep.Type, ep.Options); err != nil {
				return errCode(2, err)
			}
			created[ep.Tag] = true
		}
		outbounds, err := single.ParsedOutbounds()
		if err != nil {
			return errCode(2, err)
		}
		endpointTags := map[string]bool{}
		for _, ep := range endpoints {
			endpointTags[ep.Tag] = true
		}
		ordered, err := topoOrderOutbounds(outbounds, endpointTags)
		if err != nil {
			return errCode(2, err)
		}
		for _, ob := range ordered {
			if err := mgr.CreateOutbound(ctx, ob.Tag, ob.Type, ob.Options); err != nil {
				return errCode(2, err)
			}
			created[ob.Tag] = true
		}
	}
	// No single config file means no config-defined outbounds:
	// the profile is SourceNone (direct), and the explicit
	// "direct" outbound below is its only outbound. A load for a
	// name without a single-file entry in a layout containing any
	// legacy file never reaches here: LoadProfile refuses it
	// layout-wide for such names before the runtime is built, so
	// no legacy file is ever read here. A name WITH a
	// single-file entry loads wholly and does reach here.
	// Synthetic dialer outbound for direct endpoint references,
	// created BEFORE Start (see defaultBuildRuntime).
	if tag, _, err := identityForProfile(prof, single); err == nil {
		if _, ok := mgr.Outbound(tag); !ok {
			if _, ok := mgr.Endpoint(tag); ok && !created[dialerOutboundTag] {
				direct := &option.DirectOutboundOptions{}
				direct.Detour = tag
				if err := mgr.CreateOutbound(ctx, dialerOutboundTag, "direct", direct); err != nil {
					return errCode(2, err)
				}
				created[dialerOutboundTag] = true
			}
		}
	}
	if !created["direct"] {
		if err := mgr.CreateOutbound(ctx, "direct", "direct", &option.DirectOutboundOptions{}); err != nil {
			return errCode(2, err)
		}
		created["direct"] = true
	}
	// Runtime-only per-profile direct detour target for the
	// active profile's DNS (direct-profile default DoH, or an
	// own dns block detouring to it). Created after the plain
	// "direct" outbound and before dnsClient.Start() (the caller
	// starts DNS after this function returns), so the detour
	// resolves at Start. Never a config tag: validation accepts
	// it only as a direct profile's own reachable detour, and
	// parse time rejects any config tag carrying the reserved
	// castctl-direct: prefix. Defence in depth: if the tag is
	// nevertheless already taken (e.g. a SingleConfig built
	// without going through parse), FAIL LOUDLY — never silently
	// skip creation and let the DNS detour dial the colliding
	// config outbound.
	if synthDirectTag != "" {
		if created[synthDirectTag] {
			return errCode(2, fmt.Errorf("synthesised direct outbound tag %q is already taken by a config outbound or endpoint; the castctl-direct: prefix is reserved, rename the config tag", synthDirectTag))
		}
		if err := mgr.CreateOutbound(ctx, synthDirectTag, "direct", SynthesizedDirectOutbound()); err != nil {
			return errCode(2, err)
		}
		created[synthDirectTag] = true
	}
	return nil
}

// topoOrderOutbounds sorts outbounds so every Detour target is
// created before the outbound that references it. File order is
// preserved otherwise (stable). A missing detour or a cycle is an
// error: the F3 guard would refuse the chain anyway, and surfacing
// it here names the tag.
//
// endpointTags are the single config's endpoint tags: a detour
// naming an endpoint (e.g. socks -> WireGuard endpoint) is valid
// — endpoints are created before outbounds, and sing-box's
// Outbound() falls back to endpoint lookup — so endpoint detour
// targets are leaves in this ordering, not errors. The detour
// guard semantics (detour-before-outer, allow-list) are unchanged:
// only the known-tag set grows. A nil endpointTags set means no
// endpoints exist.
func topoOrderOutbounds(obs []option.Outbound, endpointTags map[string]bool) ([]option.Outbound, error) {
	byTag := map[string]option.Outbound{}
	for _, ob := range obs {
		byTag[ob.Tag] = ob
	}
	const (
		white = iota
		grey
		black
	)
	color := map[string]int{}
	var ordered []option.Outbound
	var visit func(ob option.Outbound) error
	visit = func(ob option.Outbound) error {
		switch color[ob.Tag] {
		case grey:
			return fmt.Errorf("outbound detour cycle involving tag %q", ob.Tag)
		case black:
			return nil
		}
		color[ob.Tag] = grey
		if detour := outboundDetour(ob); detour != "" {
			if endpointTags[detour] {
				// Endpoint detour target: created before
				// outbounds; a leaf, not a cycle candidate.
			} else if target, ok := byTag[detour]; ok {
				if err := visit(target); err != nil {
					return err
				}
			} else {
				return fmt.Errorf("outbound %q has detour %q that is not defined in the config", ob.Tag, detour)
			}
		}
		color[ob.Tag] = black
		ordered = append(ordered, ob)
		return nil
	}
	for _, ob := range obs {
		if err := visit(ob); err != nil {
			return nil, err
		}
	}
	return ordered, nil
}

// outboundDetour returns the detour tag of an outbound, "" when it
// has none. The Detour field lives in the embedded DialerOptions, so
// it is read reflectively (the same promotion walk
// outbound.describeOutbound uses), on the parsed Options value.
func outboundDetour(ob option.Outbound) string {
	v := reflect.ValueOf(ob.Options)
	for v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return ""
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return ""
	}
	if f := v.FieldByName("Detour"); f.IsValid() && f.Kind() == reflect.String {
		return f.String()
	}
	return ""
}

// detourChain returns the detour chain starting at tag, following
// Detour fields through the single config's outbounds. Used by
// `profile test` output. Cycles and missing tags terminate the
// chain; the chain always starts with tag itself.
func detourChain(single *profile.SingleConfig, tag string) []string {
	chain := []string{tag}
	if single == nil || tag == "" || tag == "direct" {
		return chain
	}
	obs, err := single.ParsedOutbounds()
	if err != nil {
		return chain
	}
	byTag := map[string]option.Outbound{}
	for _, ob := range obs {
		byTag[ob.Tag] = ob
	}
	seen := map[string]bool{tag: true}
	cur := tag
	for {
		ob, ok := byTag[cur]
		if !ok {
			break
		}
		next := outboundDetour(ob)
		if next == "" || seen[next] {
			break
		}
		seen[next] = true
		chain = append(chain, next)
		cur = next
	}
	return chain
}

// tempNodeID generates an in-memory node id for profiles whose
// config has none. It is never written to disk: LoadProfile does not
// generate node ids on read (only `config migrate --write` does).
func tempNodeID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}

// sortedKeys returns the sorted keys of m (for deterministic
// iteration over decoded JSON objects).
func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
