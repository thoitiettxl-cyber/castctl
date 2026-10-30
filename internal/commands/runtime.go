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
	"net/http"
	"net/netip"
	"os"
	"reflect"
	"sort"
	"strings"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/dns"
	"github.com/thoitiettxl-cyber/castctl/internal/gateway"
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
	DNS      *dns.Client // nil when the config has no DNS section
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
// running. Sing-box internal logs are discarded (NOP factory) so
// command output stays clean JSON/text; sing-box failures surface
// as returned errors.
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

	mgr, err := outbound.NewManager(ctx, log.NewNOPFactory().NewLogger("castctl"))
	if err != nil {
		return nil, errCode(2, err)
	}
	rt.Manager = mgr
	rt.closeFuncs = append(rt.closeFuncs, func() error { return mgr.Close() })

	// DNS: build and register BEFORE creating outbounds.
	var dnsClient *dns.Client
	if single != nil {
		dnsOpts, err := single.ParsedDNS()
		if err != nil {
			return fail(errCode(2, err))
		}
		if dnsOpts != nil {
			dnsClient, err = dns.New(mgr.Context(), *dnsOpts, mgr.OutboundManager())
			if err != nil {
				return fail(errCode(2, err))
			}
			rt.DNS = dnsClient
			rt.closeFuncs = append(rt.closeFuncs, func() error { return dnsClient.Close() })
			mgr.RegisterDNS(dnsClient.Router(), dnsClient.TransportManager())
		}
	}

	// Endpoints and outbounds, detour-first (topological order).
	if err := createOutbounds(ctx, mgr, single, prof); err != nil {
		return fail(err)
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
	connector := env.newConnector(dialer)
	var muse *conn.Muse
	if env.Logger != nil {
		muse = conn.New(connector, conn.WithConfig(cfg), conn.WithLogger(env.Logger))
	} else {
		muse = conn.New(connector, conn.WithConfig(cfg))
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
func createOutbounds(ctx context.Context, mgr *outbound.Manager, single *profile.SingleConfig, prof *profile.Profile) error {
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
	// "direct" outbound below is its only outbound. A layout
	// containing any legacy file never reaches here: LoadProfile
	// refuses it layout-wide (for every profile name) before the
	// runtime is built, so no legacy file is ever read here.
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
