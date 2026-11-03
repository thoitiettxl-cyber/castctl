// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build with_chromedp

package keeper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/storage"
	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"
	"github.com/chromedp/chromedp/remote"
)

// CDP re-export (with_chromedp only): read the live session
// cookies from an already-running Chrome over the DevTools
// protocol, read-only.
//
// Discipline (§15.2/§15.4 as adopted, K-LIVE-2 fix): the
// PRIMARY read is target-level — Network.getCookies on each
// open Muse page target (muse.ai, auth.muse.ai, www.muse.ai),
// merged and deduplicated. The FALLBACK is the browser-level
// read: Storage.getCookies, then Network.getCookies with
// explicit URLs. The browser-level Storage read is NOT
// trusted on its own: against Chrome 155 headless it succeeds
// with zero cookies while the browser holds a live session
// (measured 2026-11-03: browser-level Storage empty, Network
// error, target-level reads full), so an empty read at any
// level is a FAILED read, never a result — the exporter falls
// through to the next level. Only when every level yields
// empty with success does Export return an empty result, and
// the tick's validation gate decides (P1: an export with no
// usable filtered set still stops the entry).
//
// Attaching to a target runs chromedp's target bootstrap —
// the SAME bootstrap as the screencast attach path in
// screencast.go: it enables Runtime, Log, Network, Inspector,
// Page, DOM, and CSS on the target, sets
// Target.setDiscoverTargets and Target.setAutoAttach, enables
// Page.setLifecycleEventsEnabled, and evaluates the constant
// "self". Castctl's own code sends no Runtime/JS, no
// navigation, no input, no target creation/activation/
// closure, no Emulation. The browser is the user's own: the
// exporter attaches, reads, and detaches. It never kills,
// closes, or navigates anything. Do not shorten this comment
// back to a blanket claim.
//
// Discovery never goes through chromedp's unchecked
// remote.modifyURL path: /json/version and /json/list are
// fetched with typed decodes in castctl code, and the
// allocator is given the full WebSocket URL with
// remote.NoModifyURL.

// CDPAvailable reports whether this build can re-export cookies
// from a browser over CDP.
func CDPAvailable() bool { return true }

// ExportURLs is the explicit Network.getCookies URL list:
// the Muse origins only. An empty URL list would mean "page
// + subframes", which is NOT all cookies, so the list is
// explicit wherever Network.getCookies is used (target-level
// primary and browser-level fallback alike).
var ExportURLs = []string{"https://muse.ai/", "https://auth.muse.ai/"}

// errNoCookies is the internal empty-read signal: a CDP read
// that succeeded with zero cookies. It is never returned by
// Export itself; it only drives the fall-through between read
// levels (an empty read is a failed read, never a result).
var errNoCookies = errors.New("cdp read returned no cookies")

type cdpExporter struct{ browserURL string }

// NewCDPExporter returns an Exporter that attaches to the
// browser at browserURL (the keeper entry's `browser` value:
// an http:// loopback debug URL or a ws:// WebSocket URL).
func NewCDPExporter(browserURL string) Exporter { return cdpExporter{browserURL: browserURL} }

// Export attaches to the browser, reads the live session
// cookies, and returns them unfiltered: the tick applies the
// domain filter and the hatch_sess gate before any write. It
// performs no navigation, no input, and no target mutation.
//
// Read levels, in order (an empty read at any level is a
// failed read: the next level runs instead):
//
//  1. Target-level: Network.getCookies on each open Muse page
//     target (or the first page target of any URL when no Muse
//     page is open — the explicit URL list scopes the read),
//     merged and deduplicated.
//  2. Browser-level Storage.getCookies.
//  3. Browser-level Network.getCookies with explicit URLs.
//
// When every level yields empty with success, Export returns
// an empty result with a nil error and the tick's validation
// gate decides (P1: an export with no usable filtered set
// still stops the entry). When the reads fail, Export
// returns an error and the tick treats it as transient
// (export_failed: no stop, the next tick retries).
func (e cdpExporter) Export(ctx context.Context) ([]ExportedCookie, error) {
	wsURL, err := DiscoverWebSocketURL(ctx, e.browserURL)
	if err != nil {
		return nil, err
	}
	allocCtx, cancelAlloc := remote.NewAllocator(ctx, wsURL, remote.NoModifyURL, remote.WithDialTimeout(10*time.Second))
	defer cancelAlloc()

	// Level 1: target-level read. Any failure — no page target
	// at all, an attach error, an empty read — falls through
	// to the browser-level read below.
	cookies, targetErr := e.exportFromTargets(ctx, allocCtx)
	if targetErr == nil {
		return cookies, nil
	}
	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx)
	defer cancelBrowser()

	// Level 2: browser-level Storage.getCookies. A
	// successful read with cookies is the result; an
	// empty success falls through to level 3 (guard:
	// Storage can succeed empty while the browser
	// holds a live session).
	var storageErr error
	if res, serr := chromedp.CallBrowser(browserCtx, storage.GetCookies, storage.GetCookiesParams{}); serr == nil {
		if len(res.Cookies) > 0 {
			return fromNetworkCookies(res.Cookies), nil
		}
		storageErr = errNoCookies
	} else {
		storageErr = serr
	}

	// Level 3: browser-level Network.getCookies with
	// explicit URLs. Its result stands even when empty,
	// but ONLY when it succeeds: on real Chrome 155 the
	// browser-level Network call can error -32601, in
	// which case the joined error below is returned
	// instead. When it succeeds empty, every level agreed
	// empty, so the tick decides.
	fb, ferr := chromedp.CallBrowser(browserCtx, network.GetCookies, network.GetCookiesParams{URLs: ExportURLs})
	if ferr != nil {
		return nil, fmt.Errorf("cdp cookie read failed: target: %v; storage: %v; network: %w", targetErr, storageErr, ferr)
	}
	return fromNetworkCookies(fb.Cookies), nil
}

// exportHosts are the page hosts a cookie export may attach
// to: the Muse app and its auth subdomain only — the same set
// the screencast target resolver uses.
var exportHosts = map[string]bool{"muse.ai": true, "auth.muse.ai": true, "www.muse.ai": true}

// exportFromTargets reads Network.getCookies from the
// resolved page targets (every open Muse page, or the first
// page target when no Muse page is open) and merges the
// results, deduplicated by (name, domain, path). A per-target
// when another target yields cookies; when no target yields
// cookies it returns errNoCookies (targets existed but read
// empty) or the joined target errors (no target read at all).
// Either way the caller falls through to the browser-level
// read: a failed target read must never hide cookies the
// browser-level read can see.
func (e cdpExporter) exportFromTargets(ctx context.Context, allocCtx context.Context) ([]ExportedCookie, error) {
	httpBase, err := httpBaseFromBrowserURL(e.browserURL)
	if err != nil {
		return nil, err
	}
	ids, err := resolveExportTargets(ctx, httpBase)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var merged []ExportedCookie
	var errs []error
	for _, id := range ids {
		cookies, err := exportFromTarget(allocCtx, id)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, c := range cookies {
			key := c.Name + "\x00" + c.Domain + "\x00" + c.Path
			if seen[key] {
				continue
			}
			seen[key] = true
			merged = append(merged, c)
		}
	}
	if len(merged) > 0 {
		return merged, nil
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return nil, errNoCookies
}

// resolveExportTargets lists the browser's page targets from
// a typed /json/list decode and returns the IDs to read from,
// in list order: every open Muse page when any exists,
// otherwise the first page target of any URL. The fallback
// matters: Network.getCookies with the explicit URL list
// returns the browser's Muse cookies from ANY page target —
// even an about:blank tab (measured 2026-11-03) — so a
// browser whose Muse tab was closed still exports through
// the target level instead of depending on the flaky
// browser-level Storage read. The read itself is scoped to
// the Muse origins by the URL list, so attaching to a
// non-Muse tab exposes nothing about that tab. Zero page
// targets is an error: there is nothing to attach to.
// Titles are never read or logged (page titles are user
// content); only type and host decide.
func resolveExportTargets(ctx context.Context, httpBase string) ([]target.ID, error) {
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(httpBase, "/")+"/json/list", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("browser /json/list unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("browser /json/list returned status %d", resp.StatusCode)
	}
	var targets []listTarget
	dec := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	if err := dec.Decode(&targets); err != nil {
		return nil, fmt.Errorf("browser /json/list is not valid JSON: %w", err)
	}
	var ids []target.ID
	var firstPage target.ID
	for _, t := range targets {
		if t.Type != "page" || t.ID == "" {
			continue
		}
		if firstPage == "" {
			firstPage = target.ID(t.ID)
		}
		u, err := url.Parse(t.URL)
		if err != nil {
			continue
		}
		if exportHosts[strings.ToLower(u.Hostname())] {
			ids = append(ids, target.ID(t.ID))
		}
	}
	if len(ids) > 0 {
		return ids, nil
	}
	if firstPage != "" {
		return []target.ID{firstPage}, nil
	}
	return nil, errors.New("no page target is open in the attached browser")
}

// exportFromTarget attaches to one page target, reads
// Network.getCookies with the explicit URL list, and
// detaches on cancel. It sends no navigation, no input, and
// no target mutation; the attach itself runs chromedp's
// bootstrap (see the file header).
func exportFromTarget(allocCtx context.Context, id target.ID) ([]ExportedCookie, error) {
	tctx, cancel := chromedp.NewContext(allocCtx, chromedp.WithTargetID(id), chromedp.WithDetachOnCancel())
	defer cancel()
	res, err := chromedp.Call(tctx, network.GetCookies, network.GetCookiesParams{URLs: ExportURLs})
	if err != nil {
		return nil, fmt.Errorf("target cookie read failed: %w", err)
	}
	return fromNetworkCookies(res.Cookies), nil
}

func fromNetworkCookies(cookies []*network.Cookie) []ExportedCookie {
	out := make([]ExportedCookie, 0, len(cookies))
	for _, c := range cookies {
		if c == nil {
			continue
		}
		out = append(out, ExportedCookie{
			Name: c.Name, Value: c.Value, Domain: c.Domain, Path: c.Path,
			Expires: c.Expires, Secure: c.Secure, HTTPOnly: c.HTTPOnly, Session: c.Session,
		})
	}
	return out
}

// versionResponse is the TYPED decode of /json/version. The
// unchecked map + type-assertion path in chromedp's
// remote.modifyURL panics on a malformed payload; this struct
// turns the same payloads into errors. Only the field castctl
// needs is decoded; the rest is ignored.
type versionResponse struct {
	WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
}

// DiscoverWebSocketURL resolves a keeper `browser` URL to the
// browser WebSocket URL. An http:// loopback URL is resolved
// via a typed GET of /json/version; a ws:// URL is used as
// given (after loopback validation). The returned URL is
// always a loopback WebSocket URL: a version endpoint that
// answers with a remote or non-WebSocket URL is rejected
// fail-closed. No error here ever includes the URL's value
// beyond its scheme/host class: the URL is loopback config,
// not a secret, but the rule stays conservative.
func DiscoverWebSocketURL(ctx context.Context, browserURL string) (string, error) {
	raw := strings.TrimSpace(browserURL)
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid browser URL")
	}
	switch u.Scheme {
	case "ws":
		if err := validateLoopbackURL(u); err != nil {
			return "", err
		}
		return raw, nil
	case "http":
		// Fall through to /json/version discovery.
	default:
		return "", fmt.Errorf("browser URL scheme must be http or ws")
	}
	if err := validateLoopbackURL(u); err != nil {
		return "", err
	}
	versionURL := &url.URL{Scheme: "http", Host: u.Host, Path: "/json/version"}
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			// Loopback only, direct: never via a proxy.
			Proxy: nil,
			DialContext: (&net.Dialer{
				Timeout: 5 * time.Second,
			}).DialContext,
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, versionURL.String(), nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("browser /json/version unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("browser /json/version returned status %d", resp.StatusCode)
	}
	var ver versionResponse
	dec := json.NewDecoder(io.LimitReader(resp.Body, 64<<10))
	if err := dec.Decode(&ver); err != nil {
		return "", fmt.Errorf("browser /json/version is not valid JSON: %w", err)
	}
	if ver.WebSocketDebuggerURL == "" {
		return "", fmt.Errorf("browser /json/version has no webSocketDebuggerUrl")
	}
	wsURL, err := url.Parse(ver.WebSocketDebuggerURL)
	if err != nil {
		return "", fmt.Errorf("browser webSocketDebuggerUrl is unparseable")
	}
	if wsURL.Scheme != "ws" {
		return "", fmt.Errorf("browser webSocketDebuggerUrl scheme must be ws")
	}
	if err := validateLoopbackURL(wsURL); err != nil {
		return "", err
	}
	return ver.WebSocketDebuggerURL, nil
}

// validateLoopbackURL requires a loopback host, a port in
// range, and no userinfo — the same rules the config-time
// validator (profile.validateKeeperBrowserURL) enforces, so a
// URL the config accepted cannot fail here on a weaker rule
// and vice versa. It names the rule violated, never the URL
// value.
func validateLoopbackURL(u *url.URL) error {
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("browser URL has no host")
	}
	if u.User != nil {
		return fmt.Errorf("browser URL must not carry userinfo")
	}
	if u.Port() == "" {
		return fmt.Errorf("browser URL has no port")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("browser URL port out of range")
	}
	if ip := net.ParseIP(host); ip != nil {
		if !ip.IsLoopback() {
			return fmt.Errorf("browser URL host must be loopback")
		}
		return nil
	}
	if !strings.EqualFold(host, "localhost") {
		return fmt.Errorf("browser URL host must be loopback")
	}
	return nil
}
