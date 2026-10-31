// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build with_chromedp

package keeper

import (
	"context"
	"encoding/json"
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
	"github.com/chromedp/chromedp"
	"github.com/chromedp/chromedp/remote"
)

// CDP re-export (with_chromedp only): read the live session
// cookies from an already-running Chrome over the DevTools
// protocol, read-only.
//
// Discipline (§15.2/§15.4 as adopted): this file's path uses
// browser-level calls ONLY — Storage and Network cookie reads
// plus Browser version — and sends no Runtime/JS, no
// navigation, no input, no target creation/activation/
// closure, no Emulation. The browser is the user's own: the
// exporter attaches, reads, and detaches. It never kills,
// closes, or navigates anything.
//
// This "no Runtime" statement covers THIS file's browser-level
// path only. The ATTACH path in screencast.go goes through
// chromedp's target bootstrap, which DOES enable Runtime, DOM,
// CSS, Log, Inspector, and Page, sets
// Target.setDiscoverTargets and Target.setAutoAttach, enables
// Page.setLifecycleEventsEnabled, and evaluates the constant
// "self": see the bootstrap note in screencast.go, which lists
// the full observed method set. Do not shorten this comment
// back to a blanket claim.
//
// Discovery never goes through chromedp's unchecked
// remote.modifyURL path: /json/version is fetched with a
// typed decode in castctl code, and the allocator is given
// the full WebSocket URL with remote.NoModifyURL.

// CDPAvailable reports whether this build can re-export cookies
// from a browser over CDP.
func CDPAvailable() bool { return true }

// ExportURLs is the fallback Network.getCookies URL list: the
// Muse origins only. Browser-level Storage.getCookies is
// primary; this list is used only when it is unavailable
// against the browser, and only with these explicit URLs.
var ExportURLs = []string{"https://muse.ai/", "https://auth.muse.ai/"}

type cdpExporter struct{ browserURL string }

// NewCDPExporter returns an Exporter that attaches to the
// browser at browserURL (the keeper entry's `browser` value:
// an http:// loopback debug URL or a ws:// WebSocket URL).
func NewCDPExporter(browserURL string) Exporter { return cdpExporter{browserURL: browserURL} }

// Export attaches to the browser, reads all browser cookies,
// and returns them unfiltered: the tick applies the domain
// filter and the hatch_sess gate before any write. It performs
// no navigation, no input, and no target mutation.
func (e cdpExporter) Export(ctx context.Context) ([]ExportedCookie, error) {
	wsURL, err := DiscoverWebSocketURL(ctx, e.browserURL)
	if err != nil {
		return nil, err
	}
	allocCtx, cancelAlloc := remote.NewAllocator(ctx, wsURL, remote.NoModifyURL, remote.WithDialTimeout(10*time.Second))
	defer cancelAlloc()
	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx)
	defer cancelBrowser()

	// Primary: browser-level Storage.getCookies, no target
	// attach at all. It returns every cookie the browser
	// holds for the endpoint's contexts.
	if res, err := chromedp.CallBrowser(browserCtx, storage.GetCookies, storage.GetCookiesParams{}); err == nil {
		return fromNetworkCookies(res.Cookies), nil
	} else {
		// Fallback: Network.getCookies with explicit URLs,
		// only when the browser-level read is unavailable.
		// An empty URL list would mean "page + subframes",
		// which is NOT all cookies, so the list is explicit.
		fb, ferr := chromedp.CallBrowser(browserCtx, network.GetCookies, network.GetCookiesParams{URLs: ExportURLs})
		if ferr != nil {
			return nil, fmt.Errorf("cdp cookie read failed: storage: %v; network: %w", err, ferr)
		}
		return fromNetworkCookies(fb.Cookies), nil
	}
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
