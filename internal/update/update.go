// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package update

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Body and time limits. Every limit is a named constant with a
// both-sides fixture rationale in the failure report (§9): the real
// release JSON is a few KB, checksums.txt is ~416 bytes, archives are
// ~16 MB, and the downloaded binary's --version output is one line.
const (
	maxReleaseJSONBytes = 1 << 20
	maxAssetBytes       = 256 << 20
	maxExtractedBytes   = 256 << 20
	maxTarEntries       = 64
	maxExecOutputBytes  = 64 * 1024
)

// execCheckTimeout bounds the --version check of a downloaded binary.
const execCheckTimeout = 10 * time.Second

var (
	// metadataTimeout bounds release-metadata, checksums, and
	// redirect-probe requests. assetTimeout bounds the whole asset
	// download (a slow drip cannot hang the command past it).
	// Package vars so tests can inject short values.
	metadataTimeout = 60 * time.Second
	assetTimeout    = 10 * time.Minute
)

// updateMu serialises in-process concurrent Run calls (F-64). The
// inter-process flock (lock_unix.go) serialises separate processes.
var updateMu sync.Mutex

// Deps carries the injectable dependencies of an update run. Zero
// values select production behaviour. Tests set the fields to point
// at httptest servers, temp binaries, and synthetic build info; no
// test ever touches a real release or the real running binary.
type Deps struct {
	// HTTPClient, when non-nil, is cloned and used with the update
	// redirect policy (its Transport is preserved, so httptest TLS
	// servers keep working). Nil builds the production client.
	HTTPClient *http.Client
	// Executable overrides os.Executable. "" means os.Executable().
	Executable string
	// BuildInfo overrides debug.ReadBuildInfo. Nil means the real
	// build info of the running binary.
	BuildInfo *debug.BuildInfo
	// APIBase is the GitHub API root. "" means https://api.github.com.
	APIBase string
	// GitHubBase is the github.com root for the rate-limit fallback.
	// "" means https://github.com.
	GitHubBase string
}

// Options is the full input to one update run.
type Options struct {
	Deps
	// CurrentVersion is the stamped Version var ("0.6.3", no 'v').
	CurrentVersion string
	// Commit and BuildDate are the stamped vars. Both empty means an
	// unstamped/dev build, which always refuses (decision 1).
	Commit    string
	BuildDate string
	// TargetVersion, when set, is an explicit --version <tag> value
	// (parsed strictly; a leading 'v' is allowed).
	TargetVersion   string
	DryRun          bool
	AllowDowngrade  bool
	AllowPrerelease bool
	// Stdout receives the outcome report. Nil discards it.
	Stdout io.Writer
}

// Result describes what a run did.
type Result struct {
	Current    Version
	Target     Version
	AssetName  string
	TargetPath string
	Replaced   bool
	DryRun     bool
}

// Error is an update failure with a fixed exit code. Its message is
// built only from constants, parsed versions, and constructed asset
// names: never from server bytes, URLs with query strings, or
// transport error text. The cause is preserved via Unwrap so the
// logging boundary (SummarizeErr) can find a body-carrying error's
// LogSummary through the chain.
type Error struct {
	code  int
	msg   string
	cause error
}

func (e *Error) Error() string { return e.msg }
func (e *Error) Unwrap() error { return e.cause }
func (e *Error) Code() int     { return e.code }

func newError(code int, msg string) *Error { return &Error{code: code, msg: msg} }

func wrapError(code int, msg string, cause error) *Error {
	return &Error{code: code, msg: msg, cause: cause}
}

// httpError summarises an HTTP failure as status + class + body
// length only (logging-PR rule): no body bytes, no URL query, no
// transport error text. It implements LogSummary so SummarizeErr
// renders this summary through any wrapper chain.
type httpError struct {
	op      string // GET
	host    string // host of the request URL, no port, no query
	path    string // path of the request URL
	status  int    // 0 when no response was received
	class   string // bounded vocabulary from classifyTransportError
	bodyLen int64
}

func (e *httpError) Error() string      { return e.summary() }
func (e *httpError) LogSummary() string { return e.summary() }

func (e *httpError) summary() string {
	if e.status > 0 {
		return fmt.Sprintf("update: %s %s%s failed (status=%d class=%s body_length=%d)",
			e.op, e.host, e.path, e.status, e.class, e.bodyLen)
	}
	return fmt.Sprintf("update: %s %s%s failed (class=%s body_length=%d)",
		e.op, e.host, e.path, e.class, e.bodyLen)
}

func requestHostPath(u *url.URL) (string, string) {
	return u.Hostname(), u.EscapedPath()
}

func classifyTransportError(err error) string {
	if err == nil {
		return "transport"
	}
	if errors.Is(err, errTooManyRedirects) || errors.Is(err, errRedirectForbidden) {
		return "redirect"
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "timeout"
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return classifyTransportError(urlErr.Err)
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "connection_refused"
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return "connection_reset"
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "dns"
	}
	if isTLSError(err) {
		return "tls"
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if opErr.Op == "dial" {
			return "dial"
		}
		return "transport"
	}
	return "transport"
}

func isTLSError(err error) bool {
	var unknownAuthority *x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthority) {
		return true
	}
	var certInvalid x509.CertificateInvalidError
	if errors.As(err, &certInvalid) {
		return true
	}
	var hostnameErr x509.HostnameError
	if errors.As(err, &hostnameErr) {
		return true
	}
	var recordErr tls.RecordHeaderError
	if errors.As(err, &recordErr) {
		return true
	}
	return false
}

// updater is one Run invocation's state.
type updater struct {
	opts   Options
	client *http.Client
	stdout io.Writer
}

func (u *updater) printf(format string, args ...any) {
	fmt.Fprintf(u.stdout, format+"\n", args...)
}

// Run performs one self-update. It never loads config, never writes
// state, and never uses credentials. Exit-code contract (see docs):
// 0 success / already-latest no-op / dry-run report; 2 usage and
// policy refusals decided without fetching bytes; 1 every fetch,
// verify, or replace failure.
func Run(ctx context.Context, opts Options) (Result, error) {
	updateMu.Lock()
	defer updateMu.Unlock()
	u := &updater{opts: opts, stdout: opts.Stdout}
	if u.stdout == nil {
		u.stdout = io.Discard
	}
	u.client = newUpdateClient(opts.Deps)
	return u.run(ctx)
}

func (u *updater) run(ctx context.Context) (Result, error) {
	opts := u.opts
	// 1. Dev/stamped check (decision 1): both empty refuses in ALL
	// modes, before any network or filesystem access.
	if opts.Commit == "" && opts.BuildDate == "" {
		return Result{}, newError(2, "update: cannot determine running version: this build was not stamped with commit and build date; refusing to guess the version")
	}
	current, err := ParseVersion(opts.CurrentVersion)
	if err != nil {
		return Result{}, newError(2, "update: cannot determine running version")
	}
	// 2. Flavour from build info (decision 2 probe result: the
	// CGO_ENABLED build setting distinguishes the two release
	// flavours under the exact release flags, including -s -w).
	flavour, ok := flavourFromBuildInfo(u.buildInfo())
	if !ok {
		return Result{}, newError(2, "update: cannot determine build flavour (glibc or no-plugin); refusing to guess")
	}
	// 3. Platform: release assets exist for Linux amd64/arm64 only.
	if runtime.GOOS != "linux" {
		return Result{}, newError(2, fmt.Sprintf("update: no release asset for %s/%s", runtime.GOOS, runtime.GOARCH))
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return Result{}, newError(2, fmt.Sprintf("update: no release asset for %s/%s", runtime.GOOS, runtime.GOARCH))
	}
	// 4. Resolve the target once; every later step uses the
	// resolved path. Symlinks are followed (the target file is
	// replaced, the symlink is preserved).
	target, targetMode, err := resolveTarget(opts.Executable)
	if err != nil {
		return Result{}, wrapError(1, "update: cannot resolve the running binary", err)
	}
	if targetMode&0o111 == 0 {
		return Result{}, newError(1, "update: the running binary is not executable; refusing to replace it")
	}
	res := Result{Current: current, TargetPath: target, DryRun: opts.DryRun}

	// 5. Select the target release (latest or explicit, with the
	// 403 fallback). This may return a no-op result.
	sel, err := u.selectRelease(ctx, current, flavour)
	if err != nil {
		return Result{}, err
	}
	if sel.noop {
		res.Target = sel.target
		u.printf("castctl is up to date: %s", current.String())
		return res, nil
	}
	res.Target = sel.target
	res.AssetName = sel.assetName

	if opts.DryRun {
		return u.dryRun(ctx, res, sel, target, targetMode)
	}
	return u.install(ctx, res, sel, target, targetMode)
}

func (u *updater) buildInfo() *debug.BuildInfo {
	if u.opts.BuildInfo != nil {
		return u.opts.BuildInfo
	}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return nil
	}
	return bi
}

// flavourFromBuildInfo maps the CGO_ENABLED build setting to the
// release flavour. The release workflow builds the glibc flavour
// with CGO_ENABLED=1 and the _no-plugin flavour with CGO_ENABLED=0
// and no other build setting differs (probe: go version -m on both
// flavours built with the exact release flags shows CGO_ENABLED as
// the only differing setting). Any other value, a missing setting,
// or conflicting duplicates mean "unknown": never guess.
func flavourFromBuildInfo(bi *debug.BuildInfo) (string, bool) {
	if bi == nil {
		return "", false
	}
	seen := false
	value := ""
	for _, s := range bi.Settings {
		if s.Key != "CGO_ENABLED" {
			continue
		}
		if seen && s.Value != value {
			return "", false
		}
		seen, value = true, s.Value
	}
	if !seen {
		return "", false
	}
	switch value {
	case "1":
		return "glibc", true
	case "0":
		return "no-plugin", true
	default:
		return "", false
	}
}

func (u *updater) apiBase() string {
	if u.opts.APIBase != "" {
		return strings.TrimSuffix(u.opts.APIBase, "/")
	}
	return "https://api.github.com"
}

func (u *updater) gitHubBase() string {
	if u.opts.GitHubBase != "" {
		return strings.TrimSuffix(u.opts.GitHubBase, "/")
	}
	return "https://github.com"
}

// --- HTTP client (decision 3) ---------------------------------------

var errTooManyRedirects = errors.New("update: too many redirects")
var errRedirectForbidden = errors.New("update: redirect to a host outside the release allowlist")

// newUpdateClient builds the update command's own stdlib client. It
// never uses http.DefaultClient (banned in internal/commands), sends
// no credentials, and never consults proxy environment variables
// (Proxy is nil: release downloads are public URLs, not profile
// traffic, and must not inherit ambient proxy settings).
func newUpdateClient(deps Deps) *http.Client {
	var c *http.Client
	if deps.HTTPClient != nil {
		clone := *deps.HTTPClient
		c = &clone
	} else {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.Proxy = nil
		tr.DialContext = (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext
		tr.TLSHandshakeTimeout = 10 * time.Second
		tr.ResponseHeaderTimeout = 30 * time.Second
		tr.ExpectContinueTimeout = time.Second
		c = &http.Client{Transport: tr}
	}
	c.CheckRedirect = checkRedirectPolicy
	c.Jar = nil
	c.Timeout = 0 // timeouts come from per-request contexts
	return c
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// checkRedirectPolicy: at most 5 hops, HTTPS only (HTTP only back to
// a loopback origin, for httptest), and the target host must be the
// origin host or one of github.com, release-assets.githubusercontent.com,
// objects.githubusercontent.com (the measured browser_download_url
// redirect target). Anything else aborts before dialing.
func checkRedirectPolicy(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errTooManyRedirects
	}
	host := req.URL.Hostname()
	if req.URL.Scheme != "https" {
		if !isLoopbackHost(host) {
			return errRedirectForbidden
		}
		if len(via) > 0 && via[0].URL.Scheme == "https" {
			return errRedirectForbidden // scheme downgrade
		}
	}
	if p := req.URL.Port(); p != "" && p != "443" && !isLoopbackHost(host) {
		return errRedirectForbidden
	}
	if len(via) > 0 && host == via[0].URL.Hostname() {
		return nil
	}
	switch host {
	case "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com":
		return nil
	default:
		return errRedirectForbidden
	}
}

func (u *updater) userAgent() string {
	return "castctl/" + u.opts.CurrentVersion
}

// fetchBytes GETs url with a per-request timeout and returns the
// body capped at capBytes. Non-200 responses return an httpError
// (status + class + body length only).
func (u *updater) fetchBytes(ctx context.Context, rawURL string, capBytes int64, timeout time.Duration) ([]byte, *httpError) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := u.newRequest(ctx, rawURL)
	if err != nil {
		return nil, &httpError{op: "GET", class: "request"}
	}
	resp, err := u.client.Do(req)
	if err != nil {
		host, path := "", ""
		if req.URL != nil {
			host, path = requestHostPath(req.URL)
		}
		return nil, &httpError{op: "GET", host: host, path: path, class: classifyTransportError(err)}
	}
	defer resp.Body.Close()
	host, path := requestHostPath(resp.Request.URL)
	if resp.StatusCode != http.StatusOK {
		n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		class := "http_error"
		switch {
		case resp.StatusCode == http.StatusNotFound:
			class = "not_found"
		case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests:
			class = "rate_limited"
		case resp.StatusCode >= 500:
			class = "server_error"
		}
		return nil, &httpError{op: "GET", host: host, path: path, status: resp.StatusCode, class: class, bodyLen: n}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, capBytes+1))
	if err != nil {
		return nil, &httpError{op: "GET", host: host, path: path, status: resp.StatusCode, class: classifyTransportError(err), bodyLen: int64(len(body))}
	}
	if int64(len(body)) > capBytes {
		return nil, &httpError{op: "GET", host: host, path: path, status: resp.StatusCode, class: "too_large", bodyLen: int64(len(body))}
	}
	return body, nil
}

func (u *updater) newRequest(ctx context.Context, rawURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", u.userAgent())
	req.Header.Set("Accept", "application/vnd.github+json")
	return req, nil
}

// downloadAsset streams url to w, hashing as it goes, enforcing the
// size cap and (when known) the expected byte count. It returns the
// sha256 digest of the exact bytes written.
func (u *updater) downloadAsset(ctx context.Context, rawURL string, expectedSize int64, w io.Writer) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, assetTimeout)
	defer cancel()
	req, err := u.newRequest(ctx, rawURL)
	if err != nil {
		return nil, wrapError(1, "update: invalid download URL", err)
	}
	// Downloads do not need the API Accept header.
	req.Header.Del("Accept")
	resp, err := u.client.Do(req)
	if err != nil {
		host, path := "", ""
		if req.URL != nil {
			host, path = requestHostPath(req.URL)
		}
		return nil, wrapError(1, "update: download failed", &httpError{op: "GET", host: host, path: path, class: classifyTransportError(err)})
	}
	defer resp.Body.Close()
	host, path := requestHostPath(resp.Request.URL)
	if resp.StatusCode != http.StatusOK {
		n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		class := "http_error"
		switch {
		case resp.StatusCode == http.StatusNotFound:
			class = "not_found"
		case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests:
			class = "rate_limited"
		case resp.StatusCode >= 500:
			class = "server_error"
		}
		return nil, wrapError(1, "update: download failed", &httpError{op: "GET", host: host, path: path, status: resp.StatusCode, class: class, bodyLen: n})
	}
	if expectedSize > 0 && resp.ContentLength >= 0 && resp.ContentLength != expectedSize {
		return nil, newError(1, "update: download size does not match the release metadata")
	}
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(w, hash), io.LimitReader(resp.Body, maxAssetBytes+1))
	if err != nil {
		return nil, wrapError(1, "update: download failed", &httpError{op: "GET", host: host, path: path, status: resp.StatusCode, class: classifyTransportError(err), bodyLen: n})
	}
	if n > maxAssetBytes {
		return nil, newError(1, "update: download exceeds the size limit")
	}
	if expectedSize > 0 && n != expectedSize {
		return nil, newError(1, "update: download size does not match the release metadata")
	}
	return hash.Sum(nil), nil
}

// --- Release selection (decision 4/5/6) -----------------------------

type releaseAsset struct {
	name  string
	url   string
	size  int64
	state string
}

type releaseInfo struct {
	tag        string
	draft      bool
	prerelease bool
	assets     []releaseAsset
}

type releaseJSON struct {
	TagName    string      `json:"tag_name"`
	Draft      bool        `json:"draft"`
	Prerelease bool        `json:"prerelease"`
	Assets     []assetJSON `json:"assets"`
}

type assetJSON struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
	State              string `json:"state"`
}

type selection struct {
	target       Version
	tag          string // canonical "v"+AssetVersion
	assetName    string
	assetURL     string
	assetSize    int64 // 0 when unknown (fallback mode)
	checksumsURL string
	noop         bool
}

func expectedAssetName(v Version, flavour, goarch string) string {
	suffix := ""
	if flavour == "no-plugin" {
		suffix = "_no-plugin"
	}
	return "castctl_" + v.AssetVersion() + "_linux_" + goarch + suffix + ".tar.gz"
}

func (u *updater) selectRelease(ctx context.Context, current Version, flavour string) (*selection, error) {
	if u.opts.TargetVersion != "" {
		return u.selectExplicit(ctx, current, flavour)
	}
	return u.selectLatest(ctx, current, flavour)
}

func (u *updater) selectExplicit(ctx context.Context, current Version, flavour string) (*selection, error) {
	target, err := ParseVersion(u.opts.TargetVersion)
	if err != nil {
		return nil, newError(2, "update: invalid --version value")
	}
	if target.HasBuild() {
		return nil, newError(2, "update: --version must not carry build metadata")
	}
	tag := "v" + target.AssetVersion()
	rel, status, ferr := u.fetchRelease(ctx, u.apiBase()+"/repos/thoitiettxl-cyber/castctl/releases/tags/"+tag)
	if ferr != nil {
		if status == http.StatusForbidden {
			return u.fallbackSelection(ctx, current, flavour, tag, target)
		}
		if status == http.StatusNotFound {
			return nil, newError(2, "update: no release exists for the requested version")
		}
		return nil, ferr
	}
	if rel.draft {
		return nil, newError(2, "update: the requested release is a draft")
	}
	if rel.prerelease && !u.opts.AllowPrerelease {
		return nil, newError(2, "update: the requested release is a prerelease; pass --allow-prerelease to install it")
	}
	return u.decide(ctx, current, flavour, rel, target, tag, false)
}

func (u *updater) selectLatest(ctx context.Context, current Version, flavour string) (*selection, error) {
	rel, status, ferr := u.fetchRelease(ctx, u.apiBase()+"/repos/thoitiettxl-cyber/castctl/releases/latest")
	if ferr != nil {
		if status == http.StatusForbidden {
			return u.fallbackLatest(ctx, current, flavour)
		}
		if status == http.StatusNotFound {
			return nil, newError(2, "update: no release found")
		}
		return nil, ferr
	}
	if rel.draft || rel.prerelease {
		return nil, newError(2, "update: the latest release is not a stable release; refusing to install it")
	}
	target, err := ParseVersion(rel.tag)
	if err != nil {
		return nil, newError(2, "update: the latest release tag is not a valid version")
	}
	if target.HasBuild() {
		return nil, newError(2, "update: the latest release tag carries build metadata; refusing to install it")
	}
	return u.decide(ctx, current, flavour, rel, target, "v"+target.AssetVersion(), false)
}

// decide applies the version policy and selects the exact asset.
func (u *updater) decide(ctx context.Context, current Version, flavour string, rel *releaseInfo, target Version, tag string, fallback bool) (*selection, error) {
	_ = ctx
	if cmp := CompareVersions(target, current); cmp < 0 && !u.opts.AllowDowngrade {
		return nil, newError(2, fmt.Sprintf("update: refusing downgrade from %s to %s; pass --allow-downgrade to install it", current.String(), target.String()))
	} else if cmp == 0 {
		return &selection{target: target, tag: tag, noop: true}, nil
	}
	sel := &selection{target: target, tag: tag}
	sel.assetName = expectedAssetName(target, flavour, runtime.GOARCH)
	if fallback {
		base := u.gitHubBase()
		sel.assetURL = base + "/thoitiettxl-cyber/castctl/releases/download/" + tag + "/" + sel.assetName
		sel.checksumsURL = base + "/thoitiettxl-cyber/castctl/releases/download/" + tag + "/checksums.txt"
		sel.assetSize = 0
		return sel, nil
	}
	asset, err := selectAsset(rel, sel.assetName)
	if err != nil {
		return nil, err
	}
	sel.assetURL = asset.url
	sel.assetSize = asset.size
	checksums, err := selectChecksumsAsset(rel)
	if err != nil {
		return nil, err
	}
	sel.checksumsURL = checksums.url
	return sel, nil
}

// selectAsset finds exactly one asset with the expected name.
// Zero or multiple matches fail closed; asset ordering is never trusted.
func selectAsset(rel *releaseInfo, expected string) (*releaseAsset, error) {
	var found *releaseAsset
	count := 0
	for i := range rel.assets {
		a := &rel.assets[i]
		if a.name != expected {
			continue
		}
		count++
		if a.state != "" && a.state != "uploaded" {
			return nil, newError(2, "update: the matching release asset is not uploaded")
		}
		if a.size <= 0 {
			return nil, newError(2, "update: the matching release asset has no usable size")
		}
		if err := validateDownloadURL(a.url); err != nil {
			return nil, newError(1, "update: the matching release asset has an unusable download URL")
		}
		found = a
	}
	if count == 0 {
		return nil, newError(2, "update: no release asset matches this platform and build flavour")
	}
	if count > 1 {
		return nil, newError(2, "update: ambiguous release assets: the asset name appears more than once")
	}
	return found, nil
}

func selectChecksumsAsset(rel *releaseInfo) (*releaseAsset, error) {
	var found *releaseAsset
	count := 0
	for i := range rel.assets {
		a := &rel.assets[i]
		if a.name != "checksums.txt" {
			continue
		}
		count++
		if err := validateDownloadURL(a.url); err != nil {
			return nil, newError(1, "update: the checksums file has an unusable download URL")
		}
		found = a
	}
	if count == 0 {
		return nil, newError(1, "update: the release has no checksums file; refusing to install without verification")
	}
	if count > 1 {
		return nil, newError(1, "update: ambiguous checksums files in the release")
	}
	return found, nil
}

// validateDownloadURL requires an absolute https URL, or http to a
// loopback host (httptest only). Relative, javascript:, file:, and
// other schemes never reach the network.
func validateDownloadURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return errors.New("invalid download URL")
	}
	if parsed.Scheme == "https" {
		return nil
	}
	if parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname()) {
		return nil
	}
	return errors.New("invalid download URL")
}

// fetchRelease GETs a release endpoint. It returns the release (or
// nil), the HTTP status (0 on transport failure), and an error.
// Callers decide the fallback on status 403 themselves.
func (u *updater) fetchRelease(ctx context.Context, rawURL string) (*releaseInfo, int, error) {
	body, herr := u.fetchBytes(ctx, rawURL, maxReleaseJSONBytes, metadataTimeout)
	if herr != nil {
		if herr.status != 0 {
			return nil, herr.status, wrapError(1, "update: failed to fetch release information", herr)
		}
		return nil, 0, wrapError(1, "update: failed to fetch release information", herr)
	}
	var decoded releaseJSON
	// Unmarshal (not a streaming Decoder) so trailing garbage after
	// the object is rejected; unknown fields are tolerated for
	// forward compatibility with new GitHub API fields.
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil, http.StatusOK, wrapError(1, "update: release information is malformed", err)
	}
	rel := &releaseInfo{tag: decoded.TagName, draft: decoded.Draft, prerelease: decoded.Prerelease}
	for _, a := range decoded.Assets {
		rel.assets = append(rel.assets, releaseAsset{name: a.Name, url: a.BrowserDownloadURL, size: a.Size, state: a.State})
	}
	return rel, http.StatusOK, nil
}

func decodeReleaseJSON(body []byte, out *releaseJSON) error {
	// Unmarshal (not a streaming Decoder) so trailing garbage after
	// the object is rejected, and unknown fields are tolerated for
	// forward compatibility with new GitHub API fields.
	return json.Unmarshal(body, out)
}

// fallbackLatest handles an API 403 on /latest: follow the public
// web redirect once to learn the tag, then construct asset URLs
// ONLY from the proven matrix pattern and verify checksums.txt as
// usual. If the fallback also fails, a clear rate-limit error.
func (u *updater) fallbackLatest(ctx context.Context, current Version, flavour string) (*selection, error) {
	tag, err := u.fallbackTag(ctx)
	if err != nil {
		return nil, err
	}
	target, err := ParseVersion(tag)
	if err != nil {
		return nil, newError(1, "update: GitHub API rate limit reached and the fallback could not determine a valid release tag; try again later")
	}
	if target.HasBuild() {
		return nil, newError(1, "update: GitHub API rate limit reached and the fallback release tag carries build metadata; try again later")
	}
	if target.Prerelease() != "" && !u.opts.AllowPrerelease {
		return nil, newError(2, "update: the latest release is a prerelease; pass --allow-prerelease to install it")
	}
	return u.decide(ctx, current, flavour, nil, target, "v"+target.AssetVersion(), true)
}

// fallbackSelection handles an API 403 on an explicit /tags/ fetch:
// the tag is already known, so asset URLs are constructed directly.
func (u *updater) fallbackSelection(ctx context.Context, current Version, flavour string, tag string, target Version) (*selection, error) {
	if target.Prerelease() != "" && !u.opts.AllowPrerelease {
		return nil, newError(2, "update: the requested release is a prerelease; pass --allow-prerelease to install it")
	}
	return u.decide(ctx, current, flavour, nil, target, tag, true)
}

// fallbackTag follows the public github.com/.../releases/latest
// redirect WITHOUT following it, and extracts the tag from the
// Location path. The redirect target is validated: it must stay on
// the github.com host (or the configured base host, for tests).
func (u *updater) fallbackTag(ctx context.Context) (string, error) {
	probe := *u.client
	probe.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	rawURL := u.gitHubBase() + "/thoitiettxl-cyber/castctl/releases/latest"
	ctx, cancel := context.WithTimeout(ctx, metadataTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", rateLimitError()
	}
	req.Header.Set("User-Agent", u.userAgent())
	resp, err := probe.Do(req)
	if err != nil {
		return "", rateLimitError()
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	switch resp.StatusCode {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
	default:
		return "", rateLimitError()
	}
	loc, err := resp.Location()
	if err != nil {
		return "", rateLimitError()
	}
	baseHost, _ := requestHostPath(mustParseURL(u.gitHubBase()))
	if loc.Hostname() != baseHost && loc.Hostname() != "github.com" {
		return "", rateLimitError()
	}
	idx := strings.LastIndex(loc.EscapedPath(), "/releases/tag/")
	if idx < 0 {
		return "", rateLimitError()
	}
	tag, err := url.PathUnescape(loc.EscapedPath()[idx+len("/releases/tag/"):])
	if err != nil || tag == "" || strings.Contains(tag, "/") {
		return "", rateLimitError()
	}
	return tag, nil
}

func rateLimitError() error {
	return newError(1, "update: GitHub API rate limit reached; try again later (unauthenticated API requests are limited to 60 per hour)")
}

func mustParseURL(raw string) *url.URL {
	parsed, err := url.Parse(raw)
	if err != nil {
		return &url.URL{}
	}
	return parsed
}

func resolveTarget(exeOverride string) (string, os.FileMode, error) {
	exe := exeOverride
	if exe == "" {
		var err error
		exe, err = os.Executable()
		if err != nil {
			return "", 0, err
		}
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return "", 0, err
	}
	fi, err := os.Stat(resolved)
	if err != nil {
		return "", 0, err
	}
	if !fi.Mode().IsRegular() {
		return "", 0, errors.New("target is not a regular file")
	}
	return resolved, fi.Mode().Perm(), nil
}
