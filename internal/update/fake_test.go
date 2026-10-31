// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
)

// Fake release-server harness for slice 2/3 tests. No network, no real
// binary path, no api.github.com/github.com calls: APIBase and
// GitHubBase both point at the httptest server.

// fakeAsset is one downloadable object served by the fake server.
type fakeAsset struct {
	body   []byte
	status int // 0 = 200
}

// fakeReleaseServer serves the GitHub Releases API shape plus the
// github.com download shape from one httptest server.
type fakeReleaseServer struct {
	t *testing.T

	tag        string
	draft      bool
	prerelease bool

	assets map[string]*fakeAsset // name -> asset (checksums.txt included)
	// latestJSON, when set, is served verbatim for the /latest API call.
	latestJSON   string
	latestStatus int
	// tagStatus, when set, overrides the status of /releases/tags/*.
	tagStatus int
	// latestRedirect, when set, makes the API /latest call redirect there.
	latestRedirect string
	// downloadRedirect, when set, makes asset downloads redirect there.
	downloadRedirect string
	// fallbackTag, when empty, makes the web /releases/latest probe 404.
	fallbackTag    string
	fallbackStatus int

	mu     sync.Mutex
	counts map[string]int
	// authSeen records non-empty Authorization headers received, for
	// the userinfo-URL regression test (loop 3): no request must
	// ever carry credentials derived from a download URL.
	authSeen []string
	srv      *httptest.Server
}

func newFakeReleaseServer(t *testing.T, tag string) *fakeReleaseServer {
	t.Helper()
	f := &fakeReleaseServer{
		t:           t,
		tag:         tag,
		assets:      map[string]*fakeAsset{},
		counts:      map[string]int{},
		fallbackTag: tag,
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeReleaseServer) count(path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.counts[path]++
}

func (f *fakeReleaseServer) getCount(prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for p, c := range f.counts {
		if strings.HasPrefix(p, prefix) {
			n += c
		}
	}
	return n
}

// authHeaderCount reports how many requests carried an Authorization
// header (loop-3 userinfo regression test).
func (f *fakeReleaseServer) authHeaderCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.authSeen)
}

func (f *fakeReleaseServer) serve(w http.ResponseWriter, r *http.Request) {
	f.count(r.URL.Path)
	if auth := r.Header.Get("Authorization"); auth != "" {
		f.mu.Lock()
		f.authSeen = append(f.authSeen, auth)
		f.mu.Unlock()
	}
	switch {
	case r.URL.Path == "/repos/thoitiettxl-cyber/castctl/releases/latest":
		if f.latestRedirect != "" {
			http.Redirect(w, r, f.latestRedirect, http.StatusFound)
			return
		}
		if f.latestJSON != "" {
			status := f.latestStatus
			if status == 0 {
				status = http.StatusOK
			}
			w.WriteHeader(status)
			fmt.Fprint(w, f.latestJSON)
			return
		}
		if f.latestStatus != 0 {
			w.WriteHeader(f.latestStatus)
			return
		}
		f.writeReleaseJSON(w, f.tag)
	case strings.HasPrefix(r.URL.Path, "/repos/thoitiettxl-cyber/castctl/releases/tags/"):
		if f.tagStatus != 0 {
			w.WriteHeader(f.tagStatus)
			fmt.Fprint(w, `{"message":"Not Found"}`)
			return
		}
		tag := strings.TrimPrefix(r.URL.Path, "/repos/thoitiettxl-cyber/castctl/releases/tags/")
		f.writeReleaseJSON(w, tag)
	case r.URL.Path == "/thoitiettxl-cyber/castctl/releases/latest":
		// Fallback redirect probe (web shape).
		if f.fallbackStatus != 0 {
			w.WriteHeader(f.fallbackStatus)
			return
		}
		if f.fallbackTag == "" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		http.Redirect(w, r, f.srv.URL+"/thoitiettxl-cyber/castctl/releases/tag/"+f.fallbackTag, http.StatusFound)
	case strings.Contains(r.URL.Path, "/releases/download/"):
		f.serveDownload(w, r)
	case strings.HasPrefix(r.URL.Path, "/download/"):
		f.serveDownload(w, r)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeReleaseServer) writeReleaseJSON(w http.ResponseWriter, tag string) {
	type asset struct {
		Name            string `json:"name"`
		BrowserDownload string `json:"browser_download_url"`
		Size            int64  `json:"size"`
		State           string `json:"state"`
	}
	var assets []asset
	names := []string{}
	for name := range f.assets {
		names = append(names, name)
	}
	// Deterministic order for stable JSON.
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			if names[j] < names[i] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
	for _, name := range names {
		a := f.assets[name]
		assets = append(assets, asset{
			Name:            name,
			BrowserDownload: f.srv.URL + "/download/" + tag + "/" + name,
			Size:            int64(len(a.body)),
			State:           "uploaded",
		})
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"tag_name":   tag,
		"draft":      f.draft,
		"prerelease": f.prerelease,
		"assets":     assets,
	})
}

func (f *fakeReleaseServer) serveDownload(w http.ResponseWriter, r *http.Request) {
	if f.downloadRedirect != "" {
		http.Redirect(w, r, f.downloadRedirect, http.StatusFound)
		return
	}
	name := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
	a, ok := f.assets[name]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"message":"Not Found"}`)
		return
	}
	status := a.status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write(a.body)
}

// setChecksums computes checksums.txt over the current asset bodies
// (excluding checksums.txt itself) in sha256sum format.
func (f *fakeReleaseServer) setChecksums() {
	names := []string{}
	for name := range f.assets {
		if name != "checksums.txt" {
			names = append(names, name)
		}
	}
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			if names[j] < names[i] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
	var b strings.Builder
	for _, name := range names {
		sum := sha256.Sum256(f.assets[name].body)
		fmt.Fprintf(&b, "%s  %s\n", hex.EncodeToString(sum[:]), name)
	}
	f.assets["checksums.txt"] = &fakeAsset{body: []byte(b.String())}
}

// buildTar returns a gzip tar archive with regular-file members.
func buildTar(t *testing.T, members map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	names := []string{}
	for name := range members {
		names = append(names, name)
	}
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			if names[j] < names[i] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
	for _, name := range names {
		body := members[name]
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o755, Size: int64(len(body)),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

var (
	fakeBinaryOnce sync.Once
	fakeBinaryPath string
	fakeBinaryErr  error
)

// fakeBinary returns a real amd64 ELF whose --version prints
// "castctl <CASTCTL_FAKE_VERSION>", built once from testdata.
func fakeBinary(t *testing.T) []byte {
	t.Helper()
	fakeBinaryOnce.Do(func() {
		dir, err := os.MkdirTemp("", "castctl-fakebin-*")
		if err != nil {
			fakeBinaryErr = err
			return
		}
		out := filepath.Join(dir, "fakeversion")
		src := filepath.Join("testdata", "fakeversion", "main.go")
		cmd := exec.Command("go", "build", "-o", out, src)
		cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod")
		if bout, err := cmd.CombinedOutput(); err != nil {
			fakeBinaryErr = fmt.Errorf("build fakeversion: %v: %s", err, bout)
			return
		}
		fakeBinaryPath = out
	})
	if fakeBinaryErr != nil {
		t.Fatal(fakeBinaryErr)
	}
	b, err := os.ReadFile(fakeBinaryPath)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// glibcBuildInfo is a synthetic BuildInfo for a glibc (CGO_ENABLED=1) build.
func glibcBuildInfo() *debug.BuildInfo {
	return &debug.BuildInfo{Settings: []debug.BuildSetting{
		{Key: "CGO_ENABLED", Value: "1"},
		{Key: "GOOS", Value: "linux"},
		{Key: "GOARCH", Value: "amd64"},
	}}
}

// noPluginBuildInfo is a synthetic BuildInfo for a _no-plugin build.
func noPluginBuildInfo() *debug.BuildInfo {
	return &debug.BuildInfo{Settings: []debug.BuildSetting{
		{Key: "CGO_ENABLED", Value: "0"},
		{Key: "GOOS", Value: "linux"},
		{Key: "GOARCH", Value: "amd64"},
	}}
}

// makeTarget creates a temp dir holding an "old" castctl binary and
// returns the dir and the binary path.
func makeTarget(t *testing.T) (dir, exe string) {
	t.Helper()
	dir = t.TempDir()
	exe = filepath.Join(dir, "castctl")
	if err := os.WriteFile(exe, []byte("old-binary-bytes"), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir, exe
}

// dirSnapshot lists dir entries (name -> sha256 of contents, or "dir").
func dirSnapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if e.IsDir() {
			out[e.Name()] = "dir"
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		out[e.Name()] = hex.EncodeToString(sum[:])
	}
	return out
}

func snapshotsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// stubExecCheck replaces the --version exec check with a no-op for
// tests whose target version differs from the fake binary's baked-in
// 0.6.4 report. The real exec check is covered by dedicated tests.
func stubExecCheck(t *testing.T) {
	t.Helper()
	prev := execCheckFn
	execCheckFn = func(ctx context.Context, path string, want Version) error { return nil }
	t.Cleanup(func() { execCheckFn = prev })
}
func (f *fakeReleaseServer) baseOptions(exe string) Options {
	return Options{
		Deps: Deps{
			HTTPClient: f.srv.Client(),
			Executable: exe,
			BuildInfo:  glibcBuildInfo(),
			APIBase:    f.srv.URL,
			GitHubBase: f.srv.URL,
		},
		CurrentVersion: "0.6.3",
		Commit:         "0807125",
		BuildDate:      "2026-10-30T17:31:50Z",
		Stdout:         &bytes.Buffer{},
	}
}

// codeOf extracts the exit code from an update error (0 if err == nil).
func codeOf(err error) int {
	if err == nil {
		return 0
	}
	var ue *Error
	if errors.As(err, &ue) {
		return ue.Code()
	}
	return 1
}
