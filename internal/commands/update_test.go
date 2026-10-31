// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"testing"

	"github.com/thoitiettxl-cyber/castctl/internal/update"
)

// Slice 4 RED: `castctl update` CLI wiring through Env.UpdateDeps.
// UpdateDeps does not exist yet: these tests must fail to compile.

// setUpdateStamp stamps the package version vars for one test and
// restores them afterwards. No parallel test in this package reads
// these vars, so the mutation window is safe.
func setUpdateStamp(t *testing.T, version, commit, date string) {
	t.Helper()
	ov, oc, od := Version, Commit, BuildDate
	Version, Commit, BuildDate = version, commit, date
	t.Cleanup(func() { Version, Commit, BuildDate = ov, oc, od })
}

// buildCLI FakeBinary compiles the shared fake --version binary from
// the update package's testdata.
func buildCLIFakeBinary(t *testing.T) []byte {
	t.Helper()
	out := filepath.Join(t.TempDir(), "fakeversion")
	src := filepath.Join("..", "update", "testdata", "fakeversion", "main.go")
	cmd := exec.Command("go", "build", "-o", out, src)
	if bout, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build fakeversion: %v: %s", err, bout)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// cliReleaseServer is a minimal fake GitHub Releases server for CLI
// tests: one release (tag), one asset (tar bytes), checksums.txt.
type cliReleaseServer struct {
	t      *testing.T
	tag    string
	assets map[string][]byte
	mu     sync.Mutex
	counts map[string]int
	srv    *httptest.Server
}

func newCLIReleaseServer(t *testing.T, tag string, tarBytes []byte) *cliReleaseServer {
	t.Helper()
	assetName := "castctl_0.6.4_linux_amd64.tar.gz"
	s := &cliReleaseServer{
		t:      t,
		tag:    tag,
		assets: map[string][]byte{assetName: tarBytes},
		counts: map[string]int{},
	}
	// checksums.txt over the asset.
	sum := sha256.Sum256(tarBytes)
	s.assets["checksums.txt"] = []byte(hex.EncodeToString(sum[:]) + "  " + assetName + "\n")
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *cliReleaseServer) count(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.counts[path]++
}

func (s *cliReleaseServer) total() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, c := range s.counts {
		n += c
	}
	return n
}

func (s *cliReleaseServer) serve(w http.ResponseWriter, r *http.Request) {
	s.count(r.URL.Path)
	if strings.HasPrefix(r.URL.Path, "/repos/") {
		type asset struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
			Size int64  `json:"size"`
			State string `json:"state"`
		}
		var assets []asset
		names := []string{"castctl_0.6.4_linux_amd64.tar.gz", "checksums.txt"}
		for _, name := range names {
			assets = append(assets, asset{
				Name: name, URL: s.srv.URL + "/dl/" + name,
				Size: int64(len(s.assets[name])), State: "uploaded",
			})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tag_name": s.tag, "draft": false, "prerelease": false, "assets": assets,
		})
		return
	}
	if strings.HasPrefix(r.URL.Path, "/dl/") {
		name := strings.TrimPrefix(r.URL.Path, "/dl/")
		body, ok := s.assets[name]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write(body)
		return
	}
	w.WriteHeader(http.StatusNotFound)
}

func buildCLITar(t *testing.T, bin []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, m := range []struct {
		name string
		body []byte
	}{
		{"castctl", bin},
		{"LICENSE", []byte("license")},
	} {
		if err := tw.WriteHeader(&tar.Header{Name: m.name, Mode: 0o755, Size: int64(len(m.body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(m.body); err != nil {
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

func cliDeps(t *testing.T, srv *cliReleaseServer, exe string) *update.Deps {
	t.Helper()
	return &update.Deps{
		HTTPClient: srv.srv.Client(),
		Executable: exe,
		BuildInfo: &debug.BuildInfo{Settings: []debug.BuildSetting{
			{Key: "CGO_ENABLED", Value: "1"},
		}},
		APIBase:    srv.srv.URL,
		GitHubBase: srv.srv.URL,
	}
}

func makeCLITarget(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	exe := filepath.Join(dir, "castctl")
	if err := os.WriteFile(exe, []byte("old-binary-bytes"), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir, exe
}

func TestUpdateHelp(t *testing.T) {
	out, errb := &bytes.Buffer{}, &bytes.Buffer{}
	env := &Env{Stdout: out, Stderr: errb}
	if code := Run(context.Background(), []string{"update", "--help"}, env); code != 0 {
		t.Fatalf("update --help: code=%d err=%q", code, errb.String())
	}
	for _, want := range []string{
		"usage: castctl update", "--dry-run", "--version", "--allow-downgrade",
		"--allow-prerelease", "checksums", "no signature",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("update help missing %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "PR5") || strings.Contains(out.String(), "not implemented") {
		t.Errorf("update help must not carry a deferred note:\n%s", out.String())
	}
}

func TestUpdateParserRejections(t *testing.T) {
	for _, args := range [][]string{
		{"update", "--bogus"},
		{"update", "extra"},
		{"update", "--version"},
		{"update", "--version=0.6.4", "extra"},
		{"update", "--dry-run=true"},
	} {
		out, errb := &bytes.Buffer{}, &bytes.Buffer{}
		env := &Env{Stdout: out, Stderr: errb}
		if code := Run(context.Background(), args, env); code != 2 {
			t.Errorf("%v: code=%d, want 2 (out=%q err=%q)", args, code, out.String(), errb.String())
		}
	}
}

func TestUpdateLiveAndDryRunViaCLI(t *testing.T) {
	setUpdateStamp(t, "0.6.3", "0807125", "2026-10-30T17:31:50Z")
	srv := newCLIReleaseServer(t, "v0.6.4", buildCLITar(t, buildCLIFakeBinary(t)))
	_, exe := makeCLITarget(t)
	out, errb := &bytes.Buffer{}, &bytes.Buffer{}
	env := &Env{Stdout: out, Stderr: errb, UpdateDeps: cliDeps(t, srv, exe)}
	if code := Run(context.Background(), []string{"update"}, env); code != 0 {
		t.Fatalf("update: code=%d err=%q", code, errb.String())
	}
	got, _ := os.ReadFile(exe)
	if string(got) == "old-binary-bytes" {
		t.Fatal("live update did not replace the binary")
	}
	if !strings.Contains(out.String(), "updated") {
		t.Errorf("live output %q must say updated", out.String())
	}
	// Dry-run on a fresh target: zero writes, clear report.
	_, exe2 := makeCLITarget(t)
	out.Reset()
	env2 := &Env{Stdout: out, Stderr: errb, UpdateDeps: cliDeps(t, srv, exe2)}
	if code := Run(context.Background(), []string{"update", "--dry-run"}, env2); code != 0 {
		t.Fatalf("update --dry-run: code=%d err=%q", code, errb.String())
	}
	got2, _ := os.ReadFile(exe2)
	if string(got2) != "old-binary-bytes" {
		t.Fatal("dry-run replaced the binary")
	}
	if !strings.Contains(out.String(), "would") {
		t.Errorf("dry-run output %q must say would", out.String())
	}
}

func TestUpdateExplicitVersionViaCLI(t *testing.T) {
	setUpdateStamp(t, "0.6.3", "0807125", "2026-10-30T17:31:50Z")
	srv := newCLIReleaseServer(t, "v0.6.4", buildCLITar(t, buildCLIFakeBinary(t)))
	_, exe := makeCLITarget(t)
	out, errb := &bytes.Buffer{}, &bytes.Buffer{}
	env := &Env{Stdout: out, Stderr: errb, UpdateDeps: cliDeps(t, srv, exe)}
	if code := Run(context.Background(), []string{"update", "--version", "0.6.4"}, env); code != 0 {
		t.Fatalf("update --version 0.6.4: code=%d err=%q", code, errb.String())
	}
	// Invalid explicit version: exit 2, zero requests.
	srv2 := newCLIReleaseServer(t, "v0.6.4", buildCLITar(t, buildCLIFakeBinary(t)))
	_, exe2 := makeCLITarget(t)
	out.Reset()
	env2 := &Env{Stdout: out, Stderr: errb, UpdateDeps: cliDeps(t, srv2, exe2)}
	if code := Run(context.Background(), []string{"update", "--version", "bogus"}, env2); code != 2 {
		t.Fatalf("update --version bogus: code=%d, want 2", code)
	}
	if srv2.total() != 0 {
		t.Errorf("invalid explicit version made %d requests, want 0", srv2.total())
	}
}

func TestUpdateDevRefusalViaCLI(t *testing.T) {
	// Default test-binary state is unstamped (Version 0.6.1,
	// Commit/BuildDate empty): update refuses without networking.
	srv := newCLIReleaseServer(t, "v0.6.4", buildCLITar(t, buildCLIFakeBinary(t)))
	_, exe := makeCLITarget(t)
	out, errb := &bytes.Buffer{}, &bytes.Buffer{}
	env := &Env{Stdout: out, Stderr: errb, UpdateDeps: cliDeps(t, srv, exe)}
	if code := Run(context.Background(), []string{"update"}, env); code != 2 {
		t.Fatalf("unstamped update: code=%d, want 2", code)
	}
	if !strings.Contains(errb.String(), "cannot determine") {
		t.Errorf("dev refusal stderr %q must say cannot determine", errb.String())
	}
	if srv.total() != 0 {
		t.Errorf("dev refusal made %d requests, want 0", srv.total())
	}
}

func TestUpdateInGlobalHelpAndUnknownChoice(t *testing.T) {
	out, errb := &bytes.Buffer{}, &bytes.Buffer{}
	env := &Env{Stdout: out, Stderr: errb}
	if code := Run(context.Background(), []string{"--help"}, env); code != 0 {
		t.Fatalf("--help: code=%d", code)
	}
	if !strings.Contains(out.String(), "update") || strings.Contains(out.String(), "carried to PR5") {
		t.Errorf("global help must list update as wired:\n%s", out.String())
	}
	out.Reset()
	if code := Run(context.Background(), []string{"frobnicate"}, env); code != 2 {
		t.Fatalf("unknown command: code=%d, want 2", code)
	}
	if !strings.Contains(errb.String(), "update") {
		t.Errorf("unknown-choice message must list update: %q", errb.String())
	}
}
