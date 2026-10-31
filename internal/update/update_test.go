// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package update

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
)

// Slice 2 RED: release selection, HTTP client, flavour, dev refusal,
// orchestration. Run/Options/Deps/Error do not exist yet.

func runUpdate(t *testing.T, opts Options) (Result, error) {
	t.Helper()
	return Run(context.Background(), opts)
}

func TestDevBuildRefusesInAllModes(t *testing.T) {
	// Decision 1: unstamped builds refuse in ALL modes, without
	// touching the network (D-14, failure-report).
	f := newFakeReleaseServer(t, "v0.6.4")
	_, exe := makeTarget(t)
	modes := []Options{
		f.baseOptions(exe), // latest
	}
	dry := f.baseOptions(exe)
	dry.DryRun = true
	modes = append(modes, dry)
	explicit := f.baseOptions(exe)
	explicit.TargetVersion = "0.6.4"
	modes = append(modes, explicit)
	for i, opts := range modes {
		opts.Commit, opts.BuildDate = "", ""
		before := dirSnapshot(t, filepath.Dir(exe))
		_, err := runUpdate(t, opts)
		if err == nil {
			t.Fatalf("mode %d: want dev refusal error", i)
		}
		if codeOf(err) != 2 {
			t.Errorf("mode %d: code=%d, want 2", i, codeOf(err))
		}
		if !strings.Contains(err.Error(), "cannot determine") {
			t.Errorf("mode %d: error %q must say cannot determine", i, err.Error())
		}
		if !snapshotsEqual(before, dirSnapshot(t, filepath.Dir(exe))) {
			t.Errorf("mode %d: directory changed on refusal", i)
		}
	}
	if got := f.getCount("/repos/"); got != 0 {
		t.Errorf("dev refusal made %d API requests, want 0", got)
	}
}

func TestAlreadyLatestNoOp(t *testing.T) {
	f := newFakeReleaseServer(t, "v0.6.3")
	_, exe := makeTarget(t)
	before := dirSnapshot(t, filepath.Dir(exe))
	opts := f.baseOptions(exe)
	var stdout bytes.Buffer
	opts.Stdout = &stdout
	res, err := runUpdate(t, opts)
	if err != nil {
		t.Fatalf("already-latest: %v", err)
	}
	if res.Replaced {
		t.Error("already-latest must not replace")
	}
	if !snapshotsEqual(before, dirSnapshot(t, filepath.Dir(exe))) {
		t.Error("already-latest changed the directory")
	}
	if got := f.getCount("/download/"); got != 0 {
		t.Errorf("already-latest downloaded %d assets, want 0", got)
	}
	if out := stdout.String(); !strings.Contains(out, "up to date") {
		t.Errorf("already-latest output %q must say up to date", out)
	}
}

func TestNewerVersionInstalls(t *testing.T) {
	f := newFakeReleaseServer(t, "v0.6.4")
	assetName := "castctl_0.6.4_linux_amd64.tar.gz"
	f.assets[assetName] = &fakeAsset{body: buildTar(t, map[string][]byte{
		"castctl": fakeBinary(t),
		"LICENSE": []byte("license"),
	})}
	f.setChecksums()
	_, exe := makeTarget(t)
	oldMode := func() os.FileMode {
		fi, err := os.Stat(exe)
		if err != nil {
			t.Fatal(err)
		}
		return fi.Mode().Perm()
	}()
	opts := f.baseOptions(exe)
	var stdout bytes.Buffer
	opts.Stdout = &stdout
	res, err := runUpdate(t, opts)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if !res.Replaced {
		t.Error("install must report Replaced")
	}
	if res.AssetName != assetName {
		t.Errorf("AssetName = %q, want %q", res.AssetName, assetName)
	}
	got, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, fakeBinary(t)) {
		t.Error("target was not replaced with the downloaded binary")
	}
	if fi, err := os.Stat(exe); err != nil || fi.Mode().Perm() != oldMode {
		t.Errorf("installed mode = %v, want old mode %v preserved", fi.Mode(), oldMode)
	}
	// No temp or lock litter beyond the lock file itself.
	ents, _ := os.ReadDir(filepath.Dir(exe))
	for _, e := range ents {
		if strings.Contains(e.Name(), ".castctl-update-") || strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("leftover temp file %q", e.Name())
		}
	}
	if !strings.Contains(stdout.String(), "0.6.3") || !strings.Contains(stdout.String(), "0.6.4") {
		t.Errorf("success output %q must name old and new versions", stdout.String())
	}
}

func TestDowngradeRefusedByDefault(t *testing.T) {
	f := newFakeReleaseServer(t, "v0.6.2")
	_, exe := makeTarget(t)
	before := dirSnapshot(t, filepath.Dir(exe))
	_, err := runUpdate(t, f.baseOptions(exe))
	if err == nil {
		t.Fatal("downgrade: want error")
	}
	if codeOf(err) != 2 {
		t.Errorf("downgrade code=%d, want 2", codeOf(err))
	}
	if !snapshotsEqual(before, dirSnapshot(t, filepath.Dir(exe))) {
		t.Error("downgrade changed the directory")
	}
	if got := f.getCount("/download/"); got != 0 {
		t.Errorf("downgrade downloaded %d assets, want 0", got)
	}
	// Explicit --allow-downgrade installs the older release. The
	// fake binary reports 0.6.4, so the exec check is stubbed here;
	// version reporting is covered by dedicated exec tests.
	stubExecCheck(t)
	f.assets["castctl_0.6.2_linux_amd64.tar.gz"] = &fakeAsset{body: buildTar(t, map[string][]byte{
		"castctl": fakeBinary(t),
	})}
	f.setChecksums()
	opts := f.baseOptions(exe)
	opts.AllowDowngrade = true
	if _, err := runUpdate(t, opts); err != nil {
		t.Fatalf("allow-downgrade install: %v", err)
	}
	if got, _ := os.ReadFile(exe); !bytes.Equal(got, fakeBinary(t)) {
		t.Error("allow-downgrade did not replace the binary")
	}
}

func TestPrereleaseRefusedUnlessAllowed(t *testing.T) {
	// /latest returning a prerelease must abort, never install it (C-14).
	f := newFakeReleaseServer(t, "v0.6.4-rc.1")
	f.prerelease = true
	_, exe := makeTarget(t)
	_, err := runUpdate(t, f.baseOptions(exe))
	if err == nil {
		t.Fatal("prerelease latest: want error")
	}
	if codeOf(err) != 2 {
		t.Errorf("prerelease latest code=%d, want 2", codeOf(err))
	}
	// Explicit prerelease target without the flag refuses too.
	f2 := newFakeReleaseServer(t, "v0.6.4-rc.1")
	f2.prerelease = true
	opts := f2.baseOptions(exe)
	opts.TargetVersion = "0.6.4-rc.1"
	if _, err := runUpdate(t, opts); err == nil || codeOf(err) != 2 {
		t.Fatalf("explicit prerelease: err=%v code=%d, want code 2", err, codeOf(err))
	}
	// With --allow-prerelease it installs. The fake binary reports
	// 0.6.4, so the exec check is stubbed here (see stubExecCheck).
	stubExecCheck(t)
	f2.assets["castctl_0.6.4-rc.1_linux_amd64.tar.gz"] = &fakeAsset{body: buildTar(t, map[string][]byte{
		"castctl": fakeBinary(t),
	})}
	f2.setChecksums()
	opts.AllowPrerelease = true
	if _, err := runUpdate(t, opts); err != nil {
		t.Fatalf("allow-prerelease install: %v", err)
	}
}

func TestExplicitVersion(t *testing.T) {
	f := newFakeReleaseServer(t, "v0.6.4")
	_, exe := makeTarget(t)
	// Invalid explicit versions refuse before any network (D-10/D-05).
	for _, bad := range []string{"abc", "v1", "01.2.3", "1.0.0-", "v1.0.0 ", "1.0.0+build"} {
		opts := f.baseOptions(exe)
		opts.TargetVersion = bad
		if _, err := runUpdate(t, opts); err == nil || codeOf(err) != 2 {
			t.Fatalf("explicit %q: err=%v code=%d, want code 2", bad, err, codeOf(err))
		}
	}
	if got := f.getCount("/repos/"); got != 0 {
		t.Errorf("invalid explicit versions made %d API requests, want 0", got)
	}
	// Explicit 404 refuses (code 2, no release exists for the request).
	opts := f.baseOptions(exe)
	opts.TargetVersion = "9.9.9"
	f.tagStatus = 404
	if _, err := runUpdate(t, opts); err == nil || codeOf(err) != 2 {
		t.Fatalf("explicit missing: err=%v code=%d, want code 2", err, codeOf(err))
	}
	// Explicit equal version is a no-op.
	f.tagStatus = 0
	opts2 := f.baseOptions(exe)
	opts2.TargetVersion = "0.6.3"
	res, err := runUpdate(t, opts2)
	if err != nil || res.Replaced {
		t.Fatalf("explicit equal: res=%+v err=%v, want no-op", res, err)
	}
	// Explicit newer installs via the /tags/ endpoint.
	f.assets["castctl_0.6.4_linux_amd64.tar.gz"] = &fakeAsset{body: buildTar(t, map[string][]byte{
		"castctl": fakeBinary(t),
	})}
	f.setChecksums()
	opts3 := f.baseOptions(exe)
	opts3.TargetVersion = "0.6.4"
	if _, err := runUpdate(t, opts3); err != nil {
		t.Fatalf("explicit install: %v", err)
	}
	if got, _ := os.ReadFile(exe); !bytes.Equal(got, fakeBinary(t)) {
		t.Error("explicit install did not replace the binary")
	}
}

func TestInvalidRemoteTagRefuses(t *testing.T) {
	f := newFakeReleaseServer(t, "v0.6.4")
	f.latestJSON = `{"tag_name":"not-a-version!!","draft":false,"prerelease":false,"assets":[]}`
	_, exe := makeTarget(t)
	_, err := runUpdate(t, f.baseOptions(exe))
	if err == nil || codeOf(err) != 2 {
		t.Fatalf("invalid remote tag: err=%v code=%d, want code 2", err, codeOf(err))
	}
	// Hostile tag bytes must never reach output verbatim (D-04/A-21).
	if strings.Contains(err.Error(), "!!") {
		t.Errorf("error echoes hostile tag bytes: %q", err.Error())
	}
	if strings.Contains(err.Error(), "\n") {
		t.Errorf("error is multi-line: %q", err.Error())
	}
}

func TestAPIErrorRefuses(t *testing.T) {
	// 404 on /latest: no release found (C-01).
	f := newFakeReleaseServer(t, "v0.6.4")
	f.latestStatus = 404
	f.latestJSON = `{"message":"Not Found"}`
	_, exe := makeTarget(t)
	_, err := runUpdate(t, f.baseOptions(exe))
	if err == nil || codeOf(err) != 2 {
		t.Fatalf("API 404: err=%v code=%d, want code 2", err, codeOf(err))
	}
	// 500 with a hostile body: no body bytes in the error (status/host/path/class/length summary only).
	f2 := newFakeReleaseServer(t, "v0.6.4")
	f2.latestStatus = 500
	f2.latestJSON = `{"message":"SECRET-MARKER-12345 boom"}`
	_, err = runUpdate(t, f2.baseOptions(exe))
	if err == nil || codeOf(err) != 1 {
		t.Fatalf("API 500: err=%v code=%d, want code 1", err, codeOf(err))
	}
	if strings.Contains(err.Error(), "SECRET-MARKER-12345") {
		t.Errorf("error leaks response body: %q", err.Error())
	}
	// Malformed JSON refuses.
	f3 := newFakeReleaseServer(t, "v0.6.4")
	f3.latestJSON = `{"tag_name": 123, "assets": "nope"`
	if _, err := runUpdate(t, f3.baseOptions(exe)); err == nil {
		t.Fatal("malformed JSON: want error")
	}
}

func TestRateLimitFallback(t *testing.T) {
	// API 403 -> fallback via the web redirect learns the tag and
	// installs from constructed URLs (decision 4).
	f := newFakeReleaseServer(t, "v0.6.4")
	f.latestStatus = 403
	f.latestJSON = `{"message":"API rate limit exceeded"}`
	assetName := "castctl_0.6.4_linux_amd64.tar.gz"
	f.assets[assetName] = &fakeAsset{body: buildTar(t, map[string][]byte{
		"castctl": fakeBinary(t),
	})}
	f.setChecksums()
	_, exe := makeTarget(t)
	res, err := runUpdate(t, f.baseOptions(exe))
	if err != nil {
		t.Fatalf("rate-limit fallback: %v", err)
	}
	if !res.Replaced {
		t.Error("fallback must install")
	}
	// API 403 + broken fallback -> clear rate-limit message, code 1,
	// nothing written.
	f2 := newFakeReleaseServer(t, "v0.6.4")
	f2.latestStatus = 403
	f2.latestJSON = `{"message":"API rate limit exceeded"}`
	f2.fallbackStatus = 404
	_, exe2 := makeTarget(t)
	before := dirSnapshot(t, filepath.Dir(exe2))
	_, err = runUpdate(t, f2.baseOptions(exe2))
	if err == nil || codeOf(err) != 1 {
		t.Fatalf("fallback failure: err=%v code=%d, want code 1", err, codeOf(err))
	}
	if !strings.Contains(strings.ToLower(err.Error()), "rate limit") {
		t.Errorf("fallback failure error %q must mention rate limit", err.Error())
	}
	if !snapshotsEqual(before, dirSnapshot(t, filepath.Dir(exe2))) {
		t.Error("fallback failure changed the directory")
	}
}

func TestRedirectPolicy(t *testing.T) {
	// Redirect to a non-allowlisted host refuses before dialing (C-05).
	f := newFakeReleaseServer(t, "v0.6.4")
	f.latestRedirect = "https://evil.example.invalid/castctl.tar.gz"
	_, exe := makeTarget(t)
	_, err := runUpdate(t, f.baseOptions(exe))
	if err == nil {
		t.Fatal("evil redirect: want error")
	}
	if strings.Contains(err.Error(), "evil.example") {
		t.Errorf("error echoes redirect host bytes: %q", err.Error())
	}
	// Redirect loop refuses (C-07): the API endpoint redirects to itself.
	f2 := newFakeReleaseServer(t, "v0.6.4")
	f2.latestRedirect = f2.srv.URL + "/repos/thoitiettxl-cyber/castctl/releases/latest"
	_, exe2 := makeTarget(t)
	if _, err := runUpdate(t, f2.baseOptions(exe2)); err == nil {
		t.Fatal("redirect loop: want error")
	}
	// Same-host redirect to the download path is allowed: the fake
	// server redirects the metadata call to a mirror path that the
	// handler also serves. (Covered by fallback tests; here assert
	// that a redirect to the CDN allowlist shape is not rejected
	// for its host: use the fake server itself via the loopback
	// rule by redirecting latest -> /download mirror is not valid
	// JSON, so assert refusal is a JSON error, not a redirect error.)
}

func TestFlavourSelectsAsset(t *testing.T) {
	// CGO_ENABLED=1 -> glibc asset; =0 -> _no-plugin asset; absent ->
	// refuse (decision 2 probe result).
	cases := []struct {
		name      string
		buildInfo *debug.BuildInfo
		wantAsset string
		wantCode  int
	}{
		{"glibc", glibcBuildInfo(), "castctl_0.6.4_linux_amd64.tar.gz", 0},
		{"no-plugin", noPluginBuildInfo(), "castctl_0.6.4_linux_amd64_no-plugin.tar.gz", 0},
		{"absent", &debug.BuildInfo{}, "", 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeReleaseServer(t, "v0.6.4")
			for _, name := range []string{
				"castctl_0.6.4_linux_amd64.tar.gz",
				"castctl_0.6.4_linux_amd64_no-plugin.tar.gz",
			} {
				f.assets[name] = &fakeAsset{body: buildTar(t, map[string][]byte{
					"castctl": fakeBinary(t),
				})}
			}
			f.setChecksums()
			_, exe := makeTarget(t)
			opts := f.baseOptions(exe)
			opts.BuildInfo = tc.buildInfo
			res, err := runUpdate(t, opts)
			if tc.wantCode != 0 {
				if err == nil || codeOf(err) != tc.wantCode {
					t.Fatalf("err=%v code=%d, want code %d", err, codeOf(err), tc.wantCode)
				}
				return
			}
			if err != nil {
				t.Fatalf("install: %v", err)
			}
			if res.AssetName != tc.wantAsset {
				t.Errorf("AssetName = %q, want %q", res.AssetName, tc.wantAsset)
			}
		})
	}
}

func TestFlavourUnknownRefuses(t *testing.T) {
	// Conflicting duplicate CGO_ENABLED settings -> unknown -> refuse.
	f := newFakeReleaseServer(t, "v0.6.4")
	_, exe := makeTarget(t)
	opts := f.baseOptions(exe)
	opts.BuildInfo = &debug.BuildInfo{Settings: []debug.BuildSetting{
		{Key: "CGO_ENABLED", Value: "1"},
		{Key: "CGO_ENABLED", Value: "0"},
	}}
	if _, err := runUpdate(t, opts); err == nil || codeOf(err) != 2 {
		t.Fatalf("conflicting CGO_ENABLED: err=%v code=%d, want code 2", err, codeOf(err))
	}
	// Other values refuse too.
	for _, v := range []string{"", "2", "yes"} {
		opts.BuildInfo = &debug.BuildInfo{Settings: []debug.BuildSetting{
			{Key: "CGO_ENABLED", Value: v},
		}}
		if _, err := runUpdate(t, opts); err == nil || codeOf(err) != 2 {
			t.Fatalf("CGO_ENABLED=%q: err=%v, want code 2", v, err)
		}
	}
}

func TestNoAssetFailsClosed(t *testing.T) {
	// Assets list has no amd64 glibc archive (C-14/Q-12 family).
	f := newFakeReleaseServer(t, "v0.6.4")
	f.assets["castctl_0.6.4_linux_arm64.tar.gz"] = &fakeAsset{body: []byte("arm")}
	f.setChecksums()
	_, exe := makeTarget(t)
	before := dirSnapshot(t, filepath.Dir(exe))
	_, err := runUpdate(t, f.baseOptions(exe))
	if err == nil || codeOf(err) != 2 {
		t.Fatalf("no asset: err=%v code=%d, want code 2", err, codeOf(err))
	}
	if !snapshotsEqual(before, dirSnapshot(t, filepath.Dir(exe))) {
		t.Error("no-asset changed the directory")
	}
	// Duplicate asset names are ambiguous (E-16): the fake server
	// cannot emit duplicates via the map, so this is covered by
	// selectAsset unit tests in slice 3; here assert that a
	// checksums.txt asset is required in primary mode.
	f2 := newFakeReleaseServer(t, "v0.6.4")
	f2.assets["castctl_0.6.4_linux_amd64.tar.gz"] = &fakeAsset{body: buildTar(t, map[string][]byte{
		"castctl": fakeBinary(t),
	})}
	// No setChecksums: no checksums.txt asset listed.
	_, exe2 := makeTarget(t)
	if _, err := runUpdate(t, f2.baseOptions(exe2)); err == nil || codeOf(err) != 1 {
		t.Fatalf("missing checksums: err=%v code=%d, want code 1", err, codeOf(err))
	}
}

func TestChecksumMismatchRefuses(t *testing.T) {
	// checksums.txt lists a hash that does not match the asset (A-18/B-01).
	f := newFakeReleaseServer(t, "v0.6.4")
	assetName := "castctl_0.6.4_linux_amd64.tar.gz"
	f.assets[assetName] = &fakeAsset{body: buildTar(t, map[string][]byte{
		"castctl": fakeBinary(t),
	})}
	f.setChecksums()
	// Corrupt the checksums entry for the asset.
	sum := sha256.Sum256([]byte("different bytes"))
	f.assets["checksums.txt"] = &fakeAsset{body: []byte(hex.EncodeToString(sum[:]) + "  " + assetName + "\n")}
	_, exe := makeTarget(t)
	before := dirSnapshot(t, filepath.Dir(exe))
	_, err := runUpdate(t, f.baseOptions(exe))
	if err == nil || codeOf(err) != 1 {
		t.Fatalf("checksum mismatch: err=%v code=%d, want code 1", err, codeOf(err))
	}
	after := dirSnapshot(t, filepath.Dir(exe))
	delete(after, lockFileName) // the never-deleted lock file is expected
	if !snapshotsEqual(before, after) {
		t.Error("checksum mismatch changed the directory (old binary or temps)")
	}
	old, _ := os.ReadFile(exe)
	if string(old) != "old-binary-bytes" {
		t.Error("checksum mismatch modified the target binary")
	}
}

func TestDryRunWritesNothing(t *testing.T) {
	f := newFakeReleaseServer(t, "v0.6.4")
	assetName := "castctl_0.6.4_linux_amd64.tar.gz"
	f.assets[assetName] = &fakeAsset{body: buildTar(t, map[string][]byte{
		"castctl": fakeBinary(t),
	})}
	f.setChecksums()
	_, exe := makeTarget(t)
	before := dirSnapshot(t, filepath.Dir(exe))
	opts := f.baseOptions(exe)
	opts.DryRun = true
	var stdout bytes.Buffer
	opts.Stdout = &stdout
	res, err := runUpdate(t, opts)
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if res.Replaced {
		t.Error("dry-run must not replace")
	}
	if !snapshotsEqual(before, dirSnapshot(t, filepath.Dir(exe))) {
		t.Errorf("dry-run changed the directory: before=%v after=%v", before, dirSnapshot(t, filepath.Dir(exe)))
	}
	out := stdout.String()
	if !strings.Contains(out, "would") || !strings.Contains(out, assetName) || !strings.Contains(out, "0.6.4") {
		t.Errorf("dry-run output %q must say what would happen", out)
	}
	if !strings.Contains(out, "exec check") {
		t.Errorf("dry-run output %q must disclose the skipped exec check", out)
	}
}

// TestPrereleaseTagWithFlagFalseRefuses (loop 3, F1): a release tag
// carrying a prerelease part must refuse in primary mode even when
// the release JSON prerelease flag is false (the GitHub checkbox is
// independent of the tag). The guard lives in decide(), after the
// equal-version no-op return and before asset selection.
func TestPrereleaseTagWithFlagFalseRefuses(t *testing.T) {
	const tag = "v0.7.0-rc.1"
	assetName := "castctl_0.7.0-rc.1_linux_amd64.tar.gz"

	// Latest mode, flag=false, no flags: code 2, zero asset downloads,
	// old binary intact. The exec check is NOT stubbed here: refusal
	// happens before any download, so it must never be reached.
	t.Run("latestFlagFalse", func(t *testing.T) {
		f := newFakeReleaseServer(t, tag)
		f.prerelease = false
		f.assets[assetName] = &fakeAsset{body: buildTar(t, map[string][]byte{
			"castctl": fakeBinary(t),
		})}
		f.setChecksums()
		_, exe := makeTarget(t)
		before := dirSnapshot(t, filepath.Dir(exe))
		_, err := runUpdate(t, f.baseOptions(exe))
		if err == nil || codeOf(err) != 2 {
			t.Fatalf("latest flag-false prerelease tag: err=%v code=%d, want code 2", err, codeOf(err))
		}
		if !strings.Contains(err.Error(), "0.7.0-rc.1") || !strings.Contains(err.Error(), "--allow-prerelease") {
			t.Errorf("refusal %q must name the target version and --allow-prerelease", err.Error())
		}
		if got := f.getCount("/download/"); got != 0 {
			t.Errorf("refusal downloaded %d assets, want 0", got)
		}
		if !snapshotsEqual(before, dirSnapshot(t, filepath.Dir(exe))) {
			t.Error("refusal changed the directory")
		}
		if old, _ := os.ReadFile(exe); string(old) != "old-binary-bytes" {
			t.Error("refusal modified the target binary")
		}
	})

	// Explicit mode, flag=false, no flags: same guarantees.
	t.Run("explicitFlagFalse", func(t *testing.T) {
		f := newFakeReleaseServer(t, tag)
		f.prerelease = false
		f.assets[assetName] = &fakeAsset{body: buildTar(t, map[string][]byte{
			"castctl": fakeBinary(t),
		})}
		f.setChecksums()
		_, exe := makeTarget(t)
		before := dirSnapshot(t, filepath.Dir(exe))
		opts := f.baseOptions(exe)
		opts.TargetVersion = "0.7.0-rc.1"
		_, err := runUpdate(t, opts)
		if err == nil || codeOf(err) != 2 {
			t.Fatalf("explicit flag-false prerelease tag: err=%v code=%d, want code 2", err, codeOf(err))
		}
		if !strings.Contains(err.Error(), "0.7.0-rc.1") || !strings.Contains(err.Error(), "--allow-prerelease") {
			t.Errorf("refusal %q must name the target version and --allow-prerelease", err.Error())
		}
		if got := f.getCount("/download/"); got != 0 {
			t.Errorf("refusal downloaded %d assets, want 0", got)
		}
		if !snapshotsEqual(before, dirSnapshot(t, filepath.Dir(exe))) {
			t.Error("refusal changed the directory")
		}
	})

	// With --allow-prerelease, flag=false installs in both modes
	// (exec check stubbed: the fake binary reports 0.6.4).
	t.Run("allowInstalls", func(t *testing.T) {
		for _, explicit := range []bool{false, true} {
			f := newFakeReleaseServer(t, tag)
			f.prerelease = false
			f.assets[assetName] = &fakeAsset{body: buildTar(t, map[string][]byte{
				"castctl": fakeBinary(t),
			})}
			f.setChecksums()
			_, exe := makeTarget(t)
			stubExecCheck(t)
			opts := f.baseOptions(exe)
			opts.AllowPrerelease = true
			if explicit {
				opts.TargetVersion = "0.7.0-rc.1"
			}
			res, err := runUpdate(t, opts)
			if err != nil {
				t.Fatalf("explicit=%v allow-prerelease install: %v", explicit, err)
			}
			if !res.Replaced {
				t.Errorf("explicit=%v allow-prerelease must replace", explicit)
			}
			if got, _ := os.ReadFile(exe); !bytes.Equal(got, fakeBinary(t)) {
				t.Errorf("explicit=%v allow-prerelease did not replace the binary", explicit)
			}
		}
	})

	// Flag=true without --allow-prerelease still refuses (existing
	// behaviour, pinned): latest and explicit.
	t.Run("flagTrueStillRefuses", func(t *testing.T) {
		f := newFakeReleaseServer(t, tag)
		f.prerelease = true
		_, exe := makeTarget(t)
		if _, err := runUpdate(t, f.baseOptions(exe)); err == nil || codeOf(err) != 2 {
			t.Fatalf("latest flag-true: err=%v code=%d, want code 2", err, codeOf(err))
		}
		f2 := newFakeReleaseServer(t, tag)
		f2.prerelease = true
		opts := f2.baseOptions(exe)
		opts.TargetVersion = "0.7.0-rc.1"
		if _, err := runUpdate(t, opts); err == nil || codeOf(err) != 2 {
			t.Fatalf("explicit flag-true: err=%v code=%d, want code 2", err, codeOf(err))
		}
	})

	// Equal prerelease no-op: current == target prerelease is already
	// latest — exit 0, zero writes, zero downloads. Refusing a no-op
	// would be wrong; the decide() guard sits after this return.
	t.Run("equalPrereleaseNoOp", func(t *testing.T) {
		f := newFakeReleaseServer(t, tag)
		f.prerelease = false
		_, exe := makeTarget(t)
		before := dirSnapshot(t, filepath.Dir(exe))
		opts := f.baseOptions(exe)
		opts.CurrentVersion = "0.7.0-rc.1"
		res, err := runUpdate(t, opts)
		if err != nil {
			t.Fatalf("equal prerelease no-op: %v", err)
		}
		if res.Replaced {
			t.Error("equal prerelease no-op must not replace")
		}
		if !snapshotsEqual(before, dirSnapshot(t, filepath.Dir(exe))) {
			t.Error("equal prerelease no-op changed the directory")
		}
		if got := f.getCount("/download/"); got != 0 {
			t.Errorf("equal prerelease no-op downloaded %d assets, want 0", got)
		}
	})

	// Fallback paths still refuse prerelease tags (pins of the
	// existing fallback guards, which decide() must not disturb).
	t.Run("fallbackStillRefuses", func(t *testing.T) {
		f := newFakeReleaseServer(t, tag)
		f.latestStatus = 403
		f.latestJSON = `{"message":"API rate limit exceeded"}`
		f.fallbackTag = tag
		_, exe := makeTarget(t)
		if _, err := runUpdate(t, f.baseOptions(exe)); err == nil || codeOf(err) != 2 {
			t.Fatalf("fallback latest prerelease: err=%v code=%d, want code 2", err, codeOf(err))
		}
		f2 := newFakeReleaseServer(t, tag)
		f2.tagStatus = 403
		_, exe2 := makeTarget(t)
		opts := f2.baseOptions(exe2)
		opts.TargetVersion = "0.7.0-rc.1"
		if _, err := runUpdate(t, opts); err == nil || codeOf(err) != 2 {
			t.Fatalf("fallback explicit prerelease: err=%v code=%d, want code 2", err, codeOf(err))
		}
	})
}

// TestDownloadURLWithUserinfoRefuses (loop 3, red-team N4): a
// browser_download_url carrying userinfo must be refused by
// validateDownloadURL before any request, so no Authorization
// header derived from the URL is ever sent.
func TestDownloadURLWithUserinfoRefuses(t *testing.T) {
	for _, raw := range []string{
		"https://user:pass@example.com/castctl.tar.gz",
		"https://user@example.com/castctl.tar.gz",
		"http://user:pass@127.0.0.1:1/castctl.tar.gz",
	} {
		if err := validateDownloadURL(raw); err == nil {
			t.Errorf("validateDownloadURL(%q): want refusal", raw)
		}
	}
	// Clean URLs still validate.
	for _, raw := range []string{
		"https://example.com/castctl.tar.gz",
		"http://127.0.0.1:1/castctl.tar.gz",
	} {
		if err := validateDownloadURL(raw); err != nil {
			t.Errorf("validateDownloadURL(%q): %v, want nil", raw, err)
		}
	}

	// Run-level: asset URL with userinfo refuses (code 1, the
	// existing unusable-URL class), zero download requests, and no
	// Authorization header reaches the fake server.
	releaseWithUserinfo := func(t *testing.T, userinfoAsset, userinfoChecksums bool) *fakeReleaseServer {
		t.Helper()
		f := newFakeReleaseServer(t, "v0.6.4")
		assetName := "castctl_0.6.4_linux_amd64.tar.gz"
		f.assets[assetName] = &fakeAsset{body: buildTar(t, map[string][]byte{
			"castctl": fakeBinary(t),
		})}
		f.setChecksums()
		withUserinfo := func(name string) string {
			return strings.Replace(f.srv.URL, "://", "://user:pass@", 1) + "/download/v0.6.4/" + name
		}
		clean := func(name string) string {
			return f.srv.URL + "/download/v0.6.4/" + name
		}
		assetURL, sumsURL := clean(assetName), clean("checksums.txt")
		if userinfoAsset {
			assetURL = withUserinfo(assetName)
		}
		if userinfoChecksums {
			sumsURL = withUserinfo("checksums.txt")
		}
		f.latestJSON = `{"tag_name":"v0.6.4","draft":false,"prerelease":false,"assets":[` +
			`{"name":"` + assetName + `","browser_download_url":"` + assetURL + `","size":1,"state":"uploaded"},` +
			`{"name":"checksums.txt","browser_download_url":"` + sumsURL + `","size":1,"state":"uploaded"}]}`
		return f
	}
	for _, tc := range []struct {
		name              string
		userinfoAsset     bool
		userinfoChecksums bool
	}{
		{"asset", true, false},
		{"checksums", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := releaseWithUserinfo(t, tc.userinfoAsset, tc.userinfoChecksums)
			_, exe := makeTarget(t)
			before := dirSnapshot(t, filepath.Dir(exe))
			_, err := runUpdate(t, f.baseOptions(exe))
			if err == nil || codeOf(err) != 1 {
				t.Fatalf("userinfo %s URL: err=%v code=%d, want code 1", tc.name, err, codeOf(err))
			}
			if got := f.getCount("/download/"); got != 0 {
				t.Errorf("userinfo %s URL: %d download requests, want 0", tc.name, got)
			}
			if got := f.authHeaderCount(); got != 0 {
				t.Errorf("userinfo %s URL: %d requests carried Authorization, want 0", tc.name, got)
			}
			if !snapshotsEqual(before, dirSnapshot(t, filepath.Dir(exe))) {
				// The refusal happens inside install(), after the
				// lock file is created; the lock persists by
				// design, so compare ignoring it.
				after := dirSnapshot(t, filepath.Dir(exe))
				delete(after, lockFileName)
				delete(before, lockFileName)
				if !snapshotsEqual(before, after) {
					t.Error("userinfo refusal changed the directory beyond the lock file")
				}
			}
			if old, _ := os.ReadFile(exe); string(old) != "old-binary-bytes" {
				t.Error("userinfo refusal modified the target binary")
			}
		})
	}
}

// TestRedirectUserinfoRefuses (loop 4, red-team R-F1): a download
// server that redirects to a URL carrying userinfo must be refused
// by the redirect policy before the follow-up request is sent, so
// no Authorization header derived from URL userinfo is ever sent
// and nothing is installed. The redirect policy is the single choke
// point for every client path, so the checksums leg, the asset leg,
// both legs, and a userinfo target reached on the second hop of a
// redirect chain are all covered; a redirect without userinfo
// still installs (control). The exec check is stubbed in every
// case, exactly as in the loop-3 redirect probe: a refusal must
// precede any download, so the stub is irrelevant to the refusal
// cases, and it lets the pre-fix run proceed far enough to prove
// the channel end-to-end (install + Authorization headers).
func TestRedirectUserinfoRefuses(t *testing.T) {
	const tag = "v0.7.0"
	assetName := "castctl_0.7.0_linux_amd64.tar.gz"
	stubExecCheck(t)

	// newFixture builds a two-server fixture. The API server serves
	// the release JSON; each leg either points straight at the
	// object server (direct, clean) or at the API server, which
	// redirects to the object server. Redirect targets carry
	// userinfo only when userinfo is set; with secondHop, the
	// redirect leg first hops to /hop/, which redirects on to /dl/,
	// so the userinfo target is the second redirect in the chain.
	newFixture := func(t *testing.T, checksumsRedirect, assetRedirect, userinfo, secondHop bool) (run func(exe string) (Result, error), authCount func() int) {
		t.Helper()
		assetBody := buildTar(t, map[string][]byte{"castctl": fakeBinary(t)})
		sum := sha256.Sum256(assetBody)
		checksumsBody := []byte(hex.EncodeToString(sum[:]) + "  " + assetName + "\n")

		var mu sync.Mutex
		var auth []string
		obj := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if a := r.Header.Get("Authorization"); a != "" {
				mu.Lock()
				auth = append(auth, a)
				mu.Unlock()
			}
			switch {
			case strings.HasSuffix(r.URL.Path, "checksums.txt"):
				_, _ = w.Write(checksumsBody)
			case strings.HasSuffix(r.URL.Path, assetName):
				_, _ = w.Write(assetBody)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		t.Cleanup(obj.Close)
		objURL, err := url.Parse(obj.URL)
		if err != nil {
			t.Fatal(err)
		}
		// target builds the object-server URL for a download
		// object, optionally carrying userinfo.
		target := func(name string, withUserinfo bool) string {
			u := *objURL
			u.Path = "/obj/" + name
			if withUserinfo {
				u.User = url.UserPassword("user", "pass")
			}
			return u.String()
		}

		api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			base := "http://" + r.Host
			switch {
			case r.URL.Path == "/repos/thoitiettxl-cyber/castctl/releases/latest":
				checksumsURL, assetURL := target("checksums.txt", false), target(assetName, false)
				if checksumsRedirect {
					checksumsURL = base + "/dl/checksums.txt"
					if secondHop {
						checksumsURL = base + "/hop/checksums.txt"
					}
				}
				if assetRedirect {
					assetURL = base + "/dl/" + assetName
					if secondHop {
						assetURL = base + "/hop/" + assetName
					}
				}
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"tag_name":%q,"draft":false,"prerelease":false,"assets":[
					{"name":%q,"browser_download_url":%q,"size":%d,"state":"uploaded"},
					{"name":"checksums.txt","browser_download_url":%q,"size":%d,"state":"uploaded"}]}`,
					tag, assetName, assetURL, len(assetBody), checksumsURL, len(checksumsBody))
			case strings.HasPrefix(r.URL.Path, "/hop/"):
				name := strings.TrimPrefix(r.URL.Path, "/hop/")
				http.Redirect(w, r, base+"/dl/"+name, http.StatusFound)
			case strings.HasPrefix(r.URL.Path, "/dl/"):
				name := strings.TrimPrefix(r.URL.Path, "/dl/")
				withUserinfo := userinfo && ((name == "checksums.txt" && checksumsRedirect) || (name == assetName && assetRedirect))
				http.Redirect(w, r, target(name, withUserinfo), http.StatusFound)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		t.Cleanup(api.Close)

		run = func(exe string) (Result, error) {
			opts := Options{
				Deps: Deps{
					HTTPClient: api.Client(),
					Executable: exe,
					BuildInfo:  glibcBuildInfo(),
					APIBase:    api.URL,
					GitHubBase: api.URL,
				},
				CurrentVersion: "0.6.3",
				Commit:         "0807125",
				BuildDate:      "2026-10-30T17:31:50Z",
				Stdout:         &bytes.Buffer{},
			}
			return runUpdate(t, opts)
		}
		authCount = func() int {
			mu.Lock()
			defer mu.Unlock()
			return len(auth)
		}
		return run, authCount
	}

	for _, tc := range []struct {
		name              string
		checksumsRedirect bool
		assetRedirect     bool
		secondHop         bool
	}{
		{"checksums", true, false, false},
		{"asset", false, true, false},
		{"both", true, true, false},
		{"secondHop", true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run, authCount := newFixture(t, tc.checksumsRedirect, tc.assetRedirect, true, tc.secondHop)
			_, exe := makeTarget(t)
			before := dirSnapshot(t, filepath.Dir(exe))
			res, err := run(exe)
			t.Logf("redirect-userinfo %s: err=%v replaced=%v authHeaders=%d", tc.name, err, res.Replaced, authCount())
			if err == nil || codeOf(err) != 1 {
				t.Fatalf("userinfo redirect (%s): err=%v code=%d, want code 1", tc.name, err, codeOf(err))
			}
			if res.Replaced {
				t.Errorf("userinfo redirect (%s) replaced the binary", tc.name)
			}
			if got := authCount(); got != 0 {
				t.Errorf("userinfo redirect (%s): %d Authorization headers sent, want 0", tc.name, got)
			}
			if old, _ := os.ReadFile(exe); string(old) != "old-binary-bytes" {
				t.Errorf("userinfo redirect (%s) modified the target binary", tc.name)
			}
			after := dirSnapshot(t, filepath.Dir(exe))
			delete(after, lockFileName)
			delete(before, lockFileName)
			if !snapshotsEqual(before, after) {
				t.Errorf("userinfo redirect (%s) changed the directory beyond the lock file", tc.name)
			}
		})
	}

	// Control: the same redirect chain without userinfo installs,
	// with zero Authorization headers.
	t.Run("cleanControl", func(t *testing.T) {
		run, authCount := newFixture(t, true, true, false, false)
		_, exe := makeTarget(t)
		res, err := run(exe)
		if err != nil || !res.Replaced {
			t.Fatalf("clean redirect control: err=%v replaced=%v, want install", err, res.Replaced)
		}
		if got := authCount(); got != 0 {
			t.Errorf("clean redirect control: %d Authorization headers sent, want 0", got)
		}
		if got, _ := os.ReadFile(exe); string(got) == "old-binary-bytes" {
			t.Error("clean redirect control did not replace the target binary")
		}
	})
}
