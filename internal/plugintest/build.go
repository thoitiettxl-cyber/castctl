// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package plugintest

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// FakePluginOptions drives the -X variables of the fake
// c-shared plugin fixture (testdata/fakeplugin/main.go).
// Zero values select the fixture defaults: schema 1, name
// "fake", version "0.1.0", author "plugintest", Provider
// capability.
type FakePluginOptions struct {
	// Schema is the schema_version the fixture reports
	// ("1", "2", "0" for missing, ...).
	Schema string
	// ABI overrides the abi_version the fixture reports
	// ("" keeps the contract constant 1).
	ABI string
	// Name, Version, Author override the registration
	// metadata ("" keeps the fixture default). EmptyName
	// forces an empty name to test the metadata gate.
	Name      string
	EmptyName bool
	Version   string
	Author    string
	// Caps is "provider", "command", "both", or "none".
	Caps string
	// FailRegister makes plugin.register return an error
	// envelope.
	FailRegister bool
	// CookieHosts is the comma-separated cookie_hosts list
	// the fixture declares in its registration ("" keeps
	// the fixture default: no declaration).
	CookieHosts string
	// RawRC makes provider.call return rc != 0 with raw
	// (non-envelope) bytes carrying the exact C1 byte
	// sequences, exercising the loader's rc != 0 error
	// construction (the C1 rc!=0 test gap). Register and
	// quiesce are unaffected, so the plugin still loads.
	RawRC bool
	// NoInit makes the fixture omit the entry symbol (built
	// from the noinit source instead).
	NoInit bool
}

// BuildFakePlugin compiles the fake c-shared plugin fixture
// into dir and returns the .so path. It requires a C toolchain
// (CGO_ENABLED=1) and fails the test otherwise; callers must
// run it only from cgo-tagged tests. The fixture source is
// never committed as a binary: it is built fresh by each test.
func BuildFakePlugin(t *testing.T, dir string, opts FakePluginOptions) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake plugin fixture is built for unix-like targets in this test")
	}
	// Resolve the fixture source relative to this file, not
	// the test's working directory: loader tests live in
	// internal/pluginhost, the fixture in internal/plugintest.
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	pkgDir := filepath.Dir(thisFile)
	srcDir := filepath.Join(pkgDir, "testdata", "fakeplugin")
	if opts.NoInit {
		srcDir = filepath.Join(pkgDir, "testdata", "noinit")
	}
	absSrc := srcDir
	if _, err := os.Stat(absSrc); err != nil {
		t.Fatalf("fake plugin source missing: %v", err)
	}
	out := filepath.Join(dir, "fake.so")
	ldflags := "-X main.testSchema=" + orDefault(opts.Schema, "1")
	if opts.ABI != "" {
		ldflags += " -X main.testABI=" + opts.ABI
	}
	if opts.EmptyName {
		ldflags += " -X main.testName="
	} else if opts.Name != "" {
		ldflags += " -X main.testName=" + opts.Name
	}
	if opts.Version != "" {
		ldflags += " -X main.testVersion=" + opts.Version
	}
	if opts.Author != "" {
		ldflags += " -X main.testAuthor=" + opts.Author
	}
	if opts.Caps != "" {
		ldflags += " -X main.testCaps=" + opts.Caps
	}
	if opts.FailRegister {
		ldflags += " -X main.testFailRegister=1"
	}
	if opts.CookieHosts != "" {
		ldflags += " -X main.testCookieHosts=" + opts.CookieHosts
	}
	if opts.RawRC {
		ldflags += " -X main.testRawRC=1"
	}
	cmd := exec.Command("go", "build", "-buildmode=c-shared", "-ldflags", ldflags, "-o", out, ".")
	cmd.Dir = absSrc
	cmd.Env = append(os.Environ(), "CGO_ENABLED=1")
	var stderr []byte
	// Capture combined output without a pipe for the exit code.
	outFile := filepath.Join(dir, "build.log")
	f, err := os.Create(outFile)
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout = f
	cmd.Stderr = f
	runErr := cmd.Run()
	_ = f.Close()
	stderr, _ = os.ReadFile(outFile)
	if runErr != nil {
		t.Fatalf("build fake plugin: %v\n%s", runErr, stderr)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("fake plugin missing after build: %v", err)
	}
	return out
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// BuildNoSymbolPlugin compiles a c-shared library with no
// entry symbol (package main with an empty main function).
func BuildNoSymbolPlugin(t *testing.T, dir string) string {
	t.Helper()
	return BuildFakePlugin(t, dir, FakePluginOptions{NoInit: true})
}
