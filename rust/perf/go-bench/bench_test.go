// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

// Package bench holds M-perf-0 pure-logic benchmarks for the Go side:
// ParseSingleConfig (config parse) and MDToHTML / SplitText (Telegram
// text render). Fixtures are the same files the Rust bench crate reads
// (rust/perf/fixtures/), located via runtime.Caller so the bench works
// from any working directory. Run: go test -bench . -benchtime=100x
// -count=5 -run '^$' ./rust/perf/go-bench/
package bench

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/thoitiettxl-cyber/castctl/internal/profile"
	"github.com/thoitiettxl-cyber/castctl/internal/telegram"
)

func fixture(t *testing.B, name string) []byte {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "fixtures", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

func BenchmarkParseConfigMin(b *testing.B) {
	data := fixture(b, "config-min.json")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cfg, err := profile.ParseSingleConfig(data, "/base")
		if err != nil {
			b.Fatal(err)
		}
		_ = len(cfg.Profiles)
	}
}

func BenchmarkParseConfigLarge(b *testing.B) {
	data := fixture(b, "config-large.json")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cfg, err := profile.ParseSingleConfig(data, "/base")
		if err != nil {
			b.Fatal(err)
		}
		_ = len(cfg.Profiles)
	}
}

func BenchmarkMDToHTML(b *testing.B) {
	text := string(fixture(b, "message-long.md"))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = telegram.MDToHTML(text)
	}
}

func BenchmarkSplitText(b *testing.B) {
	text := string(fixture(b, "message-long.md"))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = telegram.SplitText(text)
	}
}

func BenchmarkRenderChain(b *testing.B) {
	text := string(fixture(b, "message-long.md"))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		html := telegram.MDToHTML(text)
		_ = telegram.SplitText(html)
	}
}
