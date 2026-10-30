// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

// TestSPDXHeaders enforces the licence-header rule for the whole Go
// port: EVERY .go file under the repo root must carry the SPDX header below at
// the top, after any build-tag block. Build-tag lines (//go:build,
// // +build) stay first, followed by one blank line, then the header,
// then one blank line, then the rest of the file.
//
// Generated files are NOT exempt. The *.pb.go files carry the same
// header: protoc-gen-go does not emit it, so generate.sh injects it
// deterministically on every regeneration (see
// internal/proto/generate/README.md). If a regeneration drops the
// header, this test fails by design — never hand-edit a .pb.go file
// to restore it; fix the generator step instead.
package spdx_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var spdxHeaderLines = []string{
	"// Copyright (c) 2026 muse-cli contributors",
	"// SPDX-License-Identifier: GPL-3.0-or-later",
	"// Licensed under the GNU General Public License v3.0 or later.",
}

func TestSPDXHeaders(t *testing.T) {
	t.Parallel()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	root := ""
	for dir := filepath.Dir(thisFile); ; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			root = dir
			break
		}
		if parent := filepath.Dir(dir); parent == dir {
			t.Fatal("no go.mod found above spdx_test.go")
		}
	}

	var missing []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("read %s: %v", path, err)
			return nil
		}
		lines := strings.Split(string(data), "\n")
		i := 0
		for i < len(lines) && (strings.HasPrefix(lines[i], "//go:build") || strings.HasPrefix(lines[i], "// +build")) {
			i++
		}
		if i > 0 && i < len(lines) && lines[i] == "" {
			i++
		}
		hasHeader := len(lines)-i >= len(spdxHeaderLines)+1
		if hasHeader {
			for j, want := range spdxHeaderLines {
				if lines[i+j] != want {
					hasHeader = false
					break
				}
			}
			if hasHeader && lines[i+len(spdxHeaderLines)] != "" {
				hasHeader = false
			}
		}
		if !hasHeader {
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				rel = path
			}
			missing = append(missing, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) > 0 {
		t.Errorf("%d .go file(s) lack the SPDX header:\n%s", len(missing), strings.Join(missing, "\n"))
	}
}
