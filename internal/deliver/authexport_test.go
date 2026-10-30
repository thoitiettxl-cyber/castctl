// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package deliver_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thoitiettxl-cyber/castctl/internal/deliver"
)

func TestAuthExport(t *testing.T) {
	err := deliver.AuthExport()
	if err == nil {
		t.Fatal("AuthExport: got nil error, want *ExportError with guidance")
	}
	var exportErr *deliver.ExportError
	if !errors.As(err, &exportErr) {
		t.Fatalf("AuthExport error type = %T, want *deliver.ExportError", err)
	}
	if exportErr.Guidance == "" {
		t.Error("ExportError.Guidance is empty")
	}
	if !strings.Contains(exportErr.Guidance, "https://muse.ai/") {
		t.Errorf("guidance does not mention https://muse.ai/: %q", exportErr.Guidance)
	}
	if !strings.Contains(exportErr.Guidance, "leave the tab open") {
		t.Errorf("guidance does not say to leave the tab open: %q", exportErr.Guidance)
	}
	if !strings.Contains(exportErr.Guidance, "No file was written") {
		t.Errorf("guidance does not state that no file was written: %q", exportErr.Guidance)
	}
	if got := exportErr.ExitCode(); got != 1 {
		t.Errorf("ExitCode() = %d, want 1", got)
	}
	if err.Error() != exportErr.Guidance {
		t.Errorf("Error() = %q, want the guidance text", err.Error())
	}
}

func TestAuthExportWritesNothing(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	sentinel := filepath.Join(dir, "cookies.txt")
	if err := os.WriteFile(sentinel, []byte("hatch_sess=FAKE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := snapshotDir(t, dir)

	if err := deliver.AuthExport(); err == nil {
		t.Fatal("AuthExport: got nil error")
	}

	after := snapshotDir(t, dir)
	if len(after) != len(before) {
		t.Fatalf("files changed: before %v, after %v", keys(before), keys(after))
	}
	for name, content := range before {
		if after[name] != content {
			t.Errorf("file %s changed: before %q, after %q", name, content, after[name])
		}
	}
}

func snapshotDir(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		out[rel] = string(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
