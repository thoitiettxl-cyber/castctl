// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func writeTestConfig(t *testing.T, base string, profiles map[string]*Profile) {
	t.Helper()
	cfg := &SingleConfig{Profiles: profiles}
	if err := SaveSingleConfig(base, cfg); err != nil {
		t.Fatal(err)
	}
}

func testProfile(name string) *Profile {
	return &Profile{
		Name:        name,
		CookiesFile: filepath.Join("/base", "cookies.txt"),
		AutoApprove: "off",
		Outbound:    OutboundRef{Kind: OutboundDirect, Type: "direct"},
	}
}

func TestConfigStateSaveHappyPath(t *testing.T) {
	t.Parallel()
	base := BaseDir(t.TempDir())
	writeTestConfig(t, base, map[string]*Profile{"p1": testProfile("p1")})

	state, err := LoadConfigState(base)
	if err != nil {
		t.Fatal(err)
	}
	if !state.Found || !state.Exists || state.Config == nil {
		t.Fatalf("state = %+v; want Found+Exists+Config", state)
	}
	data, err := os.ReadFile(filepath.Join(base, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if state.SHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("SHA256 = %q; want hex sha256 of file bytes", state.SHA256)
	}

	// Mutate through the state: default_profile set, then save again
	// with the same (refreshed) state.
	cfg := state.Config
	cfg.DefaultProfile = "p1"
	if err := state.Save(cfg); err != nil {
		t.Fatal(err)
	}
	loaded, found, err := LoadSingleConfig(base)
	if err != nil || !found {
		t.Fatalf("reload = %+v, %v, %v", loaded, found, err)
	}
	if loaded.DefaultProfile != "p1" {
		t.Errorf("DefaultProfile = %q; want p1", loaded.DefaultProfile)
	}
	cfg.DefaultProfile = ""
	if err := state.Save(cfg); err != nil {
		t.Fatalf("second Save with refreshed state: %v", err)
	}
}

func TestConfigStateSaveRefusesConcurrentChange(t *testing.T) {
	t.Parallel()
	base := BaseDir(t.TempDir())
	writeTestConfig(t, base, map[string]*Profile{"p1": testProfile("p1")})
	path := filepath.Join(base, "config.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	state, err := LoadConfigState(base)
	if err != nil {
		t.Fatal(err)
	}
	// A concurrent writer changes the file between load and save.
	if err := os.WriteFile(path, []byte(`{"profiles":{"other":{"cookies_file":"/x","auto_approve":"off","auto_allow_once":false}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if saveErr := state.Save(state.Config); !errors.Is(saveErr, ErrConcurrentChange) {
		t.Fatalf("Save after concurrent change = %v; want ErrConcurrentChange", saveErr)
	} else if code := ExitCode(saveErr); code != 2 {
		t.Errorf("ExitCode = %d; want 2", code)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) == string(before) {
		t.Error("concurrent writer's change vanished; the test setup failed")
	}
	// The file must hold the concurrent writer's bytes, untouched by Save.
	if string(after) != `{"profiles":{"other":{"cookies_file":"/x","auto_approve":"off","auto_allow_once":false}}}` {
		t.Errorf("file after refused Save changed: %s", after)
	}
}

func TestConfigStateSaveRefusesStaleHash(t *testing.T) {
	t.Parallel()
	base := BaseDir(t.TempDir())
	writeTestConfig(t, base, map[string]*Profile{"p1": testProfile("p1")})
	state, err := LoadConfigState(base)
	if err != nil {
		t.Fatal(err)
	}
	// The unchecked path overwrites the file; the stale state must
	// then refuse.
	other := &SingleConfig{Profiles: map[string]*Profile{"p2": testProfile("p2")}}
	if err := SaveSingleConfig(base, other); err != nil {
		t.Fatal(err)
	}
	if err := state.Save(state.Config); !errors.Is(err, ErrConcurrentChange) {
		t.Fatalf("Save with stale hash = %v; want ErrConcurrentChange", err)
	}
	loaded, _, err := LoadSingleConfig(base)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := loaded.Profiles["p2"]; !ok {
		t.Error("stale Save overwrote the newer file; want refusal")
	}
}

func TestConfigStateAbsentCreatedDeleted(t *testing.T) {
	t.Parallel()
	base := BaseDir(t.TempDir())
	path := filepath.Join(base, "config.json")

	// Absent at load, created before save: refuse.
	absent, err := LoadConfigState(base)
	if err != nil {
		t.Fatal(err)
	}
	if absent.Found || absent.Exists || absent.SHA256 != "" || absent.Config != nil {
		t.Fatalf("absent state = %+v; want all zero", absent)
	}
	writeTestConfig(t, base, map[string]*Profile{"p1": testProfile("p1")})
	if err := absent.Save(&SingleConfig{Profiles: map[string]*Profile{}}); !errors.Is(err, ErrConcurrentChange) {
		t.Fatalf("Save after file created = %v; want ErrConcurrentChange", err)
	}

	// Present at load, deleted before save: refuse.
	present, err := LoadConfigState(base)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := present.Save(present.Config); !errors.Is(err, ErrConcurrentChange) {
		t.Fatalf("Save after file deleted = %v; want ErrConcurrentChange", err)
	}
}

func TestLoadConfigStateLegacyAndMalformed(t *testing.T) {
	t.Parallel()
	base := BaseDir(t.TempDir())
	legacyPath := filepath.Join(base, "config.json")
	writeFile(t, legacyPath, `{"auto_approve":"always","node_id":"N1"}`, 0o600)
	state, err := LoadConfigState(base)
	if err != nil {
		t.Fatal(err)
	}
	// The legacy-flat state is kept deliberately (Q6): Exists
	// without Found is exactly "unmigrated legacy file". The
	// write-path guards (refuseUnmigrated) branch on it, and
	// LoadProfile — not LoadConfigState — is the refusal point.
	if state.Found || !state.Exists || state.Config != nil || state.SHA256 == "" {
		t.Fatalf("legacy state = %+v; want Found=false Exists=true Config=nil SHA256 set", state)
	}
	if _, err := LoadProfile(base, "default", lookupEnv(map[string]string{})); !errors.Is(err, ErrLegacyLayout) {
		t.Fatalf("LoadProfile over legacy-flat file = %v; want ErrLegacyLayout refusal", err)
	}

	writeFile(t, filepath.Join(base, "config.json"), `{not json`, 0o600)
	if _, err := LoadConfigState(base); err == nil {
		t.Error("malformed single file: LoadConfigState = nil error; want error, never silent fallback")
	}
}

// TestLoadConfigStateRefusesFIFO (R3): readConfigState must
// Stat/type-guard before opening baseDir/config.json. A FIFO (or a
// symlink to one) at the base path must be an exit-2 error naming
// the path, promptly — never a hang on open.
func TestLoadConfigStateRefusesFIFO(t *testing.T) {
	t.Parallel()

	runPrompt := func(t *testing.T, base string) error {
		t.Helper()
		done := make(chan error, 1)
		go func() {
			_, err := LoadConfigState(base)
			done <- err
		}()
		select {
		case err := <-done:
			return err
		case <-time.After(5 * time.Second):
			t.Fatal("LoadConfigState hung; want a prompt exit-2 error")
			return nil
		}
	}

	fifoBase := BaseDir(t.TempDir())
	fifoPath := filepath.Join(fifoBase, "config.json")
	if err := os.MkdirAll(fifoBase, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatal(err)
	}
	err := runPrompt(t, fifoBase)
	if err == nil {
		t.Fatal("LoadConfigState over a FIFO = nil error; want exit 2")
	}
	if ExitCode(err) != 2 {
		t.Errorf("LoadConfigState over a FIFO ExitCode = %d; want 2", ExitCode(err))
	}
	if !strings.Contains(err.Error(), fifoPath) {
		t.Errorf("LoadConfigState error = %q; want it to name %q", err.Error(), fifoPath)
	}

	// Symlink to a FIFO (Stat follows symlinks).
	linkBase := BaseDir(t.TempDir())
	realFIFO := filepath.Join(t.TempDir(), "real-fifo")
	if err := syscall.Mkfifo(realFIFO, 0o600); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(linkBase, "config.json")
	if err := os.MkdirAll(linkBase, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realFIFO, linkPath); err != nil {
		t.Fatal(err)
	}
	err = runPrompt(t, linkBase)
	if err == nil {
		t.Fatal("LoadConfigState over a symlink-to-FIFO = nil error; want exit 2")
	}
	if ExitCode(err) != 2 {
		t.Errorf("LoadConfigState over a symlink-to-FIFO ExitCode = %d; want 2", ExitCode(err))
	}
	if !strings.Contains(err.Error(), linkPath) {
		t.Errorf("LoadConfigState error = %q; want it to name %q", err.Error(), linkPath)
	}
}

func TestSaveSingleConfigCreatesLockFile(t *testing.T) {
	t.Parallel()
	base := BaseDir(t.TempDir())
	writeTestConfig(t, base, map[string]*Profile{"p1": testProfile("p1")})
	if _, err := os.Stat(filepath.Join(base, "config.json.lock")); err != nil {
		t.Errorf("lock file missing after SaveSingleConfig: %v", err)
	}
	if mode := fileMode(t, filepath.Join(base, "config.json")); mode != 0o600 {
		t.Errorf("config mode = %o; want 600", mode)
	}
}

func TestUpdateSingleConfigSerialisesWriters(t *testing.T) {
	t.Parallel()
	base := BaseDir(t.TempDir())
	const writers = 16
	var wg sync.WaitGroup
	errs := make([]error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := fmt.Sprintf("w%02d", i)
			errs[i] = UpdateSingleConfig(base, func(cfg *SingleConfig) error {
				if cfg.Profiles == nil {
					cfg.Profiles = make(map[string]*Profile)
				}
				cfg.Profiles[name] = testProfile(name)
				return nil
			})
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("writer %d: %v", i, err)
		}
	}
	loaded, found, err := LoadSingleConfig(base)
	if err != nil || !found {
		t.Fatalf("reload = %+v, %v, %v", loaded, found, err)
	}
	if len(loaded.Profiles) != writers {
		t.Errorf("profiles = %d; want %d (a lost update means serialisation failed)", len(loaded.Profiles), writers)
	}
	for i := 0; i < writers; i++ {
		if _, ok := loaded.Profiles[fmt.Sprintf("w%02d", i)]; !ok {
			t.Errorf("profile w%02d missing after concurrent updates", i)
		}
	}
}

func TestUpdateSingleConfigErrorWritesNothing(t *testing.T) {
	t.Parallel()
	base := BaseDir(t.TempDir())
	boom := errors.New("boom")
	err := UpdateSingleConfig(base, func(cfg *SingleConfig) error {
		cfg.Profiles["x"] = testProfile("x")
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("Update error = %v; want boom propagated", err)
	}
	if _, err := os.Stat(filepath.Join(base, "config.json")); !os.IsNotExist(err) {
		t.Errorf("config.json exists after errored update; want no write (stat err %v)", err)
	}

	// Existing file: error leaves bytes untouched.
	writeTestConfig(t, base, map[string]*Profile{"p1": testProfile("p1")})
	before, _ := os.ReadFile(filepath.Join(base, "config.json"))
	err = UpdateSingleConfig(base, func(cfg *SingleConfig) error { return boom })
	if !errors.Is(err, boom) {
		t.Fatalf("Update error = %v; want boom", err)
	}
	after, _ := os.ReadFile(filepath.Join(base, "config.json"))
	if string(before) != string(after) {
		t.Error("errored update modified the file; want no write")
	}
}

func TestUpdateSingleConfigRefusesBypassChange(t *testing.T) {
	t.Parallel()
	base := BaseDir(t.TempDir())
	writeTestConfig(t, base, map[string]*Profile{"p1": testProfile("p1")})
	path := filepath.Join(base, "config.json")
	before, _ := os.ReadFile(path)

	err := UpdateSingleConfig(base, func(cfg *SingleConfig) error {
		// A writer bypassing the lock (e.g. an editor writing in
		// place) changes the file while the update holds the lock.
		return os.WriteFile(path, []byte(`{"profiles":{}}`), 0o600)
	})
	if !errors.Is(err, ErrConcurrentChange) {
		t.Fatalf("Update after bypass change = %v; want ErrConcurrentChange", err)
	}
	after, _ := os.ReadFile(path)
	if string(after) != `{"profiles":{}}` {
		t.Errorf("bypass bytes overwritten: %s (want them untouched)", after)
	}
	if string(after) == string(before) {
		t.Error("test setup failed: bypass write did not change the file")
	}
}
