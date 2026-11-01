// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
)

// Concurrent-write guard for the single-file config.json (CLIProxyAPI
// ideas 6-7, plan decision (b)).
//
// Every guarded write holds, for the whole read-modify-write:
//
//   - configWriteMu, the in-process mutex (serialises writers in this
//     process, including writers that reach the file through
//     different spellings of the same directory), and
//   - an inter-process flock (LOCK_EX, blocking) on
//     baseDir/config.json.lock, created mode 0600. The lock file is
//     never deleted: deleting it would let a later opener lock a
//     different inode while an earlier holder still holds the old
//     one.
//
// Checked writes additionally record the sha256 of the bytes read and
// re-read under the lock before writing: if the file changed since
// the load (created, deleted, or different bytes), the write is
// refused with ErrConcurrentChange (exit 2 at command level) and the
// file is left untouched. The caller retries the whole command.
//
// Which paths check, and which do not:
//
//   - CHECKED: ConfigState.Save (load once, decide, save) and
//     UpdateSingleConfig (load, mutate, and write in one call, under
//     one lock hold; the re-read is defence against writers that
//     bypass the lock, e.g. a text editor).
//   - LOCK ONLY, NO HASH CHECK: SaveSingleConfig. It serialises
//     writers but overwrites whatever is on disk. It is the write
//     path for callers that hold no prior read. Migrate does NOT
//     use it: write-mode Migrate holds the lock across its whole
//     decide+write (see migrate.go) and writes with
//     writeSingleConfigLocked under that hold, so a concurrent
//     migrate re-reads the winner's file and a concurrent
//     profile add is never clobbered. New profile write
//     commands MUST use the checked paths, never SaveSingleConfig.
//   - NO LOCK: all reads (LoadSingleConfig, LoadProfile, Migrate's
//     reads). A read that races a write sees either the old or the
//     new atomic rename, never a torn file; staleness is caught by
//     the hash check at write time, not by locking reads.
//
// flock is implemented with syscall.Flock on unix build targets
// (flock_unix.go); on any other target lock acquisition fails closed
// with a config error, so a guarded write never silently runs
// unlocked. No cgo is involved.
var configWriteMu sync.Mutex

// ConfigState is a load-time snapshot of baseDir/config.json for one
// checked write. It is created by LoadConfigState and consumed by
// Save; the two calls must use the same state value, and Save must
// be given the same baseDir the state was loaded from (it is stored
// in the state, so callers cannot mix directories by accident).
type ConfigState struct {
	// Found reports whether a parseable single file existed at load.
	Found bool
	// Exists reports whether config.json existed at load in any
	// form (single file or legacy-flat). Found implies Exists.
	// Exists without Found is exactly the unmigrated legacy-flat
	// state: LoadProfile refuses it, and the write-path guards
	// (refuseUnmigrated) branch on it.
	Exists bool
	// SHA256 is the lowercase hex sha256 of the raw bytes read at
	// load, or "" when the file was absent.
	SHA256 string
	// Config is the parsed single file when Found, nil otherwise.
	// A legacy-flat file leaves Config nil: callers must not treat
	// a nil Config as an empty single file, and must not write
	// over the legacy file without the refuseUnmigrated guard.
	Config *SingleConfig

	baseDir string
}

// LoadConfigState reads baseDir/config.json once and records its
// sha256. It returns Found=false when the file is absent or is a
// legacy-flat config, and an error when a single file is present but
// unparseable (never a silent fallback). Found=false with
// Exists=true is the unmigrated legacy-flat state, kept deliberately:
// the write-path guards branch on it, and LoadProfile — not this
// function — refuses legacy reads. It takes no lock.
func LoadConfigState(baseDir string) (*ConfigState, error) {
	state, _, err := readConfigState(baseDir)
	return state, err
}

// readConfigState reads the file and returns the state plus the raw
// bytes (nil when absent). An unparseable single file is an error.
func readConfigState(baseDir string) (*ConfigState, []byte, error) {
	state := &ConfigState{baseDir: baseDir}
	path := filepath.Join(baseDir, "config.json")
	data, err := readRegularFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return state, nil, nil
		}
		return nil, nil, newConfigErrorf("read config: %v", err)
	}
	state.Exists = true
	state.SHA256 = sha256Hex(data)
	marker, err := HasProfilesMarker(data)
	if err != nil {
		return nil, nil, err
	}
	if !marker {
		return state, data, nil
	}
	cfg, err := ParseSingleConfig(data, baseDir)
	if err != nil {
		return nil, nil, err
	}
	state.Found = true
	state.Config = cfg
	return state, data, nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Save writes cfg to the config.json this state was loaded from,
// refusing (ErrConcurrentChange, file untouched) when the file has
// changed since the load. On success the state is refreshed to the
// just-written bytes, so the same state can be Saved again for a
// further sequential write. cfg must not be nil.
func (s *ConfigState) Save(cfg *SingleConfig) error {
	if s == nil {
		return newConfigError("cannot save with nil config state")
	}
	if cfg == nil {
		return newConfigError("cannot save nil config")
	}
	release, err := lockConfigDir(s.baseDir)
	if err != nil {
		return err
	}
	defer release()
	current, _, err := readConfigState(s.baseDir)
	if err != nil {
		return err
	}
	if current.Exists != s.Exists || current.Found != s.Found || current.SHA256 != s.SHA256 {
		return newConcurrentChangeError(s.baseDir)
	}
	hash, err := writeSingleConfigLocked(s.baseDir, cfg)
	if err != nil {
		return err
	}
	s.Exists = true
	s.Found = true
	s.SHA256 = hash
	s.Config = cfg
	return nil
}

// UpdateSingleConfig performs one guarded read-modify-write: under a
// single lock hold it loads the current single file (or a fresh empty
// config when no single file exists), calls update to mutate it in
// place, re-reads the file bytes to confirm nothing changed under
// the lock, and writes. update returning an error writes nothing.
// update must not call SaveSingleConfig, ConfigState.Save, or
// UpdateSingleConfig itself (the lock is already held; nested calls
// deadlock), and must not read proxy environment variables.
//
// When no single file exists, update receives a fresh empty
// SingleConfig (no profiles, no default_profile). A legacy-flat file
// is NOT loaded into it: callers that must refuse on an unmigrated
// old layout (e.g. AddProfile) check for it themselves, inside
// update, before mutating.
func UpdateSingleConfig(baseDir string, update func(cfg *SingleConfig) error) error {
	if update == nil {
		return newConfigError("UpdateSingleConfig requires an update function")
	}
	release, err := lockConfigDir(baseDir)
	if err != nil {
		return err
	}
	defer release()
	state, data, err := readConfigState(baseDir)
	if err != nil {
		return err
	}
	var cfg *SingleConfig
	if state.Found {
		cfg = state.Config
	} else {
		cfg = &SingleConfig{Profiles: make(map[string]*Profile)}
	}
	if err := update(cfg); err != nil {
		return err
	}
	// Re-read under the lock: the only way the bytes changed since
	// the load is a writer that bypassed the lock (e.g. an editor
	// writing in place). Refuse rather than overwrite its change.
	// The re-read is Stat/type-guarded like every other config.json
	// read: a FIFO swapped in for the file must not hang the write.
	current, err := readRegularFile(filepath.Join(baseDir, "config.json"))
	if err != nil && !os.IsNotExist(err) {
		return newConfigErrorf("read config: %v", err)
	}
	if sha256Hex(current) != sha256Hex(data) {
		return newConcurrentChangeError(baseDir)
	}
	_, err = writeSingleConfigLocked(baseDir, cfg)
	return err
}

// lockConfigDir acquires the in-process mutex and the inter-process
// flock for baseDir, and returns a release function that drops the
// flock (by closing the lock file) and then the mutex. The caller
// must call release exactly once. The base directory is created if
// needed, so locking a fresh directory works.
func lockConfigDir(baseDir string) (release func(), err error) {
	configWriteMu.Lock()
	releaseMu := func() { configWriteMu.Unlock() }
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		releaseMu()
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(baseDir, "config.json.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		releaseMu()
		return nil, err
	}
	if err := flockExclusive(f); err != nil {
		_ = f.Close()
		releaseMu()
		return nil, newConfigErrorf("lock config: %v", err)
	}
	return func() {
		_ = f.Close()
		releaseMu()
	}, nil
}

// writeSingleConfigLocked encodes cfg and writes it atomically
// (temp file + rename, mode 0600) to baseDir/config.json. The caller
// must hold the config lock. It returns the hex sha256 of the bytes
// written.
func writeSingleConfigLocked(baseDir string, cfg *SingleConfig) (string, error) {
	if cfg == nil {
		return "", newConfigError("cannot save nil config")
	}
	if cfg.Profiles == nil {
		cfg.Profiles = make(map[string]*Profile)
	}
	data, err := encodeSingleConfig(cfg)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return "", err
	}
	if err := writeFileAtomic(filepath.Join(baseDir, "config.json"), data, 0o600); err != nil {
		return "", err
	}
	return sha256Hex(data), nil
}

// encodeSingleConfig renders cfg in the canonical saved encoding:
// fixed top-level key order (buildSingleFileOrdered), indent 2,
// and exactly one trailing newline, matching `sing-box format -w`
// output shape. Raw blocks keep their input key order; only
// synthesized blocks render in canonical within-block order.
// The trailing newline is appended here, not in
// encodeOrderedJSONIndent, so display encodings (redaction)
// keep their existing byte shape — but every file written
// through this function (saves and migrate writes alike)
// gains the newline.
func encodeSingleConfig(cfg *SingleConfig) ([]byte, error) {
	root, err := buildSingleFileOrdered(cfg)
	if err != nil {
		return nil, err
	}
	data, err := encodeOrderedJSONIndent(root, 2)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
