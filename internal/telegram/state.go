// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package telegram

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

// Persistent bot runtime state.
//
// Python 0.6.1 keeps this in telegram-state.json beside the
// profile config (src/muse_cli/tgbot.py:151-154, 593-641): the
// per-chat session mapping, watermarks, runtime toggles, and the
// poll offset. Castctl keeps the same split — config in
// config.json (the telegram block, token-bearing), runtime state
// in a sibling file that never holds a secret — derived from the
// resolved config location through the profile directory (the
// chat.json / keeper session-state.json precedent: a state file
// next to the profile's other files, never inside config.json).
// No new config field exists for it.
//
// Crash semantics mirror Python: the poll offset is persisted
// BEFORE an update is handled (tgbot.py:2445-2450), so a crash
// mid-handle loses that update instead of redelivering it
// (at-most-once per update id). Every other mutation rewrites
// the whole file atomically (temp file + rename in the same
// directory, mode 0600). A crash between a mutation and its save
// loses the mutation; a crash during a save leaves either the
// old or the new whole file, never a torn one.
//
// A missing or empty file is a fresh state. A present file
// with corrupt JSON loads as fresh state and reports corrupt:
// the bot keeps running on fresh state (Python's read_json is
// likewise lenient, tgbot.py:138-145) and the caller logs the
// corruption once, stating that the offset resets to 0 and
// any stored mappings, watermarks, and toggles are discarded
// (their counts are unknowable from unreadable JSON). An
// unknown schema version is NOT lenient: it is an error, and
// the bot refuses to start rather than silently discard the
// stored offset, mappings, watermarks, and toggles — the
// error names the version and the counts that would be lost.
// Unknown fields are ignored on load (forward tolerance). The
// stored offset is the last handled update_id; the polling
// library adds 1 when it resumes, matching
// Settings.InitialOffset.

// telegramStateVersion is the frozen schema version.
const telegramStateVersion = 1

// telegramStateFileName is the state file name within a profile dir.
const telegramStateFileName = "telegram-state.json"

// mainWatermarkKey is the watermark key for the main chat
// (Python's MAIN = "main" sentinel, tgbot.py:56).
const mainWatermarkKey = "main"

// WatermarkKey returns the watermark key for a session: the
// session id, or "main" for the main chat (empty session id).
func WatermarkKey(sessionID string) string {
	if sessionID == "" {
		return mainWatermarkKey
	}
	return sessionID
}

// StatePath returns the state file path for a profile directory.
func StatePath(profileDir string) string {
	return filepath.Join(profileDir, telegramStateFileName)
}

// ChatEntry is one Telegram chat's session mapping: the Muse
// session it talks to ("" = main chat) and its display title.
// Many Telegram chats may map to one session (Python
// state["chats"], tgbot.py:670-681); an unseen chat defaults to
// the main chat and is not written until it switches.
type ChatEntry struct {
	SessionID string `json:"session_id,omitempty"`
	Title     string `json:"title"`
}

// telegramStateFile is the on-disk v1 body. Toggle fields are
// pointers: nil means "never toggled at runtime" (the telegram
// block's values apply), non-nil means the state file wins after
// the first runtime toggle (gate D4).
type telegramStateFile struct {
	Version       int                  `json:"version"`
	Offset        int64                `json:"offset,omitempty"`
	Chats         map[string]ChatEntry `json:"chats,omitempty"`
	Watermarks    map[string]int64     `json:"watermarks,omitempty"`
	AutoApprove   *bool                `json:"auto_approve,omitempty"`
	AutoAllowOnce *bool                `json:"auto_allow_once,omitempty"`
	Watch         *bool                `json:"watch,omitempty"`
}

// StateStore is the loaded state file plus its path. All methods
// are safe for concurrent use; every mutation saves atomically
// before returning. The in-memory copy is the authority between
// saves; a save failure is returned and the in-memory copy keeps
// the mutation (the next mutation retries the save).
type StateStore struct {
	mu   sync.Mutex
	path string
	st   telegramStateFile
}

// isJSONIntegerLiteral reports whether b is a JSON integer
// literal: an optional minus followed by ASCII digits. It
// rejects floats (2.0), exponents (2e0), strings, booleans,
// and null, so a mistyped version field can never pass the
// shape check in LoadStateStore.
func isJSONIntegerLiteral(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	i := 0
	if b[0] == '-' {
		i = 1
	}
	if i == len(b) {
		return false
	}
	for ; i < len(b); i++ {
		if b[i] < '0' || b[i] > '9' {
			return false
		}
	}
	return true
}

// LoadStateStore reads the state file in profileDir. A missing or
// empty file yields a fresh store with corrupt=false. A present
// file with corrupt JSON yields a fresh store with corrupt=true.
// A present file with an unknown schema version is an error: the
// caller must not run on silently discarded state. Any other
// read failure is an error: the caller must not run on silently
// unpersistable state.
func LoadStateStore(profileDir string) (*StateStore, bool, error) {
	path := StatePath(profileDir)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return newStateStore(path), false, nil
		}
		return nil, false, err
	}
	if len(data) == 0 {
		return newStateStore(path), false, nil
	}
	// Two-phase parse: the version field's SHAPE is checked
	// before the body is decoded. A single unmarshal into
	// telegramStateFile would turn a string ("2") or float
	// (2.0) version into a JSON type error, reported as
	// corrupt — and the corrupt path loads fresh, silently
	// discarding the state the unknown-version refusal
	// exists to protect. Any present version that is not a
	// JSON integer literal refuses, like an unknown numeric
	// version; the file is left unmutated. A missing version
	// decodes as 0 below and refuses as before.
	var probe struct {
		Version json.RawMessage `json:"version"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return newStateStore(path), true, nil
	}
	if len(probe.Version) > 0 && !isJSONIntegerLiteral(probe.Version) {
		return nil, false, fmt.Errorf("telegram: state file version has non-integer shape %s; refusing to start rather than discard state", string(probe.Version))
	}
	var st telegramStateFile
	if err := json.Unmarshal(data, &st); err != nil {
		return newStateStore(path), true, nil
	}
	if st.Version != telegramStateVersion {
		toggles := 0
		if st.AutoApprove != nil {
			toggles++
		}
		if st.AutoAllowOnce != nil {
			toggles++
		}
		if st.Watch != nil {
			toggles++
		}
		return nil, false, fmt.Errorf("telegram: state file version %d is not supported (want %d); refusing to start rather than discard %d chat mappings, %d watermarks, offset %d, and %d runtime toggles", st.Version, telegramStateVersion, len(st.Chats), len(st.Watermarks), st.Offset, toggles)
	}
	store := newStateStore(path)
	store.st = st
	if store.st.Chats == nil {
		store.st.Chats = map[string]ChatEntry{}
	}
	if store.st.Watermarks == nil {
		store.st.Watermarks = map[string]int64{}
	}
	return store, false, nil
}

func newStateStore(path string) *StateStore {
	return &StateStore{
		path: path,
		st: telegramStateFile{
			Version:    telegramStateVersion,
			Chats:      map[string]ChatEntry{},
			Watermarks: map[string]int64{},
		},
	}
}

// saveLocked writes the whole state atomically (temp file +
// rename in the same directory, mode 0600, synced before
// rename), like the keeper state writer. The caller holds s.mu.
func (s *StateStore) saveLocked() error {
	s.st.Version = telegramStateVersion
	data, err := json.MarshalIndent(s.st, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".telegram-state-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return err
	}
	return nil
}

// Offset returns the last handled update_id (0 = none).
func (s *StateStore) Offset() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.Offset
}

// NoteOffset advances the stored offset to id when id is newer,
// and saves. Smaller or equal ids are no-ops. A save failure is
// returned; the in-memory offset still advances (the next
// mutation retries the save).
func (s *StateStore) NoteOffset(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id <= s.st.Offset {
		return nil
	}
	s.st.Offset = id
	return s.saveLocked()
}

// Chat returns the stored mapping for a Telegram chat, or false
// when the chat has never switched (callers default to main).
func (s *StateStore) Chat(chatID int64) (ChatEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.st.Chats[strconv.FormatInt(chatID, 10)]
	return entry, ok
}

// SetChat stores a chat's session mapping and saves.
func (s *StateStore) SetChat(chatID int64, entry ChatEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.Chats[strconv.FormatInt(chatID, 10)] = entry
	return s.saveLocked()
}

// Watermark returns the stored watermark for a watermark key
// (see WatermarkKey), or 0 when none was ever set.
func (s *StateStore) Watermark(key string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.Watermarks[key]
}

// SetWatermark advances the watermark for key to seq when seq is
// newer, and saves only then. Watermarks are monotonic-max
// (Python set_watermark, tgbot.py:683-694): they never move
// backward, and a seq is recorded only after its delivery
// succeeded (callers advance after delivery, capped at the last
// seq the turn delivered).
func (s *StateStore) SetWatermark(key string, seq int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if seq <= s.st.Watermarks[key] {
		return nil
	}
	s.st.Watermarks[key] = seq
	return s.saveLocked()
}

// Toggles returns the runtime-toggled values, or nil per field
// when that toggle was never set at runtime (the telegram block's
// values apply then). Returned pointers are fresh copies.
func (s *StateStore) Toggles() (autoApprove, autoAllowOnce, watch *bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return copyBool(s.st.AutoApprove), copyBool(s.st.AutoAllowOnce), copyBool(s.st.Watch)
}

func copyBool(p *bool) *bool {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

// SetToggles records a runtime toggle change (both toggles are
// written together, as one user action) and saves. After this,
// the state file wins over the telegram block for both toggles
// until the process restarts into a fresh load — the stored
// values persist across restarts.
func (s *StateStore) SetToggles(autoApprove, autoAllowOnce bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.AutoApprove = &autoApprove
	s.st.AutoAllowOnce = &autoAllowOnce
	return s.saveLocked()
}

// SetWatch records a runtime /watch toggle change and saves.
func (s *StateStore) SetWatch(watch bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.Watch = &watch
	return s.saveLocked()
}
