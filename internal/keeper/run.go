// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package keeper

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/thoitiettxl-cyber/castctl/internal/profile"
)

// Runner: `keeper run` — one goroutine per entry, foreground.
//
// Each entry ticks immediately, then waits its adaptive delay
// with ±20% jitter re-drawn per wait, until the context ends
// (SIGINT: the main.go contract, exit 130) or the entry stops
// sticky. A stopped entry's goroutine exits; the runner returns
// when every goroutine has exited or the context ends. The
// runner never holds the cookies-file lock across a wait: the
// single-flight guard is a heartbeat/owner file plus a SHORT
// flock hold per check (see singleFlight), never a flock held
// across a sleep.

// DepsFactory builds one entry's TickDeps. The command layer
// supplies it (runtime per profile, exporter per entry); the
// runner owns only scheduling.
type DepsFactory func(entry *profile.KeeperEntry, prof *profile.Profile) (TickDeps, error)

// RunResult is one entry's run outcome for the command layer's
// summary line (counts/names only, never values).
type RunResult struct {
	Tag     string
	Stopped bool
	Ticks   int
	Last    TickResult
}

// Run runs the keeper for entries until ctx ends or every entry
// stops. It returns one result per entry, in entry order.
// onTick, when non-nil, is called after every tick with the
// entry and its result (the command layer's summary line).
func Run(ctx context.Context, entries []*profile.KeeperEntry, profiles map[string]*profile.Profile, baseDir string, factory DepsFactory, onTick func(*profile.KeeperEntry, TickResult)) []RunResult {
	results := make([]RunResult, len(entries))
	var wg sync.WaitGroup
	for i, entry := range entries {
		wg.Add(1)
		go func(i int, entry *profile.KeeperEntry) {
			defer wg.Done()
			results[i] = runEntry(ctx, entry, profiles[entry.Profile], baseDir, factory, onTick)
		}(i, entry)
	}
	wg.Wait()
	return results
}

func runEntry(ctx context.Context, entry *profile.KeeperEntry, prof *profile.Profile, baseDir string, factory DepsFactory, onTick func(*profile.KeeperEntry, TickResult)) RunResult {
	res := RunResult{Tag: entry.Tag}
	deps, err := factory(entry, prof)
	if err != nil {
		res.Last = TickResult{Outcome: OutcomeError, Err: err}
		return res
	}
	clock := deps.Clock
	if clock == nil {
		clock = RealClock
	}
	for {
		if ctx.Err() != nil {
			return res
		}
		result := Tick(ctx, deps)
		res.Ticks++
		res.Last = result
		if onTick != nil {
			onTick(entry, result)
		}
		if result.Stopped {
			res.Stopped = true
			NotifyStopped(ctx, deps, deps.Notifier)
			return res
		}
		if result.Recovered && deps.Notifier != nil {
			// Best-effort, outside the tick and its locks.
			_ = deps.Notifier.Notify(ctx, NoticeReexported, prof.Name)
		}
		if ctx.Err() != nil {
			return res
		}
		delay := result.NextDelay
		if delay <= 0 {
			delay = entry.EffectiveInterval()
		}
		// ±20% jitter, re-drawn per wait. The interval cap
		// (MaxKeeperInterval) keeps this multiplication in
		// range; the non-positive guard is defence in depth
		// against a pathological NextDelay.
		j := 1 + (rand.Float64()*2-1)*0.2
		delay = time.Duration(float64(delay) * j)
		if delay <= 0 {
			delay = entry.EffectiveInterval()
		}
		select {
		case <-ctx.Done():
			return res
		case <-clock.After(delay):
		}
	}
}

// singleFlight guards a second `keeper run` for the same entry.
//
// The guard is a heartbeat/owner file, NOT a held flock: the
// flock is held only for the short check-and-update window
// while reading/writing the owner file, and is released before
// the caller sleeps or ticks. The owner file carries the PID
// and the last heartbeat (Unix seconds). A second runner
// refuses when the heartbeat is fresh (<= OwnerStaleAfter)
// AND the recorded PID is alive; a stale heartbeat, or a dead
// PID, means the previous runner is gone and the file is taken
// over. The file is removed on a clean release; a crash leaves
// it for the staleness rule to reclaim.
const (
	// OwnerStaleAfter bounds owner-file freshness.
	OwnerStaleAfter = 120 * time.Second
	// OwnerHeartbeatInterval is the refresh cadence while a
	// runner holds an entry.
	OwnerHeartbeatInterval = 60 * time.Second
)

type ownerFile struct {
	PID       int   `json:"pid"`
	Heartbeat int64 `json:"heartbeat_unix"`
}

func ownerPath(profileDir, tag string) (string, error) {
	// Defence in depth: the tag is validated at parse time,
	// but a hand-built entry must never escape the profile
	// directory through this path. The containment check
	// rejects any tag that would place the owner file
	// outside profileDir, whatever validation was skipped.
	cleanDir := filepath.Clean(profileDir)
	p := filepath.Join(cleanDir, "keeper-"+tag+".owner")
	if filepath.Dir(p) != cleanDir {
		return "", fmt.Errorf("keeper tag %q escapes the profile directory", tag)
	}
	return p, nil
}

// AcquireSingleFlight claims the entry. It returns a release
// function (stop the heartbeat, remove the file) or an error
// naming the live owner PID when the entry is already running.
func AcquireSingleFlight(profileDir, tag string, clock Clock) (release func(), err error) {
	if clock == nil {
		clock = RealClock
	}
	// Tags are validated here as well as at parse time: the
	// login flow passes the constant "login", and hand-built
	// entries must be refused before ownerPath is computed.
	if err := profile.ValidateKeeperTag(tag); err != nil {
		return nil, err
	}
	path, err := ownerPath(profileDir, tag)
	if err != nil {
		return nil, err
	}
	releaseLock, err := profile.LockShortFile(path, time.Second)
	if err != nil {
		return nil, err
	}
	// Short flock hold: check + update only. The lock is
	// released before the caller sleeps or ticks.
	raw, _ := os.ReadFile(path)
	var owner ownerFile
	if len(raw) > 0 {
		if json.Unmarshal(raw, &owner) == nil && owner.PID > 0 {
			age := clock.Now().Unix() - owner.Heartbeat
			if age <= int64(OwnerStaleAfter/time.Second) && pidAlive(owner.PID) {
				releaseLock()
				return nil, fmt.Errorf("keeper entry %q is already running (pid %d)", tag, owner.PID)
			}
		}
	}
	now := clock.Now().Unix()
	data, _ := json.Marshal(ownerFile{PID: os.Getpid(), Heartbeat: now})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		releaseLock()
		return nil, err
	}
	releaseLock()

	done := make(chan struct{})
	var once sync.Once
	refresh := func() {
		ticker := time.NewTicker(OwnerHeartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				// Locked, ownership-checked refresh: a
				// stale (SIGSTOPped) runner that resumes
				// after a takeover must not overwrite the
				// new owner's heartbeat.
				refreshOwner(path, os.Getpid(), clock)
			}
		}
	}
	go refresh()
	release = func() {
		once.Do(func() {
			close(done)
			releaseOwner(path, os.Getpid())
		})
	}
	return release, nil
}

// refreshOwner rewrites the owner file's heartbeat under the
// short flock, only when the file still names pid. False when
// the file is owned by someone else, unreadable, or the lock
// could not be taken: the caller keeps ticking either way (a
// missed heartbeat only risks a takeover after
// OwnerStaleAfter, which the PID-liveness check still guards).
func refreshOwner(path string, pid int, clock Clock) bool {
	releaseLock, err := profile.LockShortFile(path, time.Second)
	if err != nil {
		return false
	}
	defer releaseLock()
	raw, _ := os.ReadFile(path)
	var owner ownerFile
	if len(raw) == 0 || json.Unmarshal(raw, &owner) != nil || owner.PID != pid {
		return false
	}
	data, _ := json.Marshal(ownerFile{PID: pid, Heartbeat: clock.Now().Unix()})
	return os.WriteFile(path, data, 0o600) == nil
}

// releaseOwner removes the owner file under the short flock,
// only when it still names pid (or is empty: an empty file
// names no owner). A stale runner resuming after a takeover
// must never delete the new owner's file.
func releaseOwner(path string, pid int) bool {
	releaseLock, err := profile.LockShortFile(path, time.Second)
	if err != nil {
		return false
	}
	defer releaseLock()
	raw, _ := os.ReadFile(path)
	if len(raw) > 0 {
		var owner ownerFile
		if json.Unmarshal(raw, &owner) != nil || owner.PID != pid {
			return false
		}
	}
	return os.Remove(path) == nil
}

// pidAlive reports whether pid exists. On non-unix targets the
// check is unavailable and the PID is treated as alive (fail
// closed: a fresh heartbeat alone refuses a second runner).
func pidAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// Signal 0 probes existence on unix; on Windows it always
	// succeeds, which is the fail-closed direction here.
	return proc.Signal(syscall.Signal(0)) == nil
}

// Status is the `keeper status` read model: state file only, no
// network. Field names match the state file.
type Status struct {
	Tag                 string     `json:"tag"`
	Profile             string     `json:"profile"`
	LoggedOut           bool       `json:"logged_out"`
	KeeperStopped       bool       `json:"keeper_stopped"`
	KeeperStoppedReason string     `json:"keeper_stopped_reason,omitempty"`
	LastCheckedAt       *time.Time `json:"last_checked_at,omitempty"`
	LastTickOutcome     string     `json:"last_tick_outcome"`
	EarliestExpiry      *time.Time `json:"earliest_expiry,omitempty"`
	DrivingCookie       string     `json:"driving_cookie,omitempty"`
	DrivingExpiry       *time.Time `json:"driving_expiry,omitempty"`
	WarnPending         bool       `json:"warn_pending,omitempty"`
	WarnSent            bool       `json:"warn_sent,omitempty"`
	NextCheckAt         *time.Time `json:"next_check_at,omitempty"`
	// StateCorrupt reports a corrupt or unknown-version state
	// file: status still reports (with the state_corrupt
	// reason) instead of erroring, and the remedy is to
	// delete session-state.json (the keeper re-observes from
	// the cookies file). See docs/config.md.
	StateCorrupt bool `json:"state_corrupt,omitempty"`
}

// ReadStatus reads one entry's status from its profile's state
// file. A missing state file is a never-ticked entry, not an
// error. A corrupt or unknown-version state file is reported
// distinctly (StateCorrupt + state_corrupt reason), not an
// error: the remedy is documented in docs/config.md. It
// performs no network I/O.
func ReadStatus(baseDir string, entry *profile.KeeperEntry) (Status, error) {
	paths, err := profile.ProfilePaths(baseDir, entry.Profile)
	if err != nil {
		return Status{}, err
	}
	st, err := LoadState(paths.Dir)
	if err != nil {
		if IsStateCorrupt(err) {
			return Status{
				Tag: entry.Tag, Profile: entry.Profile,
				KeeperStoppedReason: StoppedStateCorrupt, StateCorrupt: true,
			}, nil
		}
		return Status{}, err
	}
	return Status{
		Tag: entry.Tag, Profile: entry.Profile,
		LoggedOut: st.LoggedOut, KeeperStopped: st.KeeperStopped,
		KeeperStoppedReason: st.KeeperStoppedReason,
		LastCheckedAt:       st.LastCheckedAt,
		LastTickOutcome:     st.LastTickOutcome,
		EarliestExpiry:      st.EarliestExpiry,
		DrivingCookie:       st.DrivingCookie, DrivingExpiry: st.DrivingExpiry,
		WarnPending: st.WarnPending, WarnSent: st.WarnSent,
		NextCheckAt: st.NextCheckAt,
	}, nil
}
