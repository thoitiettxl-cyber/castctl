// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package keeper

import (
	"context"
	"sync"
)

// Transport: the frozen screencast-login session boundary (R3).
//
// One interface carries frames out, phase notices out, and
// input + Done/Cancel in. It is frozen so the web UI relay
// (item 2) can implement it over HTTP/WebSocket without
// changing the session core, and so tests use a fake.
//
//   - Frames are latest-only: SendFrame must never block the
//     screencast loop on a slow consumer. Implementations
//     drop stale frames (a size-1 slot) and keep the newest.
//   - Ack discipline lives in the runner, not the transport:
//     the runner acks every frame after its forward attempt,
//     whether the transport kept or dropped it.
//   - Done/Cancel arrive as input events (KindDone/KindCancel),
//     never as a separate channel the core must also watch:
//     one input stream, one select.
//   - The 60s reconnect grace is a TRANSPORT parameter: a
//     transport that drops and reconnects must resume the
//     same session within 60s or the session fails. The core
//     never reconnects anything itself.
//   - No logging calls in frame/input paths: frames and
//     keystrokes are sensitive. The audit test proves marker
//     payloads appear nowhere.

// SessionPhase is the login session's user-visible phase.
type SessionPhase string

const (
	PhaseLoading      SessionPhase = "loading"
	PhaseReady        SessionPhase = "ready"
	PhaseLoggedInHint SessionPhase = "logged_in_detected"
	PhaseDone         SessionPhase = "done"
	PhaseFailed       SessionPhase = "failed"
	PhaseCancelled    SessionPhase = "cancelled"
)

// Frame is one screencast JPEG frame. Data is the raw JPEG
// bytes (base64-decoded by the runner); SessionID is the CDP
// frame number, used only for the ack.
type Frame struct {
	Data      []byte
	SessionID int64
	Width     int
	Height    int
}

// InputKind is the closed set of input event kinds.
type InputKind string

const (
	InputMouse  InputKind = "mouse"
	InputKey    InputKind = "key"
	InputText   InputKind = "text"
	InputDone   InputKind = "done"
	InputCancel InputKind = "cancel"
)

// InputEvent is one user input, a Done trigger, or a Cancel.
// MouseType/KeyType use the CDP Input domain vocabularies
// ("mousePressed", "mouseReleased", "mouseMoved",
// "mouseWheel", "keyDown", "keyUp", "rawKeyDown", "char").
// Modifiers is the CDP bitmask (Alt=1, Ctrl=2, Meta=4,
// Shift=8). No event carries a secret: text is the user's own
// keystrokes, handled only by the runner's dispatch path and
// never logged.
type InputEvent struct {
	Kind       InputKind
	MouseType  string
	Button     string
	X, Y       float64
	ClickCount int
	DeltaX     float64
	DeltaY     float64
	KeyType    string
	Key        string
	Text       string
	Modifiers  int
}

// Transport is the frozen session boundary.
type Transport interface {
	// SendFrame delivers the newest frame; implementations
	// drop stale frames rather than blocking.
	SendFrame(ctx context.Context, frame Frame) error
	// SendPhase delivers a phase notice (ready, hint, done,
	// failed, cancelled). detail is a fixed string, never a
	// secret or an error value.
	SendPhase(ctx context.Context, phase SessionPhase, detail string) error
	// Inputs is the single input stream: mouse/key/text plus
	// Done and Cancel events.
	Inputs() <-chan InputEvent
	// Done closes when the transport itself dies (the relay
	// went away, the stdin driver hit EOF). The session ends
	// without saving.
	Done() <-chan struct{}
}

// FakeTransport is the test/support Transport: a size-1
// latest-frame slot, a buffered input channel, and a done
// channel. It is exported so embedders (item 2) and command
// tests can drive sessions without a browser or a network.
type FakeTransport struct {
	frameMu sync.Mutex
	frame   *Frame
	dropped int

	inputs   chan InputEvent
	done     chan struct{}
	phasesMu sync.Mutex
	phases   []SessionPhase

	closeOnce sync.Once
}

// NewFakeTransport returns a FakeTransport with an input
// buffer of size n.
func NewFakeTransport(n int) *FakeTransport {
	return &FakeTransport{inputs: make(chan InputEvent, n), done: make(chan struct{})}
}

func (f *FakeTransport) SendFrame(_ context.Context, frame Frame) error {
	f.frameMu.Lock()
	defer f.frameMu.Unlock()
	if f.frame != nil {
		f.dropped++
	}
	cp := frame
	f.frame = &cp
	return nil
}

// LatestFrame returns the newest frame delivered, or nil.
func (f *FakeTransport) LatestFrame() *Frame {
	f.frameMu.Lock()
	defer f.frameMu.Unlock()
	return f.frame
}

// DroppedFrames counts frames replaced before delivery.
func (f *FakeTransport) DroppedFrames() int {
	f.frameMu.Lock()
	defer f.frameMu.Unlock()
	return f.dropped
}

func (f *FakeTransport) SendPhase(_ context.Context, phase SessionPhase, _ string) error {
	f.phasesMu.Lock()
	defer f.phasesMu.Unlock()
	f.phases = append(f.phases, phase)
	return nil
}

// Phases returns the phases delivered, in order.
func (f *FakeTransport) Phases() []SessionPhase {
	f.phasesMu.Lock()
	defer f.phasesMu.Unlock()
	cp := make([]SessionPhase, len(f.phases))
	copy(cp, f.phases)
	return cp
}

func (f *FakeTransport) Inputs() <-chan InputEvent { return f.inputs }

// SendInput queues an input event for the session.
func (f *FakeTransport) SendInput(ev InputEvent) { f.inputs <- ev }

func (f *FakeTransport) Done() <-chan struct{} { return f.done }

// CloseDone closes the transport-death channel.
func (f *FakeTransport) CloseDone() {
	f.closeOnce.Do(func() { close(f.done) })
}
