package gateway

import (
	"errors"
	"fmt"

	"github.com/thoitiettxl-cyber/muse-cli/go/internal/conn"
)

// Phase records how far a gateway call got before it failed
// (S1, CLIProxyAPI "retry only before commit"). It is metadata
// only: it never changes the error type, the exit-code mapping, or
// conn.SharedConn's retry decision, and it is attached through a
// wrapper that preserves errors.As/errors.Is for every conn error
// type.
//
//   - PhaseNotSent: nothing was written to the wire. The call is
//     safe to repeat; this is the phase of a *conn.ConnectionDown
//     returned before the stream opens (Python: retry, max 3).
//   - PhaseSentNoReply: the request frame was written (or the
//     write was attempted) but no response frame arrived. The
//     call must NEVER be re-sent: for chat.stream this means the
//     frame may already have created server-side state, and
//     recovery is ack-poll + wait (PR4), not a re-send.
//   - PhaseStreaming: at least one response frame arrived. The
//     call is mid-stream; recovery re-observes state, it never
//     replays the request.
type Phase int

const (
	// PhaseNotSent: no byte was sent.
	PhaseNotSent Phase = iota
	// PhaseSentNoReply: sent (or send attempted), no reply frame.
	PhaseSentNoReply
	// PhaseStreaming: at least one reply frame arrived.
	PhaseStreaming
)

// String renders the phase name for logs.
func (p Phase) String() string {
	switch p {
	case PhaseNotSent:
		return "not_sent"
	case PhaseSentNoReply:
		return "sent_no_reply"
	case PhaseStreaming:
		return "streaming"
	default:
		return fmt.Sprintf("phase(%d)", int(p))
	}
}

// PhasedError attaches a Phase to an error without changing the
// error itself: Error() returns the inner error's text unchanged,
// and Unwrap() exposes the inner error, so errors.As finds
// conn.AuthError, conn.GatewayError, conn.ConnectionDown,
// conn.ConnectionError and conn.TimeoutError exactly as before.
type PhasedError struct {
	Err   error
	Phase Phase
}

// Error returns the inner error's text, unchanged.
func (e *PhasedError) Error() string { return e.Err.Error() }

// Unwrap exposes the inner error for errors.As/errors.Is.
func (e *PhasedError) Unwrap() error { return e.Err }

// withPhase attaches phase to err, unless err is nil or already
// carries a phase (the first, innermost phase wins).
func withPhase(err error, phase Phase) error {
	if err == nil {
		return nil
	}
	var phased *PhasedError
	if errors.As(err, &phased) {
		return err
	}
	return &PhasedError{Err: err, Phase: phase}
}

// PhaseOf reports the phase attached to err, if any.
func PhaseOf(err error) (Phase, bool) {
	var phased *PhasedError
	if errors.As(err, &phased) {
		return phased.Phase, true
	}
	return PhaseNotSent, false
}

// phaseForOpenErr maps an error from open() to a phase: a
// ConnectionDown means the pre-send check failed (nothing
// written); any other open error means the send was attempted and
// the frame may be on the wire.
func phaseForOpenErr(err error) Phase {
	var down *conn.ConnectionDown
	if errors.As(err, &down) {
		return PhaseNotSent
	}
	return PhaseSentNoReply
}
