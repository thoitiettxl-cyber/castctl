// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

import (
	"context"
	"errors"
	"testing"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
)

// TestPhaseForOpenErr (NB-R2): errors raised before sendEnvelope
// — the pre-send ConnectionDown check, unknown-method validation,
// and unencodable-body validation — are PhaseNotSent: no byte hit
// the wire. Only a send attempt (marshal/send failure) is
// PhaseSentNoReply.
func TestPhaseForOpenErr(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want Phase
	}{
		{"connection down", conn.NewConnectionDown(nil), PhaseNotSent},
		{"connection down wrapping cause", conn.NewConnectionDown(errors.New("dead")), PhaseNotSent},
		{"unknown method validation", &ValidationError{Message: `unknown method: "nope"`}, PhaseNotSent},
		{"unencodable body validation", &ValidationError{Message: "encode body: json: unsupported type"}, PhaseNotSent},
		{"send failure", &conn.ConnectionError{Err: errors.New("gateway send failed")}, PhaseSentNoReply},
		{"timeout", &conn.TimeoutError{Message: "slow"}, PhaseSentNoReply},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := phaseForOpenErr(tc.err); got != tc.want {
				t.Errorf("phaseForOpenErr(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestOpenStreamPreSendErrorsAreNotSent (NB-R2, end to end): an
// unknown method and an unencodable body fail in OpenStream with
// PhaseNotSent and the server records no request.
func TestOpenStreamPreSendErrorsAreNotSent(t *testing.T) {
	s := startE2E(t, jsonOKHandler(`{}`))
	defer s.cleanup()
	ctx := context.Background()

	_, err := s.gw.OpenStream(ctx, "no.such.method", conn.OpenStreamOptions{Track: true})
	if err == nil {
		t.Fatal("OpenStream(unknown method) = nil error")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("OpenStream(unknown) error = %T (%v), want *ValidationError", err, err)
	}
	if phase, _ := PhaseOf(err); phase != PhaseNotSent {
		t.Errorf("OpenStream(unknown) phase = %v, want PhaseNotSent", phase)
	}

	_, err = s.gw.OpenStream(ctx, "connection.ping", conn.OpenStreamOptions{Body: func() {}})
	if err == nil {
		t.Fatal("OpenStream(unencodable body) = nil error")
	}
	if !errors.As(err, &ve) {
		t.Fatalf("OpenStream(unencodable) error = %T (%v), want *ValidationError", err, err)
	}
	if phase, _ := PhaseOf(err); phase != PhaseNotSent {
		t.Errorf("OpenStream(unencodable) phase = %v, want PhaseNotSent", phase)
	}
	if got := s.server.RequestCount(); got != 0 {
		t.Errorf("server requests = %d, want 0 (nothing was sent)", got)
	}
}
