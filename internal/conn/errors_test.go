// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package conn

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestAuthErrorErrorsAs(t *testing.T) {
	t.Parallel()
	inner := NewAuthError("cookies expired")
	wrapped := fmt.Errorf("connect: %w", inner)
	var target *AuthError
	if !errors.As(wrapped, &target) {
		t.Fatalf("errors.As(wrapped AuthError) = false, want true")
	}
	if target.Message != "cookies expired" {
		t.Fatalf("AuthError message = %q", target.Message)
	}
}

func TestGatewayErrorFields(t *testing.T) {
	t.Parallel()
	err := &GatewayError{Status: 404, Payload: "not found"}
	if err.Error() == "" || err.Status != 404 || err.Payload != "not found" {
		t.Fatalf("GatewayError = %+v", err)
	}
	var target *GatewayError
	if !errors.As(fmt.Errorf("x: %w", err), &target) {
		t.Fatalf("errors.As(wrapped GatewayError) = false")
	}
}

func TestConnectionDownErrorsAs(t *testing.T) {
	t.Parallel()
	down := NewConnectionDown(errors.New("socket closed"))
	wrapped := fmt.Errorf("request: %w", down)
	var target *ConnectionDown
	if !errors.As(wrapped, &target) {
		t.Fatalf("errors.As(wrapped ConnectionDown) = false")
	}
	if errors.Unwrap(down) == nil {
		t.Fatalf("ConnectionDown Unwrap() = nil, want the cause")
	}
	var ce *ConnectionError
	if errors.As(wrapped, &ce) {
		t.Fatalf("ConnectionDown must not match *ConnectionError")
	}
}

func TestConnectionErrorDistinctFromDown(t *testing.T) {
	t.Parallel()
	ce := &ConnectionError{Err: errors.New("lost mid-stream")}
	var target *ConnectionError
	if !errors.As(fmt.Errorf("x: %w", ce), &target) {
		t.Fatalf("errors.As(wrapped ConnectionError) = false")
	}
	var down *ConnectionDown
	if errors.As(ce, &down) {
		t.Fatalf("ConnectionError must not match *ConnectionDown")
	}
}

func TestTimeoutErrorIsDeadlineExceeded(t *testing.T) {
	t.Parallel()
	err := &TimeoutError{Message: "no response for chat.history"}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("errors.Is(TimeoutError, DeadlineExceeded) = false")
	}
	if err.Error() == "" {
		t.Fatalf("TimeoutError.Error() is empty")
	}
}
