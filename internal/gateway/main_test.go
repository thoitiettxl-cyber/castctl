package gateway

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain verifies no goroutine leaks: every Gateway's reader
// goroutine and every fake server goroutine must exit when its
// Gateway/Server is closed.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
