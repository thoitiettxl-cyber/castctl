package conn

import (
	"testing"
)

// Compile-time interface satisfaction: the frozen consumer contract.
var (
	_ Gateway = (*fakeGateway)(nil)
	_ Leaser  = (*fakeGateway)(nil)
	_ Gateway = (*SharedConn)(nil)
	_ Leaser  = (*SharedConn)(nil)
)

func TestConfigIdentity(t *testing.T) {
	t.Parallel()
	a := Config{CookiesFile: "/c", VMID: "v", NodeID: "n"}
	b := Config{CookiesFile: "/c", VMID: "v", NodeID: "n"}
	if a.Identity() != b.Identity() {
		t.Fatalf("identical configs have different identities: %+v vs %+v", a.Identity(), b.Identity())
	}
	c := Config{CookiesFile: "/other", VMID: "v", NodeID: "n"}
	if a.Identity() == c.Identity() {
		t.Fatal("different cookies_file values share an identity")
	}
}

func TestConstantsMatchPython(t *testing.T) {
	t.Parallel()
	// conn.py: CONNECT_TIMEOUT=60, HEARTBEAT=25, DOWN_NOTICE=60,
	// DOWN_FAILS=5, RETRY_FOR=30, FAIL_SPACING=2 (seconds).
	if ConnectTimeout.String() != "1m0s" {
		t.Fatalf("ConnectTimeout = %v, want 60s", ConnectTimeout)
	}
	if Heartbeat.String() != "25s" {
		t.Fatalf("Heartbeat = %v, want 25s", Heartbeat)
	}
	if DownNotice.String() != "1m0s" {
		t.Fatalf("DownNotice = %v, want 60s", DownNotice)
	}
	if DownFails != 5 {
		t.Fatalf("DownFails = %d, want 5", DownFails)
	}
	if RetryFor.String() != "30s" {
		t.Fatalf("RetryFor = %v, want 30s", RetryFor)
	}
	if FailSpacing.String() != "2s" {
		t.Fatalf("FailSpacing = %v, want 2s", FailSpacing)
	}
	if StalePingTimeout.String() != "5s" {
		t.Fatalf("StalePingTimeout = %v, want 5s (Python ping(timeout=5) in _probe_stale)", StalePingTimeout)
	}
	if HeartbeatPingTimeout.String() != "10s" {
		t.Fatalf("HeartbeatPingTimeout = %v, want 10s (Python ping() default)", HeartbeatPingTimeout)
	}
	if MaxSubscribeAttempts != 3 {
		t.Fatalf("MaxSubscribeAttempts = %d, want 3", MaxSubscribeAttempts)
	}
}
