package profile

import (
	"errors"
	"strings"
	"testing"
)

func TestExitCode(t *testing.T) {
	t.Parallel()
	if got := ExitCode(nil); got != 0 {
		t.Errorf("ExitCode(nil) = %d; want 0", got)
	}
	if got := ExitCode(ErrInvalidProfile); got != 2 {
		t.Errorf("ExitCode(ErrInvalidProfile) = %d; want 2", got)
	}
	if got := ExitCode(ErrConfigParse); got != 2 {
		t.Errorf("ExitCode(ErrConfigParse) = %d; want 2", got)
	}
	if got := ExitCode(ErrAuth); got != 2 {
		t.Errorf("ExitCode(ErrAuth) = %d; want 2", got)
	}
	if got := ExitCode(errors.New("plain")); got != 1 {
		t.Errorf("ExitCode(plain) = %d; want 1", got)
	}
	// Wrapped typed errors keep their exit code without string matching.
	_, err := ValidateProfileName("a/b")
	if !errors.Is(err, ErrInvalidProfile) {
		t.Errorf("wrapped error %v; want errors.Is ErrInvalidProfile", err)
	}
	if got := ExitCode(err); got != 2 {
		t.Errorf("ExitCode(wrapped) = %d; want 2", got)
	}
}

func TestErrorMessagesDoNotLeakSecrets(t *testing.T) {
	t.Parallel()
	secret := "FAKE-SECRET-VALUE-12345"
	// A config carrying a secret plus an unknown field must fail, and the
	// error must not echo the secret.
	data := `{"profiles":{"p":{"outbound":{"type":"socks","tag":"x","server":"127.0.0.1","server_port":1080,"password":"` + secret + `","bogus_field_xyz":1}}}}`
	_, err := ParseSingleConfig([]byte(data), "/tmp/nonexistent-base")
	if err == nil {
		t.Fatal("ParseSingleConfig = nil error; want error for unknown field")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("error %q contains secret", err.Error())
	}
}
