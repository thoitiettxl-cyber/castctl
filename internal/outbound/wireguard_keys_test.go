//go:build with_wireguard

package outbound

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

// generateWGKey creates a fresh X25519 key per test with crypto/ecdh
// and returns its base64 form. Keys never leave the test process.
// They are not fixtures and not secrets.
func generateWGKey(t *testing.T) string {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(key.Bytes())
}
