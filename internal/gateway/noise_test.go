package gateway

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/flynn/noise"
)

// handshakePair runs a full Noise XX handshake between two
// in-process HandshakeStates, exchanging byte slices directly
// (no socket). responderPayload is the payload the responder puts
// in msg2. It returns both peers' (send, recv) CipherStates.
func handshakePair(t *testing.T, responderPayload []byte) (iSend, iRecv, rSend, rRecv *noise.CipherState) {
	t.Helper()
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)
	newState := func(initiator bool) *noise.HandshakeState {
		kp, err := cs.GenerateKeypair(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKeypair: %v", err)
		}
		hs, err := noise.NewHandshakeState(noise.Config{
			CipherSuite:   cs,
			Pattern:       noise.HandshakeXX,
			Initiator:     initiator,
			StaticKeypair: kp,
		})
		if err != nil {
			t.Fatalf("NewHandshakeState: %v", err)
		}
		return hs
	}
	init := newState(true)
	resp := newState(false)

	msg1, _, _, err := init.WriteMessage(nil, []byte{})
	if err != nil {
		t.Fatalf("msg1: %v", err)
	}
	if len(msg1) != 32 {
		t.Fatalf("msg1 len=%d, want 32 (PR0 vector)", len(msg1))
	}
	if _, _, _, err := resp.ReadMessage(nil, msg1); err != nil {
		t.Fatalf("resp read msg1: %v", err)
	}
	msg2, _, _, err := resp.WriteMessage(nil, responderPayload)
	if err != nil {
		t.Fatalf("msg2: %v", err)
	}
	payload, _, _, err := init.ReadMessage(nil, msg2)
	if err != nil {
		t.Fatalf("init read msg2: %v", err)
	}
	if !bytes.Equal(payload, responderPayload) {
		t.Fatalf("msg2 payload = %d bytes, want %d", len(payload), len(responderPayload))
	}
	msg3, cs1, cs2, err := init.WriteMessage(nil, []byte{})
	if err != nil {
		t.Fatalf("msg3: %v", err)
	}
	if cs1 == nil || cs2 == nil {
		t.Fatal("msg3 returned nil CipherState(s)")
	}
	iSend, iRecv = cs1, cs2
	if _, rcs1, rcs2, err := resp.ReadMessage(nil, msg3); err != nil {
		t.Fatalf("resp read msg3: %v", err)
	} else {
		if rcs1 == nil || rcs2 == nil {
			t.Fatal("msg3 responder returned nil CipherState(s)")
		}
		rSend, rRecv = rcs2, rcs1
	}
	return iSend, iRecv, rSend, rRecv
}

// TestNoiseHandshakeVectors re-runs the PR0 noise-probe vectors
// against the flynn/noise version used by the product code:
// empty-payload handshake message lengths, and transport in both
// directions for sizes 0, 11, 1000 and 60000.
func TestNoiseHandshakeVectors(t *testing.T) {
	iSend, iRecv, rSend, rRecv := handshakePair(t, []byte{})
	for _, size := range []int{0, 11, 1000, 60000} {
		pt := make([]byte, size)
		for i := range pt {
			pt[i] = byte((i*31 + 7) & 0xff)
		}
		ct, err := iSend.Encrypt(nil, nil, pt)
		if err != nil {
			t.Fatalf("encrypt size=%d: %v", size, err)
		}
		got, err := rRecv.Decrypt(nil, nil, ct)
		if err != nil {
			t.Fatalf("decrypt size=%d: %v", size, err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("initiator->responder size=%d mismatch", size)
		}
		ct, err = rSend.Encrypt(nil, nil, pt)
		if err != nil {
			t.Fatalf("encrypt back size=%d: %v", size, err)
		}
		got, err = iRecv.Decrypt(nil, nil, ct)
		if err != nil {
			t.Fatalf("decrypt back size=%d: %v", size, err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("responder->initiator size=%d mismatch", size)
		}
	}
}

// TestNoiseCipherStateOrder asserts the Split() order binding:
// (cs1, cs2) is the same pair for both peers, cs1 is
// initiator->responder and cs2 responder->initiator. The
// initiator sends on cs1/receives on cs2; the responder does the
// opposite. Cross-pair decryption must fail.
func TestNoiseCipherStateOrder(t *testing.T) {
	iSend, iRecv, rSend, rRecv := handshakePair(t, []byte{})
	ct, err := iSend.Encrypt(nil, nil, []byte("hello"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := rRecv.Decrypt(nil, nil, ct); err != nil {
		t.Fatalf("cs1 must decrypt on responder recv side: %v", err)
	}
	if _, err := rSend.Decrypt(nil, nil, ct); err == nil {
		t.Fatal("cs1 ciphertext decrypted with cs2: order assumption wrong")
	}
	ct2, err := rSend.Encrypt(nil, nil, []byte("back"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := iRecv.Decrypt(nil, nil, ct2); err != nil {
		t.Fatalf("cs2 must decrypt on initiator recv side: %v", err)
	}
	if _, err := iSend.Decrypt(nil, nil, ct2); err == nil {
		t.Fatal("cs2 ciphertext decrypted with cs1: order assumption wrong")
	}
}

// TestNoiseAcceptsAnyMsg2PayloadLength asserts the PR0 lesson:
// the handshake accepts a msg2 payload of ANY length (36 bytes
// observed live; Python accepts any length) and the handshake
// still completes with working transport states. The product
// code must never assert the payload is empty.
func TestNoiseAcceptsAnyMsg2PayloadLength(t *testing.T) {
	for _, n := range []int{1, 36, 100, 1000} {
		payload := make([]byte, n)
		for i := range payload {
			payload[i] = byte(i)
		}
		iSend, _, _, rRecv := handshakePair(t, payload)
		ct, err := iSend.Encrypt(nil, nil, []byte("after-handshake"))
		if err != nil {
			t.Fatalf("n=%d encrypt: %v", n, err)
		}
		got, err := rRecv.Decrypt(nil, nil, ct)
		if err != nil {
			t.Fatalf("n=%d decrypt: %v", n, err)
		}
		if string(got) != "after-handshake" {
			t.Fatalf("n=%d transport mismatch", n)
		}
	}
}
