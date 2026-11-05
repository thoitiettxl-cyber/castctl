// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Noise XX test vector (fail-before proof for M4a).
//!
//! Source: the official Cacophony vector for
//! `Noise_XX_25519_AESGCM_SHA256`, copied verbatim from
//! `~/go/pkg/mod/github.com/flynn/noise@v1.1.0/vectors.txt`
//! (the same vector flynn runs in `vector_test.go:101`
//! `TestVectors`). The Go gateway uses exactly this suite
//! (`internal/gateway/gateway.go:147-148`: DH25519 /
//! CipherAESGCM / HashSHA256, pattern XX, no PSK, no prologue).
//!
//! `snow` has no API to set the ephemeral keypair directly, so
//! the fixed ephemeral keys are injected through a deterministic
//! RNG resolver (`Builder::with_resolver`): the resolver's RNG
//! serves `gen_init_ephemeral` / `gen_resp_ephemeral` as the
//! first (and only) 32 random bytes the handshake draws.
//! Static keys come from `init_static` / `resp_static` via
//! `.local_private_key()`.
//!
//! TDD: this test was written BEFORE `castctl_gateway::noise`
//! existed and must FAIL until the implementation is wired to
//! `snow` with the exact params above. It must never be edited
//! to match the code — the vector is the source of truth.

use snow::params::{CipherChoice, DHChoice, HashChoice, NoiseParams};
use snow::resolvers::{CryptoResolver, DefaultResolver};
use snow::types::Random;
// NOTE: `Random` lives in `snow::types` (not re-exported at the crate root).
use snow::{Builder, Error};

/// A `Random` that serves one fixed 32-byte draw, then zeros.
/// The Noise XX handshake draws exactly 32 bytes for the
/// ephemeral keypair; anything after that would mean the test's
/// model of the handshake is wrong, and the vector comparison
/// below will fail loudly instead of silently passing.
struct FixedRandom {
    bytes: [u8; 32],
    pos: usize,
}

impl Random for FixedRandom {
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        for (i, b) in dest.iter_mut().enumerate() {
            let idx = self.pos + i;
            *b = if idx < 32 { self.bytes[idx] } else { 0 };
        }
        self.pos += dest.len();
        Ok(())
    }
}

/// Resolver that delegates DH/hash/cipher to the default
/// resolver but serves a fixed ephemeral seed from its RNG.
struct DeterministicResolver {
    seed: [u8; 32],
}

impl CryptoResolver for DeterministicResolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        Some(Box::new(FixedRandom {
            bytes: self.seed,
            pos: 0,
        }))
    }

    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn snow::types::Dh>> {
        DefaultResolver.resolve_dh(choice)
    }

    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn snow::types::Hash>> {
        DefaultResolver.resolve_hash(choice)
    }

    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn snow::types::Cipher>> {
        DefaultResolver.resolve_cipher(choice)
    }
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn params() -> NoiseParams {
    "Noise_XX_25519_AESGCM_SHA256".parse().unwrap()
}

#[test]
fn noise_xx_25519_aesgcm_sha256_cacophony_vector() {
    let init_static = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let resp_static = hex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    let gen_init_eph = hex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
    let gen_resp_eph = hex("4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60");
    let msg_0 = hex("358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254");
    let msg_1 = hex(
        "64b101b1d0be5a8704bd078f9895001fc03e8e9f9522f188dd128d9846d484665393019dbd6f438795da206db0886610b26108e424142c2e9b5fd1f7ea70cde8767ce62d7e3c0e9bcefe4ab872c0505b9e824df091b74ffe10a2b32809cab21f",
    );
    let msg_2 = hex(
        "e610eadc4b00c17708bf223f29a66f02342fbedf6c0044736544b9271821ae40e70144cecd9d265dffdc5bb8e051c3f83db32a425e04d8f510c58a43325fbc56",
    );
    let msg_3 = hex("9ea1da1ec3bfecfffab213e537ed1791bfa887dd9c631351b3f63d6315ab9a");
    let msg_4 = hex("217c5111fad7afde33bd28abaff3def88a57ab50515115d23a10f28621f842");

    let mut init_seed = [0u8; 32];
    init_seed.copy_from_slice(&gen_init_eph);
    let mut resp_seed = [0u8; 32];
    resp_seed.copy_from_slice(&gen_resp_eph);

    let mut init = Builder::with_resolver(
        params(),
        Box::new(DeterministicResolver { seed: init_seed }),
    )
    .local_private_key(&init_static)
    .unwrap()
    .build_initiator()
    .unwrap();
    let mut resp = Builder::with_resolver(
        params(),
        Box::new(DeterministicResolver { seed: resp_seed }),
    )
    .local_private_key(&resp_static)
    .unwrap()
    .build_responder()
    .unwrap();

    let mut buf = vec![0u8; 65535];
    // msg0: initiator -> responder, empty payload. Go pins
    // len(msg1) == 32 (internal/gateway/noise_test.go:85-120).
    let n = init.write_message(&[], &mut buf).unwrap();
    assert_eq!(n, 32, "msg0 length must be 32 (PR0 vector)");
    assert_eq!(&buf[..n], msg_0.as_slice(), "msg0 ciphertext mismatch");

    // msg1: responder -> initiator, empty payload.
    let mut buf2 = vec![0u8; 65535];
    let m = resp.read_message(&msg_0, &mut buf2).unwrap();
    assert_eq!(m, 0, "msg0 payload must be empty");
    let n = resp.write_message(&[], &mut buf).unwrap();
    assert_eq!(&buf[..n], msg_1.as_slice(), "msg1 ciphertext mismatch");

    // msg2: initiator -> responder, empty payload.
    let m = init.read_message(&msg_1, &mut buf2).unwrap();
    assert_eq!(m, 0, "msg1 payload must be empty");
    let n = init.write_message(&[], &mut buf).unwrap();
    assert_eq!(&buf[..n], msg_2.as_slice(), "msg2 ciphertext mismatch");

    let m = resp.read_message(&msg_2, &mut buf2).unwrap();
    assert_eq!(m, 0, "msg2 payload must be empty");

    let mut init_ts = init.into_transport_mode().unwrap();
    let mut resp_ts = resp.into_transport_mode().unwrap();

    // msg3: initiator -> responder. The payload hex decodes to
    // "yellowsubmarine" (15 bytes; 15+16 tag = 31 = len(msg_3)).
    // NOTE: research-noise.md §5.1 mislabels this payload as
    // "hellosubmarine" (14 bytes) — the hex in that same file is
    // correct and decodes to "yellowsubmarine"; this test follows
    // the hex, and the mismatch it first produced is what caught
    // the mislabel. Do not "fix" the plaintext back.
    let n = init_ts.write_message(b"yellowsubmarine", &mut buf).unwrap();
    assert_eq!(&buf[..n], msg_3.as_slice(), "msg3 ciphertext mismatch");
    let m = resp_ts.read_message(&msg_3, &mut buf2).unwrap();
    assert_eq!(&buf2[..m], b"yellowsubmarine");

    // msg4: responder -> initiator ("submarineyellow").
    let n = resp_ts.write_message(b"submarineyellow", &mut buf).unwrap();
    assert_eq!(&buf[..n], msg_4.as_slice(), "msg4 ciphertext mismatch");
    let m = init_ts.read_message(&msg_4, &mut buf2).unwrap();
    assert_eq!(&buf2[..m], b"submarineyellow");
}

/// Mirror of Go `TestNoiseAcceptsAnyMsg2PayloadLength`
/// (`internal/gateway/noise_test.go:151-170`): a msg2 payload
/// of any length (1, 36, 100, 1000) is accepted and ignored,
/// and transport still works afterwards.
#[test]
fn noise_msg2_payload_any_length_accepted() {
    for len in [1usize, 36, 100, 1000] {
        let mut init = Builder::new(params())
            .local_private_key(&Builder::new(params()).generate_keypair().unwrap().private)
            .unwrap()
            .build_initiator()
            .unwrap();
        let mut resp = Builder::new(params())
            .local_private_key(&Builder::new(params()).generate_keypair().unwrap().private)
            .unwrap()
            .build_responder()
            .unwrap();
        let mut buf = vec![0u8; 65535];
        let mut buf2 = vec![0u8; 65535];
        let n = init.write_message(&[], &mut buf).unwrap();
        let msg0 = buf[..n].to_vec();
        resp.read_message(&msg0, &mut buf2).unwrap();
        let payload = vec![0xabu8; len];
        let n = resp.write_message(&payload, &mut buf).unwrap();
        let msg1 = buf[..n].to_vec();
        let m = init.read_message(&msg1, &mut buf2).unwrap();
        // Payload is delivered to the caller but the gateway
        // ignores it (gateway.go:180-183); assert only that
        // the handshake completes and transport works.
        assert_eq!(m, len, "msg1 payload length must round-trip");
        let n = init.write_message(&[], &mut buf).unwrap();
        let msg2 = buf[..n].to_vec();
        resp.read_message(&msg2, &mut buf2).unwrap();
        let mut init_ts = init.into_transport_mode().unwrap();
        let mut resp_ts = resp.into_transport_mode().unwrap();
        let n = init_ts.write_message(b"ok", &mut buf).unwrap();
        let ct = buf[..n].to_vec();
        let m = resp_ts.read_message(&ct, &mut buf2).unwrap();
        assert_eq!(&buf2[..m], b"ok");
    }
}

/// Mirror of Go `TestNoiseHandshakeVectors` transport sizes
/// and `TestNoiseCipherStateOrder`: plaintext
/// `pt[i] = (i*31+7) & 0xff` at sizes 0, 11, 1000, 60000 in
/// both directions, and decrypting in the wrong direction
/// (a state reading its own write) fails.
#[test]
fn noise_transport_sizes_and_direction() {
    let mut init = Builder::new(params())
        .local_private_key(&Builder::new(params()).generate_keypair().unwrap().private)
        .unwrap()
        .build_initiator()
        .unwrap();
    let mut resp = Builder::new(params())
        .local_private_key(&Builder::new(params()).generate_keypair().unwrap().private)
        .unwrap()
        .build_responder()
        .unwrap();
    let mut buf = vec![0u8; 65535];
    let mut buf2 = vec![0u8; 65535];
    let n = init.write_message(&[], &mut buf).unwrap();
    let msg0 = buf[..n].to_vec();
    resp.read_message(&msg0, &mut buf2).unwrap();
    let n = resp.write_message(&[], &mut buf).unwrap();
    let msg1 = buf[..n].to_vec();
    init.read_message(&msg1, &mut buf2).unwrap();
    let n = init.write_message(&[], &mut buf).unwrap();
    let msg2 = buf[..n].to_vec();
    resp.read_message(&msg2, &mut buf2).unwrap();
    let mut init_ts = init.into_transport_mode().unwrap();
    let mut resp_ts = resp.into_transport_mode().unwrap();

    for size in [0usize, 11, 1000, 60000] {
        let pt: Vec<u8> = (0..size).map(|i| ((i * 31 + 7) & 0xff) as u8).collect();
        // initiator -> responder
        let n = init_ts.write_message(&pt, &mut buf).unwrap();
        let ct = buf[..n].to_vec();
        let m = resp_ts.read_message(&ct, &mut buf2).unwrap();
        assert_eq!(&buf2[..m], pt.as_slice(), "init->resp size {size}");
        // responder -> initiator
        let n = resp_ts.write_message(&pt, &mut buf).unwrap();
        let ct = buf[..n].to_vec();
        let m = init_ts.read_message(&ct, &mut buf2).unwrap();
        assert_eq!(&buf2[..m], pt.as_slice(), "resp->init size {size}");
    }

    // Wrong direction: a transport state reading a message it
    // itself wrote (same-direction key) must fail.
    let n = init_ts.write_message(b"self", &mut buf).unwrap();
    let ct = buf[..n].to_vec();
    assert!(
        init_ts.read_message(&ct, &mut buf2).is_err(),
        "self-direction decrypt must fail"
    );
}
