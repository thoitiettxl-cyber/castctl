// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Noise XX handshake + transport via the `snow` crate (M4a).
//!
//! Go sources: `internal/gateway/gateway.go:144-193`
//! (`noiseHandshake`) and `internal/gateway/gatewaytest/server.go:376-410`
//! (`responderHandshake`).
//!
//! Suite (identical on both sides): `Noise_XX_25519_AESGCM_SHA256`
//! — DH25519 / CipherAESGCM / HashSHA256, pattern XX, initiator.
//! No PSK, no prologue, no pre-known remote static key. The
//! static keypair is freshly generated (OS randomness) for every
//! handshake, on both sides; all three handshake messages carry
//! empty payloads, and the initiator accepts a msg2 payload of
//! ANY length and ignores it (`gateway.go:180-183`).
//!
//! After `Split`, `cs1` is initiator→responder and `cs2` is
//! responder→initiator for BOTH peers: the initiator sends on
//! cs1 and receives on cs2; the responder is the mirror image.
//! `snow` has no public split API — it keeps both directions in
//! one `TransportState` — so `NoiseTransport` holds the single
//! state behind one `Mutex`. That is an API-shape difference
//! only (Go keeps two `CipherState`s behind `sendMu`/`recvMu`);
//! the wire bytes are identical, as the Cacophony vector test
//! (`tests/noise_vector.rs`) proves byte-for-byte.
//!
//! Error mapping: every `snow::Error` becomes
//! `TransportError::ConnectionError` with a fixed label — snow
//! errors never contain key material, and no handshake error
//! text is ever rendered with a payload. Handshake timeouts are
//! applied by the caller (`dial.rs` bounds each step with
//! `HANDSHAKE_TIMEOUT`); this module is the pure state machine
//! and takes no clock.

use std::sync::Mutex;
use std::time::Duration;

use castctl_transport::error::TransportError;
use snow::{Builder, HandshakeState, TransportState};

/// Noise params string, verbatim from Go
/// (`gateway.go:147-148`).
pub const NOISE_PARAMS: &str = "Noise_XX_25519_AESGCM_SHA256";

/// Bounds each handshake send and the msg2 reply (Go
/// `internal/gateway/gateway.go:24` `HandshakeTimeout`).
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);

/// Maximum bytes in one Noise message (handshake or transport),
/// including the 16-byte AEAD tag. Handshake reads use a buffer
/// this large so a msg2 payload of any length is accepted
/// instead of failing on a short buffer (Go `gateway.go:180-183`).
pub const MAX_NOISE_MESSAGE: usize = 65535;

fn conn_err(label: &str, err: snow::Error) -> TransportError {
    TransportError::ConnectionError {
        message: format!("{label}: {err}"),
    }
}

fn new_builder() -> Result<Builder<'static>, TransportError> {
    let params: snow::params::NoiseParams =
        NOISE_PARAMS
            .parse()
            .map_err(|e: snow::Error| TransportError::ConnectionError {
                message: format!("noise params invalid: {e}"),
            })?;
    Ok(Builder::new(params))
}

/// Fresh static keypair for one handshake (Go
/// `gateway.go:149-152`: `GenerateKeypair(rand.Reader)` per
/// handshake, never reused, never loaded from config).
fn fresh_static_keypair(builder: &Builder<'_>) -> Result<Vec<u8>, TransportError> {
    builder
        .generate_keypair()
        .map(|kp| kp.private)
        .map_err(|e| conn_err("gateway: generate noise keypair", e))
}

/// Initiator side of the Noise XX handshake (the client).
/// Drive it with `msg1` → send → `read_msg2` → `msg3` → send →
/// `into_transport`, exactly as Go `noiseHandshake` does.
pub struct InitiatorHandshake {
    state: HandshakeState,
}

impl InitiatorHandshake {
    /// Start a handshake with a fresh static keypair.
    pub fn new() -> Result<Self, TransportError> {
        let builder = new_builder()?;
        let keypair = fresh_static_keypair(&builder)?;
        let state = builder
            .local_private_key(&keypair)
            .map_err(|e| conn_err("gateway: noise handshake state", e))?
            .build_initiator()
            .map_err(|e| conn_err("gateway: noise handshake state", e))?;
        Ok(Self { state })
    }

    /// First handshake message (32 bytes, empty payload).
    pub fn msg1(&mut self) -> Result<Vec<u8>, TransportError> {
        let mut buf = vec![0u8; MAX_NOISE_MESSAGE];
        let n = self
            .state
            .write_message(&[], &mut buf)
            .map_err(|e| conn_err("gateway: noise msg1", e))?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Consume the responder's msg2. The payload is accepted at
    /// any length and ignored — never asserted empty (Go
    /// `gateway.go:180-183`).
    pub fn read_msg2(&mut self, msg2: &[u8]) -> Result<(), TransportError> {
        let mut payload = vec![0u8; MAX_NOISE_MESSAGE];
        self.state
            .read_message(msg2, &mut payload)
            .map_err(|e| conn_err("gateway: noise msg2", e))?;
        Ok(())
    }

    /// Third handshake message (empty payload). Completes the
    /// handshake; the returned transport encrypts on cs1 and
    /// decrypts on cs2 (initiator directions).
    pub fn msg3(&mut self) -> Result<Vec<u8>, TransportError> {
        let mut buf = vec![0u8; MAX_NOISE_MESSAGE];
        let n = self
            .state
            .write_message(&[], &mut buf)
            .map_err(|e| conn_err("gateway: noise msg3", e))?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Split into transport mode. Must be called only after
    /// `msg3` was produced (snow returns an error otherwise,
    /// mirroring Go's "did not split into transport states"
    /// check at `gateway.go:187-190`).
    pub fn into_transport(self) -> Result<NoiseTransport, TransportError> {
        let ts = self.state.into_transport_mode().map_err(|e| {
            conn_err(
                "gateway: noise handshake did not split into transport states",
                e,
            )
        })?;
        Ok(NoiseTransport {
            inner: Mutex::new(ts),
        })
    }
}

/// Responder side of the Noise XX handshake (the fake-server
/// side; mirrors Go `gatewaytest/server.go:376-410`
/// `responderHandshake`). Used by the integration-test fake
/// server and the parity client; production code never acts as
/// a responder.
pub struct ResponderHandshake {
    state: HandshakeState,
}

impl ResponderHandshake {
    /// Start a handshake with a fresh static keypair.
    pub fn new() -> Result<Self, TransportError> {
        let builder = new_builder()?;
        let keypair = fresh_static_keypair(&builder)?;
        let state = builder
            .local_private_key(&keypair)
            .map_err(|e| conn_err("gateway: noise handshake state", e))?
            .build_responder()
            .map_err(|e| conn_err("gateway: noise handshake state", e))?;
        Ok(Self { state })
    }

    /// Consume the initiator's msg1 (payload ignored).
    pub fn read_msg1(&mut self, msg1: &[u8]) -> Result<(), TransportError> {
        let mut payload = vec![0u8; MAX_NOISE_MESSAGE];
        self.state
            .read_message(msg1, &mut payload)
            .map_err(|e| conn_err("gateway: noise msg1", e))?;
        Ok(())
    }

    /// Second handshake message (empty payload).
    pub fn msg2(&mut self) -> Result<Vec<u8>, TransportError> {
        let mut buf = vec![0u8; MAX_NOISE_MESSAGE];
        let n = self
            .state
            .write_message(&[], &mut buf)
            .map_err(|e| conn_err("gateway: noise msg2", e))?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Consume the initiator's msg3 (payload ignored at any
    /// length, as in Go `server.go`).
    pub fn read_msg3(&mut self, msg3: &[u8]) -> Result<(), TransportError> {
        let mut payload = vec![0u8; MAX_NOISE_MESSAGE];
        self.state
            .read_message(msg3, &mut payload)
            .map_err(|e| conn_err("gateway: noise msg3", e))?;
        Ok(())
    }

    /// Split into transport mode. The responder sends on cs2 and
    /// receives on cs1 — `snow` keeps both directions in the one
    /// state, so no swap is needed here (unlike Go, which returns
    /// `(cs2, cs1)` explicitly).
    pub fn into_transport(self) -> Result<NoiseTransport, TransportError> {
        let ts = self.state.into_transport_mode().map_err(|e| {
            conn_err(
                "gateway: noise handshake did not split into transport states",
                e,
            )
        })?;
        Ok(NoiseTransport {
            inner: Mutex::new(ts),
        })
    }
}

/// Post-handshake Noise transport: one `snow::TransportState`
/// behind one `Mutex` (see the module docs for why this is one
/// lock instead of Go's two). A single ciphertext here is one
/// Noise message; framing into WS messages lives in
/// `framing.rs`, not here.
pub struct NoiseTransport {
    inner: Mutex<TransportState>,
}

impl NoiseTransport {
    /// Encrypt one plaintext message (at most 65535 bytes
    /// including the tag — callers chunk first, see
    /// `framing::SEND_PIECE`).
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, TransportError> {
        let mut buf = vec![0u8; MAX_NOISE_MESSAGE];
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| TransportError::ConnectionError {
                message: "gateway: noise transport lock poisoned".to_string(),
            })?;
        let n = guard
            .write_message(plaintext, &mut buf)
            .map_err(|e| conn_err("gateway encrypt failed", e))?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Decrypt one ciphertext message.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, TransportError> {
        let mut buf = vec![0u8; MAX_NOISE_MESSAGE];
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| TransportError::ConnectionError {
                message: "gateway: noise transport lock poisoned".to_string(),
            })?;
        let n = guard
            .read_message(ciphertext, &mut buf)
            .map_err(|e| conn_err("gateway decrypt failed", e))?;
        buf.truncate(n);
        Ok(buf)
    }
}

// Hand-written Debug: a transport holds key material in the
// snow state, so the derived Debug (which would print the
// state) is forbidden. Only the shape is printed.
impl std::fmt::Debug for NoiseTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NoiseTransport")
    }
}

impl std::fmt::Debug for InitiatorHandshake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "InitiatorHandshake")
    }
}

impl std::fmt::Debug for ResponderHandshake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ResponderHandshake")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn params_parse_to_xx_25519_aesgcm_sha256() {
        let p: snow::params::NoiseParams = NOISE_PARAMS.parse().unwrap();
        assert_eq!(p.name, NOISE_PARAMS);
    }

    #[test]
    fn debug_renders_no_key_material() {
        let hs = InitiatorHandshake::new().unwrap();
        let dbg = format!("{hs:?}");
        assert_eq!(dbg, "InitiatorHandshake");
    }

    #[test]
    fn noise_transport_debug_renders_shape_only() {
        // Full in-process handshake with the crate's own
        // handshake types; the resulting transport's Debug
        // must be exactly the shape, with no key material.
        let mut init = InitiatorHandshake::new().unwrap();
        let mut resp = ResponderHandshake::new().unwrap();
        let msg1 = init.msg1().unwrap();
        resp.read_msg1(&msg1).unwrap();
        let msg2 = resp.msg2().unwrap();
        init.read_msg2(&msg2).unwrap();
        let msg3 = init.msg3().unwrap();
        resp.read_msg3(&msg3).unwrap();
        let transport = init.into_transport().unwrap();
        assert_eq!(format!("{transport:?}"), "NoiseTransport");
        let transport2 = resp.into_transport().unwrap();
        assert_eq!(format!("{transport2:?}"), "NoiseTransport");
    }
}
