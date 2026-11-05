// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Integration tests for `honk_tls_wrap` (M4c): the gateway WS
//! dial's TLS wrap over BoringSSL (honk Chrome connector).
//!
//! Seam: a record-only loopback listener captures the first TLS
//! record (ClientHello) the wrap sends, parses SNI / ALPN /
//! Chrome markers out of it, then closes without a ServerHello
//! — so the handshake must fail, and that failure must map to
//! the pinned fixed string `gateway: websocket TLS failed`
//! (28 chars), never to a boring/OpenSSL error text (which can
//! embed peer material).
//!
//! The live proof (101 vs 502 on the real edge) is NOT here —
//! it is the cue live probe in the M4c plan. This test pins
//! the wire shape + the error mapping; the edge verdict comes
//! from live.

use std::time::Duration;

use castctl_transport::error::TransportError;
use castctl_transport::honk_tls_wrap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Minimal ClientHello parse: SNI hostname, ALPN list, and the
/// Chrome markers (a GREASE cipher, ECH GREASE ext `fe0d`,
/// MLKEM768 group `11ec` in supported_groups). Returns
/// `(sni, alpn, has_grease_cipher, has_ech_grease, has_mlkem768)`.
fn parse_client_hello(record: &[u8]) -> (Option<String>, Vec<String>, bool, bool, bool) {
    assert_eq!(record[0], 0x16, "first record must be a TLS handshake");
    assert_eq!(
        record[5], 0x01,
        "first handshake message must be ClientHello"
    );
    // Handshake body starts at record[9]: legacy_version(2),
    // random(32), session_id len(1)+n, cipher_suites len(2)+n,
    // compression len(1)+n, extensions len(2), extensions.
    let mut p = 9 + 2 + 32;
    let sess_len = record[p] as usize;
    p += 1 + sess_len;
    let cipher_len = u16::from_be_bytes([record[p], record[p + 1]]) as usize;
    p += 2;
    let ciphers = &record[p..p + cipher_len];
    p += cipher_len;
    let comp_len = record[p] as usize;
    p += 1 + comp_len;
    let exts_len = u16::from_be_bytes([record[p], record[p + 1]]) as usize;
    p += 2;
    let exts_end = p + exts_len;

    let mut has_grease_cipher = false;
    for pair in ciphers.as_chunks::<2>().0 {
        let v = u16::from_be_bytes([pair[0], pair[1]]);
        // GREASE: both bytes equal, low nibble 0xa.
        if pair[0] == pair[1] && pair[0] & 0x0f == 0x0a {
            has_grease_cipher = true;
        }
        let _ = v;
    }

    let mut sni: Option<String> = None;
    let mut alpn: Vec<String> = Vec::new();
    let mut has_ech_grease = false;
    let mut has_mlkem768 = false;
    while p + 4 <= exts_end {
        let ext_type = u16::from_be_bytes([record[p], record[p + 1]]);
        let ext_len = u16::from_be_bytes([record[p + 2], record[p + 3]]) as usize;
        let body = &record[p + 4..p + 4 + ext_len];
        match ext_type {
            0x0000 => {
                // server_name list: len(2), type(1)=host_name,
                // name len(2), name bytes.
                let mut q = 2;
                if body[q] == 0 {
                    q += 1;
                    let nlen = u16::from_be_bytes([body[q], body[q + 1]]) as usize;
                    q += 2;
                    sni = Some(String::from_utf8_lossy(&body[q..q + nlen]).into_owned());
                }
            }
            0x0010 => {
                // ALPN: list len(2), then len(1)+bytes per protocol.
                let mut q = 2;
                while q < body.len() {
                    let nlen = body[q] as usize;
                    q += 1;
                    alpn.push(String::from_utf8_lossy(&body[q..q + nlen]).into_owned());
                    q += nlen;
                }
            }
            0xfe0d => has_ech_grease = true,
            0x000a => {
                // supported_groups: list len(2), then 2-byte groups.
                let mut q = 2;
                while q + 2 <= body.len() {
                    if u16::from_be_bytes([body[q], body[q + 1]]) == 0x11ec {
                        has_mlkem768 = true;
                    }
                    q += 2;
                }
            }
            _ => {}
        }
        p += 4 + ext_len;
    }
    (sni, alpn, has_grease_cipher, has_ech_grease, has_mlkem768)
}

/// A listener that records the first TLS record of one
/// connection, then closes without answering (no ServerHello).
struct ClientHelloRecorder {
    port: u16,
    record_rx: tokio::sync::oneshot::Receiver<Vec<u8>>,
}

impl ClientHelloRecorder {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("INVARIANT: recorder binds loopback");
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let mut header = [0u8; 5];
            if socket.read_exact(&mut header).await.is_err() {
                return;
            }
            let len = u16::from_be_bytes([header[3], header[4]]) as usize;
            let mut record = vec![0u8; 5 + len];
            record[..5].copy_from_slice(&header);
            if socket.read_exact(&mut record[5..]).await.is_err() {
                return;
            }
            let _ = tx.send(record);
            // Close without a ServerHello: the handshake fails.
            let _ = socket.shutdown().await;
        });
        Self {
            port,
            record_rx: rx,
        }
    }
}

#[tokio::test]
async fn honk_tls_wrap_sends_chrome_client_hello_and_maps_handshake_failure() {
    let recorder = ClientHelloRecorder::start().await;
    let stream = TcpStream::connect(("127.0.0.1", recorder.port))
        .await
        .expect("INVARIANT: loopback TCP connect succeeds");
    // `expect_err` would need `Debug` on the Ok type
    // (`Box<dyn TlsStream>` has none by design), so match.
    let wrapped = tokio::time::timeout(Duration::from_secs(20), honk_tls_wrap(stream, "localhost"))
        .await
        .expect("INVARIANT: honk_tls_wrap must settle within 20s");
    let err = match wrapped {
        Ok(_) => panic!("handshake against a silent listener must fail"),
        Err(e) => e,
    };
    // Error mapping seam: exactly the pinned fixed string, never
    // boring/OpenSSL text (which could embed peer material).
    let message = match &err {
        TransportError::ConnectionError { message } => message.clone(),
        other => panic!("want ConnectionError, got {other:?}"),
    };
    assert_eq!(
        message, "gateway: websocket TLS failed",
        "honk handshake failure must render the pinned 29-char string"
    );
    assert_eq!(message.len(), 29, "the TLS-failed error_length=29");
    assert_eq!(err.exit_code(), 1);

    // Connector-build seam: the ClientHello the wrap sent.
    let record = tokio::time::timeout(Duration::from_secs(5), recorder.record_rx)
        .await
        .expect("INVARIANT: recorder must receive the ClientHello")
        .expect("INVARIANT: recorder must send the record");
    let (sni, alpn, has_grease, has_ech, has_mlkem) = parse_client_hello(&record);
    assert_eq!(sni.as_deref(), Some("localhost"), "SNI must be the WS host");
    assert_eq!(
        alpn,
        vec!["http/1.1".to_string()],
        "ALPN must be pinned to [http/1.1] (Go connector.go:240)"
    );
    assert!(has_grease, "Chrome ClientHello must carry a GREASE cipher");
    assert!(has_ech, "Chrome ClientHello must GREASE ECH (ext fe0d)");
    assert!(
        has_mlkem,
        "Chrome ClientHello must offer X25519MLKEM768 (group 11ec)"
    );
}
