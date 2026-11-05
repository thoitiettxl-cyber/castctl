// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Golden protobuf vectors (M4a gate, no mock).
//!
//! Mirror of Go `internal/proto/golden_cases_test.go`
//! (`builders`, 58 cases) + `golden_test.go`
//! (`TestGoldenVectors`, `TestNoiseTransportFramePresence`,
//! `TestServiceFrameOneofKind`, `TestEnumNames`). The `.bin`
//! files are the Python-produced vectors in
//! `internal/proto/testdata/vectors/` (the single source of
//! truth; included by path, never copied). For every case,
//! three comparisons (mirror `TestGoldenVectors`):
//! 1. `encode(rust_built) == <name>.bin` (byte-for-byte);
//! 2. `decode(<name>.bin) == rust_built` (struct equality);
//! 3. `encode(decode(<name>.bin)) == <name>.bin`
//!    (parse + re-serialize).
//!
//! Gate: 58/58 must match; any mismatch is a fail.

use castctl_gateway::proto::{
    ApplicationRequest, ApplicationResponse, BodyChunk, Header, NoiseTransportFrame, Reset,
    ResetCode, ServiceFrame, ServiceFrameKind, ServiceRequest, ServiceResponse, ServiceType,
};
use prost::Message;

const UNI: &str = "café ☃ — lý do";

fn payload60k() -> Vec<u8> {
    (0..60000).map(|i| ((i * 7 + 3) % 256) as u8).collect()
}

fn body60k() -> Vec<u8> {
    (0..60000).map(|i| (255 - (i % 256)) as u8).collect()
}

fn data60k() -> Vec<u8> {
    let mut b = Vec::with_capacity(60000);
    for _ in 0..30000 {
        b.push(b'A');
        b.push(0xff);
    }
    b
}

fn hdr(k: &str, v: &str) -> Header {
    Header {
        key: k.to_string(),
        value: v.to_string(),
    }
}

/// One golden case, as an enum over the 9 message types
/// (prost types all derive `PartialEq`, so struct equality
/// is the `proto.Equal` analogue).
#[derive(Debug, Clone, PartialEq)]
enum Case {
    Ntf(NoiseTransportFrame),
    Sr(ServiceRequest),
    Sresp(ServiceResponse),
    Sf(ServiceFrame),
    Ar(ApplicationRequest),
    Aresp(ApplicationResponse),
    Bc(BodyChunk),
    Reset(Reset),
    Header(Header),
}

impl Case {
    fn encode(&self) -> Vec<u8> {
        match self {
            Case::Ntf(m) => m.encode_to_vec(),
            Case::Sr(m) => m.encode_to_vec(),
            Case::Sresp(m) => m.encode_to_vec(),
            Case::Sf(m) => m.encode_to_vec(),
            Case::Ar(m) => m.encode_to_vec(),
            Case::Aresp(m) => m.encode_to_vec(),
            Case::Bc(m) => m.encode_to_vec(),
            Case::Reset(m) => m.encode_to_vec(),
            Case::Header(m) => m.encode_to_vec(),
        }
    }

    fn decode(name: &str, bytes: &[u8]) -> Self {
        match name {
            _ if name.starts_with("ntf_") => Case::Ntf(NoiseTransportFrame::decode(bytes).unwrap()),
            _ if name.starts_with("sr_") => Case::Sr(ServiceRequest::decode(bytes).unwrap()),
            _ if name.starts_with("sresp_") => Case::Sresp(ServiceResponse::decode(bytes).unwrap()),
            _ if name.starts_with("sf_") => Case::Sf(ServiceFrame::decode(bytes).unwrap()),
            _ if name.starts_with("ar_") => Case::Ar(ApplicationRequest::decode(bytes).unwrap()),
            _ if name.starts_with("aresp_") => {
                Case::Aresp(ApplicationResponse::decode(bytes).unwrap())
            }
            _ if name.starts_with("bc_") => Case::Bc(BodyChunk::decode(bytes).unwrap()),
            _ if name.starts_with("reset_") => Case::Reset(Reset::decode(bytes).unwrap()),
            _ if name.starts_with("header_") => Case::Header(Header::decode(bytes).unwrap()),
            _ => panic!("unknown golden case {name}"),
        }
    }
}

fn ntf(id: Option<i64>, idx: Option<u32>, total: Option<u32>, payload: Option<Vec<u8>>) -> Case {
    Case::Ntf(NoiseTransportFrame {
        chunk_id: id,
        chunk_index: idx,
        total_chunks: total,
        payload,
    })
}

/// Mirror of Go `builders` in `golden_cases_test.go` — same
/// names, same field values, same byte patterns.
fn build(name: &str) -> Case {
    match name {
        // --- NoiseTransportFrame (13) ---
        "ntf_all" => ntf(
            Some(1_234_567_890_123),
            Some(2),
            Some(5),
            Some(b"hello\xff\xfe\x00\x80\xc3\xa9".to_vec()),
        ),
        "ntf_chunk_id_only" => ntf(Some(42), None, None, None),
        "ntf_chunk_index_only" => ntf(None, Some(7), None, None),
        "ntf_total_chunks_only" => ntf(None, None, Some(9), None),
        "ntf_payload_only" => ntf(None, None, None, Some(b"\x00\xffabc".to_vec())),
        "ntf_none" => ntf(None, None, None, None),
        "ntf_chunk_id_zero_present" => ntf(Some(0), None, None, None),
        "ntf_chunk_index_zero_present" => ntf(None, Some(0), None, None),
        "ntf_total_chunks_zero_present" => ntf(None, None, Some(0), None),
        "ntf_payload_empty_present" => ntf(None, None, None, Some(vec![])),
        "ntf_all_zero_present" => ntf(Some(0), Some(0), Some(0), Some(vec![])),
        "ntf_negative_max" => ntf(Some(-1), Some(u32::MAX), Some(u32::MAX), Some(payload60k())),
        "ntf_payload_60000" => ntf(Some(1), Some(0), Some(1), Some(data60k())),
        // --- ServiceRequest (5) ---
        "sr_daemon" => Case::Sr(ServiceRequest {
            service: ServiceType::ServiceDaemon as i32,
            payload: b"frame-bytes-\xff".to_vec(),
        }),
        "sr_sentinel" => Case::Sr(ServiceRequest {
            service: ServiceType::ServiceSentinel as i32,
            payload: vec![],
        }),
        "sr_vault" => Case::Sr(ServiceRequest {
            service: ServiceType::ServiceVault as i32,
            payload: vec![0x00, 0x01, 0x02],
        }),
        "sr_authd" => Case::Sr(ServiceRequest {
            service: ServiceType::ServiceAuthd as i32,
            payload: vec![b'x'; 1000],
        }),
        "sr_empty" => Case::Sr(ServiceRequest {
            service: 0,
            payload: vec![],
        }),
        // --- ServiceResponse (3) ---
        "sresp_payload" => Case::Sresp(ServiceResponse {
            payload: b"resp\xff".to_vec(),
        }),
        "sresp_empty" => Case::Sresp(ServiceResponse { payload: vec![] }),
        "sresp_60000" => Case::Sresp(ServiceResponse {
            payload: payload60k(),
        }),
        // --- ServiceFrame (9) ---
        "sf_request" => Case::Sf(ServiceFrame {
            stream_id: 1,
            kind: Some(ServiceFrameKind::Request(ApplicationRequest {
                verb: "GET".to_string(),
                path: "/x".to_string(),
                headers: vec![hdr("k", "v")],
                body: b"hi".to_vec(),
                end_body: true,
            })),
        }),
        "sf_response" => Case::Sf(ServiceFrame {
            stream_id: 2,
            kind: Some(ServiceFrameKind::Response(ApplicationResponse {
                status: 200,
                headers: vec![hdr("a", "b")],
                body: b"ok\xff".to_vec(),
                end_body: true,
            })),
        }),
        "sf_body_chunk" => Case::Sf(ServiceFrame {
            stream_id: 3,
            kind: Some(ServiceFrameKind::BodyChunk(BodyChunk {
                data: b"chunk\xff".to_vec(),
                end_body: false,
            })),
        }),
        "sf_reset" => Case::Sf(ServiceFrame {
            stream_id: 4,
            kind: Some(ServiceFrameKind::Reset(Reset {
                code: ResetCode::Cancelled as i32,
                reason: UNI.to_string(),
            })),
        }),
        "sf_no_kind" => Case::Sf(ServiceFrame {
            stream_id: 5,
            kind: None,
        }),
        "sf_empty" => Case::Sf(ServiceFrame {
            stream_id: 0,
            kind: None,
        }),
        "sf_stream_id_zero_with_request" => Case::Sf(ServiceFrame {
            stream_id: 0,
            kind: Some(ServiceFrameKind::Request(ApplicationRequest {
                verb: "GET".to_string(),
                path: "/p".to_string(),
                headers: vec![],
                body: vec![],
                end_body: false,
            })),
        }),
        "sf_stream_negative" => Case::Sf(ServiceFrame {
            stream_id: -1,
            kind: Some(ServiceFrameKind::BodyChunk(BodyChunk {
                data: b"d".to_vec(),
                end_body: true,
            })),
        }),
        "sf_stream_min" => Case::Sf(ServiceFrame {
            stream_id: i64::MIN,
            kind: Some(ServiceFrameKind::BodyChunk(BodyChunk {
                data: vec![],
                end_body: false,
            })),
        }),
        // --- ApplicationRequest (5) ---
        "ar_full" => Case::Ar(ApplicationRequest {
            verb: "POST".to_string(),
            path: "/api/test?q=café".to_string(),
            headers: vec![
                hdr("content-type", "application/json"),
                hdr("x-request-id", "abc-123"),
                hdr("", ""),
                hdr("x-unicode", UNI),
            ],
            body: b"\x00\xff\xfe binary \x80".to_vec(),
            end_body: true,
        }),
        "ar_end_body_false" => Case::Ar(ApplicationRequest {
            verb: "GET".to_string(),
            path: "/p".to_string(),
            headers: vec![],
            body: vec![],
            end_body: false,
        }),
        "ar_empty" => Case::Ar(ApplicationRequest {
            verb: String::new(),
            path: String::new(),
            headers: vec![],
            body: vec![],
            end_body: false,
        }),
        "ar_headers_only" => Case::Ar(ApplicationRequest {
            verb: String::new(),
            path: String::new(),
            headers: vec![hdr("a", "1"), hdr("b", "2"), hdr("c", "3")],
            body: vec![],
            end_body: false,
        }),
        "ar_body_60000" => Case::Ar(ApplicationRequest {
            verb: "POST".to_string(),
            path: "/big".to_string(),
            headers: vec![],
            body: body60k(),
            end_body: true,
        }),
        // --- ApplicationResponse (5) ---
        "aresp_full" => Case::Aresp(ApplicationResponse {
            status: 200,
            headers: vec![hdr("content-type", "text/plain"), hdr("x-u", UNI)],
            body: b"body\xff\x00end".to_vec(),
            end_body: true,
        }),
        "aresp_status_zero" => Case::Aresp(ApplicationResponse {
            status: 0,
            headers: vec![],
            body: b"zero".to_vec(),
            end_body: false,
        }),
        "aresp_negative" => Case::Aresp(ApplicationResponse {
            status: -1,
            headers: vec![],
            body: b"err".to_vec(),
            end_body: false,
        }),
        "aresp_empty" => Case::Aresp(ApplicationResponse {
            status: 0,
            headers: vec![],
            body: vec![],
            end_body: false,
        }),
        "aresp_404" => Case::Aresp(ApplicationResponse {
            status: 404,
            headers: vec![],
            body: b"not found".to_vec(),
            end_body: true,
        }),
        // --- BodyChunk (5) ---
        "bc_data" => Case::Bc(BodyChunk {
            data: b"chunk\xff\x00".to_vec(),
            end_body: false,
        }),
        "bc_end" => Case::Bc(BodyChunk {
            data: b"last".to_vec(),
            end_body: true,
        }),
        "bc_empty" => Case::Bc(BodyChunk {
            data: vec![],
            end_body: false,
        }),
        "bc_60000" => Case::Bc(BodyChunk {
            data: data60k(),
            end_body: true,
        }),
        "bc_empty_data_end" => Case::Bc(BodyChunk {
            data: vec![],
            end_body: true,
        }),
        // --- Reset (9) ---
        "reset_unspecified" => Case::Reset(Reset {
            code: ResetCode::Unspecified as i32,
            reason: UNI.to_string(),
        }),
        "reset_cancelled" => Case::Reset(Reset {
            code: ResetCode::Cancelled as i32,
            reason: UNI.to_string(),
        }),
        "reset_timeout" => Case::Reset(Reset {
            code: ResetCode::Timeout as i32,
            reason: UNI.to_string(),
        }),
        "reset_protocol_error" => Case::Reset(Reset {
            code: ResetCode::ProtocolError as i32,
            reason: UNI.to_string(),
        }),
        "reset_refused_stream" => Case::Reset(Reset {
            code: ResetCode::RefusedStream as i32,
            reason: UNI.to_string(),
        }),
        "reset_internal_error" => Case::Reset(Reset {
            code: ResetCode::InternalError as i32,
            reason: UNI.to_string(),
        }),
        "reset_service_unavailable" => Case::Reset(Reset {
            code: ResetCode::ServiceUnavailable as i32,
            reason: UNI.to_string(),
        }),
        "reset_empty" => Case::Reset(Reset {
            code: 0,
            reason: String::new(),
        }),
        "reset_code0_empty_reason" => Case::Reset(Reset {
            code: ResetCode::Unspecified as i32,
            reason: String::new(),
        }),
        // --- Header (4) ---
        "header_full" => Case::Header(hdr("x-custom", UNI)),
        "header_empty" => Case::Header(hdr("", "")),
        "header_key_only" => Case::Header(hdr("k", "")),
        "header_value_only" => Case::Header(hdr("", "v")),
        _ => panic!("unknown golden case {name}"),
    }
}

const NAMES: [&str; 58] = [
    "ntf_all",
    "ntf_chunk_id_only",
    "ntf_chunk_index_only",
    "ntf_total_chunks_only",
    "ntf_payload_only",
    "ntf_none",
    "ntf_chunk_id_zero_present",
    "ntf_chunk_index_zero_present",
    "ntf_total_chunks_zero_present",
    "ntf_payload_empty_present",
    "ntf_all_zero_present",
    "ntf_negative_max",
    "ntf_payload_60000",
    "sr_daemon",
    "sr_sentinel",
    "sr_vault",
    "sr_authd",
    "sr_empty",
    "sresp_payload",
    "sresp_empty",
    "sresp_60000",
    "sf_request",
    "sf_response",
    "sf_body_chunk",
    "sf_reset",
    "sf_no_kind",
    "sf_empty",
    "sf_stream_id_zero_with_request",
    "sf_stream_negative",
    "sf_stream_min",
    "ar_full",
    "ar_end_body_false",
    "ar_empty",
    "ar_headers_only",
    "ar_body_60000",
    "aresp_full",
    "aresp_status_zero",
    "aresp_negative",
    "aresp_empty",
    "aresp_404",
    "bc_data",
    "bc_end",
    "bc_empty",
    "bc_60000",
    "bc_empty_data_end",
    "reset_unspecified",
    "reset_cancelled",
    "reset_timeout",
    "reset_protocol_error",
    "reset_refused_stream",
    "reset_internal_error",
    "reset_service_unavailable",
    "reset_empty",
    "reset_code0_empty_reason",
    "header_full",
    "header_empty",
    "header_key_only",
    "header_value_only",
];

macro_rules! vector_bytes {
    ($name:expr) => {
        include_bytes!(concat!(
            "../../../internal/proto/testdata/vectors/",
            $name,
            ".bin"
        ))
    };
}

#[test]
fn golden_vectors_58_of_58() {
    assert_eq!(NAMES.len(), 58);
    let mut matched = 0;
    for name in NAMES {
        let py: &[u8] = match name {
            "ntf_all" => vector_bytes!("ntf_all"),
            "ntf_chunk_id_only" => vector_bytes!("ntf_chunk_id_only"),
            "ntf_chunk_index_only" => vector_bytes!("ntf_chunk_index_only"),
            "ntf_total_chunks_only" => vector_bytes!("ntf_total_chunks_only"),
            "ntf_payload_only" => vector_bytes!("ntf_payload_only"),
            "ntf_none" => vector_bytes!("ntf_none"),
            "ntf_chunk_id_zero_present" => vector_bytes!("ntf_chunk_id_zero_present"),
            "ntf_chunk_index_zero_present" => vector_bytes!("ntf_chunk_index_zero_present"),
            "ntf_total_chunks_zero_present" => vector_bytes!("ntf_total_chunks_zero_present"),
            "ntf_payload_empty_present" => vector_bytes!("ntf_payload_empty_present"),
            "ntf_all_zero_present" => vector_bytes!("ntf_all_zero_present"),
            "ntf_negative_max" => vector_bytes!("ntf_negative_max"),
            "ntf_payload_60000" => vector_bytes!("ntf_payload_60000"),
            "sr_daemon" => vector_bytes!("sr_daemon"),
            "sr_sentinel" => vector_bytes!("sr_sentinel"),
            "sr_vault" => vector_bytes!("sr_vault"),
            "sr_authd" => vector_bytes!("sr_authd"),
            "sr_empty" => vector_bytes!("sr_empty"),
            "sresp_payload" => vector_bytes!("sresp_payload"),
            "sresp_empty" => vector_bytes!("sresp_empty"),
            "sresp_60000" => vector_bytes!("sresp_60000"),
            "sf_request" => vector_bytes!("sf_request"),
            "sf_response" => vector_bytes!("sf_response"),
            "sf_body_chunk" => vector_bytes!("sf_body_chunk"),
            "sf_reset" => vector_bytes!("sf_reset"),
            "sf_no_kind" => vector_bytes!("sf_no_kind"),
            "sf_empty" => vector_bytes!("sf_empty"),
            "sf_stream_id_zero_with_request" => vector_bytes!("sf_stream_id_zero_with_request"),
            "sf_stream_negative" => vector_bytes!("sf_stream_negative"),
            "sf_stream_min" => vector_bytes!("sf_stream_min"),
            "ar_full" => vector_bytes!("ar_full"),
            "ar_end_body_false" => vector_bytes!("ar_end_body_false"),
            "ar_empty" => vector_bytes!("ar_empty"),
            "ar_headers_only" => vector_bytes!("ar_headers_only"),
            "ar_body_60000" => vector_bytes!("ar_body_60000"),
            "aresp_full" => vector_bytes!("aresp_full"),
            "aresp_status_zero" => vector_bytes!("aresp_status_zero"),
            "aresp_negative" => vector_bytes!("aresp_negative"),
            "aresp_empty" => vector_bytes!("aresp_empty"),
            "aresp_404" => vector_bytes!("aresp_404"),
            "bc_data" => vector_bytes!("bc_data"),
            "bc_end" => vector_bytes!("bc_end"),
            "bc_empty" => vector_bytes!("bc_empty"),
            "bc_60000" => vector_bytes!("bc_60000"),
            "bc_empty_data_end" => vector_bytes!("bc_empty_data_end"),
            "reset_unspecified" => vector_bytes!("reset_unspecified"),
            "reset_cancelled" => vector_bytes!("reset_cancelled"),
            "reset_timeout" => vector_bytes!("reset_timeout"),
            "reset_protocol_error" => vector_bytes!("reset_protocol_error"),
            "reset_refused_stream" => vector_bytes!("reset_refused_stream"),
            "reset_internal_error" => vector_bytes!("reset_internal_error"),
            "reset_service_unavailable" => vector_bytes!("reset_service_unavailable"),
            "reset_empty" => vector_bytes!("reset_empty"),
            "reset_code0_empty_reason" => vector_bytes!("reset_code0_empty_reason"),
            "header_full" => vector_bytes!("header_full"),
            "header_empty" => vector_bytes!("header_empty"),
            "header_key_only" => vector_bytes!("header_key_only"),
            "header_value_only" => vector_bytes!("header_value_only"),
            _ => unreachable!(),
        };
        let want = build(name);
        // 1. Rust-built encode == Python bytes, byte-for-byte.
        assert_eq!(want.encode(), py, "case {name}: rust-built != python bytes");
        // 2. Decode == Rust-built struct.
        let parsed = Case::decode(name, py);
        assert_eq!(parsed, want, "case {name}: decode != rust-built");
        // 3. Re-encode == Python bytes.
        assert_eq!(
            parsed.encode(),
            py,
            "case {name}: re-encode != python bytes"
        );
        matched += 1;
    }
    assert_eq!(matched, 58, "golden cases matched = {matched}, want 58");
}

/// Mirror of Go `TestNoiseTransportFramePresence`:
/// `chunk_id == 0` present differs from absent; payload
/// `Some(vec![])` differs from absent.
#[test]
fn noise_transport_frame_presence() {
    // Presence is visible in the encoding: Some(0) emits a
    // tag, None emits nothing.
    let present = NoiseTransportFrame {
        chunk_id: Some(0),
        chunk_index: Some(0),
        total_chunks: Some(0),
        payload: Some(vec![]),
    };
    let absent = NoiseTransportFrame {
        chunk_id: None,
        chunk_index: None,
        total_chunks: None,
        payload: None,
    };
    assert_eq!(present.encode_to_vec(), vec![8, 0, 16, 0, 24, 0, 34, 0]);
    assert_eq!(absent.encode_to_vec(), Vec::<u8>::new());
    // And it round-trips through decode.
    let back = NoiseTransportFrame::decode(present.encode_to_vec().as_slice()).unwrap();
    assert_eq!(back.chunk_id, Some(0));
    assert_eq!(back.payload, Some(vec![]));
    let back = NoiseTransportFrame::decode(absent.encode_to_vec().as_slice()).unwrap();
    assert_eq!(back.chunk_id, None);
    assert_eq!(back.payload, None);
}

/// Mirror of Go `TestServiceFrameOneofKind`.
#[test]
fn service_frame_oneof_kind() {
    let kinds = [
        ("sf_request", Some("request")),
        ("sf_response", Some("response")),
        ("sf_body_chunk", Some("body_chunk")),
        ("sf_reset", Some("reset")),
        ("sf_no_kind", None),
        ("sf_empty", None),
    ];
    for (name, want) in kinds {
        let Case::Sf(sf) = build(name) else {
            panic!("{name} is not a ServiceFrame");
        };
        let got = match &sf.kind {
            Some(ServiceFrameKind::Request(_)) => Some("request"),
            Some(ServiceFrameKind::Response(_)) => Some("response"),
            Some(ServiceFrameKind::BodyChunk(_)) => Some("body_chunk"),
            Some(ServiceFrameKind::Reset(_)) => Some("reset"),
            None => None,
        };
        assert_eq!(got, want, "case {name}");
    }
}

/// Mirror of Go `TestEnumNames`: the verified enum value
/// names and numbers (names do not affect wire bytes, but
/// they do affect `as_str_name` output).
#[test]
fn enum_names_and_numbers() {
    assert_eq!(ServiceType::ServiceDaemon as i32, 0);
    assert_eq!(ServiceType::ServiceSentinel as i32, 1);
    assert_eq!(ServiceType::ServiceVault as i32, 2);
    assert_eq!(ServiceType::ServiceAuthd as i32, 3);
    assert_eq!(ServiceType::ServiceDaemon.as_str_name(), "SERVICE_DAEMON");
    assert_eq!(
        ServiceType::ServiceSentinel.as_str_name(),
        "SERVICE_SENTINEL"
    );
    assert_eq!(ServiceType::ServiceVault.as_str_name(), "SERVICE_VAULT");
    assert_eq!(ServiceType::ServiceAuthd.as_str_name(), "SERVICE_AUTHD");
    assert_eq!(ResetCode::Unspecified as i32, 0);
    assert_eq!(ResetCode::Cancelled as i32, 1);
    assert_eq!(ResetCode::Timeout as i32, 2);
    assert_eq!(ResetCode::ProtocolError as i32, 3);
    assert_eq!(ResetCode::RefusedStream as i32, 4);
    assert_eq!(ResetCode::InternalError as i32, 5);
    assert_eq!(ResetCode::ServiceUnavailable as i32, 6);
    assert_eq!(ResetCode::Unspecified.as_str_name(), "CODE_UNSPECIFIED");
    assert_eq!(ResetCode::Cancelled.as_str_name(), "CANCELLED");
}
