// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package proto_test

import (
	"fmt"
	"sort"

	"google.golang.org/protobuf/proto"

	pb "github.com/thoitiettxl-cyber/castctl/internal/proto"
)

// Builders for the same 58 golden cases the PR0 probe built on both
// sides (Python gen_vectors.py from the bin-loaded descriptors, and
// the probe's Go cases). Case names and field values mirror the Python
// side exactly; any drift fails the byte comparison in golden_test.go.
// This file is test-only: production code must not depend on it.

// UNI is the non-ASCII string used in string fields. Written with \u
// escapes so the bytes are exact regardless of source-file encoding:
// "café ☃ — lý do" in UTF-8.
const uni = "caf\u00e9 \u2603 \u2014 l\u00fd do"

func payload60k() []byte {
	b := make([]byte, 60000)
	for i := range b {
		b[i] = byte((i*7 + 3) % 256)
	}
	return b
}

func body60k() []byte {
	b := make([]byte, 60000)
	for i := range b {
		b[i] = byte(255 - (i % 256))
	}
	return b
}

func data60k() []byte {
	b := make([]byte, 60000)
	for i := 0; i < 60000; i += 2 {
		b[i] = 'A'
		b[i+1] = 0xff
	}
	return b
}

func hdr(k, v string) *pb.Header { return &pb.Header{Key: k, Value: v} }

// Names returns every golden case name, sorted, matching gen_vectors.py.
func Names() []string {
	names := make([]string, 0, len(builders))
	for n := range builders {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Build constructs the named case with the generated typed API.
func Build(name string) (proto.Message, error) {
	fn, ok := builders[name]
	if !ok {
		return nil, fmt.Errorf("unknown golden case %q", name)
	}
	return fn(), nil
}

var builders = map[string]func() proto.Message{
	// --- NoiseTransportFrame ---
	"ntf_all": func() proto.Message {
		return &pb.NoiseTransportFrame{ChunkId: proto.Int64(1234567890123), ChunkIndex: proto.Uint32(2), TotalChunks: proto.Uint32(5), Payload: []byte("hello\xff\xfe\x00\x80\xc3\xa9")}
	},
	"ntf_chunk_id_only": func() proto.Message {
		return &pb.NoiseTransportFrame{ChunkId: proto.Int64(42)}
	},
	"ntf_chunk_index_only": func() proto.Message {
		return &pb.NoiseTransportFrame{ChunkIndex: proto.Uint32(7)}
	},
	"ntf_total_chunks_only": func() proto.Message {
		return &pb.NoiseTransportFrame{TotalChunks: proto.Uint32(9)}
	},
	"ntf_payload_only": func() proto.Message {
		return &pb.NoiseTransportFrame{Payload: []byte("\x00\xffabc")}
	},
	"ntf_none": func() proto.Message { return &pb.NoiseTransportFrame{} },
	"ntf_chunk_id_zero_present": func() proto.Message {
		return &pb.NoiseTransportFrame{ChunkId: proto.Int64(0)}
	},
	"ntf_chunk_index_zero_present": func() proto.Message {
		return &pb.NoiseTransportFrame{ChunkIndex: proto.Uint32(0)}
	},
	"ntf_total_chunks_zero_present": func() proto.Message {
		return &pb.NoiseTransportFrame{TotalChunks: proto.Uint32(0)}
	},
	// Empty but non-nil slice: presence must survive as tag 22 00.
	"ntf_payload_empty_present": func() proto.Message {
		return &pb.NoiseTransportFrame{Payload: []byte{}}
	},
	"ntf_all_zero_present": func() proto.Message {
		return &pb.NoiseTransportFrame{ChunkId: proto.Int64(0), ChunkIndex: proto.Uint32(0), TotalChunks: proto.Uint32(0), Payload: []byte{}}
	},
	"ntf_negative_max": func() proto.Message {
		return &pb.NoiseTransportFrame{ChunkId: proto.Int64(-1), ChunkIndex: proto.Uint32(4294967295), TotalChunks: proto.Uint32(4294967295), Payload: payload60k()}
	},
	"ntf_payload_60000": func() proto.Message {
		return &pb.NoiseTransportFrame{ChunkId: proto.Int64(1), ChunkIndex: proto.Uint32(0), TotalChunks: proto.Uint32(1), Payload: data60k()}
	},
	// --- ServiceRequest ---
	"sr_daemon": func() proto.Message {
		return &pb.ServiceRequest{Service: pb.ServiceType_SERVICE_DAEMON, Payload: []byte("frame-bytes-\xff")}
	},
	"sr_sentinel": func() proto.Message {
		return &pb.ServiceRequest{Service: pb.ServiceType_SERVICE_SENTINEL, Payload: []byte{}}
	},
	"sr_vault": func() proto.Message {
		return &pb.ServiceRequest{Service: pb.ServiceType_SERVICE_VAULT, Payload: []byte("\x00\x01\x02")}
	},
	"sr_authd": func() proto.Message {
		b := make([]byte, 1000)
		for i := range b {
			b[i] = 'x'
		}
		return &pb.ServiceRequest{Service: pb.ServiceType_SERVICE_AUTHD, Payload: b}
	},
	"sr_empty": func() proto.Message { return &pb.ServiceRequest{} },
	// --- ServiceResponse ---
	"sresp_payload": func() proto.Message {
		return &pb.ServiceResponse{Payload: []byte("resp\xff")}
	},
	"sresp_empty": func() proto.Message { return &pb.ServiceResponse{} },
	"sresp_60000": func() proto.Message {
		return &pb.ServiceResponse{Payload: payload60k()}
	},
	// --- ServiceFrame ---
	"sf_request": func() proto.Message {
		return &pb.ServiceFrame{StreamId: 1, Kind: &pb.ServiceFrame_Request{Request: &pb.ApplicationRequest{Verb: "GET", Path: "/x", Headers: []*pb.Header{hdr("k", "v")}, Body: []byte("hi"), EndBody: true}}}
	},
	"sf_response": func() proto.Message {
		return &pb.ServiceFrame{StreamId: 2, Kind: &pb.ServiceFrame_Response{Response: &pb.ApplicationResponse{Status: 200, Headers: []*pb.Header{hdr("a", "b")}, Body: []byte("ok\xff"), EndBody: true}}}
	},
	"sf_body_chunk": func() proto.Message {
		return &pb.ServiceFrame{StreamId: 3, Kind: &pb.ServiceFrame_BodyChunk{BodyChunk: &pb.BodyChunk{Data: []byte("chunk\xff"), EndBody: false}}}
	},
	"sf_reset": func() proto.Message {
		return &pb.ServiceFrame{StreamId: 4, Kind: &pb.ServiceFrame_Reset_{Reset_: &pb.Reset{Code: pb.Reset_CANCELLED, Reason: uni}}}
	},
	"sf_no_kind": func() proto.Message {
		return &pb.ServiceFrame{StreamId: 5}
	},
	"sf_empty": func() proto.Message { return &pb.ServiceFrame{} },
	"sf_stream_id_zero_with_request": func() proto.Message {
		return &pb.ServiceFrame{StreamId: 0, Kind: &pb.ServiceFrame_Request{Request: &pb.ApplicationRequest{Verb: "GET", Path: "/p"}}}
	},
	"sf_stream_negative": func() proto.Message {
		return &pb.ServiceFrame{StreamId: -1, Kind: &pb.ServiceFrame_BodyChunk{BodyChunk: &pb.BodyChunk{Data: []byte("d"), EndBody: true}}}
	},
	"sf_stream_min": func() proto.Message {
		return &pb.ServiceFrame{StreamId: -9223372036854775808, Kind: &pb.ServiceFrame_BodyChunk{BodyChunk: &pb.BodyChunk{}}}
	},
	// --- ApplicationRequest ---
	"ar_full": func() proto.Message {
		return &pb.ApplicationRequest{Verb: "POST", Path: "/api/test?q=caf\u00e9", Headers: []*pb.Header{hdr("content-type", "application/json"), hdr("x-request-id", "abc-123"), hdr("", ""), hdr("x-unicode", uni)}, Body: []byte("\x00\xff\xfe binary \x80"), EndBody: true}
	},
	"ar_end_body_false": func() proto.Message {
		return &pb.ApplicationRequest{Verb: "GET", Path: "/p", Body: []byte{}, EndBody: false}
	},
	"ar_empty": func() proto.Message { return &pb.ApplicationRequest{} },
	"ar_headers_only": func() proto.Message {
		return &pb.ApplicationRequest{Headers: []*pb.Header{hdr("a", "1"), hdr("b", "2"), hdr("c", "3")}}
	},
	"ar_body_60000": func() proto.Message {
		return &pb.ApplicationRequest{Verb: "POST", Path: "/big", Body: body60k(), EndBody: true}
	},
	// --- ApplicationResponse ---
	"aresp_full": func() proto.Message {
		return &pb.ApplicationResponse{Status: 200, Headers: []*pb.Header{hdr("content-type", "text/plain"), hdr("x-u", uni)}, Body: []byte("body\xff\x00end"), EndBody: true}
	},
	"aresp_status_zero": func() proto.Message {
		return &pb.ApplicationResponse{Status: 0, Body: []byte("zero")}
	},
	"aresp_negative": func() proto.Message {
		return &pb.ApplicationResponse{Status: -1, Body: []byte("err"), EndBody: false}
	},
	"aresp_empty": func() proto.Message { return &pb.ApplicationResponse{} },
	"aresp_404": func() proto.Message {
		return &pb.ApplicationResponse{Status: 404, Body: []byte("not found"), EndBody: true}
	},
	// --- BodyChunk ---
	"bc_data": func() proto.Message {
		return &pb.BodyChunk{Data: []byte("chunk\xff\x00"), EndBody: false}
	},
	"bc_end": func() proto.Message {
		return &pb.BodyChunk{Data: []byte("last"), EndBody: true}
	},
	"bc_empty": func() proto.Message { return &pb.BodyChunk{} },
	"bc_60000": func() proto.Message {
		return &pb.BodyChunk{Data: data60k(), EndBody: true}
	},
	"bc_empty_data_end": func() proto.Message {
		return &pb.BodyChunk{Data: []byte{}, EndBody: true}
	},
	// --- Reset (each Code) ---
	"reset_unspecified": func() proto.Message {
		return &pb.Reset{Code: pb.Reset_CODE_UNSPECIFIED, Reason: uni}
	},
	"reset_cancelled": func() proto.Message {
		return &pb.Reset{Code: pb.Reset_CANCELLED, Reason: uni}
	},
	"reset_timeout": func() proto.Message {
		return &pb.Reset{Code: pb.Reset_TIMEOUT, Reason: uni}
	},
	"reset_protocol_error": func() proto.Message {
		return &pb.Reset{Code: pb.Reset_PROTOCOL_ERROR, Reason: uni}
	},
	"reset_refused_stream": func() proto.Message {
		return &pb.Reset{Code: pb.Reset_REFUSED_STREAM, Reason: uni}
	},
	"reset_internal_error": func() proto.Message {
		return &pb.Reset{Code: pb.Reset_INTERNAL_ERROR, Reason: uni}
	},
	"reset_service_unavailable": func() proto.Message {
		return &pb.Reset{Code: pb.Reset_SERVICE_UNAVAILABLE, Reason: uni}
	},
	"reset_empty": func() proto.Message { return &pb.Reset{} },
	"reset_code0_empty_reason": func() proto.Message {
		return &pb.Reset{Code: pb.Reset_CODE_UNSPECIFIED, Reason: ""}
	},
	// --- Header ---
	"header_full":       func() proto.Message { return hdr("x-custom", uni) },
	"header_empty":      func() proto.Message { return &pb.Header{} },
	"header_key_only":   func() proto.Message { return hdr("k", "") },
	"header_value_only": func() proto.Message { return hdr("", "v") },
}
