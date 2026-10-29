// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/thoitiettxl-cyber/muse-cli/go/internal/proto"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestRoutesCounts(t *testing.T) {
	tbl, err := DefaultRoutes()
	if err != nil {
		t.Fatalf("DefaultRoutes: %v", err)
	}
	if got := tbl.Total(); got != 258 {
		t.Fatalf("total = %d, want 258", got)
	}
	cases := map[string]int{"POST": 141, "GET": 91, "PATCH": 14, "DELETE": 12}
	for verb, want := range cases {
		if got := tbl.CountHTTP(verb); got != want {
			t.Errorf("CountHTTP(%s) = %d, want %d", verb, got, want)
		}
	}
}

func TestLookupRoute(t *testing.T) {
	tbl, _ := DefaultRoutes()
	cases := []struct {
		method  string
		want    bool
		http    string
		path    string
		service string
	}{
		{"connection.ping", true, "POST", "/api/ping", ""},
		{"chat.history", true, "GET", "/chat/history", ""},
		{"chat.mark_seen", true, "POST", "/api/chat/{thread_id}/seen", ""},
		{"egress.approval.decide", true, "POST", "/approvals/{approval_id}/decide", "sentinel"},
		{"vault.luks_status", true, "GET", "/luks/status", "vault"},
		{"custom_connectors.list", true, "POST", "/v1/custom-connectors/list", "authd"},
		{"media.raw", false, "", "", ""},
		{"no.such.method", false, "", "", ""},
		{"", false, "", "", ""},
		{"CHAT.HISTORY", false, "", "", ""},
		{"chat", false, "", "", ""},
	}
	for _, tc := range cases {
		r, ok := tbl.LookupRoute(tc.method)
		if ok != tc.want {
			t.Errorf("LookupRoute(%q) ok = %v, want %v", tc.method, ok, tc.want)
			continue
		}
		if !tc.want {
			continue
		}
		if r.Method != tc.method || r.HTTP != tc.http || r.Path != tc.path || r.Service != tc.service {
			t.Errorf("LookupRoute(%q) = %+v, want http=%q path=%q service=%q", tc.method, r, tc.http, tc.path, tc.service)
		}
	}
}

func TestServiceID(t *testing.T) {
	cases := map[string]pb.ServiceType{
		"":         pb.ServiceType_SERVICE_DAEMON,
		"daemon":   pb.ServiceType_SERVICE_DAEMON,
		"sentinel": pb.ServiceType_SERVICE_SENTINEL,
		"vault":    pb.ServiceType_SERVICE_VAULT,
		"authd":    pb.ServiceType_SERVICE_AUTHD,
		"unknown":  pb.ServiceType_SERVICE_DAEMON,
	}
	for name, want := range cases {
		if got := serviceID(name); got != want {
			t.Errorf("serviceID(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestParseRoutesMalformed(t *testing.T) {
	if _, err := ParseRoutes([]byte(`not json`)); err == nil {
		t.Error("ParseRoutes(malformed) = nil error, want error")
	}
	if _, err := ParseRoutes([]byte(`[]`)); err != nil {
		t.Errorf("ParseRoutes([]) = %v, want nil", err)
	}
}

func framePtrs(id int64, index, total uint32, payload []byte) *pb.NoiseTransportFrame {
	return &pb.NoiseTransportFrame{ChunkId: &id, ChunkIndex: &index, TotalChunks: &total, Payload: payload}
}

func TestJoinChunks(t *testing.T) {
	t.Run("total<=1 returns immediately", func(t *testing.T) {
		partial := map[int64]map[uint32][]byte{}
		for _, tc := range []*pb.NoiseTransportFrame{
			{Payload: []byte("abc")},
			framePtrs(7, 0, 1, []byte("one")),
			framePtrs(7, 0, 0, []byte("zero-total")),
		} {
			got, ok := joinChunks(partial, tc)
			if !ok {
				t.Fatalf("joinChunks total<=1: ok=false")
			}
			if string(got) != string(tc.GetPayload()) {
				t.Fatalf("joinChunks = %q, want %q", got, tc.GetPayload())
			}
		}
		if len(partial) != 0 {
			t.Fatalf("partial accumulator touched for total<=1: %v", partial)
		}
	})
	t.Run("joins by chunk_index out of order", func(t *testing.T) {
		partial := map[int64]map[uint32][]byte{}
		frames := []*pb.NoiseTransportFrame{
			framePtrs(99, 2, 3, []byte("C")),
			framePtrs(99, 0, 3, []byte("A")),
			framePtrs(99, 1, 3, []byte("B")),
		}
		for i, f := range frames[:2] {
			if _, ok := joinChunks(partial, f); ok {
				t.Fatalf("frame %d: complete early", i)
			}
		}
		got, ok := joinChunks(partial, frames[2])
		if !ok || string(got) != "ABC" {
			t.Fatalf("join = %q ok=%v, want ABC true", got, ok)
		}
		if len(partial) != 0 {
			t.Fatalf("partial not cleaned: %v", partial)
		}
	})
	t.Run("different chunk ids do not mix", func(t *testing.T) {
		partial := map[int64]map[uint32][]byte{}
		if _, ok := joinChunks(partial, framePtrs(1, 0, 2, []byte("x"))); ok {
			t.Fatal("complete with one of two pieces")
		}
		if _, ok := joinChunks(partial, framePtrs(2, 1, 2, []byte("y"))); ok {
			t.Fatal("complete across chunk ids")
		}
		got, ok := joinChunks(partial, framePtrs(1, 1, 2, []byte("z")))
		if !ok || string(got) != "xz" {
			t.Fatalf("join = %q ok=%v, want xz", got, ok)
		}
	})
	t.Run("payload is copied", func(t *testing.T) {
		partial := map[int64]map[uint32][]byte{}
		payload := []byte("mutable")
		got, ok := joinChunks(partial, &pb.NoiseTransportFrame{Payload: payload})
		if !ok {
			t.Fatal("not complete")
		}
		payload[0] = 'X'
		if got[0] == 'X' {
			t.Fatal("returned payload aliases input")
		}
	})
}

func TestSplitPieces(t *testing.T) {
	cases := []struct {
		size  int
		wantN int
	}{
		{0, 1}, {1, 1}, {60000, 1}, {60001, 2}, {120000, 2}, {120001, 3},
	}
	for _, tc := range cases {
		data := make([]byte, tc.size)
		pieces := splitPieces(data)
		if len(pieces) != tc.wantN {
			t.Errorf("splitPieces(%d): %d pieces, want %d", tc.size, len(pieces), tc.wantN)
		}
		total := 0
		for _, p := range pieces {
			if len(p) > SendPiece {
				t.Errorf("splitPieces(%d): piece %d > %d", tc.size, len(p), SendPiece)
			}
			total += len(p)
		}
		if total != tc.size {
			t.Errorf("splitPieces(%d): total %d", tc.size, total)
		}
	}
}

func TestMarshalTransportFramePresence(t *testing.T) {
	// Chunk id 0 present must serialize (field 1, varint 0) and
	// round-trip with Has() true; an absent id must not.
	b, err := marshalTransportFrame(0, 0, 1, []byte("x"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var fr pb.NoiseTransportFrame
	if err := proto.Unmarshal(b, &fr); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	fd := fr.ProtoReflect().Descriptor().Fields()
	for _, name := range []string{"chunk_id", "chunk_index", "total_chunks", "payload"} {
		if !fr.ProtoReflect().Has(fd.ByName(protoreflect.Name(name))) {
			t.Errorf("field %s not present after marshal", name)
		}
	}
	if fr.GetChunkId() != 0 || fr.GetTotalChunks() != 1 {
		t.Errorf("round-trip values: id=%d total=%d", fr.GetChunkId(), fr.GetTotalChunks())
	}
}

// TestGoldenVectorsSubset re-runs the PR0 proto-probe golden
// checks against the gateway's framing helpers: messages built
// with the generated code must marshal byte-identically to the
// bytes Python produced (vectors/*.bin in internal/proto).
func TestGoldenVectorsSubset(t *testing.T) {
	uni := "café ☃ — lý do"
	builders := map[string]func() proto.Message{
		"ntf_all": func() proto.Message {
			return &pb.NoiseTransportFrame{ChunkId: proto.Int64(1234567890123), ChunkIndex: proto.Uint32(2), TotalChunks: proto.Uint32(5), Payload: []byte("hello\xff\xfe\x00\x80\xc3\xa9")}
		},
		"ntf_chunk_id_zero_present": func() proto.Message {
			return &pb.NoiseTransportFrame{ChunkId: proto.Int64(0)}
		},
		"ntf_payload_empty_present": func() proto.Message {
			return &pb.NoiseTransportFrame{Payload: []byte{}}
		},
		"sr_daemon": func() proto.Message {
			return &pb.ServiceRequest{Service: pb.ServiceType_SERVICE_DAEMON, Payload: []byte("frame-bytes-\xff")}
		},
		"sr_sentinel": func() proto.Message {
			return &pb.ServiceRequest{Service: pb.ServiceType_SERVICE_SENTINEL, Payload: []byte{}}
		},
		"sf_request": func() proto.Message {
			return &pb.ServiceFrame{StreamId: 1, Kind: &pb.ServiceFrame_Request{Request: &pb.ApplicationRequest{Verb: "GET", Path: "/x", Headers: []*pb.Header{{Key: "k", Value: "v"}}, Body: []byte("hi"), EndBody: true}}}
		},
		"ar_full": func() proto.Message {
			return &pb.ApplicationRequest{Verb: "POST", Path: "/api/test?q=café", Headers: []*pb.Header{{Key: "content-type", Value: "application/json"}, {Key: "x-request-id", Value: "abc-123"}, {Key: "", Value: ""}, {Key: "x-unicode", Value: uni}}, Body: []byte("\x00\xff\xfe binary \x80"), EndBody: true}
		},
		"aresp_full": func() proto.Message {
			return &pb.ApplicationResponse{Status: 200, Headers: []*pb.Header{{Key: "content-type", Value: "text/plain"}, {Key: "x-u", Value: uni}}, Body: []byte("body\xff\x00end"), EndBody: true}
		},
		"reset_cancelled": func() proto.Message {
			return &pb.Reset{Code: pb.Reset_CANCELLED, Reason: uni}
		},
	}
	for name, build := range builders {
		t.Run(name, func(t *testing.T) {
			pyBytes, err := os.ReadFile(filepath.Join("..", "proto", "testdata", "vectors", name+".bin"))
			if err != nil {
				t.Fatalf("read vector: %v", err)
			}
			goBytes, err := proto.Marshal(build())
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if !bytes.Equal(goBytes, pyBytes) {
				t.Fatalf("go bytes != python bytes:\n go: %x\n py: %x", goBytes, pyBytes)
			}
			parsed := build().ProtoReflect().New().Interface()
			if err := proto.Unmarshal(pyBytes, parsed); err != nil {
				t.Fatalf("unmarshal python bytes: %v", err)
			}
			if !proto.Equal(build(), parsed) {
				t.Fatalf("proto.Equal(go-built, parsed) = false")
			}
		})
	}
}
