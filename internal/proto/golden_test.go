// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package proto_test

import (
	"bytes"
	"embed"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	pb "github.com/thoitiettxl-cyber/castctl/internal/proto"
)

//go:embed testdata/vectors/*.bin
var vectors embed.FS

// TestGoldenVectors is the Python -> Go direction: parse the bytes
// Python produced from the bin-loaded descriptors, re-serialize in Go,
// and require byte identity; then require that Go's own typed
// construction of the same case marshals to exactly the same bytes.
// The embedded vectors are the PR0 probe's vectors/*.bin, copied
// verbatim (58 cases, fake payload bytes only, no secrets).
func TestGoldenVectors(t *testing.T) {
	names := Names()
	if len(names) != 58 {
		t.Fatalf("golden cases = %d, want 58", len(names))
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			pyBytes, err := vectors.ReadFile("testdata/vectors/" + name + ".bin")
			if err != nil {
				t.Fatalf("read python vector: %v", err)
			}
			want, err := Build(name)
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			goBytes, err := proto.Marshal(want)
			if err != nil {
				t.Fatalf("marshal go-built: %v", err)
			}
			if !bytes.Equal(goBytes, pyBytes) {
				t.Fatalf("go-built bytes != python bytes:\n go: %x\n py: %x", goBytes, pyBytes)
			}
			// Parse + re-serialize: fresh empty message of the same type.
			parsed := want.ProtoReflect().New().Interface()
			if err := proto.Unmarshal(pyBytes, parsed); err != nil {
				t.Fatalf("unmarshal python bytes: %v", err)
			}
			if !proto.Equal(want, parsed) {
				t.Fatalf("proto.Equal(go-built, parsed) = false")
			}
			reser, err := proto.Marshal(parsed)
			if err != nil {
				t.Fatalf("re-marshal parsed: %v", err)
			}
			if !bytes.Equal(reser, pyBytes) {
				t.Fatalf("re-serialized bytes != python bytes:\n re: %x\n py: %x", reser, pyBytes)
			}
		})
	}
}

// TestNoiseTransportFramePresence checks proto3-optional presence
// through protoreflect Has() and through the generated pointer fields,
// the semantics the gateway will rely on (chunk_id == 0 present vs
// absent must stay distinguishable). Payload is []byte, not a pointer:
// nil means absent, []byte{} means present.
func TestNoiseTransportFramePresence(t *testing.T) {
	cases := []struct {
		name   string
		fields map[string]bool
	}{
		{"ntf_none", map[string]bool{"chunk_id": false, "chunk_index": false, "total_chunks": false, "payload": false}},
		{"ntf_chunk_id_zero_present", map[string]bool{"chunk_id": true}},
		{"ntf_chunk_index_zero_present", map[string]bool{"chunk_index": true}},
		{"ntf_total_chunks_zero_present", map[string]bool{"total_chunks": true}},
		{"ntf_payload_empty_present", map[string]bool{"payload": true}},
		{"ntf_all_zero_present", map[string]bool{"chunk_id": true, "chunk_index": true, "total_chunks": true, "payload": true}},
		{"ntf_all", map[string]bool{"chunk_id": true, "chunk_index": true, "total_chunks": true, "payload": true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m, err := Build(tc.name)
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			ntf, ok := m.(*pb.NoiseTransportFrame)
			if !ok {
				t.Fatalf("not a NoiseTransportFrame: %T", m)
			}
			// Pointer-field presence (the generated API the gateway uses).
			if _, ok := tc.fields["chunk_id"]; ok && (ntf.ChunkId == nil) != !tc.fields["chunk_id"] {
				t.Fatalf("ChunkId nil=%v want present=%v", ntf.ChunkId == nil, tc.fields["chunk_id"])
			}
			if _, ok := tc.fields["chunk_index"]; ok && (ntf.ChunkIndex == nil) != !tc.fields["chunk_index"] {
				t.Fatalf("ChunkIndex nil=%v want present=%v", ntf.ChunkIndex == nil, tc.fields["chunk_index"])
			}
			if _, ok := tc.fields["total_chunks"]; ok && (ntf.TotalChunks == nil) != !tc.fields["total_chunks"] {
				t.Fatalf("TotalChunks nil=%v want present=%v", ntf.TotalChunks == nil, tc.fields["total_chunks"])
			}
			// protoreflect presence for every field, including []byte payload.
			desc := m.ProtoReflect().Descriptor()
			for fname, present := range tc.fields {
				fd := desc.Fields().ByName(protoreflect.Name(fname))
				if fd == nil {
					t.Fatalf("no field %q", fname)
				}
				if got := m.ProtoReflect().Has(fd); got != present {
					t.Fatalf("Has(%s)=%v want %v", fname, got, present)
				}
			}
		})
	}
}

// TestServiceFrameOneofKind checks WhichOneof for each kind, including none.
func TestServiceFrameOneofKind(t *testing.T) {
	cases := []struct {
		name string
		kind string
	}{
		{"sf_request", "request"},
		{"sf_response", "response"},
		{"sf_body_chunk", "body_chunk"},
		{"sf_reset", "reset"},
		{"sf_no_kind", ""},
		{"sf_empty", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m, err := Build(tc.name)
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			sf := m.(*pb.ServiceFrame)
			kindDesc := sf.ProtoReflect().Descriptor().Oneofs().ByName("kind")
			fd := sf.ProtoReflect().WhichOneof(kindDesc)
			gotKind := ""
			if fd != nil {
				gotKind = string(fd.Name())
			}
			if gotKind != tc.kind {
				t.Fatalf("kind=%q want %q", gotKind, tc.kind)
			}
		})
	}
}

// TestEnumNames guards the verified enum value names and numbers.
// The names do not affect wire bytes, but they do affect String() and
// JSON names; the planner's shortened DAEMON/SENTINEL/VAULT/AUTHD
// names must not come back.
func TestEnumNames(t *testing.T) {
	t.Parallel()
	serviceCases := []struct {
		value pb.ServiceType
		name  string
	}{
		{pb.ServiceType_SERVICE_DAEMON, "SERVICE_DAEMON"},
		{pb.ServiceType_SERVICE_SENTINEL, "SERVICE_SENTINEL"},
		{pb.ServiceType_SERVICE_VAULT, "SERVICE_VAULT"},
		{pb.ServiceType_SERVICE_AUTHD, "SERVICE_AUTHD"},
	}
	for i, tc := range serviceCases {
		if int32(tc.value) != int32(i) {
			t.Fatalf("ServiceType %s = %d, want %d", tc.name, int32(tc.value), i)
		}
		if got := tc.value.String(); got != tc.name {
			t.Fatalf("ServiceType String()=%q want %q", got, tc.name)
		}
	}
	resetCases := []struct {
		value pb.Reset_Code
		name  string
	}{
		{pb.Reset_CODE_UNSPECIFIED, "CODE_UNSPECIFIED"},
		{pb.Reset_CANCELLED, "CANCELLED"},
		{pb.Reset_TIMEOUT, "TIMEOUT"},
		{pb.Reset_PROTOCOL_ERROR, "PROTOCOL_ERROR"},
		{pb.Reset_REFUSED_STREAM, "REFUSED_STREAM"},
		{pb.Reset_INTERNAL_ERROR, "INTERNAL_ERROR"},
		{pb.Reset_SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE"},
	}
	for i, tc := range resetCases {
		if int32(tc.value) != int32(i) {
			t.Fatalf("Reset.Code %s = %d, want %d", tc.name, int32(tc.value), i)
		}
		if got := tc.value.String(); got != tc.name {
			t.Fatalf("Reset.Code String()=%q want %q", got, tc.name)
		}
	}
}
