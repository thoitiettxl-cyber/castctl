// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package proto_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"

	pb "github.com/thoitiettxl-cyber/castctl/internal/proto"
)

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// TestEmbeddedDescriptors pins the embedded descriptor bins to the
// original Python copies (byte-identical) and checks they parse as
// FileDescriptorProtos with the expected names, packages, and types.
func TestEmbeddedDescriptors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		get      func() []byte
		sha      string
		length   int
		fdName   string
		package_ string
	}{
		{
			name: "transport", get: pb.TransportDescriptor,
			sha: "5479a20cd5a9bf817c2a7ba4eec56b354d8576f565d9096fd2a3a8223e820d00", length: 230,
			fdName: "noise_transport.proto", package_: "ingress_rev_proxy",
		},
		{
			name: "envelope", get: pb.EnvelopeDescriptor,
			sha: "5ea3f209386a4d47d28ee06473a2defad35536725bf2d3d847d31b04ec1a8868", length: 1006,
			fdName: "noise_envelope.proto", package_: "hatch.noise",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b := tc.get()
			if len(b) != tc.length {
				t.Fatalf("descriptor length = %d, want %d", len(b), tc.length)
			}
			if got := sha256Hex(b); got != tc.sha {
				t.Fatalf("descriptor sha256 = %s, want %s", got, tc.sha)
			}
			var fd descriptorpb.FileDescriptorProto
			if err := proto.Unmarshal(b, &fd); err != nil {
				t.Fatalf("unmarshal descriptor: %v", err)
			}
			if fd.GetName() != tc.fdName {
				t.Fatalf("descriptor name = %q, want %q", fd.GetName(), tc.fdName)
			}
			if fd.GetPackage() != tc.package_ {
				t.Fatalf("descriptor package = %q, want %q", fd.GetPackage(), tc.package_)
			}
			if fd.GetSyntax() != "proto3" {
				t.Fatalf("descriptor syntax = %q, want proto3", fd.GetSyntax())
			}
			// Mutating the returned copy must not corrupt the embed.
			b[0] ^= 0xff
			if got := sha256Hex(tc.get()); got != tc.sha {
				t.Fatalf("accessor does not return a copy: sha256 after mutation = %s", got)
			}
		})
	}
}

// TestGeneratedDescriptorsMatchEmbeds proves the generated code was
// produced from the same descriptors as the embedded bins. The only
// allowed differences are the ones generation necessarily adds: the
// go_package option and the derived json_name fields. Everything else
// (names, numbers, types, labels, proto3_optional, oneofs, enums,
// packages, syntax) must be identical after normalising those away.
func TestGeneratedDescriptorsMatchEmbeds(t *testing.T) {
	t.Parallel()
	cases := []struct {
		fdName string
		embed  func() []byte
	}{
		{"noise_transport.proto", pb.TransportDescriptor},
		{"noise_envelope.proto", pb.EnvelopeDescriptor},
	}
	for _, tc := range cases {
		t.Run(tc.fdName, func(t *testing.T) {
			t.Parallel()
			generated, err := protoregistry.GlobalFiles.FindFileByPath(tc.fdName)
			if err != nil {
				t.Fatalf("generated descriptor not registered: %v", err)
			}
			var want descriptorpb.FileDescriptorProto
			if err := proto.Unmarshal(tc.embed(), &want); err != nil {
				t.Fatalf("unmarshal embedded descriptor: %v", err)
			}
			got := protodesc.ToFileDescriptorProto(generated)
			if !proto.Equal(normalizeDescriptor(&want), normalizeDescriptor(got)) {
				t.Fatalf("generated descriptor != embedded descriptor after normalization:\nembedded: %v\ngenerated: %v", &want, got)
			}
		})
	}
}

func normalizeDescriptor(fd *descriptorpb.FileDescriptorProto) *descriptorpb.FileDescriptorProto {
	out := proto.Clone(fd).(*descriptorpb.FileDescriptorProto)
	out.Options = nil
	out.SourceCodeInfo = nil
	var clearJSONNames func(msgs []*descriptorpb.DescriptorProto)
	clearJSONNames = func(msgs []*descriptorpb.DescriptorProto) {
		for _, m := range msgs {
			for _, f := range m.Field {
				f.JsonName = nil
			}
			clearJSONNames(m.NestedType)
		}
	}
	clearJSONNames(out.MessageType)
	return out
}

// TestRoutesJSON pins routes.json to the verbatim Python copy and
// checks the shape consumers rely on: 258 entries, unique methods,
// and method/http/path always present with service (when present)
// naming one of the four services. Auxiliary fields are asserted
// present somewhere in the file to prove the embed is the full
// verbatim file, not a trimmed projection — consumers must still
// only use method/http/path/service.
func TestRoutesJSON(t *testing.T) {
	t.Parallel()
	b := pb.RoutesJSON()
	if len(b) != 26811 {
		t.Fatalf("routes.json length = %d, want 26811", len(b))
	}
	if got := sha256Hex(b); got != "f13e7ec63548edd9319b655be1ffc88e3580f19b4f4f016aaec63d553ed5f033" {
		t.Fatalf("routes.json sha256 = %s, want the Python copy's hash", got)
	}
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(b, &entries); err != nil {
		t.Fatalf("routes.json is not a JSON list: %v", err)
	}
	if len(entries) != 258 {
		t.Fatalf("routes.json entries = %d, want 258", len(entries))
	}
	seenMethods := make(map[string]bool, len(entries))
	serviceCounts := make(map[string]int)
	auxSeen := make(map[string]bool)
	for i, e := range entries {
		var method, httpMethod, path string
		if err := json.Unmarshal(e["method"], &method); err != nil || method == "" {
			t.Fatalf("entry %d: missing/empty method", i)
		}
		if err := json.Unmarshal(e["http"], &httpMethod); err != nil || httpMethod == "" {
			t.Fatalf("entry %d (%s): missing/empty http", i, method)
		}
		if err := json.Unmarshal(e["path"], &path); err != nil || path == "" {
			t.Fatalf("entry %d (%s): missing/empty path", i, method)
		}
		if seenMethods[method] {
			t.Fatalf("duplicate method %q", method)
		}
		seenMethods[method] = true
		if raw, ok := e["service"]; ok {
			var service string
			if err := json.Unmarshal(raw, &service); err != nil {
				t.Fatalf("entry %d (%s): service is not a string", i, method)
			}
			switch service {
			case "daemon", "sentinel", "vault", "authd":
				serviceCounts[service]++
			default:
				t.Fatalf("entry %d (%s): unknown service %q", i, method, service)
			}
		}
		for k := range e {
			auxSeen[k] = true
		}
	}
	// 219 entries have no service; the rest break down 19/15/4/1.
	if got := serviceCounts["sentinel"]; got != 19 {
		t.Fatalf("sentinel routes = %d, want 19", got)
	}
	if got := serviceCounts["authd"]; got != 15 {
		t.Fatalf("authd routes = %d, want 15", got)
	}
	if got := serviceCounts["daemon"]; got != 4 {
		t.Fatalf("daemon routes = %d, want 4", got)
	}
	if got := serviceCounts["vault"]; got != 1 {
		t.Fatalf("vault routes = %d, want 1", got)
	}
	for _, aux := range []string{"aliases", "noiseOnly", "streamMode", "channel", "connectionClass", "responseType", "requestBody"} {
		if !auxSeen[aux] {
			t.Fatalf("auxiliary field %q absent: embed is not the verbatim file", aux)
		}
	}
	// Mutating the returned copy must not corrupt the embed.
	b[0] = 'X'
	if got := sha256Hex(pb.RoutesJSON()); got != "f13e7ec63548edd9319b655be1ffc88e3580f19b4f4f016aaec63d553ed5f033" {
		t.Fatalf("RoutesJSON does not return a copy")
	}
}
