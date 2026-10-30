// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

// Package proto holds the generated protobuf types for the Noise
// transport and the service envelope, plus the verbatim embedded data
// files the gateway code needs: the original FileDescriptorProto
// binaries and routes.json.
//
// The message and enum types (NoiseTransportFrame, ServiceRequest,
// ServiceResponse, ServiceFrame, Header, ApplicationRequest,
// ApplicationResponse, BodyChunk, Reset, ServiceType, Reset.Code) live
// in noise_transport.pb.go and noise_envelope.pb.go. Those files are
// generated — DO NOT EDIT, and do not add hand-written proto structs.
// Regenerate them with generate/generate.sh.
//
// routes.json is embedded verbatim (byte-identical to the Python
// package's copy). Only the method, http, path, and service fields are
// ever used by consumers (internal/gateway, in the next step); the
// auxiliary fields present in the file (aliases, noiseOnly,
// streamMode, channel, connectionClass, responseType, requestBody)
// are preserved verbatim for fidelity but must not be relied on.
// This package does not parse routes.json; parsing belongs to the
// gateway package.
package proto

import (
	_ "embed"
	"slices"
)

//go:embed desc0.bin
var transportDescriptor []byte

//go:embed desc1.bin
var envelopeDescriptor []byte

//go:embed routes.json
var routesJSON []byte

// TransportDescriptor returns the FileDescriptorProto bytes for
// noise_transport.proto (desc0.bin in the Python package), byte-identical
// to the original. The returned slice is a copy; callers may not mutate
// the embedded bytes.
func TransportDescriptor() []byte {
	return slices.Clone(transportDescriptor)
}

// EnvelopeDescriptor returns the FileDescriptorProto bytes for
// noise_envelope.proto (desc1.bin in the Python package), byte-identical
// to the original. The returned slice is a copy; callers may not mutate
// the embedded bytes.
func EnvelopeDescriptor() []byte {
	return slices.Clone(envelopeDescriptor)
}

// RoutesJSON returns the verbatim routes.json bytes (a JSON list of 258
// method entries). The returned slice is a copy; callers may not mutate
// the embedded bytes. Only the method, http, path, and service fields
// of each entry are used by consumers.
func RoutesJSON() []byte {
	return slices.Clone(routesJSON)
}
