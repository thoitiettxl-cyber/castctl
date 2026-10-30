// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

// Package gatewaytest is the fake-gateway harness for gateway
// tests and for PR5 differential testing: a loopback server that
// speaks the real wire protocol (WebSocket upgrade + Noise XX
// handshake + NoiseTransportFrame chunking + protobuf envelopes)
// and answers from scripted handlers, plus a fake outbound dialer
// that routes both the WebSocket dial and the muse.ai HTTPS auth
// chain to it. No live gateway, no real cookies, no real network
// beyond loopback: fixtures use hatch_sess=FAKE only.
//
// The server is the Noise responder: it accepts the client's empty
// handshake messages, splits with (cs1, cs2) in the same order as
// the initiator, sends on cs2 and receives on cs1, and accepts a
// msg2 payload of any length (the Go client always sends empty
// payloads; the responder never asserts a length).
//
// Reuse (PR5): build a Server with a Handler that replays canned
// ServiceResponses for every route, dial it through FakeDialer
// with NewConnector, and compare the Go client's parsed JSON and
// exit behaviour against the Python client driven through the
// same fake. The Handler sees the exact verb/path/headers/body
// the client sent, so differential tests can assert wire-level
// parity (path params, GET body-to-query, x-request-id, service
// selection) without a live VM.
package gatewaytest
