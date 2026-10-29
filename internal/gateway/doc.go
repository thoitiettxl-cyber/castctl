// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

// Package gateway implements conn.Gateway: the HTTPS auth chain, the
// WebSocket/Noise-XX transport, protobuf framing, unary calls,
// subscriptions, downloads, the Next.js subscription-action (usage)
// client, and the invite REST client — ported from gateway.py (859
// lines, muse-cli 0.6.1, commit b4dd8f5).
//
// The gateway NEVER dials itself. It receives a net.Conn from
// internal/outbound's Dialer through a Connector closure built by
// NewConnector (see connector.go): the connector fetches tokens over
// the outbound HTTP client, dials the WebSocket through the outbound
// Dialer, and hands the established connection to the Noise
// handshake. Tests use fake dialers and loopback servers instead
// (see the gatewaytest subpackage, reusable by PR5 differential
// testing). No live gateway work happens in this package's tests.
//
// Concurrency (ported from Python, one deliberate deviation noted
// below): exactly ONE reader goroutine per gateway demultiplexes
// frames into per-stream queues; Noise encryption is serialized by
// sendMu; decryption happens only on the reader goroutine, guarded
// by recvMu as a backstop. Writes are serialized by ioMu around the
// single WriteMessage syscall. The reader does NOT hold ioMu across
// a blocking ReadMessage — Python's reader holds _io_lock across a
// non-blocking ws_recv and waits with select() outside it; a Go
// ReadMessage blocks indefinitely, so holding the lock across it
// would starve writers and make Close's 2s lock wait meaningless.
// Observable semantics are unchanged: one reader, serialized
// writes, Close unblocks a blocked reader promptly by closing the
// socket.
//
// All deadlines are monotonic (time.Now + time.Until); wall clock
// is never used for a duration. Errors follow the conn taxonomy:
// *conn.AuthError (never retried), *conn.GatewayError (status -1
// when none, payload truncated to 500 bytes), *conn.ConnectionDown
// (nothing sent), *conn.ConnectionError (sent, reply possibly
// lost), *conn.TimeoutError (unwraps to context.DeadlineExceeded).
// No cookie, token, or auth-bearing URL ever appears in an error,
// a log line, or a fixture in this package; fixtures use the fake
// cookie hatch_sess=FAKE only.
//
// WebSocket library: gorilla/websocket v1.5.3, chosen by probe (see
// /tmp/ws-probe, probe evidence in the PR2 report): both
// coder/websocket v1.8.14 and gorilla passed a binary echo over a
// pre-handshaked TLS conn returned by a fake outbound dialer, and
// gorilla's websocket.NewClient on the same pre-TLS conn failed
// with "tls: first record does not look like a TLS handshake",
// reproducing the PR0 double-handshake lesson. The product code
// therefore uses Dialer + NetDialTLSContext only, never NewClient.
// The ALPN question (h2 vs http/1.1) stays OPEN: no ALPN is pinned
// in this package; TLS (and any ALPN) is the outbound Dialer's
// business, decided by sing-box/uTLS configuration, not here.
//
// Known deviations from gateway.py, each deliberate and recorded:
//   - String bodies are sent verbatim (conn.RequestOptions contract);
//     Python json.dumps a str body. Map/slice bodies are JSON-encoded
//     in both.
//   - Auth-chain classification divergences from gateway.py,
//     DELIBERATE and fail-fast (F5 — do not "fix" without a
//     differential-test decision; PR3/PR5 reviewers must see
//     them here, not rediscover them):
//     1. FetchAccessToken / FetchHatchToken, HTTP 200 with a
//     non-JSON body or a JSON body missing its key: Go returns
//     *conn.AuthError ("auth/check returned non-JSON or
//     missing access_token" / "hatch/token returned non-JSON
//     or missing token"). Python raises the RAW exception
//     from `r.json()["access_token"]` / `["token"]`: a
//     ValueError (JSONDecodeError) for non-JSON, a KeyError
//     for a missing key. (FetchSessionInfo is NOT divergent
//     here: Python maps non-JSON to AuthError and a missing
//     vm_id to GatewayError, and Go does the same.)
//     2. FetchSessionInfo, HTTP 200 with `{"vm_id": null}`:
//     Python's `"vm_id" in info` is true, so it returns the
//     info and the vm_id flows on as None, rendered "None"
//     in f-strings (e.g. the hatch/token vmAddress). Go
//     returns success with VMID = fmt.Sprintf("%v", nil) =
//     "<nil>", which flows on verbatim into the same
//     vmAddress. Same shape (success with a bogus id),
//     different bogus id.
//     3. FetchAccessToken / FetchHatchToken, HTTP 200 with a
//     non-object JSON body (e.g. a JSON array) or a
//     non-string token value: Go's decodeJSONObject rejects
//     the non-object (AuthError, as in (1)), and a present
//     non-string token fails the string assertion, so the
//     token reads as "" and Go returns AuthError ("missing
//     access_token"/"missing token"). Python indexes the
//     array (TypeError, raw) or returns the non-string value
//     as-is, which is only coerced by an f-string at header
//     construction and then fails downstream as a 401.
//     In all three cases Go fails earlier and with a typed
//     AuthError where Python fails later or with a raw
//     exception; no caller in this package depends on the
//     Python behaviour.
//   - _write has no 10-100ms AGAIN backoff loop: gorilla's
//     WriteMessage is atomic under a 15s write deadline, which
//     provides the same bound without spinning.
//   - find_action_id iterates discovered chunk URLs in sorted order
//     instead of Python's set order; only the found id matters.
//   - Cookie-file JSON whose top level is not an object is an
//     AuthError; Python raises AttributeError there. A missing file
//     is a plain I/O error in both.
//   - Unknown method names return *ValidationError (typed, exit
//     mapping is PR3's); Python raises KeyError on ROUTES[method].
//
// CLIProxyAPI follow-up items (S1/S2/S3/S4/S5/S6/S7/S9/S10/S11,
// (a)/(b)/(c); hypotheses reproduced on the fake gateway first,
// no exit-code/JSON change, no behaviour change beyond the items
// below — see hypotheses_test.go):
//   - S1 phase-typed errors: PhasedError/PhaseOf (phase.go). The
//     phase is metadata only; errors.As for every conn type is
//     preserved. A sent chat.stream frame is never re-sent: a
//     failure after the write is SentNoReply/Streaming, never
//     NotSent, and recovery is ack-poll + wait (PR4).
//   - S2 ErrConnectionLost (lost.go): EOF/ECONNRESET/close 1006
//     only; it wraps the reader's *conn.ConnectionError, so
//     conn's retry classification is unchanged. The close
//     code/reason are recorded by the close handler (LastClose).
//   - S3 ErrStreamEndedNoTerminal (ended.go): defined, not
//     returned by SubscribeRaw (its contract is unchanged). PR4's
//     wait must use EndedWithoutTerminal + resubscribe +
//     server_check, never settle as done.
//   - S4/S5 WS ping/pong + control priority (keepalive.go):
//     explicit ping/pong/close handlers; pongs go through
//     gorilla WriteControl, bypassing the gateway ioMu (gorilla
//     serializes all writes on its own mutex, so a pong waits at
//     most for one in-flight frame). Ping/pong control deadlines
//     are WriteDeadline (15s, F8): a shorter pong deadline could
//     expire while gorilla's write mutex is held by a legitimate
//     data write and kill the reader. Client-initiated keep-alive
//     (StartKeepAlive) is opt-in only, never started by the
//     Connector; its ticker comes from the Clock seam. Whether
//     the real gateway sends pings / libcurl auto-replied is
//     [UNVERIFIED] — a live-phase measurement, not claimed here.
//   - S6 generation-tagged demux (generation.go): frames carry
//     the gateway generation; next() drops stale generations.
//     No production path bumps the generation today (see the
//     conn-side proposal below).
//   - S9 IsTransient (transient.go): the one gateway-side
//     transient classifier. conn.SharedConn's retryCall is NOT
//     changed here (see the unification proposal below).
//   - S10 sleeps/backoffs (clock.go): every bounded wait in this
//     package goes through the Clock seam (Close bounds,
//     keep-alive ticker); queue waits are ctx-driven. Jitter is
//     NOT implemented: default OFF, for parity; jitter needs
//     Boss approval as an intentional diff.
//   - S11 Shutdown (shutdown.go): stream-level Reset{CANCELLED}
//     for open streams, best-effort within CloseBound, then
//     Close. NEVER chat.cancel. One root ctx per invocation
//     (signal.NotifyContext) is cmd/PR4 wiring, not this
//     package's.
//   - (a) Error-string redaction (redact.go): gateway-local
//     re-implementation of the redactSessionProxyInString
//     pattern (nothing copied verbatim); it strips URL userinfo,
//     token query params, cookie fragments, and Bearer tokens
//     from error text. The PR3 unification into one shared
//     helper is a carried item, not done here.
//   - (b) Per-phase timeouts (timings.go, connector.go): WS
//     upgrade (WSUpgradeTimeout) and Noise handshake
//     (HandshakeTimeout) are separate bounds with separately
//     measured timings (HandshakeTimings; DNS/TLS are -1 — the
//     dialer exposes no sub-phase timings). TLS session cache:
//     OFF by default (Boss decision (d)); no cache is
//     configured in this package — TLS lives in the outbound
//     dialer (see the PR2 report for the go-doc evidence).
//   - (c) TLS session cache: see the go-doc finding recorded in
//     the PR2 report; no cache is enabled or configured here.
//
// Recorded proposals (NOT implemented here; conn/outbound/cmd
// are out of scope for this package):
//   - S6 conn-side: Muse.Drop/Adopt and the Live replacement
//     path (internal/conn/conn.go) should bump the generation
//     of the gateway being replaced (via a type assertion to
//     an interface exposing bumpGeneration), so subscribers
//     holding old queues never see stale frames leak into a
//     new turn.
//   - S7 reconnect key: conn.Config (CookiesFile, VMID, NodeID)
//     must gain OutboundTag + OutboundHash (hash of the
//     outbound JSON as serialised by profile/outbound); the
//     PR3 wiring sets them when building Config, and
//     Muse.Live's reconnect key becomes
//     (CookiesFile, VMID, NodeID, OutboundTag, OutboundHash),
//     so changing a profile's outbound forces a reconnect.
//     The gateway's Connector only consumes Config.
//   - S9 unification: the single retry-classification point is
//     retryCall in internal/conn/shared.go, whose rule today
//     is retryable = ConnectionDown OR (safeFor(g) AND
//     ConnectionError). Unifying on IsTransient would narrow
//     safe-method ConnectionError retries to transient causes
//     and is a behaviour change needing approval; it must also
//     keep the safe-to-repeat gate and the never-retry
//     egress.approval.decide rule.
//   - Outbound nil-router guard: dialling a domain-server
//     outbound through an outbound Manager without
//     RegisterDNS/RegisterDNSRouter panics with a nil
//     dereference in sing-box common/dialer (see the PR2
//     report for the coordinator-verified evidence). This
//     package never builds a Manager/DNS client/Dialer — it
//     only consumes OutboundDialer — so the guard lives in
//     outbound.Manager.CreateOutbound (F3): a domain-server
//     outbound created without a registered DNS router is
//     refused with a clean error, and PR3 wiring must call
//     RegisterDNS/RegisterDNSRouter BEFORE CreateOutbound.
//   - Deferred (Boss decision, stay unimplemented): auth import
//     command, paste fallback for auth export, bot hot reload,
//     jitter. Release (local build script, no Actions) is PR5.
package gateway
