// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/thoitiettxl-cyber/muse-cli/go/internal/conn"
	pb "github.com/thoitiettxl-cyber/muse-cli/go/internal/proto"
)

// DefaultRequestTimeout bounds one unary call when the caller
// passes no timeout (30s in Python).
const DefaultRequestTimeout = 30 * time.Second

// DefaultDownloadTimeout bounds a download when the caller passes
// no timeout (300s in Python).
const DefaultDownloadTimeout = 300 * time.Second

// effectiveTimeout resolves a call timeout: the caller's value,
// the default when zero/negative, capped by an earlier ctx
// deadline when one exists.
func effectiveTimeout(ctx context.Context, timeout, def time.Duration) time.Duration {
	if timeout <= 0 {
		timeout = def
	}
	if dl, ok := ctx.Deadline(); ok {
		if remain := time.Until(dl); remain < timeout {
			timeout = remain
		}
	}
	return timeout
}

// OpenStream starts a stream and returns its stream ID (Python
// _open). It returns *ConnectionDown before building or sending
// anything when the gateway is dead or closed.
func (g *Gateway) OpenStream(ctx context.Context, method string, opts conn.OpenStreamOptions) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	sid, _, err := g.open(method, opts.PathParams, opts.Body, opts.Query, opts.Route, opts.Track)
	if err != nil {
		// S1: a failed open is NotSent only when the
		// pre-send check failed; a send attempt may have
		// put the frame on the wire.
		return 0, withPhase(err, phaseForOpenErr(err))
	}
	return sid, nil
}

// CancelStream ends a stream opened by OpenStream: it forgets the
// stream and sends the CANCELLED reset when the gateway is alive.
// It is a no-op for an unknown stream ID and never returns
// *ConnectionDown.
func (g *Gateway) CancelStream(ctx context.Context, streamID int64) error {
	g.cancelStream(streamID, pb.ServiceType_SERVICE_DAEMON)
	return nil
}

// Request performs one unary call and returns the raw response
// payload bytes. It gathers response.body + body_chunk frames
// until end_body; a reset is a GatewayError(-1, "stream reset …");
// expiry with no status is a TimeoutError; a status outside
// 200–299 is a GatewayError(status, payload[:500]). A stream that
// ended is forgotten; one that did not end is cancelled (reset
// code 1 CANCELLED, on the route's service). A GET with a non-nil
// body and a nil query moves the body into the query string and
// sends no body, as in Python.
func (g *Gateway) Request(ctx context.Context, method string, opts conn.RequestOptions) ([]byte, error) {
	route, err := g.resolveRoute(method, opts.Route)
	if err != nil {
		return nil, withPhase(err, PhaseNotSent)
	}
	body, query := opts.Body, opts.Query
	if route.HTTP == "GET" && body != nil && query == nil {
		q, err := bodyToQuery(body)
		if err != nil {
			return nil, withPhase(err, PhaseNotSent)
		}
		query, body = q, nil
	}
	sid, _, err := g.open(method, opts.PathParams, body, query, opts.Route, true)
	if err != nil {
		return nil, withPhase(err, phaseForOpenErr(err))
	}
	timeout := effectiveTimeout(ctx, opts.Timeout, DefaultRequestTimeout)
	deadline := time.Now().Add(timeout)
	var status *int32
	var chunks [][]byte
	ended := false
	sawFrame := false
	var loopErr error
	for {
		left := time.Until(deadline)
		if left <= 0 {
			break
		}
		sf, err := g.next(ctx, sid, left)
		if err != nil {
			if errors.Is(err, errQueueEmpty) {
				break
			}
			loopErr = err
			break
		}
		sawFrame = true
		switch kind := sf.Kind.(type) {
		case *pb.ServiceFrame_Response:
			st := kind.Response.GetStatus()
			status = &st
			if b := kind.Response.GetBody(); len(b) > 0 {
				chunks = append(chunks, cloneBytes(b))
			}
			if kind.Response.GetEndBody() {
				ended = true
			}
		case *pb.ServiceFrame_BodyChunk:
			chunks = append(chunks, cloneBytes(kind.BodyChunk.GetData()))
			if kind.BodyChunk.GetEndBody() {
				ended = true
			}
		case *pb.ServiceFrame_Reset_:
			ended = true
			loopErr = &conn.GatewayError{Status: -1, Payload: redactErrorString(fmt.Sprintf("stream reset %d: %s", kind.Reset_.GetCode(), kind.Reset_.GetReason()))}
		default:
			// An inbound request frame (or no kind) is
			// ignored, as Python's WhichOneof fall-through
			// does.
		}
		if ended {
			break
		}
	}
	if ended {
		g.forget(sid)
	} else {
		g.cancelStream(sid, serviceID(route.Service))
	}
	// S1: attach the phase. A frame on the wire means
	// Streaming (a reset is itself a frame); no frame means
	// the request was sent but unanswered.
	phase := PhaseSentNoReply
	if sawFrame {
		phase = PhaseStreaming
	}
	if loopErr != nil {
		return nil, withPhase(loopErr, phase)
	}
	if status == nil {
		if err := ctx.Err(); err != nil {
			return nil, withPhase(err, phase)
		}
		return nil, withPhase(&conn.TimeoutError{Message: fmt.Sprintf("no response for %s", method)}, phase)
	}
	payload := bytes.Join(chunks, nil)
	if *status < 200 || *status >= 300 {
		return nil, withPhase(&conn.GatewayError{Status: int(*status), Payload: redactErrorString(truncatePayload(payload, 500))}, PhaseStreaming)
	}
	return payload, nil
}

// CallJSON performs one unary call and returns the decoded JSON
// result: the "result" field of a {"ok":true} envelope, or the
// whole decoded value otherwise. Empty bodies decode as {}.
// Non-JSON is a GatewayError; {"ok":false} is a GatewayError.
// Numbers decode as int64/json.Number, never float64.
func (g *Gateway) CallJSON(ctx context.Context, method string, opts conn.RequestOptions) (any, error) {
	raw, err := g.Request(ctx, method, opts)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return map[string]any{}, nil
	}
	d, err := decodeJSONValue(raw)
	if err != nil {
		head := raw
		if len(head) > 200 {
			head = head[:200]
		}
		return nil, withPhase(&conn.GatewayError{Status: -1, Payload: redactErrorString(fmt.Sprintf("non-JSON response: %q", string(head)))}, PhaseStreaming)
	}
	if m, ok := d.(map[string]any); ok {
		if okVal, isBool := m["ok"].(bool); isBool && !okVal {
			return nil, withPhase(&conn.GatewayError{Status: -1, Payload: redactErrorString(fmt.Sprintf("api error: %v", m["error"]))}, PhaseStreaming)
		}
		if result, present := m["result"]; present {
			return result, nil
		}
	}
	return d, nil
}

// Ping is the web app's heartbeat: connection.ping with
// {"presence":"away"}, bounded by timeout (10s default when
// timeout is zero).
func (g *Gateway) Ping(ctx context.Context, timeout time.Duration) (any, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return g.CallJSON(ctx, "connection.ping", conn.RequestOptions{
		Body:    map[string]any{"presence": "away"},
		Timeout: timeout,
	})
}

// DownloadFile returns the bytes of a sandbox file. Ref is a
// sandbox:// path, a media URL, a bare /media/raw/... path, or a
// resource dict, exactly as MediaPath accepts. The request rides
// the Noise tunnel as GET /media/raw/… on the synthetic route
// media.raw (NOT in routes.json), with a 300s default timeout.
func (g *Gateway) DownloadFile(ctx context.Context, ref any, opts conn.DownloadOptions) ([]byte, error) {
	path, err := MediaPath(ref)
	if err != nil {
		return nil, err
	}
	route := &conn.Route{Method: "media.raw", HTTP: "GET", Path: path}
	if opts.Route != nil {
		route = opts.Route
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultDownloadTimeout
	}
	return g.Request(ctx, "media.raw", conn.RequestOptions{
		Timeout: timeout,
		Route:   route,
	})
}

// SubscribeRaw opens a subscription and returns the raw NDJSON
// record bytes. OnRecord is called with each record the moment it
// arrives; a true return stops the subscription right there.
// ShouldStop is polled about every 0.5s even while no records
// arrive. OnOpen is called once the subscription request is on
// the wire. Records are split on \n; a trailing partial buffer is
// appended as one record (with an OnRecord call) unless the
// subscription was halted. A subscription that ends is forgotten;
// one that is stopped is reset (the connection stays up).
// ConnectionDown is returned only when the stream never opened:
// once OnOpen has fired, connection loss surfaces as
// *ConnectionError.
func (g *Gateway) SubscribeRaw(ctx context.Context, method string, opts conn.SubscribeOptions) ([][]byte, error) {
	maxRecords := opts.MaxRecords
	if maxRecords <= 0 {
		maxRecords = 100
	}
	idleTimeout := opts.IdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = 10 * time.Second
	}
	overallTimeout := opts.OverallTimeout
	if overallTimeout <= 0 {
		overallTimeout = 120 * time.Second
	}
	sid, _, err := g.open(method, opts.PathParams, opts.Body, opts.Query, opts.Route, true)
	if err != nil {
		return nil, withPhase(err, phaseForOpenErr(err))
	}
	if opts.OnOpen != nil {
		opts.OnOpen()
	}
	var buf []byte
	var records [][]byte
	deadline := time.Now().Add(overallTimeout)
	idleDeadline := time.Now().Add(idleTimeout)
	halted, ended := false, false
	sawFrame := false
	var loopErr error

outer:
	for !halted && time.Now().Before(deadline) && len(records) < maxRecords {
		if opts.ShouldStop != nil && opts.ShouldStop() {
			halted = true
			break
		}
		sf, err := g.next(ctx, sid, 500*time.Millisecond)
		if err != nil {
			if errors.Is(err, errQueueEmpty) {
				if time.Now().After(idleDeadline) {
					break
				}
				continue
			}
			loopErr = err
			break
		}
		sawFrame = true
		idleDeadline = time.Now().Add(idleTimeout)
		switch kind := sf.Kind.(type) {
		case *pb.ServiceFrame_Response:
			if b := kind.Response.GetBody(); len(b) > 0 {
				buf = append(buf, b...)
			}
			if kind.Response.GetEndBody() {
				ended = true
				if len(buf) == 0 {
					break outer
				}
			}
		case *pb.ServiceFrame_BodyChunk:
			buf = append(buf, kind.BodyChunk.GetData()...)
			if kind.BodyChunk.GetEndBody() {
				ended = true
			}
		case *pb.ServiceFrame_Reset_:
			ended = true
			break outer
		default:
			// Other kinds are ignored; the loop continues.
		}
		for {
			idx := bytes.IndexByte(buf, '\n')
			if idx < 0 {
				break
			}
			line := buf[:idx]
			buf = buf[idx+1:]
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			rec := cloneBytes(line)
			records = append(records, rec)
			if opts.OnRecord != nil && opts.OnRecord(rec) {
				halted = true
				break
			}
			if len(records) >= maxRecords {
				break
			}
		}
		if ended {
			break
		}
	}
	if ended {
		g.forget(sid)
	} else {
		g.cancelStream(sid, pb.ServiceType_SERVICE_DAEMON)
	}
	if loopErr != nil {
		// S1: Streaming once a frame arrived, SentNoReply
		// when the stream died before any frame. The
		// contract is unchanged: a clean end (ended) is
		// still a nil error with the gathered records (S3
		// detection is EndedWithoutTerminal, not an error
		// here).
		phase := PhaseSentNoReply
		if sawFrame {
			phase = PhaseStreaming
		}
		return nil, withPhase(loopErr, phase)
	}
	if len(bytes.TrimSpace(buf)) > 0 && !halted {
		rec := cloneBytes(buf)
		records = append(records, rec)
		if opts.OnRecord != nil {
			opts.OnRecord(rec)
		}
	}
	return records, nil
}

// SubscribeJSON is SubscribeRaw with bad JSON lines dropped
// (Python subscribe_json). Numbers decode as json.Number.
func (g *Gateway) SubscribeJSON(ctx context.Context, method string, opts conn.SubscribeOptions) ([]any, error) {
	raw, err := g.SubscribeRaw(ctx, method, opts)
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(raw))
	for _, line := range raw {
		v, err := decodeJSONValue(line)
		if err != nil {
			continue
		}
		out = append(out, v)
	}
	return out, nil
}
