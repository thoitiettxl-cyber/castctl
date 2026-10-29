// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gatewaytest

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	"github.com/flynn/noise"
	"github.com/gorilla/websocket"
	pb "github.com/thoitiettxl-cyber/muse-cli/go/internal/proto"
	"google.golang.org/protobuf/proto"
)

// Response is what a Handler returns for one ApplicationRequest:
// the ServiceFrames to send back on the same stream, an optional
// delay before sending, and whether to close the connection after
// sending (CloseAfter) or instead of sending (CloseWithoutReply).
type Response struct {
	Frames            []*pb.ServiceFrame
	Delay             time.Duration
	CloseAfter        bool
	CloseWithoutReply bool
	// ShufflePieces sends the transport pieces of each response in
	// reverse chunk_index order, proving the client joins by
	// chunk_index rather than arrival order.
	ShufflePieces bool
}

// Handler answers one ApplicationRequest.
type Handler interface {
	Handle(req *pb.ApplicationRequest, service pb.ServiceType) Response
}

// HandlerFunc adapts a function to a Handler.
type HandlerFunc func(req *pb.ApplicationRequest, service pb.ServiceType) Response

// Handle implements Handler.
func (f HandlerFunc) Handle(req *pb.ApplicationRequest, service pb.ServiceType) Response {
	return f(req, service)
}

// RequestRecord is one request the server received, for assertions
// about wire-level parity (verb, path, service, headers, body).
type RequestRecord struct {
	StreamID int64
	Service  pb.ServiceType
	Verb     string
	Path     string
	Headers  map[string]string
	Body     []byte
}

// ResponseFrame builds a ServiceFrame carrying an
// ApplicationResponse on streamID.
func ResponseFrame(streamID int64, status int32, body []byte, endBody bool) *pb.ServiceFrame {
	return &pb.ServiceFrame{
		StreamId: streamID,
		Kind: &pb.ServiceFrame_Response{Response: &pb.ApplicationResponse{
			Status: status, Body: body, EndBody: endBody,
		}},
	}
}

// ChunkFrame builds a ServiceFrame carrying a BodyChunk on
// streamID.
func ChunkFrame(streamID int64, data []byte, endBody bool) *pb.ServiceFrame {
	return &pb.ServiceFrame{
		StreamId: streamID,
		Kind: &pb.ServiceFrame_BodyChunk{BodyChunk: &pb.BodyChunk{
			Data: data, EndBody: endBody,
		}},
	}
}

// ResetFrame builds a ServiceFrame carrying a Reset on streamID.
func ResetFrame(streamID int64, code pb.Reset_Code, reason string) *pb.ServiceFrame {
	return &pb.ServiceFrame{
		StreamId: streamID,
		Kind: &pb.ServiceFrame_Reset_{Reset_: &pb.Reset{
			Code: code, Reason: reason,
		}},
	}
}

// JSONHandler answers every request with one JSON response frame
// (status, body, end_body=true). body is sent verbatim.
func JSONHandler(status int32, body []byte) Handler {
	return HandlerFunc(func(req *pb.ApplicationRequest, service pb.ServiceType) Response {
		_ = req
		return Response{Frames: []*pb.ServiceFrame{ResponseFrame(0, status, body, true)}}
	})
}

// Server is a fake Noise gateway on loopback.
type Server struct {
	handler Handler

	mu       sync.Mutex
	listener net.Listener
	server   *http.Server
	conns    map[net.Conn]bool
	wsConns  map[*websocket.Conn]bool
	requests []RequestRecord
	resets   int
	pongs    []string
	pings    []string
	wg       sync.WaitGroup
}

// NewServer starts a fake gateway serving handler on 127.0.0.1:0.
func NewServer(handler Handler) (*Server, error) {
	s := &Server{handler: handler, conns: map[net.Conn]bool{}, wsConns: map[*websocket.Conn]bool{}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s.listener = ln
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/noise", s.serveWS)
	s.server = &http.Server{Handler: mux}
	go func() { _ = s.server.Serve(ln) }()
	return s, nil
}

// Addr returns the listener address (host:port) for the fake
// dialer.
func (s *Server) Addr() string { return s.listener.Addr().String() }

// Requests returns a copy of the requests received so far.
func (s *Server) Requests() []RequestRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]RequestRecord, len(s.requests))
	copy(out, s.requests)
	return out
}

// RequestCount returns how many requests have been received.
func (s *Server) RequestCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests)
}

// ResetCount returns how many CANCELLED (or other) reset frames
// the server has received, e.g. from cancelled requests and
// stopped subscriptions.
func (s *Server) ResetCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.resets
}

// Close stops the server and closes all live connections (the
// client sees a dropped connection). It waits for the per-
// connection handlers to exit, including handlers still sleeping
// a Response.Delay after the socket closed: without the wait,
// those goroutines outlive the test and trip goleak.
func (s *Server) Close() error {
	s.mu.Lock()
	conns := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
	}
	return s.server.Close()
}

// PongCount returns how many pong frames the server has received
// (answers to pings it sent, or keep-alive pings from the client).
func (s *Server) PongCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pongs)
}

// Pongs returns the pong payloads received so far, in order.
func (s *Server) Pongs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.pongs...)
}

// PingCount returns how many ping frames the server has received
// (client keep-alive pings).
func (s *Server) PingCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pings)
}

// PingAll sends one ping frame to every live connection. The
// server's pong handler records the answers; PongCount/Pongs
// observe them.
func (s *Server) PingAll(data string) {
	s.mu.Lock()
	conns := make([]*websocket.Conn, 0, len(s.wsConns))
	for ws := range s.wsConns {
		conns = append(conns, ws)
	}
	s.mu.Unlock()
	for _, ws := range conns {
		_ = ws.WriteControl(websocket.PingMessage, []byte(data), time.Now().Add(2*time.Second))
	}
}

// SendClose sends a WebSocket close frame to every live
// connection (the TCP socket stays open until Close).
func (s *Server) SendClose(code int, reason string) {
	s.mu.Lock()
	conns := make([]*websocket.Conn, 0, len(s.wsConns))
	for ws := range s.wsConns {
		conns = append(conns, ws)
	}
	s.mu.Unlock()
	for _, ws := range conns {
		_ = ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, reason), time.Now().Add(2*time.Second))
	}
}

func (s *Server) trackConn(c net.Conn, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		s.conns[c] = true
	} else {
		delete(s.conns, c)
	}
}

func (s *Server) serveWS(w http.ResponseWriter, r *http.Request) {
	// The fake server accepts any Origin: the client sends
	// Origin https://muse.ai while the Host is the loopback
	// listener, which gorilla's default CheckOrigin would reject.
	up := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	ws, err := up.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	s.wg.Add(1)
	defer s.wg.Done()
	defer ws.Close()
	s.trackConn(ws.NetConn(), true)
	defer s.trackConn(ws.NetConn(), false)
	s.mu.Lock()
	s.wsConns[ws] = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.wsConns, ws)
		s.mu.Unlock()
	}()
	// Record pongs (answers to server pings / client keep-alive
	// pings are both pong frames) and pings (client keep-alive).
	ws.SetPongHandler(func(appData string) error {
		s.mu.Lock()
		s.pongs = append(s.pongs, appData)
		s.mu.Unlock()
		return nil
	})
	ws.SetPingHandler(func(appData string) error {
		s.mu.Lock()
		s.pings = append(s.pings, appData)
		s.mu.Unlock()
		return ws.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(2*time.Second))
	})
	sendCS, recvCS, err := responderHandshake(ws)
	if err != nil {
		return
	}
	partial := map[int64]map[uint32][]byte{}
	for {
		_, data, err := ws.ReadMessage()
		if err != nil {
			return
		}
		pt, err := recvCS.Decrypt(nil, nil, data)
		if err != nil {
			return
		}
		var ntf pb.NoiseTransportFrame
		if err := proto.Unmarshal(pt, &ntf); err != nil {
			return
		}
		payload, complete := joinServer(partial, &ntf)
		if !complete {
			continue
		}
		var sr pb.ServiceRequest
		if err := proto.Unmarshal(payload, &sr); err != nil {
			return
		}
		var sf pb.ServiceFrame
		if err := proto.Unmarshal(sr.GetPayload(), &sf); err != nil {
			return
		}
		req, ok := sf.Kind.(*pb.ServiceFrame_Request)
		if !ok {
			if _, isReset := sf.Kind.(*pb.ServiceFrame_Reset_); isReset {
				s.mu.Lock()
				s.resets++
				s.mu.Unlock()
			}
			continue
		}
		s.record(sf.GetStreamId(), sr.GetService(), req.Request)
		resp := s.handler.Handle(req.Request, sr.GetService())
		if resp.Delay > 0 {
			time.Sleep(resp.Delay)
		}
		if resp.CloseWithoutReply {
			return
		}
		for _, frame := range resp.Frames {
			frame.StreamId = sf.GetStreamId()
			if err := sendServerFrame(ws, sendCS, frame, resp.ShufflePieces); err != nil {
				return
			}
		}
		if resp.CloseAfter {
			return
		}
	}
}

func (s *Server) record(streamID int64, service pb.ServiceType, req *pb.ApplicationRequest) {
	headers := map[string]string{}
	for _, h := range req.GetHeaders() {
		headers[h.GetKey()] = h.GetValue()
	}
	s.mu.Lock()
	s.requests = append(s.requests, RequestRecord{
		StreamID: streamID,
		Service:  service,
		Verb:     req.GetVerb(),
		Path:     req.GetPath(),
		Headers:  headers,
		Body:     append([]byte(nil), req.GetBody()...),
	})
	s.mu.Unlock()
}

// responderHandshake runs the Noise XX responder side over ws:
// read msg1, write msg2 (empty payload), read msg3, split. The
// responder sends on cs2 and receives on cs1.
func responderHandshake(ws *websocket.Conn) (sendCS, recvCS *noise.CipherState, err error) {
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)
	static, err := cs.GenerateKeypair(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cs,
		Pattern:       noise.HandshakeXX,
		Initiator:     false,
		StaticKeypair: static,
	})
	if err != nil {
		return nil, nil, err
	}
	_, msg1, err := ws.ReadMessage()
	if err != nil {
		return nil, nil, err
	}
	if _, _, _, err := hs.ReadMessage(nil, msg1); err != nil {
		return nil, nil, err
	}
	msg2, _, _, err := hs.WriteMessage(nil, []byte{})
	if err != nil {
		return nil, nil, err
	}
	if err := ws.WriteMessage(websocket.BinaryMessage, msg2); err != nil {
		return nil, nil, err
	}
	_, msg3, err := ws.ReadMessage()
	if err != nil {
		return nil, nil, err
	}
	// The msg3 payload is accepted at any length and ignored.
	if _, cs1, cs2, err := hs.ReadMessage(nil, msg3); err != nil {
		return nil, nil, err
	} else {
		return cs2, cs1, nil
	}
}

// joinServer mirrors the gateway's joinChunks for the fake server.
func joinServer(partial map[int64]map[uint32][]byte, frame *pb.NoiseTransportFrame) ([]byte, bool) {
	total := frame.GetTotalChunks()
	if total <= 1 {
		out := frame.GetPayload()
		if out == nil {
			return nil, true
		}
		return append([]byte(nil), out...), true
	}
	parts, ok := partial[frame.GetChunkId()]
	if !ok {
		parts = make(map[uint32][]byte)
		partial[frame.GetChunkId()] = parts
	}
	parts[frame.GetChunkIndex()] = append([]byte(nil), frame.GetPayload()...)
	if uint32(len(parts)) < total {
		return nil, false
	}
	delete(partial, frame.GetChunkId())
	var out []byte
	for i := uint32(0); i < total; i++ {
		out = append(out, parts[i]...)
	}
	return out, true
}

// sendServerFrame wraps one ServiceFrame in a ServiceResponse,
// chunks it into 60000-byte transport pieces, encrypts, and writes
// each ciphertext as one binary WebSocket message.
func sendServerFrame(ws *websocket.Conn, sendCS *noise.CipherState, frame *pb.ServiceFrame, shuffle bool) error {
	frameBytes, err := proto.Marshal(frame)
	if err != nil {
		return err
	}
	outer, err := proto.Marshal(&pb.ServiceResponse{Payload: frameBytes})
	if err != nil {
		return err
	}
	var chunkID [8]byte
	if _, err := rand.Read(chunkID[:]); err != nil {
		return err
	}
	id := int64(binary.LittleEndian.Uint64(chunkID[:]))
	pieces := [][]byte{}
	if len(outer) == 0 {
		pieces = [][]byte{{}}
	} else {
		for len(outer) > 0 {
			n := 60000
			if len(outer) < n {
				n = len(outer)
			}
			pieces = append(pieces, outer[:n])
			outer = outer[n:]
		}
	}
	order := make([]int, len(pieces))
	for i := range order {
		order[i] = i
	}
	if shuffle {
		for i, j := 0, len(order)-1; i < j; i, j = i+1, j-1 {
			order[i], order[j] = order[j], order[i]
		}
	}
	for _, idx := range order {
		ix := uint32(idx)
		tot := uint32(len(pieces))
		fr := &pb.NoiseTransportFrame{
			ChunkId:     &id,
			ChunkIndex:  &ix,
			TotalChunks: &tot,
			Payload:     pieces[idx],
		}
		frBytes, err := proto.Marshal(fr)
		if err != nil {
			return err
		}
		ct, err := sendCS.Encrypt(nil, nil, frBytes)
		if err != nil {
			return err
		}
		if err := ws.WriteMessage(websocket.BinaryMessage, ct); err != nil {
			return err
		}
	}
	return nil
}

// WriteJSON writes a pre-encoded JSON body with the given status.
func WriteJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

// RoundTripperFunc adapts a function to http.RoundTripper.
type RoundTripperFunc func(*http.Request) (*http.Response, error)

// RoundTrip implements http.RoundTripper.
func (f RoundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// HandlerRoundTripper serves requests through an http.Handler in
// memory (no socket), returning the recorded response. It is how
// FakeDialer answers muse.ai HTTPS calls.
func HandlerRoundTripper(h http.Handler) http.RoundTripper {
	return RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Result(), nil
	})
}
