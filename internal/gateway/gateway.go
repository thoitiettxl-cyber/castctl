// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/flynn/noise"
	"github.com/gorilla/websocket"
	"github.com/thoitiettxl-cyber/muse-cli/go/internal/conn"
	pb "github.com/thoitiettxl-cyber/muse-cli/go/internal/proto"
	"google.golang.org/protobuf/proto"
)

// HandshakeTimeout bounds the server's Noise handshake reply and
// each bounded handshake send (20s in Python).
const HandshakeTimeout = 20 * time.Second

// WriteDeadline bounds one _write: a socket that accepts nothing
// fails within 15s instead of hanging the writer (Python
// WRITE_DEADLINE).
const WriteDeadline = 15 * time.Second

// wsConn is the WebSocket surface the Gateway needs. gorilla's
// *websocket.Conn satisfies it; tests inject fakes. Only binary
// messages are ever sent; ReadMessage reassembles fragmented
// messages and answers pings with pongs (gorilla defaults),
// matching Python's CONT-joining, PING/PONG-skipping recv.
type wsConn interface {
	ReadMessage() (messageType int, p []byte, err error)
	WriteMessage(messageType int, data []byte) error
	SetWriteDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	Close() error
}

// Gateway is one authenticated, multiplexed connection to the
// personal VM gateway. It implements conn.Gateway and conn.Leaser
// (via Lease). It is safe for concurrent use: any number of
// goroutines may run requests and subscriptions on it at once.
type Gateway struct {
	ws     wsConn
	sendCS *noise.CipherState
	recvCS *noise.CipherState
	routes *RouteTable
	clock  Clock

	mu         sync.Mutex
	sendMu     sync.Mutex // serializes Noise encryption
	recvMu     sync.Mutex // decrypt backstop; only the reader decrypts
	ioMu       sync.Mutex // serializes WriteMessage syscalls
	streams    map[int64]*streamQueue
	services   map[int64]pb.ServiceType
	nextStream int64
	closed     bool
	dead       error
	lastUsed   time.Time
	lastRecv   time.Time
	partial    map[int64]map[uint32][]byte // reader goroutine only
	readerDone chan struct{}
	closeOnce  sync.Once

	// Generation-tagged demux (S6) and connection-loss state
	// (S2), control-frame observations (S4/S5), and connect
	// timings (item (b)): all guarded by mu unless noted.
	generation   uint64
	sentAny      bool
	closeCode    int
	closeReason  string
	closeSeen    bool
	lastPingAt   time.Time
	lastPingData string
	lastPongAt   time.Time
	lastPongData string
	pingsSent    int64
	timings      HandshakeTimings
}

// clk returns the gateway's clock, defaulting to the real clock
// for a zero-value Gateway.
func (g *Gateway) clk() Clock {
	if g.clock != nil {
		return g.clock
	}
	return realClock{}
}

var (
	_ conn.Gateway = (*Gateway)(nil)
	_ conn.Leaser  = (*Gateway)(nil)
)

// newGateway builds a Gateway over an established, Noise-handshaked
// WebSocket connection and starts its single reader goroutine.
// clock may be nil for the real clock. When ws implements
// controlConn, ping/pong/close handlers are installed (S4/S5).
func newGateway(ws wsConn, sendCS, recvCS *noise.CipherState, routes *RouteTable, clock Clock) *Gateway {
	if clock == nil {
		clock = realClock{}
	}
	now := time.Now()
	g := &Gateway{
		ws:         ws,
		sendCS:     sendCS,
		recvCS:     recvCS,
		routes:     routes,
		clock:      clock,
		streams:    make(map[int64]*streamQueue),
		services:   make(map[int64]pb.ServiceType),
		nextStream: 1,
		lastUsed:   now,
		lastRecv:   now,
		partial:    make(map[int64]map[uint32][]byte),
		readerDone: make(chan struct{}),
		generation: gatewayGenerations.Add(1),
	}
	if cc, ok := ws.(controlConn); ok {
		g.installControlHandlers(cc)
	}
	go g.readLoop()
	return g
}

// noiseHandshake runs the Noise XX handshake over an established
// WebSocket connection, as initiator with a fresh ephemeral static
// keypair and empty payloads in all three messages (gateway.py).
// timeout bounds each handshake send and the msg2 reply
// (HandshakeTimeout by default). It returns (send, recv)
// CipherStates: after Split, cs1 is the initiator->responder
// direction and cs2 the responder->initiator direction for BOTH
// peers, so the initiator sends on cs1 and receives on cs2. The
// msg2 payload is accepted at ANY length and ignored — never
// asserted to be empty.
func noiseHandshake(ws wsConn, timeout time.Duration) (sendCS, recvCS *noise.CipherState, err error) {
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)
	static, err := cs.GenerateKeypair(rand.Reader)
	if err != nil {
		return nil, nil, &conn.ConnectionError{Err: fmt.Errorf("gateway: generate noise keypair: %w", err)}
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cs,
		Pattern:       noise.HandshakeXX,
		Initiator:     true,
		StaticKeypair: static,
	})
	if err != nil {
		return nil, nil, &conn.ConnectionError{Err: fmt.Errorf("gateway: noise handshake state: %w", err)}
	}
	msg1, _, _, err := hs.WriteMessage(nil, []byte{})
	if err != nil {
		return nil, nil, &conn.ConnectionError{Err: fmt.Errorf("gateway: noise msg1: %w", err)}
	}
	if err := writeBounded(ws, msg1, timeout); err != nil {
		return nil, nil, err
	}
	msg2, err := readBounded(ws, timeout)
	if err != nil {
		return nil, nil, err
	}
	// The payload is deliberately ignored at any length.
	if _, _, _, err := hs.ReadMessage(nil, msg2); err != nil {
		return nil, nil, &conn.ConnectionError{Err: fmt.Errorf("gateway: noise msg2: %w", err)}
	}
	msg3, cs1, cs2, err := hs.WriteMessage(nil, []byte{})
	if err != nil {
		return nil, nil, &conn.ConnectionError{Err: fmt.Errorf("gateway: noise msg3: %w", err)}
	}
	if cs1 == nil || cs2 == nil {
		return nil, nil, &conn.ConnectionError{Err: errors.New("gateway: noise handshake did not split into transport states")}
	}
	if err := writeBounded(ws, msg3, timeout); err != nil {
		return nil, nil, err
	}
	return cs1, cs2, nil
}

// writeBounded sends one WebSocket binary message with a deadline.
// A deadline expiry is a TimeoutError; any other failure is a
// ConnectionError.
func writeBounded(ws wsConn, data []byte, timeout time.Duration) error {
	if err := ws.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return &conn.ConnectionError{Err: fmt.Errorf("gateway handshake send failed: %w", err)}
	}
	err := ws.WriteMessage(websocket.BinaryMessage, data)
	_ = ws.SetWriteDeadline(time.Time{})
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return &conn.TimeoutError{Message: fmt.Sprintf("gateway handshake send: no progress in %ds", int(timeout.Seconds()))}
		}
		return &conn.ConnectionError{Err: fmt.Errorf("gateway handshake send failed: %w", err)}
	}
	return nil
}

// readBounded reads one complete WebSocket message with a
// deadline. A deadline expiry is a TimeoutError ("gateway
// handshake: no answer in 20s"); a close frame is a
// ConnectionError.
func readBounded(ws wsConn, timeout time.Duration) ([]byte, error) {
	if err := ws.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, &conn.ConnectionError{Err: fmt.Errorf("gateway handshake receive failed: %w", err)}
	}
	_, data, err := ws.ReadMessage()
	_ = ws.SetReadDeadline(time.Time{})
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return nil, &conn.TimeoutError{Message: fmt.Sprintf("gateway handshake: no answer in %ds", int(timeout.Seconds()))}
		}
		if websocket.IsCloseError(err) {
			return nil, &conn.ConnectionError{Err: errors.New("gateway closed the websocket during the handshake")}
		}
		return nil, &conn.ConnectionError{Err: fmt.Errorf("gateway handshake failed: %w", err)}
	}
	return data, nil
}

// --- reader goroutine -------------------------------------------------

// readLoop is the single reader goroutine: it decrypts and
// demultiplexes frames into per-stream queues until the connection
// closes or a fatal error arrives. A panic here is recorded via
// Dead, never allowed to crash the process.
func (g *Gateway) readLoop() {
	defer func() {
		if r := recover(); r != nil {
			g.fail(&conn.ConnectionError{Err: fmt.Errorf("gateway: reader panic: %v", r)})
		}
		close(g.readerDone)
	}()
	for {
		if g.isClosed() {
			return
		}
		sf, err := g.readFrame()
		if err != nil {
			g.fail(err)
			return
		}
		g.touchRecv()
		if q := g.queueFor(sf.GetStreamId()); q != nil {
			q.put(queuedItem{frame: sf, generation: g.currentGeneration()})
		}
		// Untracked streams (track=false) are dropped here; the
		// reader still reads them off the wire, so the
		// connection stays healthy.
	}
}

// readFrame reads, decrypts and joins transport frames until one
// complete ServiceFrame is available. Only the reader goroutine
// calls it.
func (g *Gateway) readFrame() (*pb.ServiceFrame, error) {
	g.recvMu.Lock()
	defer g.recvMu.Unlock()
	for {
		_, data, err := g.ws.ReadMessage()
		if err != nil {
			if g.isClosed() {
				return nil, &conn.ConnectionError{Err: errors.New("gateway connection closed")}
			}
			return nil, &conn.ConnectionError{Err: fmt.Errorf("gateway receive failed: %w", err)}
		}
		pt, err := g.recvCS.Decrypt(nil, nil, data)
		if err != nil {
			return nil, &conn.ConnectionError{Err: fmt.Errorf("gateway decrypt failed: %w", err)}
		}
		var ntf pb.NoiseTransportFrame
		if err := proto.Unmarshal(pt, &ntf); err != nil {
			return nil, &conn.ConnectionError{Err: fmt.Errorf("gateway transport frame parse failed: %w", err)}
		}
		payload, complete := joinChunks(g.partial, &ntf)
		if !complete {
			continue
		}
		var sr pb.ServiceResponse
		if err := proto.Unmarshal(payload, &sr); err != nil {
			return nil, &conn.ConnectionError{Err: fmt.Errorf("gateway service response parse failed: %w", err)}
		}
		var sf pb.ServiceFrame
		if err := proto.Unmarshal(sr.GetPayload(), &sf); err != nil {
			return nil, &conn.ConnectionError{Err: fmt.Errorf("gateway service frame parse failed: %w", err)}
		}
		return &sf, nil
	}
}

// fail records the first fatal reader error (unless the gateway
// was closed cleanly, in which case Dead stays nil) and delivers
// it to every live stream queue, so blocked callers wake with a
// ConnectionError instead of hanging until their deadline. A
// connection loss (EOF/ECONNRESET/close 1006) is recorded as an
// ErrConnectionLost wrapping the reader error (S2).
func (g *Gateway) fail(err error) {
	g.mu.Lock()
	if !g.closed && g.dead == nil {
		g.dead = g.classifyDeadLocked(err)
	}
	deliver := g.dead
	if deliver == nil {
		deliver = err
	}
	queues := make([]*streamQueue, 0, len(g.streams))
	for _, q := range g.streams {
		queues = append(queues, q)
	}
	g.mu.Unlock()
	for _, q := range queues {
		q.put(queuedItem{err: deliver})
	}
}

// --- low-level send ---------------------------------------------------

// writeWS sends one binary WebSocket message with a 15s deadline
// under ioMu. A deadline expiry is reported as a send timeout
// ConnectionError, matching Python's "gateway send timed out".
func (g *Gateway) writeWS(data []byte) error {
	g.ioMu.Lock()
	defer g.ioMu.Unlock()
	if err := g.ws.SetWriteDeadline(time.Now().Add(WriteDeadline)); err != nil {
		return &conn.ConnectionError{Err: fmt.Errorf("gateway send failed: %w", err)}
	}
	err := g.ws.WriteMessage(websocket.BinaryMessage, data)
	_ = g.ws.SetWriteDeadline(time.Time{})
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return &conn.ConnectionError{Err: errors.New("gateway send timed out")}
		}
		return &conn.ConnectionError{Err: fmt.Errorf("gateway send failed: %w", err)}
	}
	return nil
}

// sendEnvelope wraps frame bytes in a ServiceRequest, splits them
// into 60000-byte NoiseTransportFrame pieces sharing one chunk id,
// encrypts each piece, and writes each ciphertext as one WebSocket
// binary frame. Encryption is serialized by sendMu.
func (g *Gateway) sendEnvelope(service pb.ServiceType, frameBytes []byte) error {
	outer, err := proto.Marshal(&pb.ServiceRequest{Service: service, Payload: frameBytes})
	if err != nil {
		return &conn.ConnectionError{Err: fmt.Errorf("gateway: marshal service request: %w", err)}
	}
	chunkID, err := newChunkID()
	if err != nil {
		return &conn.ConnectionError{Err: fmt.Errorf("gateway: chunk id: %w", err)}
	}
	pieces := splitPieces(outer)
	g.sendMu.Lock()
	defer g.sendMu.Unlock()
	for idx, piece := range pieces {
		frBytes, err := marshalTransportFrame(chunkID, uint32(idx), uint32(len(pieces)), piece)
		if err != nil {
			return &conn.ConnectionError{Err: fmt.Errorf("gateway: marshal transport frame: %w", err)}
		}
		ct, err := g.sendCS.Encrypt(nil, nil, frBytes)
		if err != nil {
			return &conn.ConnectionError{Err: fmt.Errorf("gateway encrypt failed: %w", err)}
		}
		if err := g.writeWS(ct); err != nil {
			return err
		}
		// The first piece that reaches the socket means bytes
		// were sent: a later failure is SentNoReply, never
		// NotSent (S1), and a reader death after this point
		// is a loss, not a pre-send failure (S2).
		g.mu.Lock()
		g.sentAny = true
		g.mu.Unlock()
	}
	return nil
}
