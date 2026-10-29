// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"

	pb "github.com/thoitiettxl-cyber/muse-cli/go/internal/proto"
	"google.golang.org/protobuf/proto"
)

// SendPiece is the max payload bytes per outgoing transport frame:
// 65535 Noise limit minus the 16-byte AEAD tag and the
// NoiseTransportFrame field overhead, with margin (gateway.py
// SEND_PIECE).
const SendPiece = 60000

// MaxReassembledSize caps one reassembled message (the joined
// payload of one chunk_id group, or one total_chunks<=1 frame).
// DELIBERATE GO-ONLY FAIL-CLOSED HARDENING, ORDERED BY BOSS —
// NOT PARITY. Python 0.6.1 (verified in the read-only 0.6.1
// copy, __version__ 0.6.1) has NO cap
// of any kind: join_chunks (gateway.py:83-93) grows an
// unbounded _partial dict and deletes an entry only when its
// group completes, and download_file (gateway.py:714-727)
// joins every response/body_chunk frame of one request into a
// single payload with no total bound. A malicious or buggy
// server could therefore make the Go client grow one message
// without bound (the F1 class of bug). The value, 64 MiB
// (Boss's example), is justified from the 0.6.1 client-side
// evidence, not from parity: the largest legitimate
// per-message sizes the Python client itself evidences are a
// 4 MiB fs.read window (fs.py:16, base64-encoded to ~5.6 MiB
// on the wire; fs.py:17 even comments on a 4 MiB gateway
// limit for writes), a 20 MiB Telegram download cap
// (tgapi.py:20) and a 49 MiB upload cap (tgapi.py:19). 64 MiB
// is 16x the 4 MiB window, over 3x the 20 MiB download cap,
// and still above the 49 MiB upload cap; it is 1117 pieces of
// SendPiece. No Python-side evidence shows a legitimate
// single frame above ~6 MiB, so 64 MiB leaves 10x headroom
// over the largest evidenced per-frame size while one 64 MiB
// message stays holdable in memory. Server-side frame
// chunking was not measured live ([UNVERIFIED]: a live
// frame-size measurement would be needed to prove the server
// never sends a larger single frame). A group that would
// exceed the cap is discarded and fails with a
// *ReassemblySizeError; it never grows past the cap.
const MaxReassembledSize = 64 << 20

// MaxUnfinishedGroups caps how many chunk_id groups may be
// unfinished (holding at least one piece, awaiting the rest)
// at once. The justification comes from how the reassembly
// code can legitimately hold groups: both Python
// (_read_frame, gateway.py:559-575) and this port (readFrame)
// have ONE reader that reads transport messages sequentially
// until one ServiceFrame completes, and the server writes one
// frame's pieces consecutively (_send_envelope,
// gateway.py:549-557, under one send lock). In normal
// operation exactly ONE unfinished group exists at a time;
// more than one requires the server to interleave pieces of
// different chunk_ids (pipelining), which the sequential
// reader tolerates but no legitimate flow needs in bulk. 16
// is 16x the normal 1, giving ample headroom for interleaved
// sends, while bounding the other F1 variant: many groups of
// tiny pieces, each too small to trip the size cap, holding
// unbounded map state. A new group past the limit is rejected
// with a *TooManyUnfinishedGroupsError and its pieces are
// dropped; existing groups are never evicted, so in-flight
// work keeps its chance to complete.
const MaxUnfinishedGroups = 16

// MaxPiecesPerGroup caps how many DISTINCT chunk_index pieces one
// chunk_id group may hold. This is the THIRD cap, and it is what
// makes the ordered total-size cap (MaxReassembledSize) effective:
// the size cap counts BYTES, so a group of empty pieces (size 0
// each, distinct indices) trips no size cap and grows the parts
// map without bound — 200,000 empty pieces were reproduced held
// with size 0 before this cap. Counting distinct indices bounds
// that map directly; duplicate-index overwrites do not grow it
// and do not count toward the cap.
//
// The value is computed from the sender-side evidence, not
// invented:
//
//   - Both senders chunk at SendPiece (60000 bytes): Python
//     _send_envelope (gateway.py:545-557, SEND_PIECE = 60000)
//     and this port's splitPieces. Every piece but the last is
//     exactly 60000 bytes; an empty message is a single empty
//     piece. A max-size (64 MiB) message therefore needs
//     ceil(64 MiB / 60000) = 1119 pieces at full-size chunking.
//     (The Noise 65535-byte ciphertext limit bounds any
//     server piece to ~65519 plaintext bytes, the same order:
//     at least 1025 pieces for 64 MiB.)
//   - 32768 is 29.3x that 1119: it tolerates a server that
//     chunks ~29x smaller than the convention (a 64 MiB
//     message averaging 2 KiB per piece: 64 MiB / 32768),
//     while bounding an empty-piece group to 32768 map
//     entries — a few megabytes of slice headers, not
//     unbounded growth.
//   - The floor is also evidence: the existing heap test
//     (TestReassemblerLargeTotalSmallHeap) exercises 20000
//     empty pieces in one group, so the cap sits above 20000
//     and preserves that behaviour; the reproduced 200,000
//     -piece bypass trips it at the 32769th distinct index.
//
// A group past the limit is discarded and fails with a
// *TooManyPiecesError; it never delivers partially, and the
// reader survives exactly as for the other two caps.
const MaxPiecesPerGroup = 32768

// Cap errors: one DISTINCT typed error per cap, each
// detectable with errors.As. Both fail only the affected
// stream: the reader discards the offending group and keeps
// reading, and the error is delivered to the streams open at
// that moment (see deliverToOpenStreams).
//
//   - *ReassemblySizeError: the MaxReassembledSize cap
//     (total reassembled size of one chunk_id group, or one
//     single-piece frame).
//   - *TooManyUnfinishedGroupsError: the
//     MaxUnfinishedGroups cap (too many unfinished chunk_id
//     groups held at once).
//   - *TooManyPiecesError: the MaxPiecesPerGroup cap (too
//     many distinct pieces in one chunk_id group).
//
// No cap error carries payload content. ChunkID is the
// offending chunk_id, or 0 for a single-piece frame that
// carried no chunk_id.
type ReassemblySizeError struct {
	ChunkID int64
	// Size is the held size in bytes, including the piece
	// that tripped the cap.
	Size int
	// Limit is MaxReassembledSize (or the test limit).
	Limit int
}

// Error renders the size-cap failure without payload content.
func (e *ReassemblySizeError) Error() string {
	return fmt.Sprintf("gateway: reassembled frame for chunk %d exceeded %d bytes (%d bytes held)", e.ChunkID, e.Limit, e.Size)
}

// TooManyUnfinishedGroupsError reports that a new chunk_id
// group was rejected because MaxUnfinishedGroups unfinished
// groups were already held.
type TooManyUnfinishedGroupsError struct {
	ChunkID int64
	// Held is how many unfinished groups were held when the
	// new group was rejected.
	Held int
	// Limit is MaxUnfinishedGroups (or the test limit).
	Limit int
}

// Error renders the groups-cap failure without payload content.
func (e *TooManyUnfinishedGroupsError) Error() string {
	return fmt.Sprintf("gateway: too many unfinished frame groups (%d held, limit %d); chunk %d rejected", e.Held, e.Limit, e.ChunkID)
}

// TooManyPiecesError reports that a chunk_id group was discarded
// because it held more than MaxPiecesPerGroup DISTINCT pieces.
// Pieces counts distinct chunk_index entries held when the
// limit was tripped (limit+1 for a group that grew past the
// cap by one new index); Limit is MaxPiecesPerGroup (or the
// test limit).
type TooManyPiecesError struct {
	ChunkID int64
	// Pieces is how many distinct pieces the group held,
	// including the piece that tripped the cap.
	Pieces int
	// Limit is MaxPiecesPerGroup (or the test limit).
	Limit int
}

// Error renders the piece-count-cap failure without payload content.
func (e *TooManyPiecesError) Error() string {
	return fmt.Sprintf("gateway: too many pieces for chunk %d (%d pieces held, limit %d)", e.ChunkID, e.Pieces, e.Limit)
}

// reassemblyCapError is implemented by all three cap error
// types so the reader can recognise any of them with one
// errors.As check.
type reassemblyCapError interface {
	error
	reassemblyCapError()
}

func (*ReassemblySizeError) reassemblyCapError()          {}
func (*TooManyUnfinishedGroupsError) reassemblyCapError() {}
func (*TooManyPiecesError) reassemblyCapError()           {}

// isReassemblyCapError reports whether err is (or wraps) any
// cap error type.
func isReassemblyCapError(err error) bool {
	var capErr reassemblyCapError
	return errors.As(err, &capErr)
}

// reassemblyGroup is one unfinished chunk_id group: its pieces
// keyed by chunk_index, and their total held size in bytes.
type reassemblyGroup struct {
	parts map[uint32][]byte
	size  int
}

// reassembler joins NoiseTransportFrame pieces into complete
// payloads, enforcing the hard caps above. It is owned by the
// single reader goroutine; callers must not share it across
// goroutines. The join is a faithful port of Python's
// join_chunks: pieces are keyed by chunk_index in a map (a
// duplicate index overwrites the earlier piece), the group
// completes when the number of DISTINCT indices reaches the
// current frame's total_chunks, and the payload is the pieces
// joined in SORTED chunk_index order — including indices >=
// total_chunks, which Python keeps, and with no empty bytes
// inserted for missing slots. Capacity is sized by the sum of
// the received piece lengths, never by total_chunks*SendPiece:
// a server-controlled total_chunks must not be able to force a
// huge preallocation (F1).
type reassembler struct {
	groups        map[int64]*reassemblyGroup
	rejected      map[int64]struct{}
	rejectedOrder []int64
	maxSize       int
	maxGroups     int
	maxPieces     int
}

// newReassembler builds a reassembler with the production caps.
func newReassembler() *reassembler {
	return newReassemblerWithLimits(MaxReassembledSize, MaxUnfinishedGroups)
}

// newReassemblerWithLimits builds a reassembler with explicit
// caps. Tests use small limits so cap behaviour is exercisable
// without sending tens of megabytes over the wire. Non-positive
// limits fall back to the production caps. The piece-count cap
// stays at the production value; tests that exercise it use
// newReassemblerWithPieceLimit.
func newReassemblerWithLimits(maxSize, maxGroups int) *reassembler {
	return newReassemblerWithPieceLimit(maxSize, maxGroups, MaxPiecesPerGroup)
}

// newReassemblerWithPieceLimit builds a reassembler with explicit
// caps including the per-group piece-count cap. Non-positive
// limits fall back to the production caps.
func newReassemblerWithPieceLimit(maxSize, maxGroups, maxPieces int) *reassembler {
	if maxSize <= 0 {
		maxSize = MaxReassembledSize
	}
	if maxGroups <= 0 {
		maxGroups = MaxUnfinishedGroups
	}
	if maxPieces <= 0 {
		maxPieces = MaxPiecesPerGroup
	}
	return &reassembler{
		groups:    make(map[int64]*reassemblyGroup),
		rejected:  make(map[int64]struct{}),
		maxSize:   maxSize,
		maxGroups: maxGroups,
		maxPieces: maxPieces,
	}
}

// markRejected records that chunk_id's group already failed, so
// its remaining pieces are dropped silently instead of
// recreating the group and failing again. The rejected set is
// bounded to maxGroups entries (oldest first out): a rejected
// group whose pieces are still arriving after eviction simply
// fails the size cap again, which is bounded by the cap itself.
func (r *reassembler) markRejected(id int64) {
	if _, ok := r.rejected[id]; ok {
		return
	}
	r.rejected[id] = struct{}{}
	r.rejectedOrder = append(r.rejectedOrder, id)
	for len(r.rejectedOrder) > r.maxGroups {
		oldest := r.rejectedOrder[0]
		r.rejectedOrder = r.rejectedOrder[1:]
		delete(r.rejected, oldest)
	}
}

// feed feeds one NoiseTransportFrame into the accumulator and
// returns the full payload once complete, or (nil, false, nil)
// while more pieces are outstanding. A frame with
// total_chunks <= 1 returns its payload immediately, without
// touching the accumulator — exactly gateway.py join_chunks
// (total = ntf.total_chunks or 1; total <= 1 returns
// immediately) — except that a single-piece payload over the
// size cap fails with a *ReassemblySizeError instead of being
// delivered. Exceeding the size cap returns
// (nil, false, *ReassemblySizeError), exceeding the
// unfinished-groups cap returns
// (nil, false, *TooManyUnfinishedGroupsError), and exceeding
// the per-group piece-count cap returns
// (nil, false, *TooManyPiecesError); in all three cases
// the offending group is discarded (its held pieces are
// released — the groups map holds no entry and no buffers for
// it afterwards) and other groups in the accumulator are
// untouched.
func (r *reassembler) feed(frame *pb.NoiseTransportFrame) ([]byte, bool, error) {
	total := frame.GetTotalChunks()
	if total <= 1 {
		payload := frame.GetPayload()
		if len(payload) > r.maxSize {
			return nil, false, &ReassemblySizeError{ChunkID: frame.GetChunkId(), Size: len(payload), Limit: r.maxSize}
		}
		return cloneBytes(payload), true, nil
	}
	id := frame.GetChunkId()
	if _, bad := r.rejected[id]; bad {
		// This group already failed a cap; drop the piece.
		return nil, false, nil
	}
	group, ok := r.groups[id]
	if !ok {
		if len(r.groups) >= r.maxGroups {
			r.markRejected(id)
			return nil, false, &TooManyUnfinishedGroupsError{ChunkID: id, Held: len(r.groups), Limit: r.maxGroups}
		}
		group = &reassemblyGroup{parts: make(map[uint32][]byte)}
		r.groups[id] = group
	}
	idx := frame.GetChunkIndex()
	payload := cloneBytes(frame.GetPayload())
	if old, dup := group.parts[idx]; dup {
		group.size -= len(old)
	}
	group.parts[idx] = payload
	group.size += len(payload)
	if group.size > r.maxSize {
		delete(r.groups, id)
		r.markRejected(id)
		return nil, false, &ReassemblySizeError{ChunkID: id, Size: group.size, Limit: r.maxSize}
	}
	// Piece-count cap: only DISTINCT indices grow the map, so
	// len(parts) is the count that matters. A duplicate-index
	// overwrite at exactly the limit does not trip it; the
	// (limit+1)th distinct index does, even if it would have
	// completed the group.
	if len(group.parts) > r.maxPieces {
		delete(r.groups, id)
		r.markRejected(id)
		return nil, false, &TooManyPiecesError{ChunkID: id, Pieces: len(group.parts), Limit: r.maxPieces}
	}
	if uint32(len(group.parts)) < total {
		return nil, false, nil
	}
	delete(r.groups, id)
	keys := make([]uint32, 0, len(group.parts))
	for k := range group.parts {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	out := make([]byte, 0, group.size)
	for _, k := range keys {
		out = append(out, group.parts[k]...)
	}
	return out, true, nil
}

func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	c := make([]byte, len(b))
	copy(c, b)
	return c
}

// splitPieces splits data into SendPiece-sized pieces, returning at
// least one (possibly empty) piece for empty data — Python's
// `pieces or [b""]`.
func splitPieces(data []byte) [][]byte {
	if len(data) == 0 {
		return [][]byte{{}}
	}
	var pieces [][]byte
	for len(data) > 0 {
		n := SendPiece
		if len(data) < n {
			n = len(data)
		}
		pieces = append(pieces, data[:n])
		data = data[n:]
	}
	return pieces
}

// newChunkID returns a chunk id from 8 random bytes read as a
// little-endian int64, as in Python
// (struct.unpack("<q", os.urandom(8))).
func newChunkID() (int64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return int64(binary.LittleEndian.Uint64(b[:])), nil
}

// marshalTransportFrame marshals one NoiseTransportFrame with all
// four proto3-optional fields present, as Python always sets them.
func marshalTransportFrame(chunkID int64, index, total uint32, payload []byte) ([]byte, error) {
	id := chunkID
	ix := index
	tot := total
	fr := &pb.NoiseTransportFrame{
		ChunkId:     &id,
		ChunkIndex:  &ix,
		TotalChunks: &tot,
		Payload:     payload,
	}
	return proto.Marshal(fr)
}
