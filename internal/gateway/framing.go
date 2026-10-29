// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

import (
	"crypto/rand"
	"encoding/binary"
	"slices"

	pb "github.com/thoitiettxl-cyber/muse-cli/go/internal/proto"
	"google.golang.org/protobuf/proto"
)

// SendPiece is the max payload bytes per outgoing transport frame:
// 65535 Noise limit minus the 16-byte AEAD tag and the
// NoiseTransportFrame field overhead, with margin (gateway.py
// SEND_PIECE).
const SendPiece = 60000

// joinChunks feeds one NoiseTransportFrame into the partial-chunk
// accumulator and returns the full payload once complete, or
// (nil, false) while more pieces are outstanding. A frame with
// total_chunks <= 1 returns its payload immediately, without
// touching the accumulator — exactly gateway.py join_chunks
// (total = ntf.total_chunks or 1; total <= 1 returns immediately).
//
// The join is a faithful port of Python's join_chunks: pieces are
// keyed by chunk_index in a map (a duplicate index overwrites the
// earlier piece), the group completes when the number of DISTINCT
// indices reaches total_chunks, and the payload is the pieces
// joined in SORTED chunk_index order — including indices >=
// total_chunks, which Python keeps, and with no empty bytes
// inserted for missing slots. Capacity is sized by the sum of the
// received piece lengths, never by total_chunks*SendPiece: a
// server-controlled total_chunks must not be able to force a
// huge preallocation (F1). The accumulator is owned by the single
// reader goroutine; callers must not share it across goroutines.
func joinChunks(partial map[int64]map[uint32][]byte, frame *pb.NoiseTransportFrame) ([]byte, bool) {
	total := frame.GetTotalChunks()
	if total <= 1 {
		return cloneBytes(frame.GetPayload()), true
	}
	parts, ok := partial[frame.GetChunkId()]
	if !ok {
		parts = make(map[uint32][]byte)
		partial[frame.GetChunkId()] = parts
	}
	parts[frame.GetChunkIndex()] = cloneBytes(frame.GetPayload())
	if uint32(len(parts)) < total {
		return nil, false
	}
	delete(partial, frame.GetChunkId())
	keys := make([]uint32, 0, len(parts))
	for k := range parts {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	size := 0
	for _, p := range parts {
		size += len(p)
	}
	out := make([]byte, 0, size)
	for _, k := range keys {
		out = append(out, parts[k]...)
	}
	return out, true
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
