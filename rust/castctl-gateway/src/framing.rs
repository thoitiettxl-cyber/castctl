// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! `NoiseTransportFrame` chunking + reassembly (M4a).
//!
//! Go source: `internal/gateway/framing.go` (ported verbatim
//! in structure, including the three hardening caps — those
//! caps are Go-only fail-closed hardening ordered by Boss, NOT
//! parity with Python 0.6.1, which has no cap of any kind; see
//! the comments on each constant below).
//!
//! Wire rules:
//! - One Noise ciphertext = one WS binary message; the
//!   plaintext after decrypt is one `NoiseTransportFrame`.
//! - `SEND_PIECE` (60000) is the max plaintext bytes per
//!   frame: 65535 Noise limit minus the 16-byte AEAD tag and
//!   frame overhead, with margin. Empty data still sends one
//!   empty piece.
//! - `marshal_transport_frame` always sets all four proto3
//!   optional fields (as Python always sets them).
//! - Reassembly joins by `chunk_index` (sorted, duplicates
//!   overwrite, indices >= total are kept), completing when
//!   the number of DISTINCT indices reaches `total_chunks`.
//!   `total_chunks <= 1` returns the payload immediately.

use std::collections::{BTreeMap, HashMap, HashSet};

use prost::Message as _;

use crate::proto::NoiseTransportFrame;
use castctl_transport::error::{BodySummary, TransportError};

/// Max payload bytes per outgoing transport frame (Go
/// `framing.go:16-21` `SendPiece`).
pub const SEND_PIECE: usize = 60000;

/// Caps one reassembled message (Go `MaxReassembledSize`).
/// 64 MiB: 16x the 4 MiB fs.read window, over 3x the 20 MiB
/// Telegram download cap, above the 49 MiB upload cap; no
/// Python-side evidence shows a legitimate single frame above
/// ~6 MiB. Go-only hardening, NOT parity.
pub const MAX_REASSEMBLED_SIZE: usize = 64 << 20;

/// Caps unfinished chunk_id groups held at once (Go
/// `MaxUnfinishedGroups`). Normal operation holds exactly 1;
/// 16 is 16x headroom. Go-only hardening, NOT parity.
pub const MAX_UNFINISHED_GROUPS: usize = 16;

/// Caps DISTINCT pieces in one group (Go
/// `MaxPiecesPerGroup`). 32768 is 29.3x the 1119 pieces a
/// 64 MiB message needs at full-size chunking, and above the
/// 20000 empty pieces the Go heap test exercises. Go-only
/// hardening, NOT parity.
pub const MAX_PIECES_PER_GROUP: usize = 32768;

/// One reassembly cap failure. Mirrors the three Go types
/// (`ReassemblySizeError`, `TooManyUnfinishedGroupsError`,
/// `TooManyPiecesError` in `framing.go`); `classifyError`
/// maps the first two to exit 3, while the third has no
/// branch (and no `ExitCode` method on the Go type) and so
/// falls through to the default exit 1. The split is kept in
/// `into_transport_error` below.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReassemblyError {
    /// One message (or group) would exceed the size cap.
    Size {
        /// Offending chunk id (0 for a single-piece frame).
        chunk_id: i64,
        /// Bytes held, including the piece that tripped the cap.
        size: usize,
        /// The cap in force.
        limit: usize,
    },
    /// A new group was rejected: too many unfinished groups.
    TooManyGroups {
        /// Rejected chunk id.
        chunk_id: i64,
        /// Groups held when rejected.
        held: usize,
        /// The cap in force.
        limit: usize,
    },
    /// A group held too many distinct pieces.
    TooManyPieces {
        /// Offending chunk id.
        chunk_id: i64,
        /// Distinct pieces held, including the one that tripped.
        pieces: usize,
        /// The cap in force.
        limit: usize,
    },
}

impl ReassemblyError {
    /// Convert to the transport error taxonomy. Size and
    /// TooManyGroups are stream failures (exit 3, like Go's
    /// `ReassemblySizeError` / `TooManyUnfinishedGroupsError`
    /// branches in `classifyError`); TooManyPieces has no
    /// branch there and falls through to the default exit 1,
    /// so it converts to a plain `ConnectionError` with a
    /// fixed message (no payload content — only ids, sizes
    /// and limits). The reader delivers them to the open
    /// streams and keeps reading.
    pub fn into_transport_error(self) -> TransportError {
        match self {
            ReassemblyError::TooManyPieces {
                chunk_id,
                pieces,
                limit,
            } => TransportError::ConnectionError {
                message: format!(
                    "gateway: chunk group {chunk_id} held {pieces} distinct pieces (limit {limit})"
                ),
            },
            ReassemblyError::Size { size, .. } => TransportError::Gateway(BodySummary {
                status: -1,
                body_length: Some(size),
                content_type: None,
                error_code: None,
            }),
            _ => TransportError::Gateway(BodySummary {
                status: -1,
                body_length: None,
                content_type: None,
                error_code: None,
            }),
        }
    }
}

impl std::fmt::Display for ReassemblyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReassemblyError::Size {
                chunk_id,
                size,
                limit,
            } => write!(
                f,
                "gateway: reassembled frame for chunk {chunk_id} exceeded {limit} bytes ({size} bytes held)"
            ),
            ReassemblyError::TooManyGroups {
                chunk_id,
                held,
                limit,
            } => write!(
                f,
                "gateway: too many unfinished frame groups ({held} held, limit {limit}); chunk {chunk_id} rejected"
            ),
            ReassemblyError::TooManyPieces {
                chunk_id,
                pieces,
                limit,
            } => write!(
                f,
                "gateway: too many pieces for chunk {chunk_id} ({pieces} pieces held, limit {limit})"
            ),
        }
    }
}

impl std::error::Error for ReassemblyError {}

/// Split data into `SEND_PIECE`-sized pieces, returning at
/// least one (possibly empty) piece for empty data (Go
/// `splitPieces`: `pieces or [b""]`).
pub fn split_pieces(data: &[u8]) -> Vec<&[u8]> {
    if data.is_empty() {
        return vec![&[]];
    }
    data.chunks(SEND_PIECE).collect()
}

/// A chunk id from 8 random bytes read as a little-endian
/// int64 (Go `newChunkID`, as in Python
/// `struct.unpack("<q", os.urandom(8))`).
pub fn new_chunk_id() -> i64 {
    let bytes: [u8; 8] = rand::random();
    i64::from_le_bytes(bytes)
}

/// Marshal one `NoiseTransportFrame` with all four proto3
/// optional fields present (Go `marshalTransportFrame`).
pub fn marshal_transport_frame(chunk_id: i64, index: u32, total: u32, payload: &[u8]) -> Vec<u8> {
    let frame = NoiseTransportFrame {
        chunk_id: Some(chunk_id),
        chunk_index: Some(index),
        total_chunks: Some(total),
        payload: Some(payload.to_vec()),
    };
    frame.encode_to_vec()
}

struct ReassemblyGroup {
    parts: BTreeMap<u32, Vec<u8>>,
    size: usize,
}

/// Joins `NoiseTransportFrame` pieces into complete payloads
/// (Go `reassembler` in `framing.go`). Owned by the single
/// reader task; callers must not share it across tasks.
/// The join is Python's `join_chunks`: pieces keyed by
/// `chunk_index` (duplicate overwrites), complete when the
/// number of DISTINCT indices reaches `total_chunks`, payload
/// joined in sorted index order — including indices >= total,
/// with no empty bytes inserted for missing slots. Capacity is
/// sized by the sum of received piece lengths, never by
/// `total_chunks * SEND_PIECE`: a server-controlled
/// `total_chunks` must not force a huge preallocation.
pub struct Reassembler {
    groups: HashMap<i64, ReassemblyGroup>,
    rejected: HashSet<i64>,
    rejected_order: Vec<i64>,
    max_size: usize,
    max_groups: usize,
    max_pieces: usize,
}

impl Reassembler {
    /// Production caps.
    pub fn new() -> Self {
        Self::with_limits(
            MAX_REASSEMBLED_SIZE,
            MAX_UNFINISHED_GROUPS,
            MAX_PIECES_PER_GROUP,
        )
    }

    /// Explicit caps. Tests use small limits so cap behaviour
    /// is exercisable without megabytes of wire traffic.
    /// Non-positive limits fall back to the production caps
    /// (Go `newReassemblerWithLimits` / `...WithPieceLimit`).
    pub fn with_limits(max_size: usize, max_groups: usize, max_pieces: usize) -> Self {
        Self {
            groups: HashMap::new(),
            rejected: HashSet::new(),
            rejected_order: Vec::new(),
            max_size: if max_size == 0 {
                MAX_REASSEMBLED_SIZE
            } else {
                max_size
            },
            max_groups: if max_groups == 0 {
                MAX_UNFINISHED_GROUPS
            } else {
                max_groups
            },
            max_pieces: if max_pieces == 0 {
                MAX_PIECES_PER_GROUP
            } else {
                max_pieces
            },
        }
    }

    fn mark_rejected(&mut self, id: i64) {
        if !self.rejected.insert(id) {
            return;
        }
        self.rejected_order.push(id);
        while self.rejected_order.len() > self.max_groups {
            let oldest = self.rejected_order.remove(0);
            self.rejected.remove(&oldest);
        }
    }

    /// Feed one frame. Returns `Ok(Some(payload))` once the
    /// group is complete, `Ok(None)` while more pieces are
    /// outstanding, or `Err` on a cap failure (the offending
    /// group is discarded; other groups are untouched; a
    /// rejected group's later pieces are dropped silently).
    pub fn feed(
        &mut self,
        frame: &NoiseTransportFrame,
    ) -> Result<Option<Vec<u8>>, ReassemblyError> {
        let total = frame.total_chunks.unwrap_or(0);
        if total <= 1 {
            let payload = frame.payload.clone().unwrap_or_default();
            if payload.len() > self.max_size {
                return Err(ReassemblyError::Size {
                    chunk_id: frame.chunk_id.unwrap_or(0),
                    size: payload.len(),
                    limit: self.max_size,
                });
            }
            return Ok(Some(payload));
        }
        let id = frame.chunk_id.unwrap_or(0);
        if self.rejected.contains(&id) {
            return Ok(None);
        }
        if !self.groups.contains_key(&id) {
            if self.groups.len() >= self.max_groups {
                self.mark_rejected(id);
                return Err(ReassemblyError::TooManyGroups {
                    chunk_id: id,
                    held: self.groups.len(),
                    limit: self.max_groups,
                });
            }
            self.groups.insert(
                id,
                ReassemblyGroup {
                    parts: BTreeMap::new(),
                    size: 0,
                },
            );
        }
        // The group was inserted (or already existed) above; a
        // missing entry here is unreachable, and is treated as a
        // dropped piece rather than a panic.
        let Some(group) = self.groups.get_mut(&id) else {
            return Ok(None);
        };
        let idx = frame.chunk_index.unwrap_or(0);
        let payload = frame.payload.clone().unwrap_or_default();
        let plen = payload.len();
        if let Some(old) = group.parts.insert(idx, payload) {
            group.size -= old.len();
        }
        group.size += plen;
        if group.size > self.max_size {
            let size = group.size;
            self.groups.remove(&id);
            self.mark_rejected(id);
            return Err(ReassemblyError::Size {
                chunk_id: id,
                size,
                limit: self.max_size,
            });
        }
        if group.parts.len() > self.max_pieces {
            let pieces = group.parts.len();
            self.groups.remove(&id);
            self.mark_rejected(id);
            return Err(ReassemblyError::TooManyPieces {
                chunk_id: id,
                pieces,
                limit: self.max_pieces,
            });
        }
        if (group.parts.len() as u32) < total {
            return Ok(None);
        }
        let Some(group) = self.groups.remove(&id) else {
            return Ok(None);
        };
        let mut out = Vec::with_capacity(group.size);
        for (_, piece) in group.parts {
            out.extend_from_slice(&piece);
        }
        Ok(Some(out))
    }
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(id: i64, idx: u32, total: u32, payload: &[u8]) -> NoiseTransportFrame {
        NoiseTransportFrame {
            chunk_id: Some(id),
            chunk_index: Some(idx),
            total_chunks: Some(total),
            payload: Some(payload.to_vec()),
        }
    }

    #[test]
    fn split_pieces_boundaries() {
        assert_eq!(split_pieces(&[]), vec![&[] as &[u8]]);
        assert_eq!(split_pieces(&[1u8; 60000]).len(), 1);
        let pieces = split_pieces(&[1u8; 60001]);
        assert_eq!(pieces.len(), 2);
        assert_eq!(pieces[0].len(), 60000);
        assert_eq!(pieces[1].len(), 1);
    }

    #[test]
    fn reassemble_shuffled_and_duplicate_overwrite() {
        let mut r = Reassembler::new();
        // A duplicate index overwrites (Go `feed`: the map
        // entry is replaced) — but only while the group is
        // still incomplete: the group completes the moment
        // the number of DISTINCT indices reaches total, so
        // the overwrite must arrive before that moment.
        assert_eq!(r.feed(&frame(7, 1, 3, b"OLD")).unwrap(), None);
        assert_eq!(r.feed(&frame(7, 1, 3, b"b")).unwrap(), None);
        assert_eq!(r.feed(&frame(7, 2, 3, b"c")).unwrap(), None);
        assert_eq!(
            r.feed(&frame(7, 0, 3, b"a")).unwrap(),
            Some(b"abc".to_vec())
        );
    }

    #[test]
    fn single_piece_returns_immediately() {
        let mut r = Reassembler::new();
        assert_eq!(
            r.feed(&frame(1, 0, 1, b"hi")).unwrap(),
            Some(b"hi".to_vec())
        );
        // total_chunks absent (= 0) also returns immediately.
        let f = NoiseTransportFrame {
            chunk_id: None,
            chunk_index: None,
            total_chunks: None,
            payload: Some(b"x".to_vec()),
        };
        assert_eq!(r.feed(&f).unwrap(), Some(b"x".to_vec()));
    }

    #[test]
    fn size_cap_discards_group_and_rejects_later_pieces() {
        let mut r = Reassembler::with_limits(10, 16, 32768);
        assert_eq!(r.feed(&frame(9, 0, 3, b"123456")).unwrap(), None);
        let err = r.feed(&frame(9, 1, 3, b"123456")).unwrap_err();
        assert_eq!(
            err,
            ReassemblyError::Size {
                chunk_id: 9,
                size: 12,
                limit: 10
            }
        );
        // Later pieces of the rejected group are dropped silently.
        assert_eq!(r.feed(&frame(9, 2, 3, b"z")).unwrap(), None);
        assert_eq!(err.into_transport_error().exit_code(), 3);
    }

    #[test]
    fn too_many_groups_cap() {
        let mut r = Reassembler::with_limits(1000, 2, 32768);
        assert_eq!(r.feed(&frame(1, 0, 2, b"a")).unwrap(), None);
        assert_eq!(r.feed(&frame(2, 0, 2, b"b")).unwrap(), None);
        let err = r.feed(&frame(3, 0, 2, b"c")).unwrap_err();
        assert_eq!(
            err,
            ReassemblyError::TooManyGroups {
                chunk_id: 3,
                held: 2,
                limit: 2
            }
        );
        assert_eq!(err.into_transport_error().exit_code(), 3);
    }

    #[test]
    fn too_many_pieces_cap_counts_distinct_only() {
        let mut r = Reassembler::with_limits(1000, 16, 3);
        assert_eq!(r.feed(&frame(5, 0, 10, b"a")).unwrap(), None);
        // Duplicate index overwrites: does not grow the count.
        assert_eq!(r.feed(&frame(5, 0, 10, b"b")).unwrap(), None);
        assert_eq!(r.feed(&frame(5, 1, 10, b"c")).unwrap(), None);
        assert_eq!(r.feed(&frame(5, 2, 10, b"d")).unwrap(), None);
        let err = r.feed(&frame(5, 3, 10, b"e")).unwrap_err();
        assert_eq!(
            err,
            ReassemblyError::TooManyPieces {
                chunk_id: 5,
                pieces: 4,
                limit: 3
            }
        );
        // Go `classifyError` has NO `TooManyPiecesError`
        // branch (and the Go type has no `ExitCode` method),
        // so it falls through to the default exit 1 — unlike
        // Size / TooManyGroups, which map to exit 3.
        assert_eq!(err.into_transport_error().exit_code(), 1);
    }

    #[test]
    fn marshal_frame_sets_all_four_fields() {
        use prost::Message as _;
        let bytes = marshal_transport_frame(42, 1, 2, b"hi");
        let back = NoiseTransportFrame::decode(bytes.as_slice()).unwrap();
        assert_eq!(back.chunk_id, Some(42));
        assert_eq!(back.chunk_index, Some(1));
        assert_eq!(back.total_chunks, Some(2));
        assert_eq!(back.payload, Some(b"hi".to_vec()));
    }
}
