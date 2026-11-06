// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-only
// Licensed under the GNU General Public License v3.0 only.

//! Minimal DNS wire codec (RFC 1035): one-question
//! queries and their responses, A/AAAA only. No EDNS,
//! no TCP pipelining, no caching. The codec exists so
//! the client can speak to the fake TCP DNS server in
//! the ported tests (Go `helpers_test.go` uses
//! `miekg/dns`); it is not a general DNS implementation.
//!
//! Responses may use name compression (pointers) in any
//! name field; the decoder follows pointers with a jump
//! cap. Queries are always encoded uncompressed.

use crate::error::DnsError;

/// Query type A (host address, RFC 1035 §3.2.2).
pub const QTYPE_A: u16 = 1;
/// Query type AAAA (IPv6 address, RFC 3596).
pub const QTYPE_AAAA: u16 = 28;
/// Query class IN (Internet).
const QCLASS_IN: u16 = 1;

const MAX_NAME_JUMPS: usize = 128;
const MAX_MESSAGE: usize = 65535;

/// One decoded question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// Owner name, trailing dot stripped
    /// (`"gateway.test"`).
    pub name: String,
    /// Query type.
    pub qtype: u16,
    /// Query class.
    pub qclass: u16,
}

/// One decoded answer record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    /// Owner name, trailing dot stripped.
    pub name: String,
    /// Record type.
    pub rtype: u16,
    /// TTL seconds.
    pub ttl: u32,
    /// Address bytes (4 for A, 16 for AAAA).
    pub rdata: Vec<u8>,
}

/// One decoded DNS message (query or response).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsMessage {
    /// Transaction id.
    pub id: u16,
    /// Flags word.
    pub flags: u16,
    /// Response code (low 4 bits of `flags`).
    pub rcode: u16,
    /// Questions.
    pub questions: Vec<Question>,
    /// Answers.
    pub answers: Vec<Answer>,
}

/// Max octets of one DNS name on the wire, length
/// bytes + root zero included (RFC 1035 §2.3.4).
const MAX_NAME_WIRE_LEN: usize = 255;
/// Max octets of one label (RFC 1035 §2.3.4).
const MAX_LABEL_LEN: usize = 63;

/// Encode one question (RD set, QDCOUNT 1). Names Go
/// would reject are rejected here instead of emitting
/// corrupt wire bytes: a label over 63 octets, a name
/// over 255 octets on the wire, or an empty label
/// (`"a..b"`, `".a.b"`) is `DnsError::Protocol`
/// (red-team F8, fix loop 1; round-2 R2-1 for the
/// empty-label rule; Go validates via sing-box /
/// miekg/dns before sending).
/// The bound also keeps the query far below 64 KiB, so
/// the 2-byte length prefix in `transport.rs` cannot
/// wrap.
pub fn encode_query(id: u16, name: &str, qtype: u16) -> Result<Vec<u8>, DnsError> {
    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    encode_name(&mut out, name)?;
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&QCLASS_IN.to_be_bytes());
    Ok(out)
}

fn encode_name(out: &mut Vec<u8>, name: &str) -> Result<(), DnsError> {
    // A name of only dots (`""` or `"."`) is the root:
    // a single zero octet. Anything else with an empty
    // label (`"a..b"`, `".a.b"`) is rejected, matching
    // Go miekg/dns `packDomainName` (v1.1.72, msg.go):
    // two dots back to back, or a leading dot other
    // than the root, is `ErrRdata` (round-2 R2-1; the
    // old code skipped empty labels, so `"a..b"`
    // encoded as `"a.b"` — a lookup for a different
    // name than the one requested).
    // No charset check: `packDomainName` copies label
    // bytes verbatim (its `default:` arm), so a space
    // or other unusual byte is legal on the wire here.
    // `castctl-transport`'s `dns_encode_query` is
    // stricter (rejects chars outside `[A-Za-z0-9_-]`),
    // but that is stricter than Go, so this encoder
    // does not copy it.
    let trimmed = name.trim_end_matches('.');
    if trimmed.is_empty() {
        out.push(0);
        return Ok(());
    }
    // Wire length: one length byte per label + the
    // labels + the root zero.
    let mut wire_len = 1;
    for label in trimmed.split('.') {
        if label.is_empty() {
            return Err(DnsError::Protocol(
                "DNS name contains an empty label".to_string(),
            ));
        }
        if label.len() > MAX_LABEL_LEN {
            return Err(DnsError::Protocol(format!(
                "DNS label too long: {} bytes (max {MAX_LABEL_LEN})",
                label.len()
            )));
        }
        wire_len += 1 + label.len();
        if wire_len > MAX_NAME_WIRE_LEN {
            return Err(DnsError::Protocol(format!(
                "DNS name too long: over {MAX_NAME_WIRE_LEN} octets on the wire"
            )));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

/// Decode one DNS message (query or response).
pub fn decode_message(buf: &[u8]) -> Result<DnsMessage, DnsError> {
    if buf.len() < 12 {
        return Err(DnsError::Protocol(
            "message shorter than header".to_string(),
        ));
    }
    if buf.len() > MAX_MESSAGE {
        return Err(DnsError::Protocol("message too large".to_string()));
    }
    let rd = Reader { buf, pos: 0 };
    let id = rd.u16(0);
    let flags = rd.u16(2);
    let qdcount = rd.u16(4) as usize;
    let ancount = rd.u16(6) as usize;
    let nscount = rd.u16(8) as usize;
    let arcount = rd.u16(10) as usize;
    let mut r = Reader { buf, pos: 12 };
    let mut questions = Vec::with_capacity(qdcount);
    for _ in 0..qdcount {
        let name = r.name()?;
        let qtype = r.u16_at()?;
        let qclass = r.u16_at()?;
        questions.push(Question {
            name,
            qtype,
            qclass,
        });
    }
    let mut answers = Vec::with_capacity(ancount);
    for _ in 0..ancount {
        let name = r.name()?;
        let rtype = r.u16_at()?;
        let _class = r.u16_at()?;
        let ttl = r.u32_at()?;
        let rdlen = r.u16_at()? as usize;
        let rdata = r.bytes(rdlen)?;
        answers.push(Answer {
            name,
            rtype,
            ttl,
            rdata: rdata.to_vec(),
        });
    }
    // Skip authority + additional sections (counts only;
    // the client never needs them).
    for _ in 0..(nscount + arcount) {
        let _name = r.name()?;
        let _rtype = r.u16_at()?;
        let _class = r.u16_at()?;
        let _ttl = r.u32_at()?;
        let rdlen = r.u16_at()? as usize;
        let _rdata = r.bytes(rdlen)?;
    }
    Ok(DnsMessage {
        id,
        flags,
        rcode: flags & 0x000f,
        questions,
        answers,
    })
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn u16(&self, at: usize) -> u16 {
        u16::from_be_bytes([self.buf[at], self.buf[at + 1]])
    }

    fn u16_at(&mut self) -> Result<u16, DnsError> {
        let b = self.bytes(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32_at(&mut self) -> Result<u32, DnsError> {
        let b = self.bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8], DnsError> {
        if self
            .pos
            .checked_add(n)
            .is_none_or(|end| end > self.buf.len())
        {
            return Err(DnsError::Protocol("truncated message".to_string()));
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    fn name(&mut self) -> Result<String, DnsError> {
        let mut labels: Vec<String> = Vec::new();
        let mut pos = self.pos;
        let mut jumps = 0;
        let mut next = None;
        loop {
            if pos >= self.buf.len() {
                return Err(DnsError::Protocol("truncated name".to_string()));
            }
            let len = self.buf[pos] as usize;
            if len == 0 {
                if next.is_none() {
                    next = Some(pos + 1);
                }
                break;
            }
            if len & 0xC0 == 0xC0 {
                if pos + 1 >= self.buf.len() {
                    return Err(DnsError::Protocol("truncated pointer".to_string()));
                }
                let target = ((len & 0x3F) << 8) | self.buf[pos + 1] as usize;
                if next.is_none() {
                    next = Some(pos + 2);
                }
                jumps += 1;
                if jumps > MAX_NAME_JUMPS {
                    return Err(DnsError::Protocol("name pointer loop".to_string()));
                }
                pos = target;
                continue;
            }
            if len & 0xC0 != 0 {
                return Err(DnsError::Protocol("bad name label".to_string()));
            }
            let start = pos + 1;
            let end = start
                .checked_add(len)
                .ok_or_else(|| DnsError::Protocol("name label overflow".to_string()))?;
            if end > self.buf.len() {
                return Err(DnsError::Protocol("truncated label".to_string()));
            }
            let label = std::str::from_utf8(&self.buf[start..end])
                .map_err(|_| DnsError::Protocol("non-UTF-8 name".to_string()))?;
            labels.push(label.to_string());
            pos = end;
        }
        self.pos = next.unwrap_or(pos);
        Ok(labels.join("."))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_query() {
        let q = encode_query(0x1234, "gateway.test", QTYPE_A).expect("valid name encodes");
        let msg = decode_message(&q).expect("query must decode");
        assert_eq!(msg.id, 0x1234);
        assert_eq!(msg.questions.len(), 1);
        assert_eq!(msg.questions[0].name, "gateway.test");
        assert_eq!(msg.questions[0].qtype, QTYPE_A);
        assert_eq!(msg.questions[0].qclass, QCLASS_IN);
    }

    #[test]
    fn overlong_label_is_protocol_error() {
        // Red-team F8: a label over 63 octets used to
        // be written with a wrapped length byte (a
        // 300-octet label became 44) and emit a corrupt
        // query.
        let long = "a".repeat(64);
        assert!(matches!(
            encode_query(1, &format!("{long}.test"), QTYPE_A),
            Err(DnsError::Protocol(_))
        ));
    }

    #[test]
    fn overlong_name_is_protocol_error() {
        // 4 labels of 63 octets: 4*(1+63)+1 = 257
        // wire octets, over the 255 limit.
        let name = vec!["a".repeat(63); 4].join(".");
        assert!(matches!(
            encode_query(1, &name, QTYPE_A),
            Err(DnsError::Protocol(_))
        ));
    }

    #[test]
    fn max_length_name_encodes() {
        // 3 labels of 63 + 1 of 61: 3*(1+63)+(1+61)+1
        // = 255 wire octets, exactly at the limit.
        let name = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        let q = encode_query(1, &name, QTYPE_A).expect("255-octet name must encode");
        let msg = decode_message(&q).expect("query must decode");
        assert_eq!(msg.questions[0].name, name);
    }

    #[test]
    fn empty_label_is_protocol_error() {
        // Round-2 R2-1: an empty label used to be
        // skipped, so "a..b" encoded as "a.b" — a
        // lookup for a different name than requested.
        // Go miekg/dns packDomainName (v1.1.72,
        // msg.go) returns ErrRdata on two dots back
        // to back, and on a leading dot other than
        // the root.
        assert!(matches!(
            encode_query(1, "a..b", QTYPE_A),
            Err(DnsError::Protocol(_))
        ));
        assert!(matches!(
            encode_query(1, ".a.b", QTYPE_A),
            Err(DnsError::Protocol(_))
        ));
    }

    #[test]
    fn root_name_encodes() {
        // "" and "." are the root: a single zero
        // octet after the 12-byte header (the
        // decoder joins zero labels into "").
        for name in ["", "."] {
            let q = encode_query(1, name, QTYPE_A).expect("root must encode");
            assert_eq!(q.len(), 12 + 1 + 4);
            assert_eq!(q[12], 0);
            let msg = decode_message(&q).expect("query must decode");
            assert_eq!(msg.questions[0].name, "");
        }
    }

    #[test]
    fn truncated_message_is_protocol_error() {
        assert!(matches!(
            decode_message(&[0, 1, 2]),
            Err(DnsError::Protocol(_))
        ));
    }
}
