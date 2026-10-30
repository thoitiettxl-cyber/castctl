// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

import (
	"fmt"
	"strings"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/logging"
)

// Allowlist extraction (loop 5, Boss ruling 2026-10-30,
// third direction): a server/peer response body is NEVER
// emitted anywhere — no error string, no log line at any
// level including trace, no stderr typed JSON, no panic
// rendering. Producers replace every body emission with the
// CLOSED allowlist summary built here:
//
//  1. status code (the caller's HTTP/WS status, kept in the
//     error's Status field, not in this summary's text),
//  2. error class (the summary's label, a constant chosen by
//     the producer — never body-derived prose),
//  3. body length (the byte length of the wire body),
//  4. content-type (the structured media type only — the
//     part before ';', validated; parameters and odd values
//     are replaced by the placeholder, never emitted),
//  5. specific known-safe fields parsed BY KEY from KNOWN
//     Muse response schemas, each length-capped AND passed
//     through SafeString.
//
// The parsed-by-key list is CLOSED. The three keys, and
// exactly how each is used in this tree (loop 6, item 6e —
// the earlier citations overstated two of them):
//
//   - "error": passed by key to summarizeBody by CallJSON
//     for the {"ok":false, "error": ...} envelope
//     (calls.go:202) — CallJSON does not read the value
//     anywhere else — and by FetchSubscription for the
//     {"success":..., "error": ...} result, whose "error"
//     value FetchSubscription reads at subscription.go:324
//     and passes to summarizeBody at :339. (Other code
//     reads allowlisted keys outside summarizeBody too —
//     see "reason" below — so this is not the only such
//     read; it is the only "error"-key read outside
//     summarizeBody.) Emitted ONLY as a short error enum
//     (see isEnumValue); a free-text, numeric, composite,
//     or over-cap value becomes the placeholder.
//   - "status": extracted ONLY inside summarizeBody, when
//     FetchSessionInfo passes the "status" key with the
//     decoded /api/session map (auth.go:141,151).
//     FetchSessionInfo never reads info["status"] directly
//     (auth.go:139 reads info["vm_id"], not "status") and
//     no production code branches on the value.
//     Emitted as body_status=, enum-gated the same way.
//   - "reason": RETAINED in the closed list, but no current
//     producer passes it to summarizeBody (the only keys
//     passed anywhere are "error" and "status"). The redeem
//     command reads bodyMap["reason"] and bodyMap["detail"]
//     for its data-output failure line (read.go:318,319,
//     out of scope for error renderings),
//     RedeemInviteCode constructs "unknown" for non-JSON
//     bodies (invite.go:125), and redeem failure bodies
//     are enum-gated through gateAllowlistValue by
//     filterRedeemFailureBody (invite.go:141). If a future
//     producer passes "reason" to summarizeBody it will be
//     enum-gated the same way.
//
// NO other key is ever extracted by summarizeBody — in
// particular "detail", "message", and "code" are never
// extracted here, even when they hold short strings: no
// code in this tree reads them as an error signal from a
// Muse response, so emitting them would be inventing a
// schema. (The one exception outside summarizeBody is the
// redeem filter, which enum-gates a "detail" value through
// gateAllowlistValue — free-text detail is replaced by the
// placeholder, never emitted.) Unknown keys are never emitted.
//
// A parsed value that is long or free-text by nature is
// NEVER emitted, truncated or otherwise: the cap is a
// second defence, not a licence. Values over the cap, or
// failing the enum shape, are REPLACED by the placeholder
// (never emitted truncated — a truncated prefix of free
// text can still leak).
//
// Python parity on raw payload bytes is EXPLICITLY WAIVED
// by the ruling; error-kind classification and retry
// semantics are NOT waived (kinds stay distinct, retry
// decisions unchanged — only payload bytes are removed).

// allowlistValueCap bounds every extracted allowlist value,
// in runes. 64 runes holds any short error enum or media
// type with headroom; anything longer is not an enum.
const allowlistValueCap = 64

// allowlistOmitted replaces an extracted value that cannot
// be emitted safely (wrong shape, wrong type, over cap).
// It carries no body bytes.
const allowlistOmitted = "[omitted]"

// allowlistKeys is the closed parsed-by-key list. The map
// value is the field name used in the summary text.
var allowlistKeys = map[string]string{
	"error":  "error",
	"status": "body_status",
	"reason": "reason",
}

// isEnumValue reports whether s is an emittable short enum:
// non-empty, at most allowlistValueCap runes, letters,
// digits, underscore, dot, or hyphen only. Anything else
// (spaces, quotes, slashes, unicode prose) is free text and
// must not be emitted.
func isEnumValue(s string) bool {
	n := 0
	for _, r := range s {
		n++
		if n > allowlistValueCap {
			return false
		}
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '.' || r == '-') {
			return false
		}
	}
	return n > 0
}

// gateAllowlistValue renders one allowlisted value: an
// emittable short enum passes through SafeString; anything
// else (free text, numeric, composite, over cap) becomes the
// placeholder, never emitted truncated.
func gateAllowlistValue(v any) string {
	s, ok := v.(string)
	if !ok || !isEnumValue(s) {
		return allowlistOmitted
	}
	return logging.SafeString(s)
}

// extractAllowlistField extracts one allowlisted field from
// a decoded response map. found=false means the key is not
// in the closed list or is absent from the map: nothing is
// emitted for it. found=true with the placeholder value
// means the key was present but its value is not an
// emittable enum. The emitted value is passed through
// SafeString (a second defence; the enum charset already
// excludes every secret-bearing shape).
func extractAllowlistField(decoded map[string]any, key string) (string, bool) {
	if _, ok := allowlistKeys[key]; !ok {
		return "", false
	}
	if decoded == nil {
		return "", false
	}
	v, ok := decoded[key]
	if !ok {
		return "", false
	}
	return gateAllowlistValue(v), true
}

// summarizeContentType reduces a raw Content-Type header
// value to its structured media type: the part before the
// first ';' (parameters dropped — a charset parameter is
// not allowlisted information), trimmed. "" means no header
// was present (nothing emitted). A present-but-invalid
// value (over cap, whitespace/control characters, no slash,
// empty side) becomes the placeholder. The result is passed
// through SafeString.
func summarizeContentType(raw string) string {
	if raw == "" {
		return ""
	}
	ct := strings.TrimSpace(strings.SplitN(raw, ";", 2)[0])
	if ct == "" || len([]rune(ct)) > allowlistValueCap {
		return allowlistOmitted
	}
	slash := strings.IndexByte(ct, '/')
	if slash <= 0 || slash >= len(ct)-1 || strings.Count(ct, "/") != 1 {
		return allowlistOmitted
	}
	for _, r := range ct {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '!' || r == '#' || r == '$' || r == '&' || r == '^' || r == '_' || r == '.' || r == '+' || r == '-' || r == '|' || r == '~' || r == '/') {
			return allowlistOmitted
		}
	}
	return logging.SafeString(ct)
}

// bodySummary is one allowlist summary: the text for a
// Payload/Message/detail field, the wire body length, whether
// that length is known (loop 8, F1), and the structured
// fields for GatewayError rendering.
type bodySummary struct {
	text        string
	length      int
	lengthKnown bool
	contentType string
	errorCode   string
}

// gatewayErrorFromSummary builds a *conn.GatewayError from an
// allowlist summary: the Payload is the summary text only
// (never body bytes), BodyLength is the wire length the
// summary measured, and BodyLengthKnown records whether the
// summary knew the length at all — renderers omit the
// body_length field entirely when it is unknown (loop 8,
// F1), never falling back to the summary-text length. The
// validated content-type / error-enum fields ride along for
// rendering.
func gatewayErrorFromSummary(status int, sum bodySummary) *conn.GatewayError {
	return &conn.GatewayError{
		Status:          status,
		Payload:         sum.text,
		BodyLength:      sum.length,
		BodyLengthKnown: sum.lengthKnown,
		ContentType:     sum.contentType,
		ErrorCode:       sum.errorCode,
	}
}

// resetSummary builds the allowlist summary for a stream
// reset frame: the reset code (a number) and the byte length
// of the peer-controlled reason — never the reason bytes.
// length is the reason length, and it IS known (the reason
// was measured), so renderers report body_length for it.
func resetSummary(code int32, reason string) bodySummary {
	return bodySummary{
		text:        fmt.Sprintf("stream reset; code=%d; reason_length=%d", code, len(reason)),
		length:      len(reason),
		lengthKnown: true,
	}
}

// summarizeBody builds the allowlist summary for one
// response body. label is the producer's constant class
// label (never body-derived). data is the wire body (nil
// when the producer has no body bytes, e.g. an already-
// parsed RSC result — then no body_length field is
// emitted). rawContentType is the response's Content-Type
// header value, "" when unknown. decoded is the decoded
// JSON body when the producer parsed one, nil otherwise;
// keys names the allowlisted keys to extract from it
// (unknown keys are ignored by extractAllowlistField).
func summarizeBody(label string, data []byte, rawContentType string, decoded map[string]any, keys ...string) bodySummary {
	return summarizeFields(label, len(data), data != nil, rawContentType, decoded, keys...)
}

// summarizeParsedBody builds the allowlist summary for a
// parsed result whose wire body length is known but whose
// bytes are not retained (the RSC case in FetchSubscription):
// body_length is always the wire length threaded through
// callAction, never the summary-text length (loop 6,
// item 6b). bodyLenKnown is callAction's explicit flag: a
// known 0-byte body renders body_length=0, an unknown
// length renders no body_length field (loop 8, F1).
func summarizeParsedBody(label string, bodyLen int, bodyLenKnown bool, decoded map[string]any, keys ...string) bodySummary {
	return summarizeFields(label, bodyLen, bodyLenKnown, "", decoded, keys...)
}

// summarizeFields is the shared allowlist-summary builder:
// the class label, the wire body length (when known —
// emitLength IS the known flag), the validated content-type,
// and the parsed-by-key fields.
func summarizeFields(label string, length int, emitLength bool, rawContentType string, decoded map[string]any, keys ...string) bodySummary {
	var s bodySummary
	s.length = length
	s.lengthKnown = emitLength
	var b strings.Builder
	b.WriteString(label)
	if emitLength {
		fmt.Fprintf(&b, "; body_length=%d", length)
	}
	if rawContentType != "" {
		ct := summarizeContentType(rawContentType)
		if ct != allowlistOmitted {
			s.contentType = ct
		}
		fmt.Fprintf(&b, "; content_type=%s", ct)
	}
	for _, key := range keys {
		value, found := extractAllowlistField(decoded, key)
		if !found {
			continue
		}
		fmt.Fprintf(&b, "; %s=%s", allowlistKeys[key], value)
		if key == "error" && value != allowlistOmitted {
			s.errorCode = value
		}
	}
	s.text = b.String()
	return s
}
