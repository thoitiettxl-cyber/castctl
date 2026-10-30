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
// The parsed-by-key list is CLOSED and evidence-based — a
// key is extracted only if this codebase actually reads it
// from a real Muse response:
//
//   - "error": the {"ok":false, "error": ...} envelope read
//     by CallJSON (calls.go) and the {"success":...,
//     "error": ...} result read by FetchSubscription
//     (subscription.go). Emitted ONLY as a short error enum
//     (see isEnumValue); a free-text, numeric, composite, or
//     over-cap value becomes the placeholder.
//   - "status": the {"status":"unavailable", ...} body of
//     GET /api/session read by FetchSessionInfo (auth.go;
//     the "unavailable" value is in the code comment there).
//     Emitted as body_status=, enum-gated the same way.
//   - "reason": the {"reason": ...} field of the redeem
//     response read by the redeem command (read.go) and
//     constructed as "unknown" by RedeemInviteCode
//     (invite.go). Enum-gated the same way.
//
// NO other key is ever extracted — in particular "detail",
// "message", and "code" are never emitted, even when they
// hold short strings: no code in this tree reads them as an
// error signal from a Muse response, so emitting them would
// be inventing a schema. Unknown keys are never emitted.
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
	s, ok := v.(string)
	if !ok || !isEnumValue(s) {
		return allowlistOmitted, true
	}
	return logging.SafeString(s), true
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
// Payload/Message/detail field, the wire body length, and
// the structured fields for GatewayError rendering.
type bodySummary struct {
	text        string
	length      int
	contentType string
	errorCode   string
}

// gatewayErrorFromSummary builds a *conn.GatewayError from an
// allowlist summary: the Payload is the summary text only
// (never body bytes), BodyLength is the wire length the
// summary measured (0 when unknown — renderers fall back to
// the summary length), and the validated content-type /
// error-enum fields ride along for rendering.
func gatewayErrorFromSummary(status int, sum bodySummary) *conn.GatewayError {
	return &conn.GatewayError{
		Status:      status,
		Payload:     sum.text,
		BodyLength:  sum.length,
		ContentType: sum.contentType,
		ErrorCode:   sum.errorCode,
	}
}

// resetSummary builds the allowlist summary for a stream
// reset frame: the reset code (a number) and the byte length
// of the peer-controlled reason — never the reason bytes.
// length is the reason length, so renderers report the size
// of the summarized peer text.
func resetSummary(code int32, reason string) bodySummary {
	return bodySummary{
		text:   fmt.Sprintf("stream reset; code=%d; reason_length=%d", code, len(reason)),
		length: len(reason),
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
	var s bodySummary
	s.length = len(data)
	var b strings.Builder
	b.WriteString(label)
	if data != nil {
		fmt.Fprintf(&b, "; body_length=%d", len(data))
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
