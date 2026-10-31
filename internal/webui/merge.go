// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package webui

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/thoitiettxl-cyber/castctl/internal/redact"
)

// Sentinel merge: the server-side port of webui/dev-mocks/redact.ts
// (mergeConfig / adoptNew / spliceUserinfo / checkElementIdentity /
// findSentinelAtSecretPosition), implementing webui/SECRETS-
// CONTRACT.md rules R1-R9. The Go implementation is the authority;
// the mock must not drift from it. Where the two could differ,
// this file wins and the mock is fixed to match, never the other
// way round.
//
// Rules, in brief: a submitted (redacted, edited) document merges
// against the stored document. An exact sentinel string at a
// present secret position keeps the stored value verbatim (R1);
// a sentinel at a path absent from stored rejects the whole save
// (R2, including renames); a sentinel at a present non-secret
// position is an ordinary literal (R-A). Arrays merge
// positionally with an identity guard (R4). A single-span URL
// userinfo edit splices the stored userinfo into the edited
// string (R6); multi-URL strings fail closed. Deletion, empty,
// and null are distinct from keep (R9). The merged document is
// asserted sentinel-free at secret positions before writing
// (R8). Error paths name the JSON path only, never a value.

// sentinelRejection names the JSON path of an offending sentinel.
// Its message is fixed: the path travels in the Path field, and
// handlers render it as "redacted value at <path>" — path only,
// never a value.
type sentinelRejection struct{ path string }

func (e *sentinelRejection) Error() string { return "submitted value rejected" }

// isHeaderMapKey mirrors redact.isHeaderMapKey (internal/redact/
// value.go, unexported there): exact after lowercasing,
// "headers" or "extra_headers" only. "custom_headers" is not a
// header map.
func isHeaderMapKey(key string) bool {
	switch strings.ToLower(key) {
	case "headers", "extra_headers":
		return true
	default:
		return false
	}
}

// reURLUserinfoSpan is the Go userinfo pattern from
// redact.RedactURLUserinfo (internal/redact/redact.go), reused
// here to locate userinfo spans for the R6 splice. The pattern
// is greedy: the userinfo run extends to the LAST '@' before
// the first '/', '?', or '#' after "://".
var reURLUserinfoSpan = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://)[^/\s?#]+@`)

type userinfoSpan struct {
	start    int // index of the first userinfo character (just after "://")
	at       int // index of the '@' delimiting userinfo from host
	userinfo string
}

func userinfoSpans(s string) []userinfoSpan {
	var spans []userinfoSpan
	for _, m := range reURLUserinfoSpan.FindAllStringSubmatchIndex(s, -1) {
		// m: [wholeStart wholeEnd group1Start group1End].
		start := m[2] + (m[3] - m[2])
		at := m[1] - 1
		spans = append(spans, userinfoSpan{start: start, at: at, userinfo: s[start:at]})
	}
	return spans
}

// spliceUserinfo is the R6 splice: the submitted string carries
// exactly one userinfo segment whose value is the sentinel, and
// the stored string carries exactly one userinfo segment. The
// submitted string IS the user's edit; splice the stored
// userinfo into it at the userinfo position. It returns false
// when the shapes do not align — then the submitted string is a
// new literal, never restored.
func spliceUserinfo(stored, submitted string) (string, bool) {
	storedSpans := userinfoSpans(stored)
	if len(storedSpans) != 1 {
		return "", false
	}
	submittedSpans := userinfoSpans(submitted)
	if len(submittedSpans) != 1 {
		return "", false
	}
	sub := submittedSpans[0]
	if sub.userinfo != redact.Marker {
		return "", false
	}
	return submitted[:sub.start] + storedSpans[0].userinfo + submitted[sub.at:], true
}

// adoptNew adopts a brand-new subtree (no stored counterpart).
// An exact sentinel anywhere in it rejects: a copied redacted
// block must have real values typed in, and a renamed secret
// key is a new path.
func adoptNew(submitted any, path string) (any, error) {
	if s, ok := submitted.(string); ok {
		if s == redact.Marker {
			return nil, &sentinelRejection{path: path}
		}
		// A userinfo span that merely contains the marker
		// is rejected here too (same rule as the merge
		// string branch): it must never be stored verbatim.
		for _, sp := range userinfoSpans(s) {
			if sp.userinfo != redact.Marker && strings.Contains(sp.userinfo, redact.Marker) {
				return nil, &sentinelRejection{path: path}
			}
		}
	}
	switch t := submitted.(type) {
	case []any:
		out := make([]any, 0, len(t))
		for i, elem := range t {
			adopted, err := adoptNew(elem, joinIndexPath(path, i))
			if err != nil {
				return nil, err
			}
			out = append(out, adopted)
		}
		return out, nil
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, child := range t {
			adopted, err := adoptNew(child, joinPath(path, k))
			if err != nil {
				return nil, err
			}
			out[k] = adopted
		}
		return out, nil
	default:
		return submitted, nil
	}
}

func joinPath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func joinIndexPath(path string, index int) string {
	return path + "[" + itoa(index) + "]"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// jsonDeepEqual is structural equality for JSON-shaped values,
// key order ignored. Identity-key values are compared by
// content: a freshly parsed submitted document never shares
// references with the stored one.
func jsonDeepEqual(a, b any) bool {
	switch at := a.(type) {
	case map[string]any:
		bt, ok := b.(map[string]any)
		if !ok || len(at) != len(bt) {
			return false
		}
		for k, av := range at {
			bv, ok := bt[k]
			if !ok || !jsonDeepEqual(av, bv) {
				return false
			}
		}
		return true
	case []any:
		bt, ok := b.([]any)
		if !ok || len(at) != len(bt) {
			return false
		}
		for i := range at {
			if !jsonDeepEqual(at[i], bt[i]) {
				return false
			}
		}
		return true
	case json.Number:
		bt, ok := b.(json.Number)
		return ok && string(at) == string(bt)
	default:
		return a == b
	}
}

// checkElementIdentity is the R4 identity guard: an array element
// whose merge restored a secret must still be the same element.
// Every identity key present in the stored element (tag, type,
// username, name, address, port) must be present and unchanged
// in the submitted element. An `address` value carrying a URL
// userinfo span is governed by R6, not by identity, and its
// comparison is skipped.
func checkElementIdentity(storedElement, submittedElement any, path string) error {
	storedObj, ok := storedElement.(map[string]any)
	if !ok {
		return nil
	}
	submittedObj, ok := submittedElement.(map[string]any)
	if !ok {
		return nil
	}
	for _, key := range []string{"tag", "type", "username", "name", "address", "port"} {
		storedValue, present := storedObj[key]
		if !present {
			continue
		}
		submittedValue, present := submittedObj[key]
		if !present {
			return &sentinelRejection{path: path}
		}
		if key == "address" {
			if sv, ok := storedValue.(string); ok {
				if uv, ok := submittedValue.(string); ok {
					if len(userinfoSpans(sv)) > 0 || len(userinfoSpans(uv)) > 0 {
						continue
					}
				}
			}
		}
		if !jsonDeepEqual(storedValue, submittedValue) {
			return &sentinelRejection{path: path}
		}
	}
	return nil
}

// mergeNode merges one submitted value against its stored
// counterpart. storedPresent distinguishes a stored null from
// an absent path. secretPosition is inherited: once inside a
// secret-key subtree (e.g. the `obfs` object, redacted
// wholesale) every nested position counts as secret, so the
// stored subtree is kept or rejected as a unit. It returns the
// merged value and whether any keep (R1 restoration) happened
// inside this subtree. Neither input is mutated.
func mergeNode(stored any, storedPresent bool, submitted any, path string, secretPosition bool) (merged any, restored bool, err error) {
	// Exact sentinel string (whole-value match after parse
	// only). A sentinel at an absent path rejects whatever the
	// key (R2/R3); at a present secret position it keeps the
	// stored value (R1); at a present non-secret position it is
	// an ordinary literal.
	if s, ok := submitted.(string); ok && s == redact.Marker {
		if !storedPresent {
			return nil, false, &sentinelRejection{path: path}
		}
		if secretPosition {
			return stored, true, nil
		}
		return redact.Marker, false, nil
	}
	if !storedPresent {
		adopted, err := adoptNew(submitted, path)
		return adopted, false, err
	}

	if storedObj, ok := stored.(map[string]any); ok {
		if submittedObj, ok := submitted.(map[string]any); ok {
			out := make(map[string]any, len(submittedObj))
			restored := false
			// Keys absent from submitted are deleted (R9);
			// keys only in submitted are new (adoptNew
			// rejects new sentinels).
			for key, child := range submittedObj {
				childSecret := secretPosition || redact.IsSecretKey(key) || isHeaderMapKey(key)
				var childStored any
				childPresent := false
				if v, ok := storedObj[key]; ok {
					childStored, childPresent = v, true
				}
				result, childRestored, err := mergeNode(childStored, childPresent, child, joinPath(path, key), childSecret)
				if err != nil {
					return nil, false, err
				}
				restored = restored || childRestored
				out[key] = result
			}
			return out, restored, nil
		}
	}

	if storedArr, ok := stored.([]any); ok {
		if submittedArr, ok := submitted.([]any); ok {
			out := make([]any, 0, len(submittedArr))
			restored := false
			for i, elem := range submittedArr {
				elemPath := joinIndexPath(path, i)
				if i < len(storedArr) {
					result, elemRestored, err := mergeNode(storedArr[i], true, elem, elemPath, secretPosition)
					if err != nil {
						return nil, false, err
					}
					if elemRestored {
						if err := checkElementIdentity(storedArr[i], elem, elemPath); err != nil {
							return nil, false, err
						}
					}
					restored = restored || elemRestored
					out = append(out, result)
				} else {
					adopted, err := adoptNew(elem, elemPath)
					if err != nil {
						return nil, false, err
					}
					out = append(out, adopted)
				}
			}
			return out, restored, nil
		}
	}

	if storedStr, ok := stored.(string); ok {
		if submittedStr, ok := submitted.(string); ok {
			if submittedStr == storedStr {
				return stored, false, nil
			}
			// Untouched userinfo-redacted string: keep stored
			// verbatim (R6). This IS a restore of the stored
			// userinfo, so it marks restored for the array
			// identity guard.
			if submittedStr == redact.RedactURLUserinfo(storedStr) {
				return stored, true, nil
			}
			// Multi-URL fail-closed: a submitted string
			// carrying a sentinel userinfo segment is
			// rejected unless both strings carry exactly one
			// userinfo span (the single-span splice below).
			// The untouched case is handled above, so
			// reaching here with a sentinel segment means
			// the string was edited; no per-span splicing
			// is attempted, and sentinel segments must
			// never persist as literals.
			storedSpans := userinfoSpans(storedStr)
			submittedSpans := userinfoSpans(submittedStr)
			hasSentinelSpan := false
			for _, sp := range submittedSpans {
				if sp.userinfo == redact.Marker {
					hasSentinelSpan = true
					break
				}
			}
			if hasSentinelSpan && (len(storedSpans) != 1 || len(submittedSpans) != 1) {
				return nil, false, &sentinelRejection{path: path}
			}
			// A span that merely CONTAINS the marker (e.g.
			// "user:<redacted>") is neither the exact
			// sentinel splice nor a clean new literal: it
			// could carry a live secret pasted by mistake
			// past the redaction boundary. Reject it.
			for _, sp := range submittedSpans {
				if sp.userinfo != redact.Marker && strings.Contains(sp.userinfo, redact.Marker) {
					return nil, false, &sentinelRejection{path: path}
				}
			}
			if spliced, ok := spliceUserinfo(storedStr, submittedStr); ok {
				return spliced, true, nil
			}
			// Tampered/removed userinfo, or any other edit:
			// new literal.
			return submitted, false, nil
		}
	}

	// Type change or scalar edit: a submitted value whose JSON
	// kind differs from the stored value's has no stored
	// counterpart for its nested paths, so it is adopted as new:
	// any exact sentinel nested inside it rejects instead of
	// persisting at a secret position. Same-kind scalar edits
	// reach here too and are taken verbatim. Deletion, empty,
	// and null are distinct from keep (R9): they arrive here,
	// never in the sentinel branch.
	if jsonKind(stored) != jsonKind(submitted) {
		adopted, err := adoptNew(submitted, path)
		return adopted, false, err
	}
	return submitted, false, nil
}

func jsonKind(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	case string:
		return "string"
	case bool:
		return "boolean"
	case json.Number:
		return "number"
	default:
		return "unknown"
	}
}

// mergeConfig merges a submitted (redacted, edited) document
// against the stored document, per R1-R9. It never mutates
// either input.
func mergeConfig(stored, submitted any) (any, error) {
	merged, _, err := mergeNode(stored, true, submitted, "", false)
	return merged, err
}

// findSentinelAtSecretPosition is the R8 assertion: the first
// path where the exact sentinel sits at a secret position —
// under a secret key, at any depth inside a secret-key subtree,
// or anywhere inside a header map. It returns "" when no such
// position holds the sentinel. A sentinel at a present
// non-secret position is an ordinary literal and is NOT
// reported.
func findSentinelAtSecretPosition(v any, secretPosition bool, path string) string {
	if s, ok := v.(string); ok {
		if s == redact.Marker && secretPosition {
			return path
		}
		return ""
	}
	switch t := v.(type) {
	case []any:
		for i, elem := range t {
			if found := findSentinelAtSecretPosition(elem, secretPosition, joinIndexPath(path, i)); found != "" {
				return found
			}
		}
	case map[string]any:
		for k, child := range t {
			childSecret := secretPosition || redact.IsSecretKey(k) || isHeaderMapKey(k)
			if found := findSentinelAtSecretPosition(child, childSecret, joinPath(path, k)); found != "" {
				return found
			}
		}
	}
	return ""
}

// checkWhitespaceKeys rejects any object key with leading or
// trailing whitespace in the submitted document, naming the
// path only. Key matching stays lowercase-exact; a padded key
// must never silently become a different key. Go's TrimSpace is
// slightly wider than the JS trim the mock uses (unicode spaces
// vs White_Space + line terminators); the wider set fails
// closed, and the difference is documented in the PR body.
func checkWhitespaceKeys(v any, path string) error {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			if strings.TrimSpace(k) != k {
				return &sentinelRejection{path: joinPath(path, k)}
			}
			if err := checkWhitespaceKeys(child, joinPath(path, k)); err != nil {
				return err
			}
		}
	case []any:
		for i, elem := range t {
			if err := checkWhitespaceKeys(elem, joinIndexPath(path, i)); err != nil {
				return err
			}
		}
	}
	return nil
}
