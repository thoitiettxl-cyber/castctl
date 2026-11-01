// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package webui

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestMarshalOrderedPreservesStoredOrder pins the first-save
// rule: rendering a merged document against the stored bytes
// keeps the stored key order inside every block, overlays
// changed values, appends new keys deterministically, and
// preserves number literals and HTML-significant characters
// byte-for-byte (the intermediate marshal is parsed again by
// ParseSingleConfig, so its order becomes the raw capture).
func TestMarshalOrderedPreservesStoredOrder(t *testing.T) {
	stored := []byte(`{"z": 1, "a": {"y": 2, "x": 3}, "m": [1, 2], "s": "v<>&"}`)
	doc := map[string]any{
		"z": json.Number("9"),
		"a": map[string]any{"x": json.Number("30"), "y": json.Number("20"), "w": json.Number("1")},
		"m": []any{json.Number("1"), json.Number("2"), json.Number("3")},
		"s": "v<>&",
		"b": "new",
	}
	out, err := marshalOrdered(stored, doc)
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	// Stored top-level order, new key appended last.
	for _, pair := range [][2]string{{`"z"`, `"a"`}, {`"a"`, `"m"`}, {`"m"`, `"s"`}, {`"s"`, `"b"`}} {
		if strings.Index(got, pair[0]) > strings.Index(got, pair[1]) {
			t.Fatalf("order wrong in %s", got)
		}
	}
	// Changed values land; within-block order preserved.
	if !strings.Contains(got, `"z":9`) || !strings.Contains(got, `"y":20`) || !strings.Contains(got, `"x":30`) {
		t.Fatalf("values not overlaid in %s", got)
	}
	if strings.Index(got, `"y"`) > strings.Index(got, `"x"`) {
		t.Fatalf("within-block order not preserved in %s", got)
	}
	// New key inside a block appends after stored keys.
	if strings.Index(got, `"x"`) > strings.Index(got, `"w"`) {
		t.Fatalf("new within-block key not appended in %s", got)
	}
	// Appended array element, literal HTML characters.
	if !strings.Contains(got, `"m":[1,2,3]`) {
		t.Fatalf("array not overlaid in %s", got)
	}
	if !strings.Contains(got, `"s":"v<>&"`) {
		t.Fatalf("HTML escaping changed a value in %s", got)
	}
	// The output parses back to the same document.
	var back map[string]any
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatalf("output does not parse: %v", err)
	}
	if back["z"] != json.Number("9") && back["z"] != float64(9) {
		t.Fatalf("round-trip z = %v", back["z"])
	}
}

func TestMarshalOrderedNoStoredRawFallsBack(t *testing.T) {
	out, err := marshalOrdered(nil, map[string]any{"b": json.Number("2"), "a": json.Number("1")})
	if err != nil {
		t.Fatal(err)
	}
	// No stored order: keys render sorted, as json.Marshal
	// would render them.
	if string(out) != `{"a":1,"b":2}` {
		t.Fatalf("fallback order wrong: %s", out)
	}
	var back map[string]any
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatalf("output does not parse: %v", err)
	}
	if len(back) != 2 {
		t.Fatalf("back = %v", back)
	}
}

// TestMarshalOrderedDedupesStoredKeys pins the duplicate-key
// collapse: a stored document with a repeated key renders
// that key once (first position, last value), matching the
// profile decoder's semantics.
func TestMarshalOrderedDedupesStoredKeys(t *testing.T) {
	stored := []byte(`{"a": 1, "b": 2, "a": 3}`)
	doc := map[string]any{"a": json.Number("3"), "b": json.Number("2")}
	out, err := marshalOrdered(stored, doc)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `{"a":3,"b":2}` {
		t.Fatalf("duplicate key rendered twice or out of order: %s", out)
	}
}
