// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
	"strings"
	"testing"
)

func TestOrderedJSONRoundTrip(t *testing.T) {
	t.Parallel()
	in := `{"b":1,"a":{"z":[1,2.50,true,null,"x"]},"c":[]}`
	v, err := decodeOrderedJSON([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	out, err := encodeOrderedJSONIndent(v, 2)
	if err != nil {
		t.Fatal(err)
	}
	// Order preserved, numbers literal, indent 2.
	s := string(out)
	if strings.Index(s, `"b"`) > strings.Index(s, `"a"`) || strings.Index(s, `"a"`) > strings.Index(s, `"c"`) {
		t.Errorf("order not preserved: %s", s)
	}
	if !strings.Contains(s, "2.50") {
		t.Errorf("number literal lost: %s", s)
	}
	if !strings.Contains(s, "\n  \"b\"") {
		t.Errorf("not indent-2: %s", s)
	}
	// Duplicate keys: last wins, first position kept.
	v2, err := decodeOrderedJSON([]byte(`{"x":1,"y":2,"x":3}`))
	if err != nil {
		t.Fatal(err)
	}
	out2, _ := encodeOrderedJSONIndent(v2, 2)
	if strings.Count(string(out2), `"x"`) != 1 || !strings.Contains(string(out2), `"x": 3`) {
		t.Errorf("duplicate key handling wrong: %s", out2)
	}
}

func TestOrderedJSONInvalid(t *testing.T) {
	t.Parallel()
	for _, in := range []string{`{`, `[1,]`, `{"a":}`, `tru`} {
		if _, err := decodeOrderedJSON([]byte(in)); err == nil {
			t.Errorf("decodeOrderedJSON(%q) = nil error; want error", in)
		}
	}
}
