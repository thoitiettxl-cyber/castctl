// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

import "testing"

func TestParseCookiesFileOrderAndPythonScalars(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "nested cookies dict preserves file order",
			raw:  `{"cookies": {"zebra": "1", "alpha": "2", "mid": "3"}}`,
			want: "zebra=1; alpha=2; mid=3",
		},
		{
			name: "flat dict preserves file order",
			raw:  `{"datr": "D", "hatch_sess": "S", "other": "O"}`,
			want: "datr=D; hatch_sess=S; other=O",
		},
		{
			name: "bool renders True and False like Python",
			raw:  `{"cookies": {"a": true, "b": false}}`,
			want: "a=True; b=False",
		},
		{
			name: "null renders None like Python",
			raw:  `{"cookies": {"a": null}}`,
			want: "a=None",
		},
		{
			name: "numbers render as their literal",
			raw:  `{"cookies": {"a": 42, "b": 1.5}}`,
			want: "a=42; b=1.5",
		},
		{
			name: "non-scalar renders compact JSON preserving inner order",
			raw:  `{"cookies": {"obj": {"y": 1, "x": 2}, "arr": [1, "a", true, null]}}`,
			want: `obj={"y":1,"x":2}; arr=[1,"a",true,null]`,
		},
		{
			name: "duplicate key keeps first position, last value wins",
			raw:  `{"cookies": {"a": "1", "b": "2", "a": "3"}}`,
			want: "a=3; b=2",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseCookies(tc.raw, "cookies.txt")
			if err != nil {
				t.Fatalf("ParseCookies: %v", err)
			}
			if got != tc.want {
				t.Errorf("ParseCookies = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseCookiesDeterministic(t *testing.T) {
	// The join must be identical on every call: Go map iteration
	// is random, so a map-based join would eventually reorder
	// entries. Run with -count=20 as well (see the fix report).
	raw := `{"cookies": {"k1": "v1", "k2": "v2", "k3": "v3", "k4": "v4", "k5": "v5", "k6": "v6"}}`
	want := "k1=v1; k2=v2; k3=v3; k4=v4; k5=v5; k6=v6"
	for i := 0; i < 50; i++ {
		got, err := ParseCookies(raw, "cookies.txt")
		if err != nil {
			t.Fatalf("ParseCookies: %v", err)
		}
		if got != want {
			t.Fatalf("iteration %d: ParseCookies = %q, want %q", i, got, want)
		}
	}
}
