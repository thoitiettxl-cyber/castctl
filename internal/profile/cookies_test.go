// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package profile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseCookies(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "json nested cookies object preserves order",
			input: `{"cookies": {"hatch_sess": "FAKE-SESS", "datr": "FAKE-DATR", "other": "FAKE-OTHER"}}`,
			want:  "hatch_sess=FAKE-SESS; datr=FAKE-DATR; other=FAKE-OTHER",
		},
		{
			name:  "json flat dict",
			input: `{"hatch_sess": "FAKE-SESS", "datr": "FAKE-DATR"}`,
			want:  "hatch_sess=FAKE-SESS; datr=FAKE-DATR",
		},
		{
			name:  "json empty dict",
			input: `{}`,
			want:  "",
		},
		{
			name:  "json cookies non-dict falls back to top level",
			input: `{"cookies": "FAKE-STR"}`,
			want:  "cookies=FAKE-STR",
		},
		{
			name:  "single line hatch sess",
			input: "hatch_sess=FAKE-SESS; datr=FAKE-DATR\n",
			want:  "hatch_sess=FAKE-SESS; datr=FAKE-DATR",
		},
		{
			name:  "single line with comment lines picks first data line",
			input: "# comment\nhatch_sess=FAKE-SESS; datr=FAKE-DATR\nother=FAKE-X; y=FAKE-Y\n",
			want:  "hatch_sess=FAKE-SESS; datr=FAKE-DATR",
		},
		{
			name:  "hatch marker but no semicolon line joins whitespace",
			input: "hatch_sess=FAKE-SESS\ndatr=FAKE-DATR\n",
			want:  "hatch_sess=FAKE-SESS datr=FAKE-DATR",
		},
		{
			name: "netscape jar",
			input: ".muse.ai\tTRUE\t/\tTRUE\t0\thatch_sess\tFAKE-SESS\n" +
				".muse.ai\tTRUE\t/\tTRUE\t0\tdatr\tFAKE-DATR\n" +
				"#HttpOnly_.muse.ai\tTRUE\t/\tTRUE\t0\tother\tFAKE-OTHER\n",
			want: "hatch_sess=FAKE-SESS; datr=FAKE-DATR",
		},
		{
			name: "netscape jar with CRLF line endings",
			input: ".muse.ai\tTRUE\t/\tTRUE\t0\thatch_sess\tFAKE-SESS\r\n" +
				".muse.ai\tTRUE\t/\tTRUE\t0\tdatr\tFAKE-DATR\r\n",
			want: "hatch_sess=FAKE-SESS; datr=FAKE-DATR",
		},
		{
			name:  "json bool renders like Python f-string",
			input: `{"hatch_sess": true, "datr": false}`,
			want:  "hatch_sess=True; datr=False",
		},
		{
			name: "netscape jar skips short lines",
			input: "short\tline\n" +
				".muse.ai\tTRUE\t/\tTRUE\t0\thatch_sess\tFAKE-SESS\n",
			want: "hatch_sess=FAKE-SESS",
		},
		{
			name:    "unparseable",
			input:   "not cookies at all\n",
			wantErr: true,
		},
		{
			name:    "empty file",
			input:   "",
			wantErr: true,
		},
		{
			name:  "json array containing hatch marker follows hatch branch verbatim",
			input: `["hatch_sess=FAKE"]`,
			want:  `["hatch_sess=FAKE"]`,
		},
		{
			name:    "broken json starting with brace falls through to unparseable",
			input:   "{not json",
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseCookies([]byte(tc.input))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseCookies = %q, nil; want error", got)
				}
				if ExitCode(err) != 2 {
					t.Errorf("ExitCode = %d; want 2", ExitCode(err))
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseCookies = %q, %v; want %q, nil", got, err, tc.want)
			}
			if got != tc.want {
				t.Errorf("ParseCookies = %q; want %q", got, tc.want)
			}
		})
	}
}

func TestLoadCookiesFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "cookies.txt")
	if err := os.WriteFile(path, []byte("hatch_sess=FAKE-SESS; datr=FAKE-DATR\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadCookiesFile(path)
	if err != nil || got != "hatch_sess=FAKE-SESS; datr=FAKE-DATR" {
		t.Errorf("LoadCookiesFile = %q, %v", got, err)
	}
	if _, err := LoadCookiesFile(filepath.Join(dir, "missing.txt")); err == nil {
		t.Error("LoadCookiesFile(missing) = nil error; want error")
	}
}
