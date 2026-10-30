// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package redact

import "testing"

func TestString(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "url userinfo uses angle marker",
			in:   "dial socks5://user:s3cret@proxy.invalid:1080: refused",
			want: "dial socks5://<redacted>@proxy.invalid:1080: refused",
		},
		{
			name: "url user only",
			in:   "get https://bob@host.example/x failed",
			want: "get https://<redacted>@host.example/x failed",
		},
		{
			name: "token query param uses bracket marker and vm_id survives",
			in:   "wss://hatch.metaaivm.com/v1/noise?vm_id=v1&auth_token=tok123 failed",
			want: "wss://hatch.metaaivm.com/v1/noise?vm_id=v1&auth_token=[redacted] failed",
		},
		{
			name: "all token query keys",
			in:   "?token=a&access_token=b&hatch_token=c&session=d",
			want: "?token=[redacted]&access_token=[redacted]&hatch_token=[redacted]&session=[redacted]",
		},
		{
			name: "fragment token",
			in:   "redirect https://host.example/x#auth_token=abcdefgh12345678",
			want: "redirect https://host.example/x#auth_token=[redacted]",
		},
		{
			name: "cookie fragments",
			in:   "cookie: hatch_sess=ABCDEF; datr=XYZ",
			want: "cookie: hatch_sess=[redacted]; datr=[redacted]",
		},
		{
			name: "json cookie",
			in:   `{"hatch_sess":"abcdefgh12345678","other":1}`,
			want: `{"hatch_sess":"[redacted]","other":1}`,
		},
		{
			name: "json session with space",
			in:   `{"session": "abcdefgh12345678"}`,
			want: `{"session": "[redacted]"}`,
		},
		{
			name: "labelled bearer",
			in:   "Authorization: Bearer sekrit-token-here",
			want: "Authorization: Bearer [redacted]",
		},
		{
			name: "bare bearer token like",
			in:   "dial failed: Bearer abcdefgh12345678",
			want: "dial failed: Bearer [redacted]",
		},
		{
			name: "bare bearer lowercase",
			in:   "error: bearer ABCDEFGH12345678 in plain text",
			want: "error: bearer [redacted] in plain text",
		},
		{
			name: "bearer prose untouched",
			in:   "the bearer of bad news",
			want: "the bearer of bad news",
		},
		{
			name: "short bearer value untouched",
			in:   "Bearer short",
			want: "Bearer short",
		},
		{
			name: "already redacted is idempotent",
			in:   "Authorization: Bearer [redacted] and ?token=[redacted]",
			want: "Authorization: Bearer [redacted] and ?token=[redacted]",
		},
		{
			name: "plain error untouched",
			in:   "plain error, no credentials, https://example.com/path?q=1",
			want: "plain error, no credentials, https://example.com/path?q=1",
		},
		{
			name: "plain email untouched",
			in:   "contact bob@example.com for help",
			want: "contact bob@example.com for help",
		},
		{
			name: "multiple urls",
			in:   "a https://user:pass@one.example/x and socks5://bob@two.example:1080 end",
			want: "a https://<redacted>@one.example/x and socks5://<redacted>@two.example:1080 end",
		},
		{
			name: "combined steps",
			in:   "dial https://u:p@h/x?token=t failed: hatch_sess=XYZ; Authorization: Bearer abcdefgh12345678",
			want: "dial https://<redacted>@h/x?token=[redacted] failed: hatch_sess=[redacted]; Authorization: Bearer [redacted]",
		},
		{
			// Matches gateway behaviour: the labelled-Bearer
			// pattern consumes \S+, so a trailing ';' attached
			// to the token is consumed with it.
			name: "labelled bearer consumes trailing semicolon",
			in:   "Authorization: Bearer abcdefgh12345678;",
			want: "Authorization: Bearer [redacted]",
		},
		{
			name: "json password fragment is not key redacted",
			in:   `{"password": "x"}`,
			want: `{"password": "x"}`,
		},
		{
			name: "empty string",
			in:   "",
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := String(tc.in); got != tc.want {
				t.Errorf("String(%q) = %q, want %q", tc.in, got, tc.want)
			}
			// Idempotence: a second pass changes nothing.
			if got2 := String(tc.want); got2 != tc.want {
				t.Errorf("String(String(%q)) = %q, want %q", tc.in, got2, tc.want)
			}
		})
	}
}
