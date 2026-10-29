// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package redact

import "testing"

func TestRedactURLUserinfo(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "userinfo in an arbitrary string value",
			in:   "proxy is socks5://user:s3cret@proxy.invalid:1080, see docs",
			want: "proxy is socks5://<redacted>@proxy.invalid:1080, see docs",
		},
		{
			name: "user only no password",
			in:   "get https://bob@host.example/x failed",
			want: "get https://<redacted>@host.example/x failed",
		},
		{
			name: "password containing a colon",
			in:   "https://user:pa:ss@host.example/x",
			want: "https://<redacted>@host.example/x",
		},
		{
			name: "empty user with password",
			in:   "https://:pass@host.example/x",
			want: "https://<redacted>@host.example/x",
		},
		{
			name: "multiple urls in one string",
			in:   "a https://user:pass@one.example/x and socks5://bob@two.example:1080 end",
			want: "a https://<redacted>@one.example/x and socks5://<redacted>@two.example:1080 end",
		},
		{
			name: "second url embedded in a query string",
			in:   "https://host.example/?next=https://user:pass@other.example/x",
			want: "https://host.example/?next=https://<redacted>@other.example/x",
		},
		{
			name: "url without userinfo unchanged",
			in:   "plain error, no credentials, https://example.com/path?q=1",
			want: "plain error, no credentials, https://example.com/path?q=1",
		},
		{
			name: "url with port but no userinfo unchanged",
			in:   "dial https://example.com:8443/path",
			want: "dial https://example.com:8443/path",
		},
		{
			name: "uppercase scheme preserved",
			in:   "HTTPS://user:pass@host.example/x",
			want: "HTTPS://<redacted>@host.example/x",
		},
		{
			name: "plain email without scheme unchanged",
			in:   "contact bob@example.com for help",
			want: "contact bob@example.com for help",
		},
		{
			name: "bare email like text unchanged",
			in:   "user@example.com",
			want: "user@example.com",
		},
		{
			name: "at sign in url path unchanged",
			in:   "https://example.com/@user/profile",
			want: "https://example.com/@user/profile",
		},
		{
			name: "empty userinfo unchanged",
			in:   "https://@host.example/x",
			want: "https://@host.example/x",
		},
		{
			name: "at sign with no scheme unchanged",
			in:   "a@b and user:pass@host are not urls",
			want: "a@b and user:pass@host are not urls",
		},
		{
			name: "already redacted is idempotent",
			in:   "https://<redacted>@host.example/x",
			want: "https://<redacted>@host.example/x",
		},
		{
			name: "empty string",
			in:   "",
			want: "",
		},
		{
			name: "no url at all unchanged",
			in:   "nothing to redact here",
			want: "nothing to redact here",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := RedactURLUserinfo(tc.in); got != tc.want {
				t.Errorf("RedactURLUserinfo(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
