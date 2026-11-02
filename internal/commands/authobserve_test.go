// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/thoitiettxl-cyber/castctl/internal/keeper"
)

// TestBuildObserveOutputStripsTokenisedURL (R-7): the FULL
// printed shape of `auth observe-login` — including the
// login_url field — must carry no token, userinfo, query,
// or fragment from a tokenised operator-supplied URL.
func TestBuildObserveOutputStripsTokenisedURL(t *testing.T) {
	t.Parallel()
	obs := keeper.LoginPageObservation{
		URL:      "https://auth.muse.ai/login?code=SENTINEL-CODE-123#frag",
		Elements: []keeper.ObservedElement{{Tag: "input", Type: "text", Name: "username"}},
	}
	out := buildObserveOutput("muse01", "https://user:SENTINEL-PASS@auth.muse.ai/login?code=SENTINEL-CODE-123#frag", obs)
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"SENTINEL-PASS", "SENTINEL-CODE-123", "user@", "code=", "#frag", "SENTINEL"} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("output %s contains %q", raw, leak)
		}
	}
	if out.LoginURL != "https://auth.muse.ai/login" {
		t.Fatalf("login_url = %q; want stripped https://auth.muse.ai/login", out.LoginURL)
	}
	if out.URL != "https://auth.muse.ai/login" {
		t.Fatalf("url = %q; want stripped https://auth.muse.ai/login", out.URL)
	}
	if out.Profile != "muse01" || len(out.Elements) != 1 {
		t.Fatalf("output = %+v; want profile muse01 with 1 element", out)
	}
}
