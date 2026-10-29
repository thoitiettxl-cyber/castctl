package profile

import (
	"encoding/json"
	"strings"
	"testing"
)

const fakeSecret = "FAKE-SECRET-VALUE-12345"

func TestRedactOutboundJSON(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		input string
		// keys that must survive with their values
		keep map[string]string
	}{
		{
			name:  "socks password",
			input: `{"type":"socks","tag":"proxy-sg","server":"127.0.0.1","server_port":1080,"username":"FAKE-USER","password":"` + fakeSecret + `"}`,
			keep:  map[string]string{"server": "127.0.0.1", "username": "FAKE-USER"},
		},
		{
			name:  "wireguard endpoint keys",
			input: `{"type":"wireguard","tag":"wg-home","address":["10.0.0.2/32"],"private_key":"` + fakeSecret + `","peers":[{"address":"203.0.113.10","port":51820,"public_key":"FAKE-PUBKEY","pre_shared_key":"FAKE-PSK","allowed_ips":["0.0.0.0/0"]}]}`,
			keep:  map[string]string{"address": "203.0.113.10"},
		},
		{
			name:  "vless uuid short_id reality",
			input: `{"type":"vless","tag":"v","server":"203.0.113.20","server_port":443,"uuid":"` + fakeSecret + `","tls":{"enabled":true,"reality":{"enabled":true,"public_key":"FAKE-REALITY-PUB","short_id":"FAKE-SHORT-ID"}}}`,
			keep:  map[string]string{"server": "203.0.113.20"},
		},
		{
			name:  "hysteria2 obfs object redacted whole",
			input: `{"type":"hysteria2","tag":"h","server":"203.0.113.21","server_port":443,"password":"` + fakeSecret + `","obfs":{"type":"salamander","password":"FAKE-OBFS-PW"}}`,
			keep:  map[string]string{"server": "203.0.113.21"},
		},
		{
			name:  "users array passwords",
			input: `{"type":"http","tag":"h","server":"127.0.0.1","server_port":8080,"users":[{"username":"FAKE-USER","password":"` + fakeSecret + `"}]}`,
			keep:  map[string]string{"username": "FAKE-USER"},
		},
		{
			name:  "token certificate key fields",
			input: `{"type":"trojan","tag":"t","server":"203.0.113.22","server_port":443,"password":"` + fakeSecret + `","token":"FAKE-TOKEN","certificate":"FAKE-CERT","key":"FAKE-KEY"}`,
			keep:  map[string]string{"server": "203.0.113.22"},
		},
		{
			name:  "openconnect cookie and secret",
			input: `{"type":"openconnect","tag":"oc","server":"203.0.113.23","cookie":"` + fakeSecret + `","token":{"mode":"totp","secret":"FAKE-TOTP-SECRET"}}`,
			keep:  map[string]string{"server": "203.0.113.23"},
		},
		{
			name:  "snell psk",
			input: `{"type":"snell","tag":"s","server":"203.0.113.24","server_port":443,"psk":"FAKE-SNELL-PSK","version":"4"}`,
			keep:  map[string]string{"server": "203.0.113.24"},
		},
		{
			name:  "ssh private key passphrase",
			input: `{"type":"ssh","tag":"ssh","server":"203.0.113.25","server_port":22,"user":"FAKE-USER","private_key":"FAKE-SSH-KEY","private_key_passphrase":"FAKE-SSH-PASSPHRASE"}`,
			keep:  map[string]string{"server": "203.0.113.25"},
		},
		{
			name:  "hysteria auth fields",
			input: `{"type":"hysteria","tag":"hy","server":"203.0.113.26","server_port":443,"auth":"FAKE-HY-AUTH","auth_str":"FAKE-HY-AUTH-STR"}`,
			keep:  map[string]string{"server": "203.0.113.26"},
		},
		{
			name:  "tailscale auth key",
			input: `{"type":"tailscale","tag":"ts","auth_key":"FAKE-TS-AUTH-KEY"}`,
			keep:  map[string]string{"type": "tailscale"},
		},
		{
			name:  "no secrets untouched except formatting",
			input: `{"type":"direct","tag":"direct"}`,
			keep:  map[string]string{"type": "direct"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			out, err := RedactOutboundJSON([]byte(tc.input))
			if err != nil {
				t.Fatal(err)
			}
			s := string(out)
			for _, secret := range []string{fakeSecret, "FAKE-PUBKEY", "FAKE-PSK", "FAKE-REALITY-PUB", "FAKE-SHORT-ID", "FAKE-OBFS-PW", "FAKE-TOKEN", "FAKE-CERT", "FAKE-KEY", "FAKE-TOTP-SECRET", "FAKE-SNELL-PSK", "FAKE-SSH-KEY", "FAKE-SSH-PASSPHRASE", "FAKE-HY-AUTH", "FAKE-HY-AUTH-STR", "FAKE-TS-AUTH-KEY"} {
				if strings.Contains(s, secret) {
					t.Errorf("redacted output contains secret %q: %s", secret, s)
				}
			}
			var decoded map[string]any
			if err := json.Unmarshal(out, &decoded); err != nil {
				t.Fatalf("redacted output is not JSON: %v: %s", err, s)
			}
			// At least one redaction marker present when input had secrets.
			if tc.name != "no secrets untouched except formatting" && !strings.Contains(s, `"<redacted>"`) {
				t.Errorf("redacted output has no <redacted> marker: %s", s)
			}
			// Indent 2.
			if !strings.Contains(s, "\n  \"") {
				t.Errorf("redacted output is not indent-2: %s", s)
			}
		})
	}
}

func TestRedactJSONPreservesFieldOrder(t *testing.T) {
	t.Parallel()
	out, err := RedactJSON([]byte(`{"zebra":"1","password":"` + fakeSecret + `","apple":"2"}`))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	zi, pi, ai := strings.Index(s, "zebra"), strings.Index(s, "password"), strings.Index(s, "apple")
	if !(zi < pi && pi < ai) {
		t.Errorf("field order not preserved: %s", s)
	}
	if strings.Contains(s, fakeSecret) {
		t.Errorf("output contains secret: %s", s)
	}
	// Numbers keep their literal form.
	out, err = RedactJSON([]byte(`{"server_port":1080,"ratio":1.50}`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "1.50") {
		t.Errorf("number literal not preserved: %s", out)
	}
}

func TestRedactJSONInvalidInput(t *testing.T) {
	t.Parallel()
	if _, err := RedactJSON([]byte(`{oops`)); err == nil {
		t.Error("RedactJSON(invalid) = nil error; want error")
	}
}

func TestRedactProfile(t *testing.T) {
	t.Parallel()
	p := &Profile{
		Name:                 "muse01",
		CookiesFile:          "/base/profiles/muse01/cookies.txt",
		VMID:                 "FAKE-VMID",
		NodeID:               "0123456789abcdef",
		AutoApprove:          "off",
		AutoAllowOnce:        false,
		SubscriptionActionID: "FAKE-ACTION-ID",
		Outbound: OutboundRef{
			Kind: OutboundInline,
			Tag:  "inline-1",
			Type: "socks",
			Raw:  []byte(`{"type":"socks","tag":"inline-1","server":"127.0.0.1","server_port":1080,"password":"` + fakeSecret + `"}`),
		},
	}
	out, err := RedactProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, fakeSecret) {
		t.Errorf("RedactProfile output contains secret: %s", s)
	}
	if !strings.Contains(s, `"password": "<redacted>"`) {
		t.Errorf("RedactProfile output missing redacted password: %s", s)
	}
	// Identifiers must be redacted too (review finding B1).
	for _, id := range []string{"FAKE-VMID", "0123456789abcdef", "FAKE-ACTION-ID"} {
		if strings.Contains(s, id) {
			t.Errorf("RedactProfile output contains identifier %q: %s", id, s)
		}
	}
	for _, field := range []string{`"vm_id": "<redacted>"`, `"node_id": "<redacted>"`, `"subscription_action_id": "<redacted>"`} {
		if !strings.Contains(s, field) {
			t.Errorf("RedactProfile output missing %s: %s", field, s)
		}
	}
	if !strings.Contains(s, "muse01") || !strings.Contains(s, "/base/profiles/muse01/cookies.txt") {
		t.Errorf("RedactProfile output missing identity/paths: %s", s)
	}
	var decoded map[string]any
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("RedactProfile output is not JSON: %v", err)
	}

	// Tag reference: tag is not a secret and survives.
	p2 := &Profile{Name: "p", CookiesFile: "/base/cookies.txt", AutoApprove: "off",
		Outbound: OutboundRef{Kind: OutboundTag, Tag: "proxy-sg", Type: "socks", From: "outbound"}}
	out2, err := RedactProfile(p2)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out2), `"outbound": "proxy-sg"`) {
		t.Errorf("tag-reference profile output = %s; want outbound tag preserved", out2)
	}

	// Direct: no outbound key.
	p3 := &Profile{Name: "p", CookiesFile: "/base/cookies.txt", AutoApprove: "off",
		Outbound: OutboundRef{Kind: OutboundDirect, Type: "direct"}}
	out3, err := RedactProfile(p3)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out3), "outbound") {
		t.Errorf("direct profile output should omit outbound: %s", out3)
	}
}
