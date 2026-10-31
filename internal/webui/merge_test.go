// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package webui

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// Merge tests port the mock's redact/configStore cases to Go
// (the Go merge is the authority). Fixture values are FAKE
// markers, never real secrets.

func mustDoc(t *testing.T, s string) any {
	t.Helper()
	v, err := decodeGeneric([]byte(s))
	if err != nil {
		t.Fatalf("decodeGeneric: %v", err)
	}
	return v
}

func mergedJSON(t *testing.T, stored, submitted string) (string, error) {
	t.Helper()
	merged, err := mergeConfig(mustDoc(t, stored), mustDoc(t, submitted))
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(merged)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(raw), nil
}

func TestMergeKeepsStoredSecret(t *testing.T) {
	out, err := mergedJSON(t,
		`{"outbounds":[{"tag":"p","type":"trojan","password":"FAKE-SECRET-1"}]}`,
		`{"outbounds":[{"tag":"p","type":"trojan","password":"<redacted>"}]}`)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if !strings.Contains(out, "FAKE-SECRET-1") {
		t.Fatalf("stored secret not kept: %s", out)
	}
	if strings.Contains(out, "<redacted>") {
		t.Fatalf("sentinel persisted: %s", out)
	}
}

func TestMergeRejectsNewSentinel(t *testing.T) {
	// New outbound element carrying a sentinel password: no
	// stored value to keep.
	_, err := mergedJSON(t,
		`{"outbounds":[]}`,
		`{"outbounds":[{"tag":"n","type":"trojan","password":"<redacted>"}]}`)
	var rej *sentinelRejection
	if !errors.As(err, &rej) {
		t.Fatalf("err = %v, want sentinelRejection", err)
	}
	if rej.path != "outbounds[0].password" {
		t.Fatalf("path = %q", rej.path)
	}
}

func TestMergeSentinelAtNonSecretIsLiteral(t *testing.T) {
	out, err := mergedJSON(t,
		`{"profiles":{"p":{"note":"hello"}}}`,
		`{"profiles":{"p":{"note":"<redacted>"}}}`)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	note := decoded["profiles"].(map[string]any)["p"].(map[string]any)["note"]
	if note != "<redacted>" {
		t.Fatalf("non-secret sentinel literal lost: %v", note)
	}
}

func TestMergeTypeChangeAdoptsNew(t *testing.T) {
	// Stored scalar replaced by an object: adopted as new;
	// a sentinel nested inside rejects.
	_, err := mergedJSON(t,
		`{"x":"old"}`,
		`{"x":{"token":"<redacted>"}}`)
	if !errors.As(err, new(*sentinelRejection)) {
		t.Fatalf("err = %v, want sentinelRejection", err)
	}
	out, err := mergedJSON(t,
		`{"x":"old"}`,
		`{"x":{"token":"FAKE-SECRET-2"}}`)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if !strings.Contains(out, "FAKE-SECRET-2") {
		t.Fatalf("adopted value lost: %s", out)
	}
}

func TestMergeArrayIdentityGuard(t *testing.T) {
	// Reorder that shifts a sentinel onto a different element
	// must reject, not restore the wrong secret.
	_, err := mergedJSON(t,
		`{"outbounds":[{"tag":"a","type":"trojan","password":"FAKE-SECRET-A"},{"tag":"b","type":"trojan","password":"FAKE-SECRET-B"}]}`,
		`{"outbounds":[{"tag":"b","type":"trojan","password":"<redacted>"},{"tag":"a","type":"trojan","password":"<redacted>"}]}`)
	if !errors.As(err, new(*sentinelRejection)) {
		t.Fatalf("reorder err = %v, want sentinelRejection", err)
	}
	// Same order keeps both secrets.
	out, err := mergedJSON(t,
		`{"outbounds":[{"tag":"a","type":"trojan","password":"FAKE-SECRET-A"},{"tag":"b","type":"trojan","password":"FAKE-SECRET-B"}]}`,
		`{"outbounds":[{"tag":"a","type":"trojan","password":"<redacted>"},{"tag":"b","type":"trojan","password":"<redacted>"}]}`)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if !strings.Contains(out, "FAKE-SECRET-A") || !strings.Contains(out, "FAKE-SECRET-B") {
		t.Fatalf("secrets not kept: %s", out)
	}
}

func TestMergeHeaderMap(t *testing.T) {
	out, err := mergedJSON(t,
		`{"outbounds":[{"tag":"h","type":"http","headers":{"Authorization":"FAKE-SECRET-H","X-Custom":"keep-me"}}]}`,
		`{"outbounds":[{"tag":"h","type":"http","headers":{"Authorization":"<redacted>","X-Custom":"keep-me"}}]}`)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if !strings.Contains(out, "FAKE-SECRET-H") {
		t.Fatalf("header secret not kept: %s", out)
	}
	// A sentinel header value with no stored counterpart rejects.
	_, err = mergedJSON(t,
		`{"outbounds":[{"tag":"h","type":"http","headers":{}}]}`,
		`{"outbounds":[{"tag":"h","type":"http","headers":{"Authorization":"<redacted>"}}]}`)
	if !errors.As(err, new(*sentinelRejection)) {
		t.Fatalf("err = %v, want sentinelRejection", err)
	}
}

func TestMergeUserinfoSplice(t *testing.T) {
	// Untouched redacted URL keeps the stored userinfo.
	out, err := mergedJSON(t,
		`{"x":"https://user:FAKE-SECRET-PASS@example.com/path"}`,
		`{"x":"https://<redacted>@example.com/path"}`)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if !strings.Contains(out, "user:FAKE-SECRET-PASS@example.com") {
		t.Fatalf("userinfo not restored: %s", out)
	}
	// Edited host splices the stored userinfo into the edit.
	out, err = mergedJSON(t,
		`{"x":"https://user:FAKE-SECRET-PASS@example.com/path"}`,
		`{"x":"https://<redacted>@other.example/path2"}`)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if !strings.Contains(out, "user:FAKE-SECRET-PASS@other.example/path2") {
		t.Fatalf("splice failed: %s", out)
	}
	// Multi-URL string with a sentinel segment fails closed.
	// Edited host in one URL with sentinel segments in both:
	// no per-span splicing is attempted, so it rejects. (The
	// byte-identical redacted form is the untouched case and
	// keeps the stored value; the edit is what fails closed.)
	_, err = mergedJSON(t,
		`{"x":"https://a:FAKE-SECRET-1@h1/ https://b:FAKE-SECRET-2@h2/"}`,
		`{"x":"https://<redacted>@h1/ https://<redacted>@h3/"}`)
	if !errors.As(err, new(*sentinelRejection)) {
		t.Fatalf("multi-URL err = %v, want sentinelRejection", err)
	}
}

func TestMergeDeletionDistinctFromKeep(t *testing.T) {
	out, err := mergedJSON(t,
		`{"a":"keep","b":"drop"}`,
		`{"a":"keep"}`)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if strings.Contains(out, "drop") {
		t.Fatalf("deleted key survived: %s", out)
	}
	out, err = mergedJSON(t,
		`{"a":"keep"}`,
		`{"a":null}`)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if !strings.Contains(out, `"a":null`) {
		t.Fatalf("null not preserved: %s", out)
	}
}

func TestFindSentinelAtSecretPosition(t *testing.T) {
	doc := mustDoc(t, `{"token":"<redacted>","note":"<redacted>","headers":{"X-A":"<redacted>"}}`)
	// Map iteration order is unspecified: either secret path
	// is a correct first hit; the non-secret literal must
	// never be reported.
	if path := findSentinelAtSecretPosition(doc, false, ""); path != "token" && path != "headers.X-A" {
		t.Fatalf("path = %q, want token or headers.X-A", path)
	}
	doc2 := mustDoc(t, `{"note":"<redacted>"}`)
	if path := findSentinelAtSecretPosition(doc2, false, ""); path != "" {
		t.Fatalf("path = %q, want empty (non-secret literal)", path)
	}
}

func TestCheckWhitespaceKeys(t *testing.T) {
	doc := mustDoc(t, `{"profiles":{"p":{"fingerprint":"chrome"}}}`)
	if err := checkWhitespaceKeys(doc, ""); err != nil {
		t.Fatalf("clean doc rejected: %v", err)
	}
	doc = mustDoc(t, `{"profiles":{"p":{" fingerprint":"chrome"}}}`)
	if err := checkWhitespaceKeys(doc, ""); err == nil {
		t.Fatal("padded key accepted")
	}
}
