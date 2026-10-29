// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Distinctive FAKE value used for the never-echo checks: it must never
// appear in stdout or stderr, on success or on failure.
const importSecretMarker = "FAKESECRETVALUE9z"

const importDefaultConfig = `{"default_profile":"default","profiles":{"default":{}}}`

// importHome writes only a config file into a temp dir: no cookies
// file, no .bak, so tests can assert exactly what import creates.
func importHome(t *testing.T, configJSON string) (string, string) {
	t.Helper()
	home := t.TempDir()
	configFile := filepath.Join(home, "config.json")
	if err := os.WriteFile(configFile, []byte(configJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	return home, configFile
}

// runImport runs `muse-cli --config <cfg> auth import ...` with stdin
// and an injected getenv map. It returns the exit code and the
// captured stdout/stderr.
func runImport(t *testing.T, cfg string, stdin io.Reader, getenv map[string]string, args ...string) (int, string, string) {
	t.Helper()
	out, errb := &bytes.Buffer{}, &bytes.Buffer{}
	env := &Env{Stdout: out, Stderr: errb, Stdin: stdin, Getenv: mapGetenv(getenv)}
	full := append([]string{"--config", cfg, "auth", "import"}, args...)
	code := Run(context.Background(), full, env)
	return code, out.String(), errb.String()
}

func importResult(t *testing.T, out string) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("success output is not JSON: %v (out=%q)", err, out)
	}
	return v
}

func importFileBytes(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func importFileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode().Perm()
}

func assertImportAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("%s exists (err=%v), want absent", path, err)
	}
}

func assertNoSecret(t *testing.T, out, errb string) {
	t.Helper()
	if strings.Contains(out, importSecretMarker) || strings.Contains(errb, importSecretMarker) {
		t.Errorf("output echoes input secret: stdout=%q stderr=%q", out, errb)
	}
}

// checkImportSuccess asserts the exit-0 JSON shape and the stored
// file bytes/mode for a fresh home (no previous cookies file).
func checkImportSuccess(t *testing.T, home, cfg, input, wantStored string) {
	t.Helper()
	code, out, errb := runImport(t, cfg, strings.NewReader(input), nil)
	if code != 0 {
		t.Fatalf("auth import: code=%d, want 0 (stderr=%q)", code, errb)
	}
	res := importResult(t, out)
	dest := filepath.Join(home, "cookies.txt")
	if res["ok"] != true || res["profile"] != "default" || res["cookies_file"] != dest || res["backup"] != false {
		t.Errorf("success JSON=%v, want ok/profile/cookies_file/backup=false for %s", res, dest)
	}
	if got := string(importFileBytes(t, dest)); got != wantStored {
		t.Errorf("stored bytes=%q, want %q", got, wantStored)
	}
	if mode := importFileMode(t, dest); mode != 0o600 {
		t.Errorf("cookies mode=%o, want 0600", mode)
	}
	assertImportAbsent(t, dest+".bak")
	assertNoSecret(t, out, errb)
}

// checkImportFailure asserts exit 2 with nothing written to a fresh home.
func checkImportFailure(t *testing.T, home, cfg, input string) {
	t.Helper()
	code, out, errb := runImport(t, cfg, strings.NewReader(input), nil)
	if code != 2 {
		t.Fatalf("auth import: code=%d, want 2 (stdout=%q stderr=%q)", code, out, errb)
	}
	dest := filepath.Join(home, "cookies.txt")
	assertImportAbsent(t, dest)
	assertImportAbsent(t, dest+".bak")
	assertNoSecret(t, out, errb)
}

func TestAuthImportOneLinePositive(t *testing.T) {
	cases := []struct {
		name       string
		input      string
		wantStored string
	}{
		{"basic", "hatch_sess=FAKE; datr=FAKE; other=FAKE", "hatch_sess=FAKE; datr=FAKE; other=FAKE\n"},
		{"single no semicolon", "hatch_sess=FAKE", "hatch_sess=FAKE\n"},
		{"tight separators", "hatch_sess=FAKE;datr=FAKE", "hatch_sess=FAKE;datr=FAKE\n"},
		{"surrounding blank lines", "\n\n  hatch_sess=FAKE; datr=FAKE  \n\n", "hatch_sess=FAKE; datr=FAKE\n"},
		// First qualifying line wins; the whole paste is stored
		// verbatim (D1), so a later read re-parses the same way.
		{"multi-line first wins", "hatch_sess=FAKE; datr=FAKE\nsecond=line; x=1\n", "hatch_sess=FAKE; datr=FAKE\nsecond=line; x=1\n"},
		{"value with equals", "hatch_sess=FAKE==; other=1", "hatch_sess=FAKE==; other=1\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home, cfg := importHome(t, importDefaultConfig)
			checkImportSuccess(t, home, cfg, tc.input, tc.wantStored)
		})
	}
}

func TestAuthImportOneLineNegative(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"datr only", "datr=FAKE; other=1"},
		{"empty hatch value", "hatch_sess=; other=1"},
		{"whitespace hatch value", "hatch_sess= ; other=1"},
		{"substring name", "xhatch_sess=FAKE; other=1"},
		{"suffixed name", "hatch_sess2=FAKE; other=1"},
		{"wrong case", "Hatch_Sess=FAKE; other=1"},
		{"hatch only in a value", "other=hatch_sess; x=1"},
		{"random text", "hello world"},
		{"no pairs", "just some words here"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home, cfg := importHome(t, importDefaultConfig)
			checkImportFailure(t, home, cfg, tc.input)
		})
	}
}

func TestAuthImportJarPositive(t *testing.T) {
	jar := func(rows ...string) string {
		return strings.Join(rows, "\n") + "\n"
	}
	row := func(name, value string) string {
		return ".muse.ai\tTRUE\t/\tTRUE\t0\t" + name + "\t" + value
	}
	cases := []struct {
		name       string
		input      string
		wantStored string
	}{
		{"with header", jar("# Netscape HTTP Cookie File", row("hatch_sess", "FAKE"), row("datr", "FAKE")), jar("# Netscape HTTP Cookie File", row("hatch_sess", "FAKE"), row("datr", "FAKE"))},
		{"no header", jar(row("hatch_sess", "FAKE")), jar(row("hatch_sess", "FAKE"))},
		{"duplicate rows preserved", jar(row("hatch_sess", "V1"), row("hatch_sess", "V2")), jar(row("hatch_sess", "V1"), row("hatch_sess", "V2"))},
		{"expired row ignored", jar(".muse.ai\tTRUE\t/\tTRUE\t1\thatch_sess\tOLD"), jar(".muse.ai\tTRUE\t/\tTRUE\t1\thatch_sess\tOLD")},
		{"extra columns ignored", jar(".muse.ai\tTRUE\t/\tTRUE\t0\thatch_sess\tFAKE\textra"), jar(".muse.ai\tTRUE\t/\tTRUE\t0\thatch_sess\tFAKE\textra")},
		{"other domain kept", jar("example.com\tFALSE\t/\tFALSE\t0\thatch_sess\tFAKE"), jar("example.com\tFALSE\t/\tFALSE\t0\thatch_sess\tFAKE")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home, cfg := importHome(t, importDefaultConfig)
			checkImportSuccess(t, home, cfg, tc.input, tc.wantStored)
		})
	}
}

func TestAuthImportJarNegative(t *testing.T) {
	row := func(name, value string) string {
		return ".muse.ai\tTRUE\t/\tTRUE\t0\t" + name + "\t" + value
	}
	cases := []struct {
		name  string
		input string
	}{
		{"space separated", ".muse.ai TRUE / TRUE 0 hatch_sess FAKE\n"},
		{"short lines only", "# comment\nfoo\tbar\n"},
		{"httponly hatch dropped", "#HttpOnly_.muse.ai\tTRUE\t/\tTRUE\t0\thatch_sess\tFAKE\n" + row("datr", "FAKE") + "\n"},
		{"empty hatch mid-file", row("hatch_sess", "") + "\n" + row("datr", "FAKE") + "\n"},
		{"empty hatch at EOF", row("hatch_sess", "") + "\n"},
		{"datr only", row("datr", "FAKE") + "\n"},
		{"no hatch row", row("other", "FAKE") + "\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home, cfg := importHome(t, importDefaultConfig)
			checkImportFailure(t, home, cfg, tc.input)
		})
	}
}

func TestAuthImportJSONPositive(t *testing.T) {
	cases := []struct {
		name       string
		input      string
		wantStored string
	}{
		{"nested", `{"cookies": {"hatch_sess": "FAKE", "datr": "FAKE"}}`, "{\"cookies\": {\"hatch_sess\": \"FAKE\", \"datr\": \"FAKE\"}}\n"},
		{"flat", `{"hatch_sess": "FAKE", "other": "FAKE"}`, "{\"hatch_sess\": \"FAKE\", \"other\": \"FAKE\"}\n"},
		{"nested non-scalar sibling", `{"cookies": {"hatch_sess": "FAKE", "obj": {"y": 1}}}`, "{\"cookies\": {\"hatch_sess\": \"FAKE\", \"obj\": {\"y\": 1}}}\n"},
		{"numeric hatch value", `{"hatch_sess": 42}`, "{\"hatch_sess\": 42}\n"},
		{"bool hatch value", `{"hatch_sess": true}`, "{\"hatch_sess\": true}\n"},
		{"trailing whitespace", "  {\"hatch_sess\": \"FAKE\"}  \n", "{\"hatch_sess\": \"FAKE\"}\n"},
		{"cookies non-object with top hatch", `{"cookies": "abc", "hatch_sess": "FAKE"}`, "{\"cookies\": \"abc\", \"hatch_sess\": \"FAKE\"}\n"},
		{"value with semicolon", `{"hatch_sess": "a;b=c"}`, "{\"hatch_sess\": \"a;b=c\"}\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home, cfg := importHome(t, importDefaultConfig)
			checkImportSuccess(t, home, cfg, tc.input, tc.wantStored)
		})
	}
}

func TestAuthImportJSONNegative(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"empty object", `{}`},
		{"empty nested", `{"cookies": {}}`},
		{"no hatch", `{"other": "FAKE"}`},
		{"empty hatch string", `{"hatch_sess": ""}`},
		{"whitespace hatch string", `{"hatch_sess": "  "}`},
		{"null hatch", `{"hatch_sess": null}`},
		{"hatch only in a value", `{"note": "hatch_sess"}`},
		{"hatch only in a nested key", `{"cookies": {"note": "hatch_sess"}}`},
		{"invalid JSON no jar", `{not json`},
		{"trailing data no hatch", `{"other": 1} xyz`},
		{"nested non-object only", `{"cookies": "abc"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home, cfg := importHome(t, importDefaultConfig)
			checkImportFailure(t, home, cfg, tc.input)
		})
	}
}

func TestAuthImportEmptyAndWhitespaceStdin(t *testing.T) {
	for _, input := range []string{"", "   ", "\n\n\t \n"} {
		home, cfg := importHome(t, importDefaultConfig)
		checkImportFailure(t, home, cfg, input)
	}
}

func TestAuthImportInvalidUTF8(t *testing.T) {
	home, cfg := importHome(t, importDefaultConfig)
	raw := []byte("hatch_sess=FAKE\xff; datr=FAKE\n")
	code, out, errb := runImport(t, cfg, bytes.NewReader(raw), nil)
	if code != 2 {
		t.Fatalf("invalid UTF-8: code=%d, want 2 (stdout=%q stderr=%q)", code, out, errb)
	}
	assertImportAbsent(t, filepath.Join(home, "cookies.txt"))
	assertImportAbsent(t, filepath.Join(home, "cookies.txt.bak"))
}

func TestAuthImportLineEndings(t *testing.T) {
	// CRLF one-line: stored with \n only.
	home, cfg := importHome(t, importDefaultConfig)
	checkImportSuccess(t, home, cfg, "hatch_sess=FAKE; datr=FAKE\r\n", "hatch_sess=FAKE; datr=FAKE\n")
	// CRLF jar: no \r survives in the stored value.
	home, cfg = importHome(t, importDefaultConfig)
	jarCRLF := "# Netscape HTTP Cookie File\r\n.muse.ai\tTRUE\t/\tTRUE\t0\thatch_sess\tFAKE\r\n.muse.ai\tTRUE\t/\tTRUE\t0\tdatr\tFAKE\r\n"
	checkImportSuccess(t, home, cfg, jarCRLF, "# Netscape HTTP Cookie File\n.muse.ai\tTRUE\t/\tTRUE\t0\thatch_sess\tFAKE\n.muse.ai\tTRUE\t/\tTRUE\t0\tdatr\tFAKE\n")
	// CR-only jar: \r is a line separator at the import boundary.
	home, cfg = importHome(t, importDefaultConfig)
	jarCR := ".muse.ai\tTRUE\t/\tTRUE\t0\thatch_sess\tV1\r.muse.ai\tTRUE\t/\tTRUE\t0\tdatr\tV2\r"
	checkImportSuccess(t, home, cfg, jarCR, ".muse.ai\tTRUE\t/\tTRUE\t0\thatch_sess\tV1\n.muse.ai\tTRUE\t/\tTRUE\t0\tdatr\tV2\n")
	// CR-only one-line.
	home, cfg = importHome(t, importDefaultConfig)
	checkImportSuccess(t, home, cfg, "hatch_sess=FAKE; datr=FAKE\rother=1; x=2\r", "hatch_sess=FAKE; datr=FAKE\nother=1; x=2\n")
}

// TestAuthImportDifferentialFixtures replays the measured Python
// fixtures from python-compat §7 (freshly authored, not copied from
// Python tests — none exist for load_cookies). Each case names the
// §7 fixture it replays.
func TestAuthImportDifferentialFixtures(t *testing.T) {
	row := func(name, value string) string {
		return ".muse.ai\tTRUE\t/\tTRUE\t0\t" + name + "\t" + value
	}
	cases := []struct {
		name       string
		input      string
		wantCode   int
		wantStored string // checked only when wantCode == 0
	}{
		// §7 crlf_jar: Python strips \r; the import boundary does too.
		{"crlf_jar", "# Netscape\r\n" + row("hatch_sess", "FAKE") + "\r\n" + row("datr", "D2") + "\r\n", 0, "# Netscape\n" + row("hatch_sess", "FAKE") + "\n" + row("datr", "D2") + "\n"},
		// §7 jar_cr_only: Python splitlines splits lone \r.
		{"jar_cr_only", row("hatch_sess", "V1") + "\r" + row("datr", "V2") + "\r", 0, row("hatch_sess", "V1") + "\n" + row("datr", "V2") + "\n"},
		// §7 bom_json: BOM defeats the "{" check; jar branch fails.
		{"bom_json", "\ufeff{\"hatch_sess\": \"FAKE\"}", 2, ""},
		// §7 bom_curl: BOM-prefixed curl line parses, BOM kept verbatim.
		{"bom_curl", "\ufeffhatch_sess=FAKE; datr=FAKE", 0, "\ufeffhatch_sess=FAKE; datr=FAKE\n"},
		// §7 json_cookies_str: {"cookies": "abc"} renders cookies=abc.
		{"json_cookies_str_no_hatch", `{"cookies": "abc"}`, 2, ""},
		{"json_cookies_str_with_hatch", `{"cookies": "abc", "hatch_sess": "FAKE"}`, 0, "{\"cookies\": \"abc\", \"hatch_sess\": \"FAKE\"}\n"},
		// §7 empty_json_then_jar: invalid JSON falls through to the jar.
		{"empty_json_then_jar", "{}\n" + row("hatch_sess", "V") + "\n", 0, "{}\n" + row("hatch_sess", "V") + "\n"},
		// §7 httponly_jar: #HttpOnly_ lines are dropped by the jar scan.
		{"httponly_jar", "#HttpOnly_.muse.ai\tTRUE\t/\tTRUE\t0\thatch_sess\tFAKE\n" + row("datr", "D2") + "\n", 2, ""},
		// §7 jar_dup: duplicates preserved in file order.
		{"jar_dup", row("hatch_sess", "V1") + "\n" + row("hatch_sess", "V2") + "\n", 0, row("hatch_sess", "V1") + "\n" + row("hatch_sess", "V2") + "\n"},
		// §7 jar_empty_value (EOF): the whole-file strip eats the row.
		{"jar_empty_value_eof", row("hatch_sess", "") + "\n", 2, ""},
		// §7 jar_empty_value_mid: empty value yields hatch_sess=.
		{"jar_empty_value_mid", row("hatch_sess", "") + "\n" + row("other", "V") + "\n", 2, ""},
		// §7 jar_expired: expiry is never read.
		{"jar_expired", ".muse.ai\tTRUE\t/\tTRUE\t1\thatch_sess\tOLD\n", 0, ".muse.ai\tTRUE\t/\tTRUE\t1\thatch_sess\tOLD\n"},
		// §7 case.txt: names are case-sensitive.
		{"case_sensitive", "Hatch_Sess=FAKE; datr=FAKE", 2, ""},
		// §7 single_no_semi: lone hatch_sess=x loads via the fallback.
		{"single_no_semi", "hatch_sess=FAKE\n", 0, "hatch_sess=FAKE\n"},
		// §7 comment_only_hatch: the fallback flattens comment text.
		{"comment_only_hatch", "# hatch_sess=FAKE; y=1\nfoo\tbar\n", 0, "# hatch_sess=FAKE; y=1\nfoo\tbar\n"},
		// §7 numbers: Python str() normalises; import stores verbatim.
		{"json_numbers", `{"hatch_sess": 1.50, "b": 1e20}`, 0, "{\"hatch_sess\": 1.50, \"b\": 1e20}\n"},
		// §7 nested values: Python renders repr; import stores verbatim.
		{"json_nested", `{"cookies": {"obj": {"y": 1, "x": 2}, "hatch_sess": "FAKE"}}`, 0, "{\"cookies\": {\"obj\": {\"y\": 1, \"x\": 2}, \"hatch_sess\": \"FAKE\"}}\n"},
		// §7 json_dup: duplicate keys collapse, last wins (verbatim store
		// keeps both spellings; the next ParseCookies read collapses).
		{"json_dup", `{"cookies": {"a": "1", "hatch_sess": "V1", "hatch_sess": "V2"}}`, 0, "{\"cookies\": {\"a\": \"1\", \"hatch_sess\": \"V1\", \"hatch_sess\": \"V2\"}}\n"},
		// §7 curl_first_line: the first qualifying line wins even
		// without hatch_sess on it.
		{"curl_first_line_no_hatch", "a=1; b=2\nhatch_sess=FAKE; y=3\n", 2, ""},
		// §7 jar_8col: extra columns ignored.
		{"jar_8col", ".muse.ai\tTRUE\t/\tTRUE\t0\thatch_sess\tFAKE\textra\n", 0, ".muse.ai\tTRUE\t/\tTRUE\t0\thatch_sess\tFAKE\textra\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home, cfg := importHome(t, importDefaultConfig)
			if tc.wantCode == 0 {
				checkImportSuccess(t, home, cfg, tc.input, tc.wantStored)
			} else {
				checkImportFailure(t, home, cfg, tc.input)
			}
		})
	}
}

func TestAuthImportNeverEcho(t *testing.T) {
	// Success path: the distinctive value must not appear anywhere.
	_, cfg := importHome(t, importDefaultConfig)
	input := "hatch_sess=" + importSecretMarker + "; datr=FAKE"
	code, out, errb := runImport(t, cfg, strings.NewReader(input), nil)
	if code != 0 {
		t.Fatalf("code=%d, want 0 (stderr=%q)", code, errb)
	}
	assertNoSecret(t, out, errb)
	// Failure path: same value in a rejected input.
	_, cfg = importHome(t, importDefaultConfig)
	code, out, errb = runImport(t, cfg, strings.NewReader("other="+importSecretMarker), nil)
	if code != 2 {
		t.Fatalf("code=%d, want 2", code)
	}
	assertNoSecret(t, out, errb)
}

func TestAuthImportNoWriteOnFailure(t *testing.T) {
	home, cfg := importHome(t, importDefaultConfig)
	dest := filepath.Join(home, "cookies.txt")
	old := []byte("hatch_sess=OLD; datr=OLD\n")
	if err := os.WriteFile(dest, old, 0o600); err != nil {
		t.Fatal(err)
	}
	bak := []byte("previous backup\n")
	if err := os.WriteFile(dest+".bak", bak, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{"", "datr=FAKE", "{}", "random text", "hatch_sess="} {
		code, _, errb := runImport(t, cfg, strings.NewReader(input), nil)
		if code != 2 {
			t.Fatalf("input %q: code=%d, want 2 (stderr=%q)", input, code, errb)
		}
		if got := importFileBytes(t, dest); string(got) != string(old) {
			t.Fatalf("input %q: cookies changed to %q", input, got)
		}
		if got := importFileBytes(t, dest+".bak"); string(got) != string(bak) {
			t.Fatalf("input %q: .bak changed to %q", input, got)
		}
		if mode := importFileMode(t, dest); mode != 0o600 {
			t.Fatalf("input %q: cookies mode=%o", input, mode)
		}
	}
}

func TestAuthImportBackupOnReplace(t *testing.T) {
	home, cfg := importHome(t, importDefaultConfig)
	dest := filepath.Join(home, "cookies.txt")
	old := []byte("hatch_sess=OLD; datr=OLD\n")
	if err := os.WriteFile(dest, old, 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errb := runImport(t, cfg, strings.NewReader("hatch_sess=NEW; datr=NEW"), nil)
	if code != 0 {
		t.Fatalf("code=%d, want 0 (stderr=%q)", code, errb)
	}
	res := importResult(t, out)
	if res["backup"] != true {
		t.Errorf("success JSON=%v, want backup=true", res)
	}
	if got := importFileBytes(t, dest+".bak"); string(got) != string(old) {
		t.Errorf(".bak=%q, want previous bytes %q", got, old)
	}
	if mode := importFileMode(t, dest+".bak"); mode != 0o600 {
		t.Errorf(".bak mode=%o, want 0600", mode)
	}
	if got := importFileBytes(t, dest); string(got) != "hatch_sess=NEW; datr=NEW\n" {
		t.Errorf("cookies=%q", got)
	}
}

func TestAuthImportProfileResolution(t *testing.T) {
	t.Run("named flag fresh", func(t *testing.T) {
		home, cfg := importHome(t, `{"default_profile":"default","profiles":{"default":{},"work":{}}}`)
		out, errb := &bytes.Buffer{}, &bytes.Buffer{}
		env := &Env{Stdout: out, Stderr: errb, Stdin: strings.NewReader("hatch_sess=FAKE"), Getenv: mapGetenv(nil)}
		code := Run(context.Background(), []string{"--config", cfg, "--profile", "work", "auth", "import"}, env)
		if code != 0 {
			t.Fatalf("code=%d, want 0 (stderr=%q)", code, errb.String())
		}
		res := importResult(t, out.String())
		dest := filepath.Join(home, "profiles", "work", "cookies.txt")
		if res["profile"] != "work" || res["cookies_file"] != dest {
			t.Errorf("JSON=%v, want profile work at %s", res, dest)
		}
		if got := importFileBytes(t, dest); string(got) != "hatch_sess=FAKE\n" {
			t.Errorf("cookies=%q", got)
		}
		assertImportAbsent(t, filepath.Join(home, "cookies.txt"))
	})

	t.Run("env profile", func(t *testing.T) {
		home, cfg := importHome(t, `{"default_profile":"default","profiles":{"default":{},"work":{}}}`)
		code, out, errb := runImport(t, cfg, strings.NewReader("hatch_sess=FAKE"), map[string]string{"MUSE_CLI_PROFILE": "work"})
		if code != 0 {
			t.Fatalf("code=%d, want 0 (stderr=%q)", code, errb)
		}
		res := importResult(t, out)
		if res["profile"] != "work" || res["cookies_file"] != filepath.Join(home, "profiles", "work", "cookies.txt") {
			t.Errorf("JSON=%v", res)
		}
	})

	t.Run("default profile from config", func(t *testing.T) {
		_, cfg := importHome(t, `{"default_profile":"work","profiles":{"default":{},"work":{}}}`)
		code, out, errb := runImport(t, cfg, strings.NewReader("hatch_sess=FAKE"), nil)
		if code != 0 {
			t.Fatalf("code=%d, want 0 (stderr=%q)", code, errb)
		}
		res := importResult(t, out)
		if res["profile"] != "work" {
			t.Errorf("JSON=%v, want profile work", res)
		}
	})

	t.Run("relative cookies_file override", func(t *testing.T) {
		home, cfg := importHome(t, `{"default_profile":"default","profiles":{"default":{"cookies_file":"custom/cookies.txt"}}}`)
		code, out, errb := runImport(t, cfg, strings.NewReader("hatch_sess=FAKE"), nil)
		if code != 0 {
			t.Fatalf("code=%d, want 0 (stderr=%q)", code, errb)
		}
		dest := filepath.Join(home, "custom", "cookies.txt")
		res := importResult(t, out)
		if res["cookies_file"] != dest {
			t.Errorf("JSON=%v, want cookies_file %s", res, dest)
		}
		if got := importFileBytes(t, dest); string(got) != "hatch_sess=FAKE\n" {
			t.Errorf("cookies=%q", got)
		}
	})

	t.Run("absolute cookies_file outside honoured", func(t *testing.T) {
		outside := t.TempDir()
		dest := filepath.Join(outside, "cookies.txt")
		home, cfg := importHome(t, fmt.Sprintf(`{"default_profile":"default","profiles":{"default":{"cookies_file":%q}}}`, dest))
		code, out, errb := runImport(t, cfg, strings.NewReader("hatch_sess=FAKE"), nil)
		if code != 0 {
			t.Fatalf("code=%d, want 0 (stderr=%q)", code, errb)
		}
		res := importResult(t, out)
		if res["cookies_file"] != dest {
			t.Errorf("JSON=%v, want cookies_file %s", res, dest)
		}
		if got := importFileBytes(t, dest); string(got) != "hatch_sess=FAKE\n" {
			t.Errorf("cookies=%q", got)
		}
		_ = home
	})

	t.Run("named coercion to own file", func(t *testing.T) {
		home, cfg := importHome(t, "")
		// Rewrite the config with a named entry borrowing another
		// in-config-dir path: LoadProfile coerces it to the
		// profile's own cookies.txt; import must not recompute.
		borrowed := filepath.Join(home, "other.txt")
		configJSON := fmt.Sprintf(`{"default_profile":"default","profiles":{"default":{},"work":{"cookies_file":%q}}}`, borrowed)
		if err := os.WriteFile(cfg, []byte(configJSON), 0o600); err != nil {
			t.Fatal(err)
		}
		out, errb := &bytes.Buffer{}, &bytes.Buffer{}
		env := &Env{Stdout: out, Stderr: errb, Stdin: strings.NewReader("hatch_sess=FAKE"), Getenv: mapGetenv(nil)}
		code := Run(context.Background(), []string{"--config", cfg, "--profile", "work", "auth", "import"}, env)
		if code != 0 {
			t.Fatalf("code=%d, want 0 (stderr=%q)", code, errb.String())
		}
		res := importResult(t, out.String())
		if res["cookies_file"] != filepath.Join(home, "profiles", "work", "cookies.txt") {
			t.Errorf("JSON=%v, want coerced own cookies.txt", res)
		}
		assertImportAbsent(t, borrowed)
	})

	t.Run("no single-file entry writes synthesised path", func(t *testing.T) {
		home, cfg := importHome(t, `{"default_profile":"default","profiles":{}}`)
		before, err := os.ReadFile(cfg)
		if err != nil {
			t.Fatal(err)
		}
		code, out, errb := runImport(t, cfg, strings.NewReader("hatch_sess=FAKE"), nil)
		if code != 0 {
			t.Fatalf("code=%d, want 0 (stderr=%q)", code, errb)
		}
		res := importResult(t, out)
		if res["cookies_file"] != filepath.Join(home, "cookies.txt") {
			t.Errorf("JSON=%v", res)
		}
		after, err := os.ReadFile(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if string(after) != string(before) {
			t.Errorf("config.json changed: before=%q after=%q", before, after)
		}
	})
}

func TestAuthImportOutsideMissingParent(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "missing")
	dest := filepath.Join(outside, "cookies.txt")
	_, cfg := importHome(t, fmt.Sprintf(`{"default_profile":"default","profiles":{"default":{"cookies_file":%q}}}`, dest))
	code, _, errb := runImport(t, cfg, strings.NewReader("hatch_sess=FAKE"), nil)
	if code != 2 {
		t.Fatalf("code=%d, want 2 (stderr=%q)", code, errb)
	}
	assertImportAbsent(t, dest)
	if _, err := os.Stat(outside); !os.IsNotExist(err) {
		t.Errorf("parent directory created (err=%v), want untouched", err)
	}
}

func TestAuthImportNoConfigFile(t *testing.T) {
	// Fresh install: no config file at the UserConfigDir-derived
	// location. Import writes the default cookies path and creates
	// no config.json.
	home := t.TempDir()
	out, errb := &bytes.Buffer{}, &bytes.Buffer{}
	env := &Env{
		Stdout: out, Stderr: errb,
		Stdin:  strings.NewReader("hatch_sess=FAKE"),
		Getenv: mapGetenv(map[string]string{"XDG_CONFIG_HOME": home}),
	}
	code := Run(context.Background(), []string{"auth", "import"}, env)
	if code != 0 {
		t.Fatalf("code=%d, want 0 (stderr=%q)", code, errb.String())
	}
	dest := filepath.Join(home, "muse-cli", "cookies.txt")
	res := importResult(t, out.String())
	if res["cookies_file"] != dest {
		t.Errorf("JSON=%v, want cookies_file %s", res, dest)
	}
	if got := importFileBytes(t, dest); string(got) != "hatch_sess=FAKE\n" {
		t.Errorf("cookies=%q", got)
	}
	assertImportAbsent(t, filepath.Join(home, "muse-cli", "config.json"))
}

func TestAuthImportHostileStdin(t *testing.T) {
	// NUL bytes are valid UTF-8 but unparseable: exit 2, no panic.
	home, cfg := importHome(t, importDefaultConfig)
	raw := bytes.Repeat([]byte{0}, 1024)
	code, _, errb := runImport(t, cfg, bytes.NewReader(raw), nil)
	if code != 2 {
		t.Fatalf("NUL stdin: code=%d, want 2 (stderr=%q)", code, errb)
	}
	assertImportAbsent(t, filepath.Join(home, "cookies.txt"))
	// 1 MiB of 'a': exit 2, no panic, no size-cap error.
	home, cfg = importHome(t, importDefaultConfig)
	code, _, errb = runImport(t, cfg, strings.NewReader(strings.Repeat("a", 1<<20)), nil)
	if code != 2 {
		t.Fatalf("1MiB stdin: code=%d, want 2 (stderr=%q)", code, errb)
	}
	assertImportAbsent(t, filepath.Join(home, "cookies.txt"))
	// 1 MiB of 'a' plus a valid line: accepted, never panics.
	home, cfg = importHome(t, importDefaultConfig)
	big := strings.Repeat("a", 1<<20) + "\nhatch_sess=FAKE; datr=FAKE\n"
	code, _, errb = runImport(t, cfg, strings.NewReader(big), nil)
	if code != 0 {
		t.Fatalf("1MiB+valid stdin: code=%d, want 0 (stderr=%q)", code, errb)
	}
	if got := importFileBytes(t, filepath.Join(home, "cookies.txt")); !strings.HasSuffix(string(got), "hatch_sess=FAKE; datr=FAKE\n") {
		t.Errorf("stored tail=%q", got[len(got)-64:])
	}
	// Binary bytes that are invalid UTF-8: exit 2.
	home, cfg = importHome(t, importDefaultConfig)
	code, _, _ = runImport(t, cfg, bytes.NewReader([]byte{0xff, 0xfe, 0xfd, '\n'}), nil)
	if code != 2 {
		t.Fatalf("binary stdin: code=%d, want 2", code)
	}
	assertImportAbsent(t, filepath.Join(home, "cookies.txt"))
}

func TestAuthImportHelpAndUsage(t *testing.T) {
	_, cfg := importHome(t, importDefaultConfig)
	// Per-subcommand help: exit 0, names all three accepted forms.
	code, out, _ := runImport(t, cfg, strings.NewReader(""), nil, "--help")
	if code != 0 {
		t.Fatalf("--help: code=%d, want 0", code)
	}
	for _, want := range []string{"one-line", "Netscape", "JSON", "hatch_sess"} {
		if !strings.Contains(out, want) {
			t.Errorf("--help output missing %q:\n%s", want, out)
		}
	}
	// auth --help lists import.
	outb, errb := &bytes.Buffer{}, &bytes.Buffer{}
	env := &Env{Stdout: outb, Stderr: errb, Stdin: strings.NewReader(""), Getenv: mapGetenv(nil)}
	if code := Run(context.Background(), []string{"--config", cfg, "auth", "--help"}, env); code != 0 {
		t.Fatalf("auth --help: code=%d", code)
	}
	if !strings.Contains(outb.String(), "import") {
		t.Errorf("auth --help missing import:\n%s", outb.String())
	}
	// Unknown subcommand names import in the choice list.
	outb.Reset()
	errb.Reset()
	env3 := &Env{Stdout: outb, Stderr: errb, Stdin: strings.NewReader(""), Getenv: mapGetenv(nil)}
	code = Run(context.Background(), []string{"--config", cfg, "auth", "bogus"}, env3)
	if code != 2 || !strings.Contains(errb.String(), "import") {
		t.Fatalf("bogus subcommand: code=%d stderr=%q, want 2 naming import", code, errb.String())
	}
	// Positional args are rejected: cookies never come from argv.
	posCode, _, posErr := runImport(t, cfg, strings.NewReader("hatch_sess=FAKE"), nil, "hatch_sess=FAKE")
	if posCode != 2 {
		t.Fatalf("positional arg: code=%d, want 2 (stderr=%q)", posCode, posErr)
	}
	// Missing subcommand: exit 2.
	outb.Reset()
	errb.Reset()
	env2 := &Env{Stdout: outb, Stderr: errb, Stdin: strings.NewReader(""), Getenv: mapGetenv(nil)}
	if code := Run(context.Background(), []string{"--config", cfg, "auth"}, env2); code != 2 {
		t.Fatalf("missing subcommand: code=%d, want 2", code)
	}
}

func TestNormaliseImportInput(t *testing.T) {
	cases := []struct {
		name    string
		raw     []byte
		want    string
		wantErr bool
	}{
		{"plain", []byte("hatch_sess=FAKE\n"), "hatch_sess=FAKE", false},
		{"crlf", []byte("a\r\nb\r\n"), "a\nb", false},
		{"cr only", []byte("a\rb\r"), "a\nb", false},
		{"mixed", []byte("a\r\nb\rc\n"), "a\nb\nc", false},
		{"trim", []byte("  \n hatch_sess=FAKE \t\n"), "hatch_sess=FAKE", false},
		{"invalid utf8", []byte{0xff}, "", true},
		{"invalid utf8 mid", []byte("a\xffb"), "", true},
		{"empty", []byte(""), "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normaliseImportInput(tc.raw)
			if tc.wantErr && err == nil {
				t.Fatalf("want error, got %q", got)
			}
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got != tc.want {
					t.Errorf("got %q, want %q", got, tc.want)
				}
			}
		})
	}
}

func TestImportHasHatchSessAdversarial(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  bool
	}{
		{"exact", "hatch_sess=FAKE; datr=FAKE", true},
		{"bom curl", "\ufeffhatch_sess=FAKE; datr=FAKE", true},
		{"in value only", "other=hatch_sess; x=1", false},
		{"in value json", `{"other": "x; hatch_sess=FAKE"}`, false},
		{"substring name", "xhatch_sess=FAKE", false},
		{"case", "HATCH_SESS=FAKE", false},
		{"empty", "hatch_sess=; x=1", false},
		{"jar exact", ".muse.ai\tTRUE\t/\tTRUE\t0\thatch_sess\tFAKE", true},
		{"jar spaced name", ".muse.ai\tTRUE\t/\tTRUE\t0\t hatch_sess \tFAKE", false},
		{"jar empty", ".muse.ai\tTRUE\t/\tTRUE\t0\thatch_sess\t", false},
		{"json nested", `{"cookies": {"hatch_sess": "FAKE"}}`, true},
		{"json flat", `{"hatch_sess": "FAKE"}`, true},
		{"json empty string", `{"hatch_sess": ""}`, false},
		{"json null", `{"hatch_sess": null}`, false},
		{"json number zero", `{"hatch_sess": 0}`, true},
		{"first line wins", "a=1; b=2\nhatch_sess=FAKE; y=3", false},
		{"fallback flattened", "hatch_sess=FAKE\nother=1", true},
		{"comment skipped", "# hatch_sess=FAKE; y=1\na=1; b=2", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := importHasHatchSess(tc.input); got != tc.want {
				t.Errorf("importHasHatchSess(%q)=%v, want %v", tc.input, got, tc.want)
			}
		})
	}
}
