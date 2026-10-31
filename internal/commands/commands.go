// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

// Package commands implements the castctl command surface for the Go
// port (muse-cli 0.6.1 contract): a hand-rolled parser mirroring
// argparse help/errors/exit 2, a single runtime-wiring path, and
// dispatch to the read, filesystem, profile and deliver-backed
// commands. Deferred commands (PR4/PR5) and the carried chat REPL are
// rejected here with explicit messages; they are never faked.
//
// Fail-closed invariant: no http.DefaultClient, no net.Dial, no
// system-resolver lookup anywhere in this package. Every HTTP call
// goes through the outbound dialer's HTTPClient, every dial through
// the Dialer. See BuildRuntime in runtime.go.
package commands

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/deliver"
	"github.com/thoitiettxl-cyber/castctl/internal/gateway"
	"github.com/thoitiettxl-cyber/castctl/internal/logging"
	"github.com/thoitiettxl-cyber/castctl/internal/profile"
)

// Version is the Go port version, mirroring the Python 0.6.1 contract
// it ports. The canonical source is go/cmd/castctl/main.go; tests pin
// the --version output format "castctl <version>".
//
// Version, Commit, and BuildDate are vars (not consts) so release
// builds can stamp them with go build -X:
//
//	-X github.com/thoitiettxl-cyber/castctl/internal/commands.Version=...
//	-X github.com/thoitiettxl-cyber/castctl/internal/commands.Commit=...
//	-X github.com/thoitiettxl-cyber/castctl/internal/commands.BuildDate=...
//
// Defaults keep the pinned output "castctl 0.6.1": Commit and
// BuildDate are empty unless stamped, and versionString() then
// returns the bare version.
var Version = "0.6.1"

// Commit is the stamped source commit (short hash) of a release
// build, empty for unstamped builds.
var Commit = ""

// BuildDate is the stamped UTC build date (RFC 3339) of a release
// build, empty for unstamped builds.
var BuildDate = ""

// versionString returns the --version payload: the bare version by
// default, with commit and build date appended in parentheses when
// stamped (e.g. "0.6.1 (abc1234 2026-10-30T12:00:00Z)").
func versionString() string {
	if Commit == "" && BuildDate == "" {
		return Version
	}
	return Version + " (" + strings.TrimSpace(Commit+" "+BuildDate) + ")"
}

// PromptFunc is the injectable prompt seam (item 15). The default
// reads one line from stdin. Tests inject fake answers; production
// code never prompts in the PR3 commands except through this seam
// (no PR3 command currently prompts: the only prompt call sites in
// Python 0.6.1 are the chat REPL in chat.py and the Telegram setup
// flow in tgbot.py, both carried/deferred).
type PromptFunc func(prompt string) (string, error)

// Env carries the process environment a command run needs, injectable
// for hermetic tests. A zero Env is usable: stdout/stderr default to
// os.Stdout/os.Stderr, stdin to os.Stdin, lookupEnv to os.LookupEnv, and
// Prompt to the stdin default.
type Env struct {
	Stdout io.Writer
	Stderr io.Writer
	Stdin  io.Reader
	// Getenv mirrors os.LookupEnv. A nil Getenv reads the real
	// environment; tests replace it with a map lookup.
	Getenv func(string) (string, bool)
	// Prompt, when non-nil, replaces the default stdin prompt.
	Prompt PromptFunc
	// Logger, when non-nil, is passed to conn.Muse. Nil means
	// slog.Default().
	Logger *slog.Logger
	// LogLevelOverride, when LogLevelSet, is the --log-level value
	// from the global pre-scan. runInner sets both from
	// globalOpts before dispatch; defaultBuildRuntime reads them
	// as the CLI tier of log precedence (CLI > config block >
	// default: sing-box's empty level means trace). Test BuildRuntime overrides read the same
	// fields; production never sets them directly.
	LogLevelOverride string
	LogLevelSet      bool
	// ConnectorOpts are appended to gateway.NewConnector options when
	// the default runtime is built. Tests use them to inject a fake
	// dialer; production passes none.
	ConnectorOpts []gateway.ConnectorOption
	// NewConnector, when non-nil, replaces gateway.NewConnector in
	// the default runtime build. Tests inject a fake connector
	// (gatewaytest) that never dials; production always uses the
	// real one.
	NewConnector func(dialer gateway.OutboundDialer, opts ...gateway.ConnectorOption) conn.Connector
	// HTTPClient, when non-nil, replaces the dialer's HTTP client
	// in the default runtime build. Tests inject an
	// httptest-backed client; production always uses the
	// dialer's client.
	HTTPClient func() *http.Client
	// BuildRuntime, when non-nil, replaces defaultBuildRuntime. Tests
	// inject fake runtimes (fake DNS/outbound/gateway) through it;
	// production always uses the real wiring.
	BuildRuntime func(ctx context.Context, loc *profile.ConfigLocation, prof *profile.Profile, env *Env) (*Runtime, error)
}

func (e *Env) stdout() io.Writer {
	if e.Stdout != nil {
		return e.Stdout
	}
	return os.Stdout
}

func (e *Env) stderr() io.Writer {
	if e.Stderr != nil {
		return e.Stderr
	}
	return os.Stderr
}

func (e *Env) stdin() io.Reader {
	if e.Stdin != nil {
		return e.Stdin
	}
	return os.Stdin
}

func (e *Env) lookupEnv(key string) (string, bool) {
	if e.Getenv != nil {
		return e.Getenv(key)
	}
	return os.LookupEnv(key)
}

// prompt reads one line through the injected PromptFunc, or the
// default stdin reader when none is set.
func (e *Env) prompt(prompt string) (string, error) {
	if e.Prompt != nil {
		return e.Prompt(prompt)
	}
	fmt.Fprint(e.stderr(), prompt)
	rd := bufio.NewReader(e.stdin())
	line, err := rd.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func (e *Env) buildRuntime(ctx context.Context, loc *profile.ConfigLocation, prof *profile.Profile) (*Runtime, error) {
	if e.BuildRuntime != nil {
		return e.BuildRuntime(ctx, loc, prof, e)
	}
	return defaultBuildRuntime(ctx, loc, prof, e)
}

// newConnector builds the gateway connector for a dialer, honouring
// the Env test hook. Extra options come first so ConnectorOpts
// (the test hook) can override them.
func (e *Env) newConnector(dialer gateway.OutboundDialer, extra ...gateway.ConnectorOption) conn.Connector {
	if e.NewConnector != nil {
		return e.NewConnector(dialer, append(extra, e.ConnectorOpts...)...)
	}
	return gateway.NewConnector(dialer, append(extra, e.ConnectorOpts...)...)
}

// cmdError is an error with a fixed exit code. Handlers return it for
// usage/validation failures (code 2), deliver export guidance (code
// 1), and other cases where the exit code is decided at the call site
// rather than by error classification.
type cmdError struct {
	Code int
	Type string // optional typed-auth-error type string; "" = plain message
	Err  error
}

func (e *cmdError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return ""
}

func (e *cmdError) Unwrap() error { return e.Err }

func errCode(code int, err error) error {
	return &cmdError{Code: code, Err: err}
}

func errCodef(code int, format string, args ...any) error {
	return &cmdError{Code: code, Err: fmt.Errorf(format, args...)}
}

// typedAuthError classifies an auth failure: it is printed as one
// JSON line {"type": ..., "error": ...} on stderr, never exits 0, and
// never carries a cookie value.
type typedAuthError struct {
	Code int
	Type string
	Err  error
}

func (e *typedAuthError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return e.Type
}

func (e *typedAuthError) Unwrap() error { return e.Err }

// classifyError maps an error to (exit code, stderr text). Plain
// errors print "castctl: <summary>"; typed auth errors print
// one JSON line. The Python exit-code contract is preserved:
// AuthError 2, GatewayError 3, ValueError-equivalent 2, TimeoutError
// 4, everything else 1, signal cancellation 130.
//
// Loop 5 (allowlist rule): the stderr text NEVER carries
// server/peer body bytes, at any level of wrapping. Every
// branch renders through logging.SummarizeErr — EXCEPT the
// ExportError guidance branch, which renders guidance text
// through the SafeString backstop only (guidance carries no
// body bytes by construction; see below). A body-carrying
// error in the chain renders as its LogSummary (status +
// class + length + validated fields), and every other error
// renders through the SafeString backstop.
// GatewayError.Error() is itself a summary since loop 5.
// AuthError.Error() is NOT: it renders Message verbatim, and
// its safety rests on producers building Message from
// allowlist summaries/constants only. SummarizeErr finds the
// inner error's LogSummary through the wrappers' Unwrap
// chains (cmdError and typedAuthError both unwrap); a wrapper
// that hid the chain would fall back to SafeString over the
// verbatim Message, so no new wrapper type may hide an
// AuthError/GatewayError chain. The boundary is pinned by
// TestLoop6ClassifyErrorAuthBoundary (loop 6, item 6d). The
// ExportError guidance carries only placeholders and keeps
// its SafeString rendering.
func classifyError(err error) (int, string) {
	if err == nil {
		return 0, ""
	}
	var export *deliver.ExportError
	if errors.As(err, &export) {
		// Guidance-only, exit 1, guidance text verbatim.
		return export.ExitCode(), logging.SafeString(export.Error())
	}
	var typed *typedAuthError
	if errors.As(err, &typed) {
		msg := logging.SummarizeErr(err)
		b, _ := json.Marshal(map[string]string{"type": typed.Type, "error": msg})
		return typed.Code, string(b)
	}
	var ce *cmdError
	if errors.As(err, &ce) {
		if ce.Type != "" {
			msg := logging.SummarizeErr(err)
			b, _ := json.Marshal(map[string]string{"type": ce.Type, "error": msg})
			return ce.Code, string(b)
		}
		if msg := ce.Error(); msg != "" {
			return ce.Code, "castctl: " + logging.SummarizeErr(err)
		}
		return ce.Code, ""
	}
	var auth *conn.AuthError
	if errors.As(err, &auth) {
		msg := logging.SummarizeErr(err)
		b, _ := json.Marshal(map[string]string{"type": "auth_failed", "error": msg})
		return 2, string(b)
	}
	var gw *conn.GatewayError
	if errors.As(err, &gw) {
		return 3, "castctl: " + logging.SummarizeErr(err)
	}
	var reassembly *gateway.ReassemblySizeError
	if errors.As(err, &reassembly) {
		return 3, "castctl: " + logging.SummarizeErr(err)
	}
	var tooMany *gateway.TooManyUnfinishedGroupsError
	if errors.As(err, &tooMany) {
		return 3, "castctl: " + logging.SummarizeErr(err)
	}
	var timeout *conn.TimeoutError
	if errors.As(err, &timeout) {
		return 4, "castctl: " + logging.SummarizeErr(err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return 4, "castctl: timeout: " + logging.SummarizeErr(err)
	}
	if errors.Is(err, context.Canceled) {
		return 130, ""
	}
	var perr *profile.Error
	if errors.As(err, &perr) {
		return profile.ExitCode(err), "castctl: " + logging.SummarizeErr(err)
	}
	var verr *gateway.ValidationError
	if errors.As(err, &verr) {
		return 2, "castctl: " + logging.SummarizeErr(err)
	}
	// Errors carrying their own exit code (profile errors not typed
	// above, deliver errors) keep it; everything else is 1.
	if ec, ok := err.(interface{ ExitCode() int }); ok {
		return ec.ExitCode(), "castctl: " + logging.SummarizeErr(err)
	}
	return 1, "castctl: " + logging.SummarizeErr(err)
}

// panicSummary renders a recovered panic value for the CLI
// panic line on stderr (loop-5 allowlist rule): NEVER the
// value's text. A panic value that is (or wraps) a
// body-carrying error renders as that error's LogSummary;
// any other value renders as its type and byte length only.
// This replaces the old redact.String rendering, which
// passed plain body words through verbatim.
func panicSummary(r any) string {
	if err, ok := r.(error); ok && err != nil {
		var s interface{ LogSummary() string }
		if errors.As(err, &s) {
			return "panic: " + s.LogSummary()
		}
	}
	return fmt.Sprintf("panic: type=%T panic_length=%d", r, len(fmt.Sprint(r)))
}

// classifyConnError wraps a failure from conn.Muse calls (connect,
// CallJSON, Download) into the typed auth taxonomy without changing
// conn/gateway code. message-substring classification is used only
// where the libraries expose no kind: gateway auth-chain errors are
// plain text carrying the failing endpoint name.
func classifyConnError(err error) error {
	if err == nil {
		return nil
	}
	// A cookies file that cannot be read (missing, permissions)
	// surfaces from the connector as an AuthError: the
	// connector converts a LoadCookies read failure into one
	// whose message keeps the "read cookies file" marker.
	// This substring branch is retained as a backstop — both
	// it and the AuthError branch below classify the failure
	// as cookies_missing, since during a connect the cookies
	// file is the only file read.
	if strings.Contains(err.Error(), "read cookies file") {
		return &typedAuthError{Code: 2, Type: "cookies_missing", Err: err}
	}
	var auth *conn.AuthError
	if errors.As(err, &auth) {
		return classifyAuthMessage(auth)
	}
	// conn.GatewayError with status -1 from the session-info step is
	// the "VM unavailable" signal: the session endpoint answered but
	// carried no vm_id.
	var gw *conn.GatewayError
	if errors.As(err, &gw) && gw.Status == -1 && strings.Contains(gw.Payload, "VM unavailable") {
		return &typedAuthError{Code: 2, Type: "session_unavailable", Err: err}
	}
	return err
}

func classifyAuthMessage(auth *conn.AuthError) error {
	msg := auth.Error()
	switch {
	case strings.Contains(msg, "could not parse cookies"),
		strings.Contains(msg, "no cookies"),
		strings.Contains(msg, "empty cookies"):
		return &typedAuthError{Code: 2, Type: "cookies_missing", Err: auth}
	case strings.Contains(msg, "api/session"),
		strings.Contains(msg, "VM unavailable"):
		return &typedAuthError{Code: 2, Type: "session_unavailable", Err: auth}
	case strings.Contains(msg, "auth/check"):
		return &typedAuthError{Code: 2, Type: "auth_check_failed", Err: auth}
	case strings.Contains(msg, "hatch/token"):
		return &typedAuthError{Code: 2, Type: "hatch_token_failed", Err: auth}
	default:
		return &typedAuthError{Code: 2, Type: "auth_failed", Err: auth}
	}
}

// writeJSON writes v as indented JSON (2 spaces, HTML unescaped like
// Python json.dumps(ensure_ascii=False)) plus a trailing newline.
func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func marshalJSONLine(v any) ([]byte, error) {
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return []byte(strings.TrimSuffix(buf.String(), "\n")), nil
}

// truncRunes truncates s to at most n runes (watch rows cap text at
// 300 characters, like Python's [:300] slice).
func truncRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n])
}

// decodeJSONNumber decodes data with json.Number preserved, mirroring
// Python's int/float fidelity for --raw passthrough.
func decodeJSONNumber(data []byte) (any, error) {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

// ---------------------------------------------------------------------
// Parser: hand-rolled, mirroring argparse (abbreviations, --flag=value,
// bundled short flags, exit 2 on errors, --help short-circuit).
// ---------------------------------------------------------------------

type flagKind int

const (
	flagBool flagKind = iota
	flagString
	flagInt
	flagStringList // repeatable, one value per occurrence (--param)
	flagPairList   // repeatable, two values per occurrence (--replace)
)

type flagDef struct {
	name  string // long name without --
	short byte   // 0 = none
	kind  flagKind
	// defInt/hasDef give an int flag its argparse default when the
	// flag was not set on the command line.
	defInt int64
	hasDef bool
}

func intFlag(name string, short byte, def int64) flagDef {
	return flagDef{name: name, short: short, kind: flagInt, defInt: def, hasDef: true}
}

type parsed struct {
	bools       map[string]bool
	strs        map[string]string
	strSet      map[string]bool
	ints        map[string]int64
	intSet      map[string]bool
	lists       map[string][]string
	pairs       map[string][][2]string
	positionals []string
}

func newParsed() *parsed {
	return &parsed{
		bools:  map[string]bool{},
		strs:   map[string]string{},
		strSet: map[string]bool{},
		ints:   map[string]int64{},
		intSet: map[string]bool{},
		lists:  map[string][]string{},
		pairs:  map[string][][2]string{},
	}
}

func (p *parsed) bool(name string) bool     { return p.bools[name] }
func (p *parsed) str(name string) string    { return p.strs[name] }
func (p *parsed) strIsSet(name string) bool { return p.strSet[name] }
func (p *parsed) intVal(name string) int64  { return p.ints[name] }
func (p *parsed) intIsSet(name string) bool { return p.intSet[name] }

// parserError is a usage error: exit 2 with usage + message.
type parserError struct{ msg string }

func (e *parserError) Error() string { return e.msg }

type argParser struct {
	defs     []flagDef
	helpText string
	prog     string // e.g. "castctl fs ls"
}

func (ap *argParser) findLong(name string) (flagDef, bool) {
	for _, d := range ap.defs {
		if d.name == name {
			return d, true
		}
	}
	// Abbreviations: argparse allows unambiguous prefixes.
	var match flagDef
	found := false
	for _, d := range ap.defs {
		if strings.HasPrefix(d.name, name) {
			if found {
				return flagDef{}, false // ambiguous
			}
			match, found = d, true
		}
	}
	// "help" is an implicit flag on every command.
	if !found && strings.HasPrefix("help", name) {
		return flagDef{name: "help", kind: flagBool}, true
	}
	return match, found
}

func (ap *argParser) findShort(c byte) (flagDef, bool) {
	for _, d := range ap.defs {
		if d.short != 0 && d.short == c {
			return d, true
		}
	}
	if c == 'h' {
		return flagDef{name: "help", short: 'h', kind: flagBool}, true
	}
	return flagDef{}, false
}

// parseResult: helpShown=true means --help was seen (help already
// printed to stdout); err is a *parserError for exit 2.
func (ap *argParser) parse(args []string, stdout io.Writer) (*parsed, bool, error) {
	p := newParsed()
	i := 0
	seenDashDash := false
	for i < len(args) {
		tok := args[i]
		i++
		if seenDashDash {
			p.positionals = append(p.positionals, tok)
			continue
		}
		switch {
		case tok == "--":
			seenDashDash = true
		case strings.HasPrefix(tok, "--") && len(tok) > 2:
			nameVal := tok[2:]
			name := nameVal
			var inlineVal string
			hasInline := false
			if j := strings.IndexByte(nameVal, '='); j >= 0 {
				name, inlineVal, hasInline = nameVal[:j], nameVal[j+1:], true
			}
			def, ok := ap.findLong(name)
			if !ok {
				return nil, false, &parserError{msg: fmt.Sprintf("unrecognized argument: --%s", name)}
			}
			if def.name == "help" {
				fmt.Fprint(stdout, ap.helpText)
				return p, true, nil
			}
			var err error
			i, err = ap.consumeLong(p, args, i, def, inlineVal, hasInline)
			if err != nil {
				return nil, false, err
			}
		case strings.HasPrefix(tok, "-") && len(tok) > 1 && tok != "-":
			// Short flags, possibly bundled: -la, -oDIR, -o DIR.
			rest := tok[1:]
			consumedNext := false
			for len(rest) > 0 {
				def, ok := ap.findShort(rest[0])
				if !ok {
					return nil, false, &parserError{msg: fmt.Sprintf("unrecognized argument: -%c", rest[0])}
				}
				if def.name == "help" {
					fmt.Fprint(stdout, ap.helpText)
					return p, true, nil
				}
				if def.kind == flagBool {
					p.bools[def.name] = true
					rest = rest[1:]
					continue
				}
				// Value-taking short: rest after the letter is the
				// value, else the next token.
				var val string
				if len(rest) > 1 {
					val = rest[1:]
					rest = ""
				} else {
					if i >= len(args) {
						return nil, false, &parserError{msg: fmt.Sprintf("argument -%c: expected one argument", def.short)}
					}
					val = args[i]
					i++
					consumedNext = true
					rest = ""
				}
				if err := ap.setValue(p, def, val); err != nil {
					return nil, false, err
				}
				_ = consumedNext
			}
		default:
			p.positionals = append(p.positionals, tok)
		}
	}
	// Apply int-flag defaults for flags never set on the command
	// line (argparse defaults).
	for _, def := range ap.defs {
		if def.kind == flagInt && def.hasDef && !p.intSet[def.name] {
			p.ints[def.name] = def.defInt
		}
	}
	return p, false, nil
}

func (ap *argParser) consumeLong(p *parsed, args []string, i int, def flagDef, inlineVal string, hasInline bool) (int, error) {
	flagDisplay := "--" + def.name
	if def.kind == flagBool {
		if hasInline {
			return i, &parserError{msg: fmt.Sprintf("argument %s: ignored explicit argument %q", flagDisplay, inlineVal)}
		}
		p.bools[def.name] = true
		return i, nil
	}
	values := []string{}
	if hasInline {
		values = append(values, inlineVal)
	}
	need := 1
	if def.kind == flagPairList {
		need = 2
	}
	for len(values) < need {
		if i >= len(args) {
			return i, &parserError{msg: fmt.Sprintf("argument %s: expected %d argument(s)", flagDisplay, need)}
		}
		next := args[i]
		if strings.HasPrefix(next, "-") && next != "-" && !looksLikeNegativeNumber(next, def.kind) {
			return i, &parserError{msg: fmt.Sprintf("argument %s: expected %d argument(s)", flagDisplay, need)}
		}
		values = append(values, next)
		i++
	}
	for _, v := range values[:1] {
		if def.kind == flagPairList {
			p.pairs[def.name] = append(p.pairs[def.name], [2]string{values[0], values[1]})
			return i, nil
		}
		if err := ap.setValue(p, def, v); err != nil {
			return i, err
		}
	}
	return i, nil
}

func looksLikeNegativeNumber(tok string, kind flagKind) bool {
	if kind != flagInt {
		return false
	}
	if _, err := strconv.ParseInt(tok, 10, 64); err == nil {
		return true
	}
	return false
}

func (ap *argParser) setValue(p *parsed, def flagDef, val string) error {
	switch def.kind {
	case flagBool:
		p.bools[def.name] = true
	case flagString:
		p.strs[def.name] = val
		p.strSet[def.name] = true
	case flagInt:
		n, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return &parserError{msg: fmt.Sprintf("argument --%s: invalid int value: %q", def.name, val)}
		}
		p.ints[def.name] = n
		p.intSet[def.name] = true
	case flagStringList:
		p.lists[def.name] = append(p.lists[def.name], val)
	}
	return nil
}

// checkPositionals enforces the positional count for a command.
func checkPositionals(p *parsed, names []string, prog string) error {
	if len(p.positionals) < len(names) {
		missing := names[len(p.positionals):]
		return &parserError{msg: fmt.Sprintf("the following arguments are required: %s", strings.Join(missing, ", "))}
	}
	if len(p.positionals) > len(names) {
		extra := p.positionals[len(names):]
		return &parserError{msg: fmt.Sprintf("unrecognized arguments: %s", strings.Join(extra, " "))}
	}
	return nil
}

// ---------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------

type handlerFunc func(ctx context.Context, env *Env, g *globalOpts, args []string) error

type commandSpec struct {
	name     string
	help     string // short help for the global listing
	helpText string
	handler  handlerFunc
}

type globalOpts struct {
	profileFlag  string
	profileSet   bool
	configFlag   string
	configSet    bool
	logLevelFlag string
	logLevelSet  bool
}

// commandTable is the full PR3 surface. Deferred commands are in
// deferredTable; unknown names are rejected, never guessed.
var commandTable = map[string]*commandSpec{}
var deferredTable = map[string]string{
	"update": "PR5",
}

func registerCommand(spec *commandSpec) {
	commandTable[spec.name] = spec
}

// Deterministic order: keep the argparse registration order by
// sorting only for the unknown-choice message is wrong; use a
// fixed order list instead.
var commandOrder = []string{
	"chat", "status", "usage", "invite", "redeem", "threads", "history",
	"send", "wait", "approvals", "approve", "auto-approve", "deny",
	"files", "download", "watch", "feed", "feed-status", "feed-react", "feed-prompt",
	"goals", "goal", "ideas", "idea", "idea-exec", "unread", "seen",
	"session-start", "session-rename", "session-pin", "session-unpin",
	"session-archive", "session-unarchive", "session-delete", "stop", "wake",
	"raw", "fs", "auth", "profile", "config", "telegram",
}

// Run is the command-line entry point. args excludes argv[0]. It
// returns the process exit code and prints to env stdout/stderr.
// Global flags (--profile/--config/--version/--help) are pre-scanned
// sequentially, mirroring Python's prescan + argparse: --help/--version
// act when reached, before profile validation.
//
// Panic contract (R2 decision): a panic anywhere on the dispatch
// path converts to exit 2 with a summary message and no stack
// trace. The panic value is rendered by panicSummary (class +
// length only, never the value's text), so no secret-bearing
// stack or peer text ever reaches output; non-panic behaviour
// and exit codes are unchanged.
func Run(ctx context.Context, args []string, env *Env) (code int) {
	defer func() {
		if r := recover(); r != nil {
			code = 2
			fmt.Fprintf(env.stderr(), "castctl: %s\n", panicSummary(r))
		}
	}()
	return runInner(ctx, args, env)
}

func runInner(ctx context.Context, args []string, env *Env) int {
	if env == nil {
		env = &Env{}
	}
	g, cmdName, cmdArgs, code, done := scanGlobal(args, env)
	if done {
		return code
	}
	// Thread the global --log-level override into the Env the
	// runtime builder reads (the only global flag that affects
	// runtime behaviour, not just location/profile resolution).
	env.LogLevelOverride, env.LogLevelSet = g.logLevelFlag, g.logLevelSet
	if cmdName == "" {
		// Bare invocation = chat in Python.
		cmdName, cmdArgs = "chat", nil
	}
	if pr, ok := deferredTable[cmdName]; ok {
		if hasHelpToken(cmdArgs) {
			fmt.Fprint(env.stdout(), deferredHelpText(cmdName, pr))
			return 0
		}
		fmt.Fprintf(env.stderr(), "%s is not implemented in the Go port yet (%s)\n", cmdName, pr)
		return 2
	}
	spec, ok := commandTable[cmdName]
	if !ok {
		fmt.Fprintf(env.stderr(), "castctl: argument cmd: invalid choice: %q (choose from %s)\n", cmdName, strings.Join(commandOrder, ", "))
		fmt.Fprint(env.stderr(), globalHelpText)
		return 2
	}
	if err := spec.handler(ctx, env, g, cmdArgs); err != nil {
		if errors.Is(err, errHelpShown) {
			return 0
		}
		// Typed-JSON ordering contract (docs/config.md): the
		// error text is written to stderr AFTER every log
		// line, so when logging is ON with stderr output the
		// typed JSON is the LAST stderr line, intact; when
		// logging is OFF (no log block, no --log-level flag)
		// it is the ONLY stderr line. Nothing may write to
		// stderr after this point in the error path.
		code, text := classifyError(err)
		if text != "" {
			fmt.Fprintln(env.stderr(), text)
		}
		return code
	}
	return 0
}

// hasHelpToken reports whether args contain a help request token
// (-h or an unambiguous --help prefix), for deferred commands whose
// parser is not implemented: --help still prints help, exit 0.
func hasHelpToken(args []string) bool {
	for _, a := range args {
		if a == "-h" || a == "--help" {
			return true
		}
		if strings.HasPrefix(a, "--h") && !strings.Contains(a, "=") && strings.HasPrefix("help", strings.TrimPrefix(a, "--")) {
			return true
		}
	}
	return false
}

// scanGlobal pre-scans global flags. done=true means Run should return
// code immediately (version/help printed, or a fatal scan error).
func scanGlobal(args []string, env *Env) (*globalOpts, string, []string, int, bool) {
	g := &globalOpts{}
	i := 0
	for i < len(args) {
		tok := args[i]
		switch {
		case tok == "--":
			i++
			if i < len(args) {
				return g, args[i], args[i+1:], 0, false
			}
			return g, "", nil, 0, false
		case tok == "--version" || tok == "--vers" || strings.HasPrefix(tok, "--version="):
			// argparse: --version is an action; --version=true is
			// rejected by the existing PR1 behaviour (pinned by
			// main tests). Keep the rejection here.
			if strings.Contains(tok, "=") {
				fmt.Fprintf(env.stderr(), "castctl: argument --version: ignored explicit argument %q\n", strings.SplitN(tok, "=", 2)[1])
				return g, "", nil, 2, true
			}
			fmt.Fprintf(env.stdout(), "castctl %s\n", versionString())
			return g, "", nil, 0, true
		case tok == "--help" || tok == "-h" || tok == "--hel":
			fmt.Fprint(env.stdout(), globalHelpText)
			return g, "", nil, 0, true
		case tok == "--profile" || tok == "--config" || strings.HasPrefix(tok, "--profile=") || strings.HasPrefix(tok, "--config="):
			isProfile := strings.HasPrefix(tok, "--profile")
			var val string
			if strings.Contains(tok, "=") {
				val = strings.SplitN(tok, "=", 2)[1]
			} else {
				if i+1 >= len(args) || (strings.HasPrefix(args[i+1], "-") && args[i+1] != "-") {
					name := "--profile"
					if !isProfile {
						name = "--config"
					}
					fmt.Fprintf(env.stderr(), "castctl: argument %s: expected one argument\n", name)
					return g, "", nil, 2, true
				}
				i++
				val = args[i]
			}
			if isProfile {
				g.profileFlag, g.profileSet = val, true
			} else {
				g.configFlag, g.configSet = val, true
			}
		case strings.HasPrefix(tok, "--"):
			// Unabbreviated unknown global flag; allow unambiguous
			// prefixes of --profile/--config/--help/--version/
			// --log-level.
			name := strings.TrimPrefix(strings.SplitN(tok, "=", 2)[0], "--")
			if strings.HasPrefix("log-level", name) && name != "" {
				// --log-level: same value rules as --profile/
				// --config, then spelling validation. The
				// supplied value is never echoed: it could be
				// a secret pasted by mistake.
				var val string
				if strings.Contains(tok, "=") {
					val = strings.SplitN(tok, "=", 2)[1]
				} else {
					if i+1 >= len(args) || (strings.HasPrefix(args[i+1], "-") && args[i+1] != "-") {
						fmt.Fprintf(env.stderr(), "castctl: argument --log-level: expected one argument\n")
						return g, "", nil, 2, true
					}
					i++
					val = args[i]
				}
				if !profile.ValidLogLevel(val) {
					fmt.Fprintf(env.stderr(), "castctl: argument --log-level: invalid log level (expected trace, debug, info, warn, warning, error, fatal, or panic)\n")
					return g, "", nil, 2, true
				}
				g.logLevelFlag, g.logLevelSet = val, true
			} else if strings.HasPrefix("profile", name) || strings.HasPrefix("config", name) {
				// Treat as the full flag with the same value rules.
				isProfile := strings.HasPrefix("profile", name)
				var val string
				if strings.Contains(tok, "=") {
					val = strings.SplitN(tok, "=", 2)[1]
				} else {
					if i+1 >= len(args) || (strings.HasPrefix(args[i+1], "-") && args[i+1] != "-") {
						fmt.Fprintf(env.stderr(), "castctl: argument --%s: expected one argument\n", name)
						return g, "", nil, 2, true
					}
					i++
					val = args[i]
				}
				if isProfile {
					g.profileFlag, g.profileSet = val, true
				} else {
					g.configFlag, g.configSet = val, true
				}
			} else if strings.HasPrefix("help", name) {
				fmt.Fprint(env.stdout(), globalHelpText)
				return g, "", nil, 0, true
			} else if strings.HasPrefix("version", name) {
				fmt.Fprintf(env.stdout(), "castctl %s\n", versionString())
				return g, "", nil, 0, true
			} else {
				fmt.Fprintf(env.stderr(), "castctl: unrecognized argument: %s\n", tok)
				return g, "", nil, 2, true
			}
		case strings.HasPrefix(tok, "-") && len(tok) > 1 && tok != "-":
			fmt.Fprintf(env.stderr(), "castctl: unrecognized argument: %s\n", tok)
			return g, "", nil, 2, true
		default:
			return g, tok, args[i+1:], 0, false
		}
		i++
	}
	return g, "", nil, 0, false
}

// resolveConfig resolves the config location for one invocation and
// enforces the basename + presence rules. allowMissingCreate is true
// only for `config migrate --write` and `config migrate --from`
// (whose destination may be a new directory).
func resolveConfig(g *globalOpts, env *Env, allowMissingCreate bool) (*profile.ConfigLocation, error) {
	if g.configSet && strings.TrimSpace(g.configFlag) == "" {
		return nil, errCodef(2, "--config requires a non-empty path")
	}
	explicit := ""
	if g.configSet {
		explicit = g.configFlag
	}
	loc, err := profile.ResolveConfigLocation(explicit, env.lookupEnv)
	if err != nil {
		return nil, err
	}
	for _, w := range loc.Warnings {
		fmt.Fprintf(env.stderr(), "castctl: warning: %s\n", w)
	}
	if filepath.Base(loc.ConfigFile) != "config.json" {
		return nil, errCodef(2, "--config path %q must name a config.json file", loc.ConfigFile)
	}
	if !allowMissingCreate {
		if err := loc.RequirePresent(); err != nil {
			return nil, err
		}
	}
	return loc, nil
}

// resolveActive resolves the active profile within the resolved
// config location. A flag value is used only when the flag was set;
// otherwise ResolveActiveProfile reads CASTCTL_PROFILE,
// default_profile, then "default".
func resolveActive(loc *profile.ConfigLocation, g *globalOpts, env *Env) (*profile.Profile, error) {
	var flag *string
	if g.profileSet {
		flag = &g.profileFlag
	}
	return profile.ResolveActiveProfile(loc.ConfigDir, flag, env.lookupEnv)
}

// runWithProfile resolves config + active profile, then calls fn.
// Most handlers use this; profile commands that target another
// profile and `config migrate` use resolveConfig directly.
func runWithProfile(ctx context.Context, env *Env, g *globalOpts, fn func(*profile.ConfigLocation, *profile.Profile) error) error {
	loc, err := resolveConfig(g, env, false)
	if err != nil {
		return err
	}
	prof, err := resolveActive(loc, g, env)
	if err != nil {
		return err
	}
	return fn(loc, prof)
}

// parseOrHelp parses args with the spec parser: help short-circuits
// with exit 0 (handler returns a sentinel), parser errors exit 2.
var errHelpShown = errors.New("help shown")

func parseOrHelp(spec *commandSpec, args []string, env *Env) (*parsed, error) {
	ap := &argParser{defs: specDefs(spec), helpText: spec.helpText, prog: "castctl " + spec.name}
	p, helpShown, err := ap.parse(args, env.stdout())
	if err != nil {
		if pe, ok := err.(*parserError); ok {
			fmt.Fprintf(env.stderr(), "castctl: %s\n", pe.msg)
			fmt.Fprintf(env.stderr(), "usage: castctl %s\n", usageLine(spec))
			return nil, errCode(2, pe)
		}
		return nil, err
	}
	if helpShown {
		return nil, errHelpShown
	}
	return p, nil
}

func specDefs(spec *commandSpec) []flagDef {
	if spec == nil || spec.handler == nil {
		return nil
	}
	if defs, ok := flagDefsByCommand[spec.name]; ok {
		return defs
	}
	return nil
}

// usageLine returns the one-line usage for a command (for parser
// errors). Kept short; --help prints the full text.
func usageLine(spec *commandSpec) string {
	if u, ok := usageByCommand[spec.name]; ok {
		return u
	}
	return spec.name
}

var flagDefsByCommand = map[string][]flagDef{}
var usageByCommand = map[string]string{}

func registerFlags(name string, usage string, defs []flagDef) {
	usageByCommand[name] = usage
	flagDefsByCommand[name] = defs
}
