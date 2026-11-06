// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

// Command m7b_driver is the Go side of the M7b Phase A parity
// gate (rust/parity/run_m7b_cases.sh): run the Go Phase A
// command implementations against a scripted gateway_server
// (serve-m7b mode) and print the CLI result shape + exit code,
// so the gate can diff it byte-for-byte against the Rust
// m7b_driver example run with the same script and argv.
//
// It CANNOT import internal/commands (unexported pendingApprovals
// / decideApproval / approveAll / printInviteText / writeMergedJSON
// / historyResult / eventMatchesRef / stringifyID), so it
// re-encodes those with local copies whose logic is copied
// verbatim from internal/commands/read.go and wait.go, calling
// the REAL exported pieces underneath: deliver.SessionStart /
// SessionOp / StopTurn / Wake, gateway.FetchInvite / CreateInvite
// / RedeemInviteCode, shared.SummarizeInvite / EventResources /
// SaveResources, approvals.DescribeApproval / OffersForever.
// That drift risk is bounded by Tier B (live CLI-vs-CLI byte
// equality on the real commands) and by the CLI's own unit
// tests. The error boundary is a local copy of
// internal/commands/classifyError over the raw error types
// (the commands package's cmdError/typedAuthError are
// unexported, so driver-side errCode equivalents use a local
// driverErr type classified first).
//
// The connection mirrors the real CLI: conn.Muse over the fake
// gateway connector (plain TCP dialer + canned auth), Connect
// returns a SharedConn lease; unary calls go through the
// lease's CallJSON (deliver.Gateway), downloads through the
// lease's DownloadFile. HTTPS steps (invite/redeem/wake/auth)
// go through an http.Client whose Transport is
// gatewaytest.HandlerRoundTripper over a handler that serves
// CannedAuth paths plus the case script's "http" map, logging
// every request as `M7B-HTTP <verb> <path> <body>` — the same
// lines the Python fake HTTP server logs for the Rust side.
//
// Usage:
//
//	m7b_driver --addr 127.0.0.1:PORT --script case.json
//	    [--download-dir DIR] <command> [args...]
//
// All credentials here are fake (hatch_sess=FAKE, AT-FAKE,
// HT-FAKE); nothing real is ever read.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/thoitiettxl-cyber/castctl/internal/approvals"
	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/deliver"
	"github.com/thoitiettxl-cyber/castctl/internal/gateway"
	"github.com/thoitiettxl-cyber/castctl/internal/gateway/gatewaytest"
	"github.com/thoitiettxl-cyber/castctl/internal/logging"
	"github.com/thoitiettxl-cyber/castctl/internal/shared"
)

const fakeCookie = "hatch_sess=FAKE; datr=FAKE"

// plainDialer is the minimal gateway.OutboundDialer for the
// fake server: plain TCP to the host:port the WS URL names
// (the fake server is loopback, no TLS), and the canned auth
// chain for the HTTPS steps. Copied from
// rust/parity/gateway_server/main.go (plainDialer); that file
// is the source of truth — keep the two in sync.
type plainDialer struct {
	auth http.Handler
}

func (d *plainDialer) WebSocketDial(ctx context.Context, network, host string, port uint16, secure bool, _ option.OutboundTLSOptions) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprint(port)))
}

func (d *plainDialer) HTTPClient() *http.Client {
	return &http.Client{Transport: gatewaytest.HandlerRoundTripper(d.auth)}
}

// --- driverErr: the local cmdError equivalent (errCode /
// errCodef in internal/commands). classifyError handles it
// first, exactly like the commands package handles cmdError.
type driverErr struct {
	code int
	msg  string // empty = silent (errCode with a nil error)
}

func (e *driverErr) Error() string { return e.msg }

func errCode(code int, msg string) error {
	if msg == "" {
		return &driverErr{code: code}
	}
	return &driverErr{code: code, msg: msg}
}

func errCodef(code int, format string, args ...any) error {
	return errCode(code, fmt.Sprintf(format, args...))
}

// classifyError mirrors internal/commands/classifyError
// (commands.go:268) over the raw error types the driver can
// see. Order matters: driverErr, typed auth (not producible
// here — no typedAuthError exists outside commands), bare
// auth, gateway, reassembly/too-many, timeout,
// DeadlineExceeded, Canceled, validation, ExitCode-bearing,
// else 1. The typed-JSON form is json.Marshal of a
// map[string]string, so keys sort (error before type).
// classifyAuthType mirrors internal/commands/classifyAuthMessage
// (commands.go:390) plus the "read cookies file" backstop from
// classifyConnError (commands.go:361): the typed auth taxonomy
// by message substring. The error field stays
// logging.SummarizeErr, as before — only the type varies.
// No harness case exercises this: the fake gateway server
// always handshakes, so a connect-path AuthError is not
// scriptable here (same limit as the Rust side, whose
// classifier is unit-tested instead).
func classifyAuthType(msg string) string {
	switch {
	case strings.Contains(msg, "read cookies file"),
		strings.Contains(msg, "could not parse cookies"),
		strings.Contains(msg, "no cookies"),
		strings.Contains(msg, "empty cookies"):
		return "cookies_missing"
	case strings.Contains(msg, "api/session"),
		strings.Contains(msg, "VM unavailable"):
		return "session_unavailable"
	case strings.Contains(msg, "auth/check"):
		return "auth_check_failed"
	case strings.Contains(msg, "hatch/token"):
		return "hatch_token_failed"
	default:
		return "auth_failed"
	}
}

func classifyError(err error) (int, string) {
	if err == nil {
		return 0, ""
	}
	var de *driverErr
	if errors.As(err, &de) {
		if de.msg == "" {
			return de.code, ""
		}
		return de.code, "castctl: " + logging.SummarizeErr(err)
	}
	var auth *conn.AuthError
	if errors.As(err, &auth) {
		msg := logging.SummarizeErr(err)
		b, _ := json.Marshal(map[string]string{"type": classifyAuthType(auth.Error()), "error": msg})
		return 2, string(b)
	}
	var gw *conn.GatewayError
	if errors.As(err, &gw) {
		// Go `classifyConnError` (`commands.go:361`): a
		// GatewayError with status -1 whose payload says
		// "VM unavailable" is the session endpoint
		// answering without a vm_id — typed
		// `session_unavailable`, exit 2, not the plain
		// exit-3 path below. (No harness case exercises
		// it: the fake gateway always handshakes.)
		if gw.Status == -1 && strings.Contains(gw.Payload, "VM unavailable") {
			msg := logging.SummarizeErr(err)
			b, _ := json.Marshal(map[string]string{"type": "session_unavailable", "error": msg})
			return 2, string(b)
		}
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
	var verr *gateway.ValidationError
	if errors.As(err, &verr) {
		return 2, "castctl: " + logging.SummarizeErr(err)
	}
	if ec, ok := err.(interface{ ExitCode() int }); ok {
		return ec.ExitCode(), "castctl: " + logging.SummarizeErr(err)
	}
	return 1, "castctl: " + logging.SummarizeErr(err)
}

// writeJSON writes v as indented JSON (2 spaces, HTML
// unescaped) plus a trailing newline — verbatim
// internal/commands/writeJSON (commands.go:411).
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

// decodeJSONNumber decodes data with json.Number preserved,
// mirroring Python's int/float fidelity for --raw passthrough
// (commands.go:440). It ignores trailing data, unlike the
// gateway's strict decodeJSONValue.
func decodeJSONNumber(data []byte) (any, error) {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

// --- minimal argv scanner (valid-argv cases only; the
// harness never feeds usage errors through the driver) ---
type argv struct {
	positionals []string
	bools       map[string]bool
	strs        map[string]string
	strsSet     map[string]bool
	lists       map[string][]string
	ints        map[string]int64
}

func parseArgv(args []string) *argv {
	a := &argv{
		bools:   map[string]bool{},
		strs:    map[string]string{},
		strsSet: map[string]bool{},
		lists:   map[string][]string{},
		// Flag defaults from the command table (read.go:54,67):
		// download --limit 50, raw --timeout 30.
		ints: map[string]int64{"limit": 50, "timeout": 30},
	}
	i := 0
	for i < len(args) {
		tok := args[i]
		i++
		if tok == "--" {
			a.positionals = append(a.positionals, args[i:]...)
			break
		}
		if strings.HasPrefix(tok, "--") {
			name := strings.TrimPrefix(tok, "--")
			val := ""
			hasVal := false
			if k, v, ok := strings.Cut(name, "="); ok {
				name, val, hasVal = k, v, true
			}
			switch name {
			case "create", "json", "raw", "recent", "approve-all", "all",
				"once", "session", "today", "always", "force":
				a.bools[name] = true
			case "title", "thread", "output", "body", "reaction":
				if !hasVal {
					if i < len(args) {
						val = args[i]
						i++
					}
				}
				a.strs[name] = val
				a.strsSet[name] = true
			case "limit", "timeout":
				if !hasVal {
					if i < len(args) {
						val = args[i]
						i++
					}
				}
				if n, err := strconv.ParseInt(val, 10, 64); err == nil {
					a.ints[name] = n
				}
				a.strs[name] = val
				a.strsSet[name] = true
			case "param":
				if !hasVal {
					if i < len(args) {
						val = args[i]
						i++
					}
				}
				a.lists["param"] = append(a.lists["param"], val)
			default:
				// Unknown flags are ignored: the harness only
				// passes flags the command table defines.
			}
			continue
		}
		if strings.HasPrefix(tok, "-") && len(tok) == 2 {
			switch tok[1] {
			case 'o':
				if i < len(args) {
					a.strs["output"] = args[i]
					a.strsSet["output"] = true
					i++
				}
			case 'f':
				a.bools["force"] = true
			}
			continue
		}
		a.positionals = append(a.positionals, tok)
	}
	return a
}

func (a *argv) bool(name string) bool    { return a.bools[name] }
func (a *argv) str(name string) string   { return a.strs[name] }
func (a *argv) strSet(name string) bool  { return a.strsSet[name] }
func (a *argv) intVal(name string) int64 { return a.ints[name] }

// --- approvals shaping: verbatim copies from
// internal/commands/wait.go (pendingApprovals,
// describeApprovals, decideApproval, approveAll,
// approvalJSON/approvedJSON/recentJSON/approvalsJSON/
// approvedListJSON, toApprovalJSON, structural helpers).
// The driver passes the lease gw where the CLI passes rt.

func pendingApprovals(ctx context.Context, gw conn.Gateway) (any, []any, error) {
	v, err := gw.CallJSON(ctx, "egress.approvals", conn.RequestOptions{})
	if err != nil {
		return nil, nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, nil, fmt.Errorf("gateway: egress.approvals result is not an object: %T", v)
	}
	var pend []any
	// Python `or` semantics: an empty first list falls through
	// to the fallback key (r.get("pending_approvals") or
	// r.get("pending") or []).
	if p, ok := m["pending_approvals"].([]any); ok && len(p) > 0 {
		pend = p
	} else if p, ok := m["pending"].([]any); ok {
		pend = p
	}
	return v, pend, nil
}

type approvalJSON struct {
	ApprovalID  *string  `json:"approval_id"`
	Title       *string  `json:"title"`
	Question    *string  `json:"question"`
	Kind        *string  `json:"kind"`
	Scope       *string  `json:"scope"`
	Why         *string  `json:"why"`
	ExpiresAtMS *float64 `json:"expires_at_ms"`
	Options     []string `json:"options"`
}

type approvedJSON struct {
	ApprovalID *string `json:"approval_id"`
	Title      *string `json:"title"`
	Kind       *string `json:"kind"`
	Scope      *string `json:"scope"`
	Decision   *string `json:"decision"`
}

type approvalsJSON struct {
	Pending []approvalJSON `json:"pending"`
	Recent  *[]recentJSON  `json:"recent,omitempty"`
}

type recentJSON struct {
	approvalJSON
	Decision any `json:"decision"`
}

type approvedListJSON struct {
	Approved []approvedJSON `json:"approved"`
}

func strPtrOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func toApprovalJSON(d approvals.DescribedApproval) approvalJSON {
	return approvalJSON{
		ApprovalID:  d.ApprovalID,
		Title:       d.Title,
		Question:    d.Question,
		Kind:        d.Kind,
		Scope:       d.Scope,
		Why:         d.Why,
		ExpiresAtMS: d.ExpiresAtMS,
		Options:     d.Options,
	}
}

func describeApprovals(list []any) []approvalJSON {
	out := make([]approvalJSON, 0, len(list))
	for _, item := range list {
		out = append(out, toApprovalJSON(approvals.DescribeApproval(item)))
	}
	return out
}

func decideApproval(ctx context.Context, gw conn.Gateway, approvalID, decision string) (any, error) {
	return gw.CallJSON(ctx, "egress.approval.decide", conn.RequestOptions{
		PathParams: map[string]string{"approval_id": approvalID},
		Body:       map[string]any{"decision": decision},
	})
}

func structuralApprovalID(id string) string {
	n := 0
	for _, r := range id {
		n++
		if n > 64 {
			return "[omitted]"
		}
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return "[omitted]"
		}
	}
	if n == 0 {
		return "[omitted]"
	}
	return id
}

var structuralDecisions = map[string]bool{
	"allow_always":  true,
	"allow_once":    true,
	"allow_session": true,
	"allow_today":   true,
}

var structuralKinds = map[string]bool{
	"browse":         true,
	"network_access": true,
	"shell":          true,
}

func structuralEnum(s string, allowed map[string]bool) string {
	if allowed[s] {
		return s
	}
	return "[omitted]"
}

func structuralDecision(s string) string { return structuralEnum(s, structuralDecisions) }
func structuralKind(s string) string     { return structuralEnum(s, structuralKinds) }
func structuralScope(_ string) string    { return "[omitted]" }

func approveAll(ctx context.Context, gw conn.Gateway, decision string) ([]approvedJSON, error) {
	_, pend, err := pendingApprovals(ctx, gw)
	if err != nil {
		return nil, err
	}
	done := []approvedJSON{}
	for _, item := range pend {
		d := approvals.DescribeApproval(item)
		if decision == approvals.Forever && !approvals.OffersForever(d) {
			fmt.Fprintf(os.Stderr, "skipped %s: no forever option option_count=%d\n", structuralApprovalID(derefStr(d.ApprovalID)), len(d.Options))
			continue
		}
		if _, err := decideApproval(ctx, gw, derefStr(d.ApprovalID), decision); err != nil {
			return nil, err
		}
		row := approvedJSON{
			ApprovalID: strPtrOrNil(derefStr(d.ApprovalID)), Title: strPtrOrNil(derefStr(d.Title)),
			Kind: strPtrOrNil(derefStr(d.Kind)), Scope: strPtrOrNil(derefStr(d.Scope)), Decision: strPtrOrNil(decision),
		}
		done = append(done, row)
		fmt.Fprintf(os.Stderr, "approved %s (%s): title_length=%d [%s %s]\n", structuralApprovalID(derefStr(row.ApprovalID)), structuralDecision(decision), len(derefStr(row.Title)), structuralKind(derefStr(row.Kind)), structuralScope(derefStr(row.Scope)))
	}
	return done, nil
}

func approveDecision(a *argv) (string, error) {
	var seen string
	count := 0
	decision := "allow_once"
	for _, k := range []string{"once", "session", "today", "always"} {
		if a.bool(k) {
			count++
			if count == 1 {
				seen = k
				decision = "allow_" + k
			} else {
				return "", fmt.Errorf("argument --%s: not allowed with argument --%s", k, seen)
			}
		}
	}
	return decision, nil
}

// --- invite/redeem rendering: verbatim from read.go ---

func printInviteText(w io.Writer, s shared.InviteSummary) {
	code := ptrStr(s.Code)
	if code != "" {
		fmt.Fprintf(w, "Invite code: %s\n", code)
		if link := ptrStr(s.Link); link != "" {
			fmt.Fprintf(w, "Link: %s\n", link)
		}
		if s.UsesRemaining != nil {
			extra := ""
			if s.MaxUses != nil {
				extra = fmt.Sprintf(" of %d", *s.MaxUses)
			}
			fmt.Fprintf(w, "Uses left: %d%s\n", *s.UsesRemaining, extra)
		}
	} else {
		fmt.Fprintf(w, "Invite code: none yet (state %s). Open Invite friends in the muse.ai app once, or run `castctl invite --create`.\n", ptrStr(s.State))
	}
	if s.Reward != nil {
		parts := []string{}
		if t := ptrStr(s.Reward.Title); t != "" {
			parts = append(parts, t)
		}
		if b := ptrStr(s.Reward.Body); b != "" {
			parts = append(parts, b)
		}
		if len(parts) > 0 {
			fmt.Fprintln(w, strings.Join(parts, " "))
		}
	}
	if offer := ptrStr(s.Offer); offer != "" {
		fmt.Fprintln(w, offer)
	}
}

func ptrStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func redeemErrorBody(body map[string]any) map[string]any {
	out := map[string]any{}
	for _, k := range []string{"success", "reason", "detail"} {
		if v, ok := body[k]; ok {
			out[k] = v
		}
	}
	return out
}

func writeMergedJSON(w io.Writer, status int, body map[string]any) error {
	var b strings.Builder
	b.WriteString("{\n")
	fmt.Fprintf(&b, "  \"status\": %d", status)
	keys := sortedKeys(body)
	for _, k := range keys {
		kb, err := json.Marshal(k)
		if err != nil {
			return err
		}
		vb, err := marshalJSONIndent(body[k])
		if err != nil {
			return err
		}
		b.WriteString(",\n  ")
		b.Write(kb)
		b.WriteString(": ")
		b.Write(vb)
	}
	b.WriteString("\n}\n")
	_, err := io.WriteString(w, b.String())
	return err
}

func marshalJSONIndent(v any) ([]byte, error) {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("  ", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return []byte(strings.TrimSuffix(b.String(), "\n")), nil
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// --- history/download helpers: verbatim from read.go ---

func historyResult(ctx context.Context, gw conn.Gateway, thread string, limit int64) (map[string]any, []any, error) {
	body := map[string]any{"limit": limit}
	if thread != "" {
		body["session_id"] = thread
	}
	v, err := gw.CallJSON(ctx, "chat.history", conn.RequestOptions{Body: body})
	if err != nil {
		return nil, nil, err
	}
	d, ok := v.(map[string]any)
	if !ok {
		return nil, nil, fmt.Errorf("gateway: chat.history result is not an object: %T", v)
	}
	events, _ := d["chat_events"].([]any)
	return d, events, nil
}

func eventMatchesRef(ev map[string]any, ref string) bool {
	p, _ := ev["payload"].(map[string]any)
	ids := []string{}
	if seq, ok := ev["seq"]; ok {
		ids = append(ids, stringifyID(seq))
	}
	if p != nil {
		ids = append(ids, stringifyID(p["message_id"]), stringifyID(p["id"]))
	}
	ids = append(ids, stringifyID(ev["message_id"]))
	for _, id := range ids {
		if id != "" && id == ref {
			return true
		}
	}
	return false
}

func stringifyID(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case json.Number:
		return t.String()
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		if t {
			return "True"
		}
		return "False"
	default:
		return fmt.Sprintf("%v", v)
	}
}

func appendIfMissingPath(res []shared.Resource, r shared.Resource) []shared.Resource {
	for _, x := range res {
		if x.Path == r.Path {
			return res
		}
	}
	return append(res, r)
}

// --- fake HTTPS handler: CannedAuth paths + the case script's
// "http" map, logging every request as
// `M7B-HTTP <verb> <path> <body>` (the same lines the Python
// fake HTTP server logs for the Rust side). ---

type m7bEntry struct {
	Status int             `json:"status"`
	Result json.RawMessage `json:"result"`
	RawB64 string          `json:"raw_b64"`
	Body   string          `json:"body"`
	// Stages answers the Nth request to this path with
	// stages[N-1] (the last repeats), for flows where the
	// same endpoint must answer differently across calls
	// (invite --create: first GET has no code, the GET after
	// the POST has one).
	Stages []m7bEntry `json:"stages"`
}

type m7bScript struct {
	Gateway map[string]m7bEntry `json:"gateway"`
	HTTP    map[string]m7bEntry `json:"http"`
}

type httpHandler struct {
	auth   *gatewaytest.CannedAuth
	script *m7bScript
	mu     sync.Mutex
	counts map[string]int
}

func (h *httpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(r.Body)
	}
	fmt.Fprintf(os.Stderr, "M7B-HTTP %s %s %s\n", r.Method, r.URL.Path, string(body))
	switch r.URL.Path {
	case "/api/session", "/api/auth/check", "/api/hatch/token":
		h.auth.ServeHTTP(w, r)
		return
	}
	entry, ok := h.script.HTTP[r.URL.Path]
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(404)
		fmt.Fprintf(w, `{"error":"m7b-http: no canned response for %s"}`, r.URL.Path)
		return
	}
	if len(entry.Stages) > 0 {
		h.mu.Lock()
		n := h.counts[r.URL.Path]
		h.counts[r.URL.Path] = n + 1
		h.mu.Unlock()
		if n >= len(entry.Stages) {
			n = len(entry.Stages) - 1
		}
		entry = entry.Stages[n]
	}
	status := entry.Status
	if status == 0 {
		status = 200
	}
	w.Header().Set("Content-Type", "application/json")
	switch {
	case entry.RawB64 != "":
		raw, err := base64.StdEncoding.DecodeString(entry.RawB64)
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprint(w, `{"error":"m7b-http: bad raw_b64"}`)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write(raw)
	case entry.Body != "":
		w.WriteHeader(status)
		fmt.Fprint(w, entry.Body)
	case entry.Result != nil:
		w.WriteHeader(status)
		_, _ = w.Write(entry.Result)
	default:
		w.WriteHeader(status)
		fmt.Fprint(w, `{}`)
	}
}

// --- command dispatch: mirrors the CLI handlers in
// internal/commands/read.go and wait.go, with the lease gw
// in place of rt.Muse.WithGateway (decision 2: equivalent
// for single unary calls — same retry path, only connection
// reuse differs, unobservable in request/response bytes).

func runCommand(ctx context.Context, gw conn.Gateway, httpClient *http.Client, cmd string, a *argv, downloadDir string) error {
	switch cmd {
	case "session-start":
		v, err := deliver.SessionStart(ctx, gw, a.str("title"))
		if err != nil {
			return err
		}
		return writeJSON(os.Stdout, v)
	case "session-rename", "session-pin", "session-unpin", "session-archive", "session-unarchive", "session-delete":
		kind := strings.TrimPrefix(cmd, "session-")
		id := ""
		if len(a.positionals) > 0 {
			id = a.positionals[0]
		}
		title := ""
		if len(a.positionals) > 1 {
			title = a.positionals[1]
		}
		v, err := deliver.SessionOp(ctx, gw, deliver.SessionOpKind(kind), id, title)
		if err != nil {
			return err
		}
		return writeJSON(os.Stdout, v)
	case "stop":
		v, err := deliver.StopTurn(ctx, gw, a.str("thread"))
		if err != nil {
			return err
		}
		return writeJSON(os.Stdout, v)
	case "seen":
		thread := ""
		if len(a.positionals) > 0 {
			thread = a.positionals[0]
		}
		v, err := gw.CallJSON(ctx, "chat.mark_seen", conn.RequestOptions{
			PathParams: map[string]string{"thread_id": thread},
		})
		if err != nil {
			return err
		}
		return writeJSON(os.Stdout, v)
	case "feed-react":
		unit := ""
		if len(a.positionals) > 0 {
			unit = a.positionals[0]
		}
		reaction := "love"
		if len(a.positionals) > 1 {
			reaction = a.positionals[1]
		}
		v, err := gw.CallJSON(ctx, "feed.unit.reaction", conn.RequestOptions{
			PathParams: map[string]string{"unit_id": unit},
			Body:       map[string]any{"reaction": reaction},
		})
		if err != nil {
			return err
		}
		return writeJSON(os.Stdout, v)
	case "idea-exec":
		id := ""
		if len(a.positionals) > 0 {
			id = a.positionals[0]
		}
		body := map[string]any{"ideaCardId": id, "mode": "full"}
		if thread := a.str("thread"); thread != "" {
			body["session_id"] = thread
		}
		v, err := gw.CallJSON(ctx, "api.idea-cards.execute", conn.RequestOptions{
			PathParams: map[string]string{"ideaCardId": id},
			Body:       body,
		})
		if err != nil {
			return err
		}
		return writeJSON(os.Stdout, v)
	case "approvals":
		if a.bool("approve-all") {
			done, err := approveAll(ctx, gw, approvals.Forever)
			if err != nil {
				return err
			}
			return writeJSON(os.Stdout, approvedListJSON{Approved: done})
		}
		raw, pend, err := pendingApprovals(ctx, gw)
		if err != nil {
			return err
		}
		if a.bool("raw") {
			return writeJSON(os.Stdout, raw)
		}
		out := approvalsJSON{Pending: describeApprovals(pend)}
		if a.bool("recent") {
			m, _ := raw.(map[string]any)
			var recent []any
			if r, ok := m["recent_approvals"].([]any); ok && len(r) > 0 {
				recent = r
			} else if r, ok := m["recent"].([]any); ok {
				recent = r
			}
			rows := []recentJSON{}
			for _, item := range recent {
				d := approvals.DescribeApproval(item)
				decision := any(nil)
				if row, ok := item.(map[string]any); ok {
					decision = row["decision"]
				}
				rows = append(rows, recentJSON{approvalJSON: toApprovalJSON(d), Decision: decision})
			}
			out.Recent = &rows
		}
		return writeJSON(os.Stdout, out)
	case "approve":
		decision, err := approveDecision(a)
		if err != nil {
			return errCode(2, err.Error())
		}
		id := ""
		if len(a.positionals) == 1 {
			id = a.positionals[0]
		}
		if a.bool("all") == (id != "") {
			return errCode(2, "give an approval ID or --all (not both)")
		}
		if a.bool("all") {
			done, err := approveAll(ctx, gw, decision)
			if err != nil {
				return err
			}
			return writeJSON(os.Stdout, approvedListJSON{Approved: done})
		}
		res, err := decideApproval(ctx, gw, id, decision)
		if err != nil {
			return err
		}
		return writeJSON(os.Stdout, res)
	case "deny":
		decision := "deny"
		if a.bool("always") {
			decision = "deny_always"
		}
		id := ""
		if len(a.positionals) > 0 {
			id = a.positionals[0]
		}
		res, err := decideApproval(ctx, gw, id, decision)
		if err != nil {
			return err
		}
		return writeJSON(os.Stdout, res)
	case "invite":
		d, err := gateway.FetchInvite(ctx, httpClient, fakeCookie)
		if err != nil {
			return err
		}
		if a.bool("create") {
			if code, _ := d["code"].(string); code == "" {
				if _, err := gateway.CreateInvite(ctx, httpClient, fakeCookie); err != nil {
					return err
				}
				d, err = gateway.FetchInvite(ctx, httpClient, fakeCookie)
				if err != nil {
					return err
				}
			}
		}
		if a.bool("raw") {
			return writeJSON(os.Stdout, d)
		}
		s := shared.SummarizeInvite(d)
		if a.bool("json") {
			return writeJSON(os.Stdout, s)
		}
		printInviteText(os.Stdout, s)
		return nil
	case "redeem":
		code := ""
		if len(a.positionals) > 0 {
			code = a.positionals[0]
		}
		status, body, err := gateway.RedeemInviteCode(ctx, httpClient, fakeCookie, code)
		if err != nil {
			return err
		}
		bodyMap, _ := body.(map[string]any)
		if bodyMap == nil {
			bodyMap = map[string]any{}
		}
		success, _ := bodyMap["success"].(bool)
		if a.bool("json") {
			if !success {
				bodyMap = redeemErrorBody(bodyMap)
			}
			if err := writeMergedJSON(os.Stdout, status, bodyMap); err != nil {
				return err
			}
		} else if success {
			redemption, _ := bodyMap["redemptionStatus"].(string)
			if redemption == "" {
				redemption = "ok"
			}
			fmt.Fprintf(os.Stdout, "Redeemed: %s\n", redemption)
		} else {
			reason, _ := bodyMap["reason"].(string)
			detail, _ := bodyMap["detail"].(string)
			line := fmt.Sprintf("Not redeemed (%s): %s", reason, detail)
			fmt.Fprintln(os.Stdout, strings.TrimRight(line, ": "))
		}
		if !success {
			return errCode(1, "")
		}
		return nil
	case "wake":
		res, err := deliver.Wake(ctx, deliver.WakeDeps{
			Client:  httpClient,
			Cookies: fakeCookie,
			VMID:    "",
			WakeVM:  gateway.WakeVM,
		})
		if err != nil {
			return err
		}
		return writeJSON(os.Stdout, res)
	case "download":
		ref := ""
		if len(a.positionals) > 0 {
			ref = a.positionals[0]
		}
		dir := downloadDir
		if a.strSet("output") {
			dir = a.str("output")
		}
		var resources []shared.Resource
		if strings.HasPrefix(ref, "sandbox://") || strings.Contains(ref, "/media/raw/") {
			resources = []shared.Resource{{Path: ref}}
		} else {
			_, events, err := historyResult(ctx, gw, a.str("thread"), a.intVal("limit"))
			if err != nil {
				return err
			}
			for _, e := range events {
				ev, ok := e.(map[string]any)
				if !ok {
					continue
				}
				if !eventMatchesRef(ev, ref) {
					continue
				}
				for _, r := range shared.EventResources(ev) {
					resources = appendIfMissingPath(resources, r)
				}
			}
			if len(resources) == 0 {
				thread := a.str("thread")
				where := " of the main chat"
				if thread != "" {
					where = " of thread " + thread
				}
				return errCodef(1, "no files found for '%s' in the last %d messages%s (try --thread / --limit)", ref, a.intVal("limit"), where)
			}
		}
		rows, err := shared.SaveResources(ctx, gw, resources, dir, a.bool("force"))
		if err != nil {
			return err
		}
		if err := writeJSON(os.Stdout, rows); err != nil {
			return err
		}
		for _, r := range rows {
			if r.Error != "" {
				return errCode(3, "")
			}
		}
		return nil
	case "raw":
		method := ""
		if len(a.positionals) > 0 {
			method = a.positionals[0]
		}
		table, err := gateway.DefaultRoutes()
		if err != nil {
			return err
		}
		if _, ok := table.LookupRoute(method); !ok {
			return errCodef(2, "unknown method '%s' (see routes.json for the %d known methods)", method, table.Total())
		}
		var body any
		if bodyStr := a.str("body"); bodyStr != "" {
			v, err := decodeJSONNumber([]byte(bodyStr))
			if err != nil {
				return errCodef(2, "invalid --body JSON: %s", err.Error())
			}
			body = v
		}
		pathParams := map[string]string{}
		for _, kv := range a.lists["param"] {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				return errCodef(2, "bad --param '%s': expected k=v", kv)
			}
			pathParams[k] = v
		}
		if len(pathParams) == 0 {
			pathParams = nil
		}
		timeout := time.Duration(a.intVal("timeout")) * time.Second
		data, err := gw.Request(ctx, method, conn.RequestOptions{
			Body:       body,
			PathParams: pathParams,
			Timeout:    timeout,
		})
		if err != nil {
			return err
		}
		if len(data) == 0 {
			return writeJSON(os.Stdout, map[string]any{})
		}
		v, err := decodeJSONNumber(data)
		if err != nil {
			fmt.Fprintln(os.Stdout, string(data))
			return nil
		}
		return writeJSON(os.Stdout, v)
	default:
		return errCodef(2, "m7b_driver: unknown command %q", cmd)
	}
}

func run() int {
	addr := flag.String("addr", "", "fake gateway addr 127.0.0.1:PORT (required)")
	scriptPath := flag.String("script", "", "case script JSON (required)")
	downloadDir := flag.String("download-dir", "", "download output dir (default: fresh temp dir)")
	flag.Parse()
	if *addr == "" || *scriptPath == "" {
		fmt.Fprintln(os.Stderr, "m7b_driver: --addr and --script are required")
		return 2
	}
	rest := flag.Args()
	if len(rest) == 0 {
		fmt.Fprintln(os.Stderr, "m7b_driver: a command is required")
		return 2
	}
	cmd, args := rest[0], rest[1:]
	rawScript, err := os.ReadFile(*scriptPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "m7b_driver: script:", err)
		return 1
	}
	var script m7bScript
	if err := json.Unmarshal(rawScript, &script); err != nil {
		fmt.Fprintln(os.Stderr, "m7b_driver: script:", err)
		return 1
	}
	dir := *downloadDir
	if dir == "" {
		tmp, err := os.MkdirTemp("", "m7b-driver-dl-*")
		if err != nil {
			fmt.Fprintln(os.Stderr, "m7b_driver:", err)
			return 1
		}
		defer os.RemoveAll(tmp)
		dir = tmp
	}

	auth := &gatewaytest.CannedAuth{VMID: "vm-test", AccessToken: "AT-FAKE", HatchToken: "HT-FAKE"}
	dialer := &plainDialer{auth: auth}
	cookiesTmp, err := os.CreateTemp("", "m7b-driver-cookies-*.txt")
	if err != nil {
		fmt.Fprintln(os.Stderr, "m7b_driver:", err)
		return 1
	}
	cookiesFile := cookiesTmp.Name()
	if _, err := cookiesTmp.Write([]byte(fakeCookie)); err != nil {
		cookiesTmp.Close()
		os.Remove(cookiesFile)
		fmt.Fprintln(os.Stderr, "m7b_driver:", err)
		return 1
	}
	if err := cookiesTmp.Close(); err != nil {
		os.Remove(cookiesFile)
		fmt.Fprintln(os.Stderr, "m7b_driver:", err)
		return 1
	}
	defer os.Remove(cookiesFile)

	connect := gateway.NewConnector(
		dialer,
		gateway.WithWebSocketSecure(false),
		gateway.WithWSURL(func(vmID, token string) string {
			// The canned hatch token from CannedAuth,
			// interpolated (it needs no URL-quoting). Do
			// NOT put the placeholder literal the M7a
			// drivers carry in the format string: Sprintf
			// then has 2 verbs for 3 args and appends
			// `%!(EXTRA string=HT-FAKE)`, and gorilla sends
			// the raw `<`/`>` in the query while the Go
			// server answers the handshake 400 (the Rust
			// client percent-encodes them and connects) —
			// so the literal breaks the Go side only. (The
			// M7a wait_driver carries the same latent bug.)
			return fmt.Sprintf("ws://%s/v1/noise?vm_id=%s&auth_token=%s", *addr, vmID, token)
		}),
	)
	muse := conn.New(connect, conn.WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	gw, err := muse.Connect(ctx, &conn.Config{CookiesFile: cookiesFile, VMID: "vm-test"})
	if err != nil {
		fmt.Fprintln(os.Stderr, "m7b_driver: connect:", err)
		return 1
	}
	defer gw.Close()

	httpClient := &http.Client{Transport: gatewaytest.HandlerRoundTripper(&httpHandler{auth: auth, script: &script, counts: map[string]int{}})}
	if err := runCommand(ctx, gw, httpClient, cmd, parseArgv(args), dir); err != nil {
		code, text := classifyError(err)
		if text != "" {
			fmt.Fprintln(os.Stderr, text)
		}
		return code
	}
	return 0
}

func main() {
	os.Exit(run())
}
