// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
	"github.com/thoitiettxl-cyber/castctl/internal/gateway"
	"github.com/thoitiettxl-cyber/castctl/internal/profile"
	"github.com/thoitiettxl-cyber/castctl/internal/shared"
)

func init() {
	boolFlag := func(name string) flagDef { return flagDef{name: name, kind: flagBool} }
	strFlag := func(name string) flagDef { return flagDef{name: name, kind: flagString} }
	registerCommand(&commandSpec{name: "status", help: "VM, session count, unread, identity", helpText: statusHelpText, handler: cmdStatus})
	registerCommand(&commandSpec{name: "usage", help: "plan usage: weekly limit % used, reset date, bonus tokens", helpText: usageHelpText, handler: cmdUsage})
	registerCommand(&commandSpec{name: "invite", help: "your invite code, uses left, rewards earned (read-only)", helpText: inviteHelpText, handler: cmdInvite})
	registerCommand(&commandSpec{name: "redeem", help: "redeem a friend's invite code (within 48h of joining)", helpText: redeemHelpText, handler: cmdRedeem})
	registerCommand(&commandSpec{name: "threads", help: "list chats and side chats", helpText: threadsHelpText, handler: cmdThreads})
	registerCommand(&commandSpec{name: "history", help: "read chat messages", helpText: historyHelpText, handler: cmdHistory})
	registerCommand(&commandSpec{name: "files", help: "list files (images/videos) in recent messages", helpText: filesHelpText, handler: cmdFiles})
	registerCommand(&commandSpec{name: "download", help: "download a file the agent produced", helpText: downloadHelpText, handler: cmdDownload})
	registerCommand(&commandSpec{name: "watch", help: "tail live agent events", helpText: watchHelpText, handler: cmdWatch})
	registerCommand(&commandSpec{name: "feed", help: "list feed units", helpText: feedHelpText, handler: cmdFeed})
	registerCommand(&commandSpec{name: "feed-status", help: "feed refresh status", helpText: feedStatusHelpText, handler: cmdFeedStatus})
	registerCommand(&commandSpec{name: "feed-react", help: "react to a feed unit", helpText: feedReactHelpText, handler: cmdFeedReact})
	registerCommand(&commandSpec{name: "feed-prompt", help: "show feed prompt", helpText: feedPromptHelpText, handler: cmdFeedPrompt})
	registerCommand(&commandSpec{name: "goals", help: "list goals", helpText: goalsHelpText, handler: cmdGoals})
	registerCommand(&commandSpec{name: "goal", help: "show one goal", helpText: goalHelpText, handler: cmdGoal})
	registerCommand(&commandSpec{name: "ideas", help: "list idea cards", helpText: ideasHelpText, handler: cmdIdeas})
	registerCommand(&commandSpec{name: "idea", help: "show one idea", helpText: ideaHelpText, handler: cmdIdea})
	registerCommand(&commandSpec{name: "idea-exec", help: "execute an idea (agent acts on it)", helpText: ideaExecHelpText, handler: cmdIdeaExec})
	registerCommand(&commandSpec{name: "unread", help: "unread counts", helpText: unreadHelpText, handler: cmdUnread})
	registerCommand(&commandSpec{name: "seen", help: "mark a thread seen", helpText: seenHelpText, handler: cmdSeen})
	registerCommand(&commandSpec{name: "raw", help: "call any gateway method (escape hatch)", helpText: rawHelpText, handler: cmdRaw})

	registerFlags("status", "status", nil)
	registerFlags("usage", "usage [--json] [--raw]", []flagDef{boolFlag("json"), boolFlag("raw")})
	registerFlags("invite", "invite [--create] [--json] [--raw]", []flagDef{boolFlag("json"), boolFlag("raw"), boolFlag("create")})
	registerFlags("redeem", "redeem CODE [--json]", []flagDef{boolFlag("json")})
	registerFlags("threads", "threads [--all]", []flagDef{boolFlag("all")})
	registerFlags("history", "history [--thread ID] [--limit N] [--raw] [--download DIR]", []flagDef{strFlag("thread"), intFlag("limit", 0, 10), boolFlag("raw"), strFlag("download")})
	registerFlags("files", "files [--thread ID] [--limit N]", []flagDef{strFlag("thread"), intFlag("limit", 0, 20)})
	registerFlags("download", "download REF [-o DIR] [--thread ID] [--limit N] [-f]", []flagDef{{name: "output", short: 'o', kind: flagString}, strFlag("thread"), intFlag("limit", 0, 50), {name: "force", short: 'f', kind: flagBool}})
	registerFlags("watch", "watch [--timeout SECONDS] [--n N] [--all] [--thread ID]", []flagDef{intFlag("timeout", 0, 60), intFlag("n", 0, 50), boolFlag("all"), strFlag("thread")})
	registerFlags("feed", "feed [--limit N] [--raw]", []flagDef{{name: "limit", kind: flagInt}, boolFlag("raw")})
	registerFlags("feed-status", "feed-status", nil)
	registerFlags("feed-react", "feed-react UNIT [REACTION]", nil)
	registerFlags("feed-prompt", "feed-prompt", nil)
	registerFlags("goals", "goals", nil)
	registerFlags("goal", "goal ID", nil)
	registerFlags("ideas", "ideas", nil)
	registerFlags("idea", "idea ID", nil)
	registerFlags("idea-exec", "idea-exec ID [--thread ID]", []flagDef{strFlag("thread")})
	registerFlags("unread", "unread", nil)
	registerFlags("seen", "seen THREAD", nil)
	registerFlags("raw", "raw METHOD [--body JSON] [--param KEY=VALUE] [--timeout SECONDS]", []flagDef{strFlag("body"), {name: "param", kind: flagStringList}, intFlag("timeout", 0, 30)})
}

// runNetwork resolves config + active profile, builds the runtime,
// runs fn, and closes the runtime in reverse order even on failure.
// Gateway/auth failures from fn are classified into the typed auth
// taxonomy.
func runNetwork(ctx context.Context, env *Env, g *globalOpts, fn func(*Runtime) error) error {
	return runWithProfile(ctx, env, g, func(loc *profile.ConfigLocation, prof *profile.Profile) error {
		rt, err := env.buildRuntime(ctx, loc, prof)
		if err != nil {
			return err
		}
		defer func() { _ = rt.Close() }()
		if err := fn(rt); err != nil {
			return classifyConnError(err)
		}
		return nil
	})
}

// callJSON is one unary call through the shared connection.
func callJSON(ctx context.Context, rt *Runtime, method string, opts conn.RequestOptions) (any, error) {
	return rt.Muse.Call(ctx, method, opts)
}

func callMap(ctx context.Context, rt *Runtime, method string, opts conn.RequestOptions) (map[string]any, error) {
	v, err := callJSON(ctx, rt, method, opts)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("gateway: %s result is not an object: %T", method, v)
	}
	return m, nil
}

// statusVMID resolves the vm_id status prints: the profile's vm_id
// when configured, else FetchSessionInfo over the dialer HTTP
// client. The conn.Gateway interface exposes no vm_id accessor, so
// this extra HTTPS call is the only way to print the gateway's id
// when the profile does not carry one; it is documented in the
// final report.
func statusVMID(ctx context.Context, rt *Runtime) (string, error) {
	if rt.Profile.VMID != "" {
		return rt.Profile.VMID, nil
	}
	cookies, err := rt.Cookies()
	if err != nil {
		return "", err
	}
	info, err := gateway.FetchSessionInfo(ctx, rt.HTTPClient(), cookies)
	if err != nil {
		return "", err
	}
	return info.VMID, nil
}

func cmdStatus(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := parseOrHelp(commandTable["status"], args, env)
	if err != nil {
		return err
	}
	if err := checkPositionals(p, nil, "status"); err != nil {
		return usageErr(err)
	}
	return runNetwork(ctx, env, g, func(rt *Runtime) error {
		sessions, err := callMap(ctx, rt, "sessions.list", conn.RequestOptions{})
		if err != nil {
			return err
		}
		unread, err := callJSON(ctx, rt, "chat.unread_count", conn.RequestOptions{})
		if err != nil {
			return err
		}
		identity, err := callJSON(ctx, rt, "identity", conn.RequestOptions{})
		if err != nil {
			return err
		}
		vmID, err := statusVMID(ctx, rt)
		if err != nil {
			return err
		}
		return writeJSON(env.stdout(), shared.SummarizeStatus(vmID, sessions, unread, identity))
	})
}

func cmdUsage(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := parseOrHelp(commandTable["usage"], args, env)
	if err != nil {
		return err
	}
	if err := checkPositionals(p, nil, "usage"); err != nil {
		return usageErr(err)
	}
	return runNetwork(ctx, env, g, func(rt *Runtime) error {
		cookies, err := rt.Cookies()
		if err != nil {
			return err
		}
		// No ActionIDStore: the Go port does not persist a
		// discovered subscription_action_id (no exported setter
		// in the profile library; a read command must not rewrite
		// the config). FetchSubscription re-discovers it on
		// every call, exactly as Python does on a first run.
		sub, _, err := gateway.FetchSubscription(ctx, rt.HTTPClient(), cookies, gateway.SubscriptionOptions{
			ActionID:         rt.Profile.SubscriptionActionID,
			IncludeAgreement: false,
			Store:            nil,
		})
		if err != nil {
			return err
		}
		if p.bool("raw") {
			return writeJSON(env.stdout(), sub)
		}
		u := shared.SummarizeUsage(sub, time.Local)
		if p.bool("json") {
			return writeJSON(env.stdout(), u)
		}
		for _, line := range shared.UsageLines(u, time.Local) {
			fmt.Fprintln(env.stdout(), line)
		}
		return nil
	})
}

func cmdInvite(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := parseOrHelp(commandTable["invite"], args, env)
	if err != nil {
		return err
	}
	if err := checkPositionals(p, nil, "invite"); err != nil {
		return usageErr(err)
	}
	return runNetwork(ctx, env, g, func(rt *Runtime) error {
		cookies, err := rt.Cookies()
		if err != nil {
			return err
		}
		d, err := gateway.FetchInvite(ctx, rt.HTTPClient(), cookies)
		if err != nil {
			return err
		}
		if p.bool("create") {
			if code, _ := d["code"].(string); code == "" {
				if _, err := gateway.CreateInvite(ctx, rt.HTTPClient(), cookies); err != nil {
					return err
				}
				d, err = gateway.FetchInvite(ctx, rt.HTTPClient(), cookies)
				if err != nil {
					return err
				}
			}
		}
		if p.bool("raw") {
			return writeJSON(env.stdout(), d)
		}
		s := shared.SummarizeInvite(d)
		if p.bool("json") {
			return writeJSON(env.stdout(), s)
		}
		printInviteText(env.stdout(), s)
		return nil
	})
}

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

func cmdRedeem(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := parseOrHelp(commandTable["redeem"], args, env)
	if err != nil {
		return err
	}
	if err := checkPositionals(p, []string{"code"}, "redeem"); err != nil {
		return usageErr(err)
	}
	code := p.positionals[0]
	return runNetwork(ctx, env, g, func(rt *Runtime) error {
		cookies, err := rt.Cookies()
		if err != nil {
			return err
		}
		status, body, err := gateway.RedeemInviteCode(ctx, rt.HTTPClient(), cookies, code)
		if err != nil {
			return err
		}
		bodyMap, _ := body.(map[string]any)
		if bodyMap == nil {
			bodyMap = map[string]any{}
		}
		success, _ := bodyMap["success"].(bool)
		if p.bool("json") {
			// On the error path --json emits only allowlisted
			// keys (loop 6, item 3): the producer already
			// enum-gates reason/detail, and this gate drops
			// every other key. Success output is data and is
			// not gated.
			if !success {
				bodyMap = redeemErrorBody(bodyMap)
			}
			if err := writeMergedJSON(env.stdout(), status, bodyMap); err != nil {
				return err
			}
		} else if success {
			redemption, _ := bodyMap["redemptionStatus"].(string)
			if redemption == "" {
				redemption = "ok"
			}
			fmt.Fprintf(env.stdout(), "Redeemed: %s\n", redemption)
		} else {
			reason, _ := bodyMap["reason"].(string)
			detail, _ := bodyMap["detail"].(string)
			line := fmt.Sprintf("Not redeemed (%s): %s", reason, detail)
			fmt.Fprintln(env.stdout(), strings.TrimRight(line, ": "))
		}
		if !success {
			return errCode(1, nil)
		}
		return nil
	})
}

// redeemErrorBody reduces a redeem failure body to the
// allowlisted keys for --json output on the error path:
// success, reason, and detail only. Values pass through as
// the producer produced them (enum-gated at the producer).
func redeemErrorBody(body map[string]any) map[string]any {
	out := map[string]any{}
	for _, k := range []string{"success", "reason", "detail"} {
		if v, ok := body[k]; ok {
			out[k] = v
		}
	}
	return out
}

// writeMergedJSON writes {"status": status, **body} with status
// first and the body keys in sorted order (Go maps have no wire
// order; Python preserves the body's order, which the decoded map
// cannot recover).
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

func cmdThreads(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := parseOrHelp(commandTable["threads"], args, env)
	if err != nil {
		return err
	}
	if err := checkPositionals(p, nil, "threads"); err != nil {
		return usageErr(err)
	}
	return runNetwork(ctx, env, g, func(rt *Runtime) error {
		d, err := callMap(ctx, rt, "sessions.list", conn.RequestOptions{})
		if err != nil {
			return err
		}
		rows := shared.SessionRows(d, p.bool("all"), time.Local)
		if rows == nil {
			rows = []shared.SessionRow{}
		}
		return writeJSON(env.stdout(), rows)
	})
}

// historyResult fetches chat.history and returns the full object and
// its chat_events list.
func historyResult(ctx context.Context, rt *Runtime, thread string, limit int64) (map[string]any, []any, error) {
	body := map[string]any{"limit": limit}
	if thread != "" {
		body["session_id"] = thread
	}
	d, err := callMap(ctx, rt, "chat.history", conn.RequestOptions{Body: body})
	if err != nil {
		return nil, nil, err
	}
	events, _ := d["chat_events"].([]any)
	return d, events, nil
}

func eventHasText(ev map[string]any) bool {
	p, ok := ev["payload"].(map[string]any)
	if !ok {
		return false
	}
	if s, ok := p["display_text"].(string); ok && s != "" {
		return true
	}
	if s, ok := p["content"].(string); ok && s != "" {
		return true
	}
	// Non-string truthy values count, as in Python's `or` check.
	if v, ok := p["display_text"]; ok && v != nil && v != false {
		return true
	}
	if v, ok := p["content"]; ok && v != nil && v != false {
		return true
	}
	return false
}

func cmdHistory(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := parseOrHelp(commandTable["history"], args, env)
	if err != nil {
		return err
	}
	if err := checkPositionals(p, nil, "history"); err != nil {
		return usageErr(err)
	}
	limit := p.intVal("limit")
	downloadDir := p.str("download")
	return runNetwork(ctx, env, g, func(rt *Runtime) error {
		return rt.Muse.WithGateway(ctx, func(gw conn.Gateway) error {
			d, events, err := historyResult(ctx, rt, p.str("thread"), limit)
			if err != nil {
				return err
			}
			if downloadDir != "" {
				res := dedupResources(events)
				rows, err := shared.SaveResources(ctx, gw, res, downloadDir, false)
				if err != nil {
					return err
				}
				d["downloads"] = rows
				if !p.bool("raw") {
					msgs := filterEvents(events)
					return writeJSON(env.stdout(), map[string]any{"messages": msgs, "downloads": rows})
				}
			}
			if p.bool("raw") {
				return writeJSON(env.stdout(), d)
			}
			return writeJSON(env.stdout(), filterEvents(events))
		})
	})
}

func filterEvents(events []any) []shared.EventRow {
	rows := []shared.EventRow{}
	for _, e := range events {
		ev, ok := e.(map[string]any)
		if !ok || !eventHasText(ev) {
			continue
		}
		rows = append(rows, shared.FmtEvent(ev))
	}
	return rows
}

func dedupResources(events []any) []shared.Resource {
	var res []shared.Resource
	seen := map[string]bool{}
	for _, e := range events {
		ev, ok := e.(map[string]any)
		if !ok {
			continue
		}
		for _, r := range shared.EventResources(ev) {
			if seen[r.Path] {
				continue
			}
			seen[r.Path] = true
			res = append(res, r)
		}
	}
	return res
}

func cmdFiles(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := parseOrHelp(commandTable["files"], args, env)
	if err != nil {
		return err
	}
	if err := checkPositionals(p, nil, "files"); err != nil {
		return usageErr(err)
	}
	return runNetwork(ctx, env, g, func(rt *Runtime) error {
		_, events, err := historyResult(ctx, rt, p.str("thread"), p.intVal("limit"))
		if err != nil {
			return err
		}
		rows := shared.FileRows(events)
		if rows == nil {
			rows = []shared.FileRow{}
		}
		return writeJSON(env.stdout(), rows)
	})
}

func downloadOutput(p *parsed) string {
	if p.strIsSet("output") {
		return p.str("output")
	}
	return "."
}

func cmdDownload(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := parseOrHelp(commandTable["download"], args, env)
	if err != nil {
		return err
	}
	if err := checkPositionals(p, []string{"ref"}, "download"); err != nil {
		return usageErr(err)
	}
	ref := p.positionals[0]
	return runNetwork(ctx, env, g, func(rt *Runtime) error {
		return rt.Muse.WithGateway(ctx, func(gw conn.Gateway) error {
			var resources []shared.Resource
			if strings.HasPrefix(ref, "sandbox://") || strings.Contains(ref, "/media/raw/") {
				resources = []shared.Resource{{Path: ref}}
			} else {
				_, events, err := historyResult(ctx, rt, p.str("thread"), p.intVal("limit"))
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
					thread := p.str("thread")
					where := " of the main chat"
					if thread != "" {
						where = " of thread " + thread
					}
					return errCodef(1, "no files found for '%s' in the last %d messages%s (try --thread / --limit)", ref, p.intVal("limit"), where)
				}
			}
			rows, err := shared.SaveResources(ctx, gw, resources, downloadOutput(p), p.bool("force"))
			if err != nil {
				return err
			}
			if err := writeJSON(env.stdout(), rows); err != nil {
				return err
			}
			for _, r := range rows {
				if r.Error != "" {
					// Any row error exits 3, after printing
					// the rows (Python: sys.exit(3)).
					return errCode(3, nil)
				}
			}
			return nil
		})
	})
}

func appendIfMissingPath(res []shared.Resource, r shared.Resource) []shared.Resource {
	for _, x := range res {
		if x.Path == r.Path {
			return res
		}
	}
	return append(res, r)
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

func cmdWatch(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := parseOrHelp(commandTable["watch"], args, env)
	if err != nil {
		return err
	}
	if err := checkPositionals(p, nil, "watch"); err != nil {
		return usageErr(err)
	}
	timeout := time.Duration(p.intVal("timeout")) * time.Second
	return runNetwork(ctx, env, g, func(rt *Runtime) error {
		return rt.Muse.WithGateway(ctx, func(gw conn.Gateway) error {
			body := map[string]any{"capabilities": []any{"chat_cancel", "delta_stream"}}
			if thread := p.str("thread"); thread != "" {
				body["session_id"] = thread
			}
			_, err := gw.SubscribeRaw(ctx, "chat.subscribe", conn.SubscribeOptions{
				Body:           body,
				MaxRecords:     int(p.intVal("n")),
				IdleTimeout:    timeout,
				OverallTimeout: timeout,
				OnRecord: func(line []byte) bool {
					printWatchRow(env.stdout(), line, p.bool("all"))
					return false // false = keep going (true stops)
				},
			})
			return err
		})
	})
}

// printWatchRow mirrors _print_watch_row: bad JSON lines are
// dropped, agent.status is dropped unless showAll, and the row
// keeps event/seq plus the first truthy text-ish payload keys,
// each truncated to 300 characters.
func printWatchRow(w io.Writer, line []byte, showAll bool) {
	ev, err := decodeJSONNumber(line)
	if err != nil {
		return
	}
	m, ok := ev.(map[string]any)
	if !ok {
		return
	}
	etVal := m["event"]
	if etVal == nil {
		etVal = m["type"]
	}
	if etStr, ok := etVal.(string); ok && etStr == "agent.status" && !showAll {
		return
	}
	p, _ := m["payload"].(map[string]any)
	// Ordered row: event, seq, then the text keys in Python order.
	var b strings.Builder
	b.WriteString("{")
	etJSON, _ := marshalJSONLine(etVal)
	b.WriteString("\"event\":")
	b.Write(etJSON)
	seqJSON, _ := marshalJSONLine(m["seq"])
	b.WriteString(",\"seq\":")
	b.Write(seqJSON)
	for _, k := range []string{"display_text", "content", "text", "activity_text", "status"} {
		if p == nil {
			break
		}
		v, ok := p[k]
		if !ok || !truthyJSON(v) {
			continue
		}
		b.WriteString(",")
		writeWatchField(&b, k, truncRunes(pythonStr(v), 300))
	}
	b.WriteString("}\n")
	_, _ = io.WriteString(w, b.String())
}

func writeWatchField(b *strings.Builder, key string, val string) {
	kb, _ := json.Marshal(key)
	vb, _ := json.Marshal(val)
	b.Write(kb)
	b.WriteString(":")
	b.Write(vb)
}

func truthyJSON(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	case json.Number:
		return t.String() != "0"
	case float64:
		return t != 0
	case []any:
		return len(t) > 0
	case map[string]any:
		return len(t) > 0
	default:
		return true
	}
}

// pythonStr renders a JSON value the way Python str() would for the
// scalar cases watch rows carry; maps/lists fall back to compact
// JSON (Python would print repr, which differs cosmetically).
func pythonStr(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		if t {
			return "True"
		}
		return "False"
	case nil:
		return "None"
	case json.Number:
		return t.String()
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		b, err := marshalJSONLine(v)
		if err != nil {
			return fmt.Sprintf("%v", v)
		}
		return string(b)
	}
}

func cmdFeed(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := parseOrHelp(commandTable["feed"], args, env)
	if err != nil {
		return err
	}
	if err := checkPositionals(p, nil, "feed"); err != nil {
		return usageErr(err)
	}
	limit := p.intVal("limit")
	return runNetwork(ctx, env, g, func(rt *Runtime) error {
		var query map[string]string
		if p.intIsSet("limit") && limit != 0 {
			query = map[string]string{"limit": strconv.FormatInt(limit, 10)}
		}
		d, err := callMap(ctx, rt, "feed.list", conn.RequestOptions{Query: query})
		if err != nil {
			return err
		}
		if p.bool("raw") {
			return writeJSON(env.stdout(), d)
		}
		rows := shared.FeedRows(d, int(limit))
		if rows == nil {
			rows = []shared.FeedRow{}
		}
		return writeJSON(env.stdout(), rows)
	})
}

func cmdFeedStatus(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := parseOrHelp(commandTable["feed-status"], args, env)
	if err != nil {
		return err
	}
	if err := checkPositionals(p, nil, "feed-status"); err != nil {
		return usageErr(err)
	}
	return runNetwork(ctx, env, g, func(rt *Runtime) error {
		v, err := callJSON(ctx, rt, "feed.status", conn.RequestOptions{})
		if err != nil {
			return err
		}
		return writeJSON(env.stdout(), v)
	})
}

func cmdFeedReact(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := parseOrHelp(commandTable["feed-react"], args, env)
	if err != nil {
		return err
	}
	// reaction is optional in Python (default "love"): 1 or 2
	// positionals are accepted.
	if len(p.positionals) < 1 {
		return usageErr(&parserError{msg: "the following arguments are required: unit"})
	}
	if len(p.positionals) > 2 {
		return usageErr(&parserError{msg: fmt.Sprintf("unrecognized arguments: %s", strings.Join(p.positionals[2:], " "))})
	}
	unit := p.positionals[0]
	reaction := "love"
	if len(p.positionals) > 1 {
		reaction = p.positionals[1]
	}
	return runNetwork(ctx, env, g, func(rt *Runtime) error {
		v, err := callJSON(ctx, rt, "feed.unit.reaction", conn.RequestOptions{
			PathParams: map[string]string{"unit_id": unit},
			Body:       map[string]any{"reaction": reaction},
		})
		if err != nil {
			return err
		}
		return writeJSON(env.stdout(), v)
	})
}

func cmdFeedPrompt(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := parseOrHelp(commandTable["feed-prompt"], args, env)
	if err != nil {
		return err
	}
	if err := checkPositionals(p, nil, "feed-prompt"); err != nil {
		return usageErr(err)
	}
	return runNetwork(ctx, env, g, func(rt *Runtime) error {
		v, err := callJSON(ctx, rt, "feed.prompt.get", conn.RequestOptions{})
		if err != nil {
			return err
		}
		return writeJSON(env.stdout(), v)
	})
}

func cmdGoals(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := parseOrHelp(commandTable["goals"], args, env)
	if err != nil {
		return err
	}
	if err := checkPositionals(p, nil, "goals"); err != nil {
		return usageErr(err)
	}
	return runNetwork(ctx, env, g, func(rt *Runtime) error {
		d, err := callMap(ctx, rt, "goals.list", conn.RequestOptions{})
		if err != nil {
			return err
		}
		rows := shared.GoalRows(d)
		if rows == nil {
			rows = []shared.GoalRow{}
		}
		return writeJSON(env.stdout(), rows)
	})
}

func cmdGoal(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := parseOrHelp(commandTable["goal"], args, env)
	if err != nil {
		return err
	}
	if err := checkPositionals(p, []string{"id"}, "goal"); err != nil {
		return usageErr(err)
	}
	id := p.positionals[0]
	return runNetwork(ctx, env, g, func(rt *Runtime) error {
		v, err := callJSON(ctx, rt, "goals.get", conn.RequestOptions{
			PathParams: map[string]string{"id": id},
		})
		if err != nil {
			return err
		}
		return writeJSON(env.stdout(), v)
	})
}

func cmdIdeas(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := parseOrHelp(commandTable["ideas"], args, env)
	if err != nil {
		return err
	}
	if err := checkPositionals(p, nil, "ideas"); err != nil {
		return usageErr(err)
	}
	return runNetwork(ctx, env, g, func(rt *Runtime) error {
		d, err := callMap(ctx, rt, "api.idea-cards.list", conn.RequestOptions{})
		if err != nil {
			return err
		}
		rows := shared.IdeaRows(d)
		if rows == nil {
			rows = []shared.IdeaRow{}
		}
		return writeJSON(env.stdout(), rows)
	})
}

func cmdIdea(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := parseOrHelp(commandTable["idea"], args, env)
	if err != nil {
		return err
	}
	if err := checkPositionals(p, []string{"id"}, "idea"); err != nil {
		return usageErr(err)
	}
	id := p.positionals[0]
	return runNetwork(ctx, env, g, func(rt *Runtime) error {
		v, err := callJSON(ctx, rt, "api.idea-cards.detail", conn.RequestOptions{
			PathParams: map[string]string{"ideaCardId": id},
		})
		if err != nil {
			return err
		}
		return writeJSON(env.stdout(), v)
	})
}

func cmdIdeaExec(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := parseOrHelp(commandTable["idea-exec"], args, env)
	if err != nil {
		return err
	}
	if err := checkPositionals(p, []string{"id"}, "idea-exec"); err != nil {
		return usageErr(err)
	}
	id := p.positionals[0]
	return runNetwork(ctx, env, g, func(rt *Runtime) error {
		body := map[string]any{"ideaCardId": id, "mode": "full"}
		if thread := p.str("thread"); thread != "" {
			body["session_id"] = thread
		}
		v, err := callJSON(ctx, rt, "api.idea-cards.execute", conn.RequestOptions{
			PathParams: map[string]string{"ideaCardId": id},
			Body:       body,
		})
		if err != nil {
			return err
		}
		return writeJSON(env.stdout(), v)
	})
}

func cmdUnread(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := parseOrHelp(commandTable["unread"], args, env)
	if err != nil {
		return err
	}
	if err := checkPositionals(p, nil, "unread"); err != nil {
		return usageErr(err)
	}
	return runNetwork(ctx, env, g, func(rt *Runtime) error {
		v, err := callJSON(ctx, rt, "chat.unread_count", conn.RequestOptions{})
		if err != nil {
			return err
		}
		return writeJSON(env.stdout(), v)
	})
}

func cmdSeen(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := parseOrHelp(commandTable["seen"], args, env)
	if err != nil {
		return err
	}
	if err := checkPositionals(p, []string{"thread"}, "seen"); err != nil {
		return usageErr(err)
	}
	thread := p.positionals[0]
	return runNetwork(ctx, env, g, func(rt *Runtime) error {
		v, err := callJSON(ctx, rt, "chat.mark_seen", conn.RequestOptions{
			PathParams: map[string]string{"thread_id": thread},
		})
		if err != nil {
			return err
		}
		return writeJSON(env.stdout(), v)
	})
}

func cmdRaw(ctx context.Context, env *Env, g *globalOpts, args []string) error {
	p, err := parseOrHelp(commandTable["raw"], args, env)
	if err != nil {
		return err
	}
	if err := checkPositionals(p, []string{"method"}, "raw"); err != nil {
		return usageErr(err)
	}
	method := p.positionals[0]
	// Unknown method exits 2, checked against the route table
	// before any connection is opened.
	table, err := gateway.DefaultRoutes()
	if err != nil {
		return err
	}
	if _, ok := table.LookupRoute(method); !ok {
		return errCodef(2, "unknown method '%s' (see routes.json for the %d known methods)", method, table.Total())
	}
	var body any
	if bodyStr := p.str("body"); bodyStr != "" {
		v, err := decodeJSONNumber([]byte(bodyStr))
		if err != nil {
			return errCodef(2, "invalid --body JSON: %s", err.Error())
		}
		body = v
	}
	pathParams := map[string]string{}
	for _, kv := range p.lists["param"] {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return errCodef(2, "bad --param '%s': expected k=v", kv)
		}
		pathParams[k] = v
	}
	if len(pathParams) == 0 {
		pathParams = nil
	}
	timeout := time.Duration(p.intVal("timeout")) * time.Second
	return runNetwork(ctx, env, g, func(rt *Runtime) error {
		return rt.Muse.WithGateway(ctx, func(gw conn.Gateway) error {
			data, err := gw.Request(ctx, method, conn.RequestOptions{
				Body:       body,
				PathParams: pathParams,
				Timeout:    timeout,
			})
			if err != nil {
				return err
			}
			if len(data) == 0 {
				return writeJSON(env.stdout(), map[string]any{})
			}
			v, err := decodeJSONNumber(data)
			if err != nil {
				// Non-JSON reply prints as text.
				fmt.Fprintln(env.stdout(), string(data))
				return nil
			}
			return writeJSON(env.stdout(), v)
		})
	})
}

// usageErr converts a parser positional error into the exit-2
// usage error shape used by parseOrHelp.
func usageErr(err error) error {
	if pe, ok := err.(*parserError); ok {
		return errCode(2, pe)
	}
	return err
}
