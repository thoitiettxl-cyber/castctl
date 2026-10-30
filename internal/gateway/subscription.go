// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/thoitiettxl-cyber/castctl/internal/conn"
)

// Subscription / usage via the Next.js server action
// fetchSubscriptionAction (gateway.py, plan § Gateway). This is NOT
// a REST route or a VM gateway method: a server action is a POST to
// a settings page with a `Next-Action: <id>` header, and the id
// changes when the web app is redeployed, so it is re-discovered
// from the JS bundles when the known one stops working.

// SubscriptionActionName is the server action's name.
const SubscriptionActionName = "fetchSubscriptionAction"

// DefaultSubscriptionActionID is the last-known action id, tried
// after a configured id and before a bundle scan.
const DefaultSubscriptionActionID = "4029ac5c4bd03136487d91ebde5de39c64b35229b4"

// SubscriptionPage is the page the action is posted to.
const SubscriptionPage = "https://muse.ai/settings"

// actionIDPattern matches createServerReference)("<id>",...,
// "fetchSubscriptionAction") in a JS chunk.
func actionIDPattern(name string) *regexp.Regexp {
	return regexp.MustCompile(`createServerReference\)\("([0-9a-f]{20,})",[^)]{0,120}"` + regexp.QuoteMeta(name) + `"`)
}

var chunkRefPattern = regexp.MustCompile(`/_next/static/chunks/[A-Za-z0-9_.-]+\.js`)
var chunkRefBarePattern = regexp.MustCompile(`static/chunks/[A-Za-z0-9_.-]+\.js`)

// ParseRSCResult returns the action's return value from a
// text/x-component (RSC) body, ported verbatim from
// gateway.py parse_rsc_result: rows are the lines whose value
// starts with { or [, parsed as JSON; row "0" holds a reference
// {a:$@1} to the result row; otherwise row "1", else the head row
// itself.
func ParseRSCResult(text string) any {
	rows := map[string]any{}
	for _, line := range strings.Split(text, "\n") {
		key, val, found := strings.Cut(line, ":")
		if found && (strings.HasPrefix(val, "{") || strings.HasPrefix(val, "[")) {
			var v any
			dec := json.NewDecoder(strings.NewReader(val))
			dec.UseNumber()
			if err := dec.Decode(&v); err == nil {
				rows[key] = v
			}
		}
	}
	head, _ := rows["0"]
	if hm, ok := head.(map[string]any); ok {
		if ref, ok := hm["a"].(string); ok && strings.HasPrefix(ref, "$@") {
			return rows[ref[2:]]
		}
	}
	if v, ok := rows["1"]; ok {
		return v
	}
	return head
}

// callAction posts one server-action call. A 401/403 is an
// AuthError. A non-200 status or a response without x-component in
// its content type returns (nil, nil): most likely a stale action
// id, and the caller tries the next id. Transport errors are
// returned through redactErr, like doHatch.
func callAction(ctx context.Context, client *http.Client, cookies, actionID string, args any, page string) (any, error) {
	body, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}
	h := hatchHeaders(cookies, "")
	h.Set("Accept", "text/x-component")
	h.Set("Content-Type", "text/plain;charset=UTF-8")
	h.Set("Next-Action", actionID)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, page, bytes.NewReader(body))
	if err != nil {
		return nil, redactErr(err)
	}
	req.Header = h
	resp, err := client.Do(req)
	if err != nil {
		return nil, redactErr(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, redactErr(err)
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return nil, conn.NewAuthError(fmt.Sprintf("server action -> %d (cookies expired? re-export)", resp.StatusCode))
	}
	if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Content-Type"), "x-component") {
		return nil, nil
	}
	return ParseRSCResult(string(data)), nil
}

// FindActionID scans the web app's JS chunks for a server action's
// id (slow: ~1k files). At most 3000 chunk files are fetched, 16
// at a time. Chunk URLs discovered inside fetched chunks are
// queued for the next round. Iteration order is sorted (Python
// iterates a set, nondeterministically); only the found id
// matters. Fetch failures yield empty text and are skipped.
func FindActionID(ctx context.Context, client *http.Client, cookies, name, page string) (string, error) {
	pat := actionIDPattern(name)
	h := http.Header{}
	h.Set("User-Agent", UserAgent)
	h.Set("Cookie", cookies)
	html, err := fetchText(ctx, client, page, h, 30*time.Second)
	if err != nil {
		return "", err
	}
	todo := map[string]bool{}
	for _, m := range chunkRefPattern.FindAllString(html, -1) {
		todo[m] = true
	}
	seen := map[string]bool{}
	for len(todo) > 0 && len(seen) < 3000 {
		batch := make([]string, 0, len(todo))
		for p := range todo {
			batch = append(batch, p)
		}
		sort.Strings(batch)
		todo = map[string]bool{}
		for _, p := range batch {
			seen[p] = true
		}
		// Chunk fetches carry only the browser UA, as in
		// Python (no Cookie header on chunk GETs).
		chunkHeaders := http.Header{}
		chunkHeaders.Set("User-Agent", UserAgent)
		texts := fetchAll(ctx, client, "https://muse.ai", batch, chunkHeaders, 16)
		for _, text := range texts {
			if m := pat.FindStringSubmatch(text); m != nil {
				return m[1], nil
			}
			for _, c := range chunkRefBarePattern.FindAllString(text, -1) {
				p := "/_next/" + c
				if !seen[p] {
					todo[p] = true
				}
			}
		}
	}
	return "", nil
}

// fetchText GETs one URL and returns its body as text.
// Transport errors are returned wrapped in the redaction wrapper
// (redactErr), like doHatch: the chain is preserved for
// errors.As/Is, the printed text is credential-free.
func fetchText(ctx context.Context, client *http.Client, url string, headers http.Header, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", redactErr(err)
	}
	req.Header = headers
	resp, err := client.Do(req)
	if err != nil {
		return "", redactErr(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", redactErr(err)
	}
	return string(data), nil
}

// fetchAll fetches paths (relative to base) with a worker pool of
// size pool, preserving batch order in the result. Failures yield
// "".
func fetchAll(ctx context.Context, client *http.Client, base string, paths []string, headers http.Header, pool int) []string {
	out := make([]string, len(paths))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < pool; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				text, err := fetchText(ctx, client, base+paths[i], headers, 30*time.Second)
				if err != nil {
					continue
				}
				out[i] = text
			}
		}()
	}
	for i := range paths {
		select {
		case jobs <- i:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return out
		}
	}
	close(jobs)
	wg.Wait()
	return out
}

// ActionIDStore is the injectable cache for the subscription
// action id. Wiring in PR3 commands implements it on top of the
// profile config (subscription_action_id in config.json): Get
// returns the stored id ("" when none), Set persists a newly
// discovered id. FetchSubscription consults the store when no
// explicit id is given, and stores a newly discovered id
// best-effort: a Set failure never fails the subscription read
// itself. A nil store means "no cache".
type ActionIDStore interface {
	GetActionID() string
	SetActionID(id string) error
}

// SubscriptionOptions carries FetchSubscription's arguments.
type SubscriptionOptions struct {
	// ActionID is an explicit action id to try first (the
	// configured subscription_action_id). Empty means "ask the
	// store, then the default".
	ActionID string
	// IncludeAgreement mirrors the page's includeAgreement arg.
	IncludeAgreement bool
	// Store caches a newly discovered action id. May be nil.
	Store ActionIDStore
	// Page overrides the settings page URL (tests only).
	Page string
}

// FetchSubscription returns the plan + usage object the Settings
// page shows, and the action id that produced it. It tries the
// configured id, then the default id, then scans the JS bundles
// for a fresh id. A 401/403 anywhere is an AuthError. A result
// that is not {"success":true,"subscription":{...}} is a
// GatewayError(-1). The returned subscription map uses
// json.Number for numbers.
func FetchSubscription(ctx context.Context, client *http.Client, cookies string, opts SubscriptionOptions) (map[string]any, string, error) {
	page := opts.Page
	if page == "" {
		page = SubscriptionPage
	}
	args := []any{map[string]any{"includeAgreement": opts.IncludeAgreement}}
	var tried []string
	candidates := []string{opts.ActionID}
	if opts.Store != nil && opts.ActionID == "" {
		candidates[0] = opts.Store.GetActionID()
	}
	candidates = append(candidates, DefaultSubscriptionActionID)
	var res any
	var aid string
	for _, cand := range candidates {
		if cand == "" {
			continue
		}
		duplicate := false
		for _, t := range tried {
			if t == cand {
				duplicate = true
			}
		}
		if duplicate {
			continue
		}
		tried = append(tried, cand)
		r, err := callAction(ctx, client, cookies, cand, args, page)
		if err != nil {
			return nil, "", err
		}
		if r != nil {
			res, aid = r, cand
			break
		}
	}
	if res == nil {
		found, err := FindActionID(ctx, client, cookies, SubscriptionActionName, page)
		if err != nil {
			return nil, "", err
		}
		if found == "" {
			return nil, "", &conn.GatewayError{Status: -1, Payload: fmt.Sprintf("could not find %s in the web app bundle", SubscriptionActionName)}
		}
		r, err := callAction(ctx, client, cookies, found, args, page)
		if err != nil {
			return nil, "", err
		}
		res, aid = r, found
	}
	sub, ok := res.(map[string]any)
	if !ok || sub["success"] != true || sub["subscription"] == nil {
		var errVal any
		if ok {
			errVal = sub["error"]
		} else {
			errVal = res
		}
		// The "error" value is peer-controlled: only an
		// enum-shaped string parsed by key may be emitted
		// (see summary.go). A non-map result has no keys
		// to parse, so nothing is extracted from it. The
		// RSC body length is not retained by callAction,
		// so no body_length field is emitted here.
		errMap, _ := errVal.(map[string]any)
		if errMap == nil && ok {
			errMap = sub
		}
		sum := summarizeBody("fetchSubscriptionAction failed", nil, "", errMap, "error")
		return nil, "", gatewayErrorFromSummary(-1, sum)
	}
	subMap, ok := sub["subscription"].(map[string]any)
	if !ok {
		return nil, "", &conn.GatewayError{Status: -1, Payload: fmt.Sprintf("%s failed: subscription is not an object", SubscriptionActionName)}
	}
	if opts.Store != nil && aid != "" && aid != opts.Store.GetActionID() {
		_ = opts.Store.SetActionID(aid) // best-effort cache; see ActionIDStore
	}
	return subMap, aid, nil
}
