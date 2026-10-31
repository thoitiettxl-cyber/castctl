// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

//go:build with_chromedp

package keeper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"
	"github.com/chromedp/chromedp/remote"
)

// Screencast runners (with_chromedp only).
//
// Attach model: the runner attaches to the user's already-running
// Chrome, screencasts ONE Muse page, and detaches. It never
// closes, kills, activates, or navigates a user tab, never
// dispatches input except the user's own transport input, and
// never enables Runtime/JS. Cancelling the target context
// detaches (WithDetachOnCancel): the tab stays open.
//
// CDP allowlist (§15.2 discipline): Page (enable, screencast,
// input dispatch via the Input domain), Network/Storage cookie
// reads (exporter), Browser.getVersion. Nothing else.

// attachRunner screencasts a Muse page in the user's browser.
type attachRunner struct{ browserURL string }

// NewAttachRunner returns a ScreencastRunner for the browser at
// browserURL (a keeper `browser` value).
func NewAttachRunner(browserURL string) ScreencastRunner {
	return attachRunner{browserURL: browserURL}
}

// Exporter returns the CDP exporter for the attached browser.
func (r attachRunner) Exporter() (Exporter, error) {
	return NewCDPExporter(r.browserURL), nil
}

func (r attachRunner) Run(ctx context.Context, transport Transport) RunnerResult {
	wsURL, err := DiscoverWebSocketURL(ctx, r.browserURL)
	if err != nil {
		return RunnerResult{Outcome: LoginFailed, Err: err}
	}
	version, err := browserVersion(ctx, wsURL)
	if err != nil {
		return RunnerResult{Outcome: LoginFailed, Err: err}
	}
	httpBase, err := httpBaseFromBrowserURL(r.browserURL)
	if err != nil {
		return RunnerResult{Outcome: LoginFailed, Err: err}
	}
	tid, err := ResolveScreencastTarget(ctx, httpBase)
	if err != nil {
		return RunnerResult{Outcome: LoginFailed, Err: err}
	}
	allocCtx, cancelAlloc := remote.NewAllocator(ctx, wsURL, remote.NoModifyURL, remote.WithDialTimeout(10*time.Second))
	defer cancelAlloc()
	tctx, cancelTarget := chromedp.NewContext(allocCtx, chromedp.WithTargetID(tid), chromedp.WithDetachOnCancel())
	defer cancelTarget()
	return serveScreencast(tctx, transport, version)
}

// browserVersion reads the browser's own identity for login
// provenance: Product (e.g. "Chrome/140.0.0.0") and UserAgent
// as the browser reports them. Nothing is invented.
func browserVersion(ctx context.Context, wsURL string) (BrowserVersion, error) {
	allocCtx, cancelAlloc := remote.NewAllocator(ctx, wsURL, remote.NoModifyURL, remote.WithDialTimeout(10*time.Second))
	defer cancelAlloc()
	bctx, cancelBrowser := chromedp.NewContext(allocCtx)
	defer cancelBrowser()
	res, err := chromedp.CallBrowser(bctx, browser.GetVersion, cdp.Empty{})
	if err != nil {
		return BrowserVersion{}, fmt.Errorf("browser version read failed: %w", err)
	}
	return BrowserVersion{Product: res.Product, UserAgent: res.UserAgent}, nil
}

// httpBaseFromBrowserURL derives the HTTP origin for /json/list
// from a keeper `browser` URL: http:// stays, ws:// maps to
// http:// on the same host:port.
func httpBaseFromBrowserURL(browserURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(browserURL))
	if err != nil {
		return "", fmt.Errorf("invalid browser URL")
	}
	switch u.Scheme {
	case "http":
		return "http://" + u.Host, nil
	case "ws":
		return "http://" + u.Host, nil
	default:
		return "", fmt.Errorf("browser URL scheme must be http or ws")
	}
}

type listTarget struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	URL  string `json:"url"`
}

// screencastHosts are the page hosts a login screencast may
// attach to: the Muse app and its auth subdomain only.
var screencastHosts = map[string]bool{"muse.ai": true, "auth.muse.ai": true}

// ResolveScreencastTarget picks the ONE Muse page in the
// attached browser from a typed /json/list decode. Zero
// matches or several matches are errors: the runner never
// guesses which tab the user means, and never activates one.
// Titles are never logged (page titles are user content).
func ResolveScreencastTarget(ctx context.Context, httpBase string) (target.ID, error) {
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(httpBase, "/")+"/json/list", nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("browser /json/list unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("browser /json/list returned status %d", resp.StatusCode)
	}
	var targets []listTarget
	dec := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	if err := dec.Decode(&targets); err != nil {
		return "", fmt.Errorf("browser /json/list is not valid JSON: %w", err)
	}
	var matches []listTarget
	for _, t := range targets {
		if t.Type != "page" || t.ID == "" {
			continue
		}
		u, err := url.Parse(t.URL)
		if err != nil {
			continue
		}
		if screencastHosts[strings.ToLower(u.Hostname())] {
			matches = append(matches, t)
		}
	}
	switch len(matches) {
	case 0:
		return "", errors.New("no Muse page is open in the attached browser (open https://muse.ai/ there first)")
	case 1:
		return target.ID(matches[0].ID), nil
	default:
		return "", fmt.Errorf("several Muse pages are open in the attached browser (%d); close all but one", len(matches))
	}
}

// serveScreencast runs the frame/input loop on an attached
// target context until the user sends Done/Cancel, the
// transport dies, or the context ends. Every received frame
// is acked immediately after its forward attempt (ack
// discipline: the browser stalls past MaxFramesInFlight
// without acks). No logging calls exist in this path: frames
// and keystrokes never reach a log.
func serveScreencast(tctx context.Context, transport Transport, version BrowserVersion) RunnerResult {
	if _, err := chromedp.Call(tctx, page.Enable, page.EnableParams{}); err != nil {
		return RunnerResult{Outcome: LoginFailed, Version: version, Err: fmt.Errorf("page enable failed: %w", err)}
	}
	tgt := chromedp.FromContext(tctx).Target
	if tgt == nil {
		return RunnerResult{Outcome: LoginFailed, Version: version, Err: errors.New("no screencast target attached")}
	}
	events := cdp.Events(tctx, tgt, page.ScreencastFrame)
	quality := int64(60)
	if _, err := chromedp.Call(tctx, page.StartScreencast, page.StartScreencastParams{
		Format: page.StartScreencastFormatJpeg, Quality: &quality,
		MaxWidth: 780, MaxHeight: 1400, EveryNthFrame: 1,
	}); err != nil {
		return RunnerResult{Outcome: LoginFailed, Version: version, Err: fmt.Errorf("screencast start failed: %w", err)}
	}
	stop := func() {
		_, _ = chromedp.Call(tctx, page.StopScreencast, cdp.Empty{})
	}

	framesDone := make(chan error, 1)
	go func() {
		for ev, err := range events {
			if err != nil {
				framesDone <- err
				return
			}
			frame := Frame{Data: ev.Data, SessionID: ev.SessionID}
			if ev.Metadata != nil {
				frame.Width = int(ev.Metadata.DeviceWidth)
				frame.Height = int(ev.Metadata.DeviceHeight)
			}
			// Forward attempt first (latest-only: the
			// transport drops stale frames), ack always.
			_ = transport.SendFrame(tctx, frame)
			_, _ = chromedp.Call(tctx, page.ScreencastFrameAck, page.ScreencastFrameAckParams{SessionID: ev.SessionID})
		}
		framesDone <- nil
	}()

	inputOutcome := make(chan LoginOutcome, 1)
	go func() {
		for ev := range transport.Inputs() {
			switch ev.Kind {
			case InputDone:
				inputOutcome <- DoneOutcome
				return
			case InputCancel:
				inputOutcome <- LoginCancelled
				return
			case InputMouse:
				dispatchMouse(tctx, ev)
			case InputKey:
				dispatchKey(tctx, ev)
			case InputText:
				_, _ = chromedp.Call(tctx, input.InsertText, input.InsertTextParams{Text: ev.Text})
			}
		}
		inputOutcome <- LoginFailed
	}()

	select {
	case <-tctx.Done():
		stop()
		return RunnerResult{Outcome: LoginCancelled, Version: version}
	case <-transport.Done():
		stop()
		return RunnerResult{Outcome: LoginFailed, Version: version, Err: errors.New("screencast transport closed")}
	case outcome := <-inputOutcome:
		stop()
		return RunnerResult{Outcome: outcome, Version: version}
	case err := <-framesDone:
		stop()
		if err != nil {
			return RunnerResult{Outcome: LoginFailed, Version: version, Err: fmt.Errorf("screencast stream ended: %w", err)}
		}
		return RunnerResult{Outcome: LoginFailed, Version: version, Err: errors.New("screencast stream ended")}
	}
}

var allowedMouseTypes = map[string]bool{
	"mousePressed": true, "mouseReleased": true, "mouseMoved": true, "mouseWheel": true,
}

var allowedKeyTypes = map[string]bool{
	"keyDown": true, "keyUp": true, "rawKeyDown": true, "char": true,
}

func dispatchMouse(tctx context.Context, ev InputEvent) {
	if !allowedMouseTypes[ev.MouseType] {
		return
	}
	button := ev.Button
	if button == "" {
		button = "none"
	}
	_, _ = chromedp.Call(tctx, input.DispatchMouseEvent, input.DispatchMouseEventParams{
		Type: input.DispatchMouseEventType(ev.MouseType), X: ev.X, Y: ev.Y,
		Button: input.MouseButton(button), ClickCount: int64(ev.ClickCount),
		DeltaX: ev.DeltaX, DeltaY: ev.DeltaY, Modifiers: int64(ev.Modifiers),
	})
}

func dispatchKey(tctx context.Context, ev InputEvent) {
	if !allowedKeyTypes[ev.KeyType] || ev.Key == "" {
		return
	}
	_, _ = chromedp.Call(tctx, input.DispatchKeyEvent, input.DispatchKeyEventParams{
		Type: input.DispatchKeyEventType(ev.KeyType), Key: ev.Key,
		Modifiers: int64(ev.Modifiers),
	})
}
