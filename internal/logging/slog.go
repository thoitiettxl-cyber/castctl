// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package logging

import (
	"context"
	"fmt"
	"log/slog"

	singlog "github.com/sagernet/sing-box/log"
)

// The slog bridge: the second logger world (conn.Muse lines and the
// bootstrap lookup line) writing through the SAME sing-box factory
// and the SAME resolved level as the factory logger. Without it,
// --log-level / the log block would govern sing-box lines only and
// slog lines would keep slog.Default()'s destination and level —
// two independent gates, which the spec forbids.
//
// Level mapping: slog has no trace/fatal/panic. slog levels below
// Debug map to sing-box Trace; Debug→Debug, Info→Info, Warn→Warn,
// Error and above→Error. The handler reads the factory's level once
// at construction (castctl never calls SetLevel after construction,
// so the captured value cannot drift from the factory's gate).
//
// Redaction: EVERY attr value passes SafeString (errors via
// SafeErr); the message passes SafeString too. Field exclusion by
// construction still applies at the call sites — no call site may
// pass a URL, header map, cookie, token, or options object as an
// attr — but a secret-bearing error string reaching a call site
// cannot cross this handler unredacted.
type slogHandler struct {
	logger   singlog.ContextLogger
	maxLevel singlog.Level
	attrs    []slog.Attr
	groups   []string
}

// NewSlogLogger builds a *slog.Logger writing through factory at
// the factory's level, tagged tag.
func NewSlogLogger(factory singlog.Factory, tag string) *slog.Logger {
	return slog.New(&slogHandler{
		logger:   factory.NewLogger(tag),
		maxLevel: factory.Level(),
	})
}

func (h *slogHandler) Enabled(_ context.Context, level slog.Level) bool {
	return singLevel(level) <= h.maxLevel
}

func singLevel(level slog.Level) singlog.Level {
	switch {
	case level < slog.LevelDebug:
		return singlog.LevelTrace
	case level < slog.LevelInfo:
		return singlog.LevelDebug
	case level < slog.LevelWarn:
		return singlog.LevelInfo
	case level < slog.LevelError:
		return singlog.LevelWarn
	default:
		return singlog.LevelError
	}
}

func (h *slogHandler) Handle(ctx context.Context, r slog.Record) error {
	msg := SafeString(r.Message)
	attrs := append([]slog.Attr{}, h.attrs...)
	r.Attrs(func(a slog.Attr) bool {
		attrs = append(attrs, a)
		return true
	})
	for _, a := range attrs {
		key := a.Key
		for _, g := range h.groups {
			key = g + "." + key
		}
		msg += " " + SafeString(key) + "=" + safeAttrValue(a.Value)
	}
	Emit(h.logger, ctx, singLevel(r.Level), msg)
	return nil
}

// safeAttrValue renders one slog value for a log line. Errors use
// SafeErr; strings use SafeString; everything else is formatted
// then passed through SafeString so a secret-bearing %v cannot
// cross the boundary raw. Groups are flattened by slog before
// Handle for record attrs; WithGroup keys are prefixed in Handle.
func safeAttrValue(v slog.Value) string {
	switch v.Kind() {
	case slog.KindLogValuer:
		return safeAttrValue(v.Resolve())
	case slog.KindAny, slog.KindGroup:
		if err, ok := v.Any().(error); ok && err != nil {
			return SafeErr(err)
		}
	}
	return SafeString(fmt.Sprint(v.Any()))
}

func (h *slogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := *h
	out.attrs = append(append([]slog.Attr{}, h.attrs...), attrs...)
	return &out
}

func (h *slogHandler) WithGroup(name string) slog.Handler {
	out := *h
	out.groups = append(append([]string{}, h.groups...), name)
	return &out
}
