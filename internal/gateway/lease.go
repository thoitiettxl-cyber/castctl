package gateway

import (
	"context"
	"net/url"
	"time"

	"github.com/thoitiettxl-cyber/muse-cli/go/internal/conn"
)

// parseURL parses a URL without ever exposing a token-bearing URL
// in an error: callers redact before formatting.
func parseURL(raw string) (*url.URL, error) {
	return url.Parse(raw)
}

// redactURL returns a URL string safe for errors and logs: the
// auth_token query value (and any other query value) is replaced
// with "[redacted]". Only the scheme/host/path shape is kept.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "[unparseable url]"
	}
	q := u.Query()
	for k := range q {
		q.Set(k, "[redacted]")
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// leaseGateway is the no-op-close view of a Gateway: every method
// delegates, except Close, which does nothing, so a shared warm
// connection stays up when callers close their lease.
type leaseGateway struct {
	gw *Gateway
}

var _ conn.Gateway = (*leaseGateway)(nil)
var _ conn.Leaser = (*leaseGateway)(nil)

func (l *leaseGateway) CallJSON(ctx context.Context, method string, opts conn.RequestOptions) (any, error) {
	return l.gw.CallJSON(ctx, method, opts)
}

func (l *leaseGateway) Request(ctx context.Context, method string, opts conn.RequestOptions) ([]byte, error) {
	return l.gw.Request(ctx, method, opts)
}

func (l *leaseGateway) SubscribeRaw(ctx context.Context, method string, opts conn.SubscribeOptions) ([][]byte, error) {
	return l.gw.SubscribeRaw(ctx, method, opts)
}

func (l *leaseGateway) SubscribeJSON(ctx context.Context, method string, opts conn.SubscribeOptions) ([]any, error) {
	return l.gw.SubscribeJSON(ctx, method, opts)
}

func (l *leaseGateway) DownloadFile(ctx context.Context, ref any, opts conn.DownloadOptions) ([]byte, error) {
	return l.gw.DownloadFile(ctx, ref, opts)
}

func (l *leaseGateway) Ping(ctx context.Context, timeout time.Duration) (any, error) {
	return l.gw.Ping(ctx, timeout)
}

func (l *leaseGateway) OpenStream(ctx context.Context, method string, opts conn.OpenStreamOptions) (int64, error) {
	return l.gw.OpenStream(ctx, method, opts)
}

func (l *leaseGateway) CancelStream(ctx context.Context, streamID int64) error {
	return l.gw.CancelStream(ctx, streamID)
}

func (l *leaseGateway) LookupRoute(method string) (conn.Route, bool) {
	return l.gw.LookupRoute(method)
}

func (l *leaseGateway) Alive() bool { return l.gw.Alive() }

func (l *leaseGateway) Dead() error { return l.gw.Dead() }

func (l *leaseGateway) LastRecv() time.Time { return l.gw.LastRecv() }

func (l *leaseGateway) LastUsed() time.Time { return l.gw.LastUsed() }

// Close is a no-op: the underlying shared connection stays up.
func (l *leaseGateway) Close() error { return nil }

// Lease returns itself: a lease of a lease is the same view.
func (l *leaseGateway) Lease() conn.Gateway { return l }
