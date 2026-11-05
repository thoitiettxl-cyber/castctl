// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package bench

// Hand-rolled stdlib SOCKS5 client for perf item 5 (mirrors the Rust
// bench crate's socks5-get mode). Reads PERF_SOCKS5_ADDR,
// PERF_HTTP_ADDR, PERF_SOCKS5_RUNS; writes one JSON line to the file
// named by PERF_OUT (or stdout). This measures the harness client,
// NOT castctl's real sing-box/honk outbound — see README.

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

func socks5Get(t *testing.T, proxyAddr, httpAddr string) (int, error) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		return 0, err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return 0, err
	}
	if resp[0] != 5 || resp[1] != 0 {
		return 0, fmt.Errorf("no-auth rejected: %v", resp)
	}
	host, port, err := net.SplitHostPort(httpAddr)
	if err != nil {
		return 0, err
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		return 0, fmt.Errorf("http addr must be IPv4: %s", httpAddr)
	}
	p, _ := strconv.Atoi(port)
	req := []byte{5, 1, 0, 1, ip[0], ip[1], ip[2], ip[3], byte(p >> 8), byte(p)}
	if _, err := conn.Write(req); err != nil {
		return 0, err
	}
	hdr := make([]byte, 10)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return 0, err
	}
	if hdr[1] != 0 {
		return 0, fmt.Errorf("CONNECT failed: rep=%d", hdr[1])
	}
	fmt.Fprintf(conn, "GET /body-1024.bin HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	raw, err := io.ReadAll(conn)
	if err != nil {
		return 0, err
	}
	parts := strings.SplitN(string(raw), "\r\n\r\n", 2)
	if len(parts) != 2 || len(parts[1]) != 1024 {
		return 0, fmt.Errorf("body len %d, want 1024", len(parts[1]))
	}
	return 1024, nil
}

func TestSocks5Get(t *testing.T) {
	proxy := os.Getenv("PERF_SOCKS5_ADDR")
	httpAddr := os.Getenv("PERF_HTTP_ADDR")
	if proxy == "" || httpAddr == "" {
		t.Skip("PERF_SOCKS5_ADDR/PERF_HTTP_ADDR unset")
	}
	runs, _ := strconv.Atoi(os.Getenv("PERF_SOCKS5_RUNS"))
	if runs <= 0 {
		runs = 20
	}
	var perReq []float64
	ok := 0
	for i := 0; i < runs; i++ {
		start := time.Now()
		if _, err := socks5Get(t, proxy, httpAddr); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		ok++
		perReq = append(perReq, time.Since(start).Seconds()*1000)
	}
	sort.Float64s(perReq)
	out := map[string]any{"mode": "socks5-get", "runs": runs, "ok": ok,
		"ms_per_request": map[string]any{"median": perReq[len(perReq)/2],
			"min": perReq[0], "max": perReq[len(perReq)-1]}}
	data, _ := json.Marshal(out)
	if f := os.Getenv("PERF_OUT"); f != "" {
		if err := os.WriteFile(f, append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	} else {
		t.Log(string(data))
	}
}
