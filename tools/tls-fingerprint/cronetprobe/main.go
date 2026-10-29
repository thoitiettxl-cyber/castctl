// Scratch cronet probe (purego): GET https://tls.peet.ws/api/all through the
// egress-proxy CONNECT tunnel via Engine.SetDialer. No cookies, no auth,
// no Muse traffic. PROXY-MASKED: the intercepting proxy terminates TLS.
// The Dialer receives only an IP (hostname recovered from a probe-only
// pre-resolution map) — that hostname loss is itself a finding.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	cronet "github.com/sagernet/cronet-go"
)

var ipToHost = map[string]string{}

var keptFiles = []*os.File{}

func proxyAddr() string {
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

func connectDialer(address string, port uint16) int {
	host, ok := ipToHost[address]
	if !ok {
		fmt.Fprintf(os.Stderr, "DIALER: unknown address %s:%d (no hostname mapping)\n", address, port)
		return -104 // ERR_CONNECTION_FAILED
	}
	raw := proxyAddr()
	u, err := url.Parse(raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "DIALER: proxy parse:", err)
		return -104
	}
	d := net.Dialer{Timeout: 20 * time.Second}
	c, err := d.Dial("tcp", u.Host)
	if err != nil {
		fmt.Fprintln(os.Stderr, "DIALER: proxy dial:", err)
		return -104
	}
	target := net.JoinHostPort(host, fmt.Sprint(port))
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: keep-alive\r\n\r\n", target, target)
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil {
		fmt.Fprintln(os.Stderr, "DIALER: CONNECT read:", err)
		c.Close()
		return -104
	}
	if !strings.Contains(line, "200") {
		fmt.Fprintln(os.Stderr, "DIALER: CONNECT status:", strings.TrimSpace(line))
		c.Close()
		return -104
	}
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			c.Close()
			return -104
		}
		if strings.TrimSpace(l) == "" {
			break
		}
	}
	tcp, ok := c.(*net.TCPConn)
	if !ok {
		fmt.Fprintln(os.Stderr, "DIALER: conn is not *net.TCPConn")
		c.Close()
		return -104
	}
	f, err := tcp.File()
	if err != nil {
		fmt.Fprintln(os.Stderr, "DIALER: File():", err)
		c.Close()
		return -104
	}
	keptFiles = append(keptFiles, f)
	fmt.Fprintf(os.Stderr, "DIALER: %s:%d -> CONNECT %s fd=%d\n", address, port, target, f.Fd())
	return int(f.Fd())
}

func main() {
	ips, err := net.LookupHost("tls.peet.ws")
	if err != nil {
		fmt.Println("LOOKUP ERROR:", err)
		os.Exit(1)
	}
	for _, ip := range ips {
		ipToHost[ip] = "tls.peet.ws"
	}
	fmt.Fprintln(os.Stderr, "resolved tls.peet.ws ->", ips)

	engine := cronet.NewEngine()
	fmt.Println("DefaultUserAgent:", engine.DefaultUserAgent())
	fmt.Println("Version:", engine.Version())
	params := cronet.NewEngineParams()
	params.SetEnableQuic(false)
	params.SetEnableHTTP2(true)
	params.SetEnableBrotli(true)
	// NOTE: no SetUserAgent — measure Cronet's own default.
	// SetDialer MUST precede StartWithParams (engine_purego.go doc).
	engine.SetDialer(connectDialer)
	if r := engine.StartWithParams(params); r != 0 {
		fmt.Println("StartWithParams result:", r)
		os.Exit(1)
	}
	params.Destroy()

	rt := &cronet.RoundTripper{Engine: engine}
	client := &http.Client{Transport: rt, Timeout: 60 * time.Second}
	req, _ := http.NewRequest("GET", "https://tls.peet.ws/api/all", nil)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("REQUEST ERROR:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("READ ERROR:", err, "bytes:", len(body))
		os.Exit(1)
	}
	fmt.Println("status:", resp.Status, "proto:", resp.Proto, "bytes:", len(body))
	var pretty map[string]any
	if err := json.Unmarshal(body, &pretty); err != nil {
		fmt.Printf("BODY[:500]: %.500s\n", body)
		os.Exit(1)
	}
	out, _ := json.MarshalIndent(pretty, "", "  ")
	fmt.Println("ECHO JSON:")
	fmt.Println(string(out))
	engine.Shutdown()
	engine.Destroy()
}
