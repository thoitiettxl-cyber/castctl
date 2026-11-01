// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package dns

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/miekg/dns"
)

// Fake TCP DNS server on 127.0.0.1. Answers the fake-only hostnames
// gateway.test and proxy.test with A 127.0.0.1, AAAA empty NOERROR,
// everything else NXDOMAIN. Counts queries and records question
// names so tests can prove which names reached the configured DNS
// path (and which did not). UDP is not used: this VM blocks
// loopback UDP sendto (EPERM, measured in the PR1 router probe).

type fakeDNSServer struct {
	t         *testing.T
	ln        net.Listener
	addr      string
	mu        sync.Mutex
	queries   int
	questions []string
}

func startFakeDNSServer(t *testing.T) *fakeDNSServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeDNSServer{t: t, ln: ln, addr: ln.Addr().String()}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(conn)
		}
	}()
	return s
}

func (s *fakeDNSServer) handle(conn net.Conn) {
	defer conn.Close()
	for {
		var lenBuf [2]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(lenBuf[:]))
		buf := make([]byte, n)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		var req dns.Msg
		if err := req.Unpack(buf); err != nil {
			return
		}
		s.mu.Lock()
		s.queries++
		if len(req.Question) == 1 {
			s.questions = append(s.questions, req.Question[0].Name)
		}
		s.mu.Unlock()
		resp := new(dns.Msg)
		resp.SetReply(&req)
		if len(req.Question) == 1 && (req.Question[0].Name == "gateway.test." || req.Question[0].Name == "proxy.test.") {
			q := req.Question[0]
			if q.Qtype == dns.TypeA {
				rr := &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP("127.0.0.1"),
				}
				resp.Answer = []dns.RR{rr}
			}
			// AAAA: NOERROR, no answers.
		} else {
			resp.Rcode = dns.RcodeNameError
		}
		out, err := resp.Pack()
		if err != nil {
			return
		}
		var hdr [2]byte
		binary.BigEndian.PutUint16(hdr[:], uint16(len(out)))
		if _, err := conn.Write(hdr[:]); err != nil {
			return
		}
		if _, err := conn.Write(out); err != nil {
			return
		}
	}
}

func (s *fakeDNSServer) queryCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.queries
}

// questions returns a copy of the question names received so far,
// in arrival order.
func (s *fakeDNSServer) questionNames() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string{}, s.questions...)
}
