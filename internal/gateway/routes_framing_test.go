// Copyright (c) 2026 muse-cli contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Licensed under the GNU General Public License v3.0 or later.

package gateway

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	pb "github.com/thoitiettxl-cyber/castctl/internal/proto"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestRoutesCounts(t *testing.T) {
	tbl, err := DefaultRoutes()
	if err != nil {
		t.Fatalf("DefaultRoutes: %v", err)
	}
	if got := tbl.Total(); got != 258 {
		t.Fatalf("total = %d, want 258", got)
	}
	cases := map[string]int{"POST": 141, "GET": 91, "PATCH": 14, "DELETE": 12}
	for verb, want := range cases {
		if got := tbl.CountHTTP(verb); got != want {
			t.Errorf("CountHTTP(%s) = %d, want %d", verb, got, want)
		}
	}
}

func TestLookupRoute(t *testing.T) {
	tbl, _ := DefaultRoutes()
	cases := []struct {
		method  string
		want    bool
		http    string
		path    string
		service string
	}{
		{"connection.ping", true, "POST", "/api/ping", ""},
		{"chat.history", true, "GET", "/chat/history", ""},
		{"chat.mark_seen", true, "POST", "/api/chat/{thread_id}/seen", ""},
		{"egress.approval.decide", true, "POST", "/approvals/{approval_id}/decide", "sentinel"},
		{"vault.luks_status", true, "GET", "/luks/status", "vault"},
		{"custom_connectors.list", true, "POST", "/v1/custom-connectors/list", "authd"},
		{"media.raw", false, "", "", ""},
		{"no.such.method", false, "", "", ""},
		{"", false, "", "", ""},
		{"CHAT.HISTORY", false, "", "", ""},
		{"chat", false, "", "", ""},
	}
	for _, tc := range cases {
		r, ok := tbl.LookupRoute(tc.method)
		if ok != tc.want {
			t.Errorf("LookupRoute(%q) ok = %v, want %v", tc.method, ok, tc.want)
			continue
		}
		if !tc.want {
			continue
		}
		if r.Method != tc.method || r.HTTP != tc.http || r.Path != tc.path || r.Service != tc.service {
			t.Errorf("LookupRoute(%q) = %+v, want http=%q path=%q service=%q", tc.method, r, tc.http, tc.path, tc.service)
		}
	}
}

func TestServiceID(t *testing.T) {
	cases := map[string]pb.ServiceType{
		"":         pb.ServiceType_SERVICE_DAEMON,
		"daemon":   pb.ServiceType_SERVICE_DAEMON,
		"sentinel": pb.ServiceType_SERVICE_SENTINEL,
		"vault":    pb.ServiceType_SERVICE_VAULT,
		"authd":    pb.ServiceType_SERVICE_AUTHD,
		"unknown":  pb.ServiceType_SERVICE_DAEMON,
	}
	for name, want := range cases {
		if got := serviceID(name); got != want {
			t.Errorf("serviceID(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestParseRoutesMalformed(t *testing.T) {
	if _, err := ParseRoutes([]byte(`not json`)); err == nil {
		t.Error("ParseRoutes(malformed) = nil error, want error")
	}
	if _, err := ParseRoutes([]byte(`[]`)); err != nil {
		t.Errorf("ParseRoutes([]) = %v, want nil", err)
	}
}

func framePtrs(id int64, index, total uint32, payload []byte) *pb.NoiseTransportFrame {
	return &pb.NoiseTransportFrame{ChunkId: &id, ChunkIndex: &index, TotalChunks: &total, Payload: payload}
}

func TestReassemblerFeed(t *testing.T) {
	// heldState reports the reassembler's retained state: how
	// many unfinished groups it holds and how many payload
	// bytes those groups retain. A cap failure or a completion
	// must leave the failed/completed group with no entry and
	// no retained buffers; the rejected set holds chunk_ids
	// only (map[int64]struct{}), never piece buffers.
	heldState := func(r *reassembler) (groups, bytesHeld int) {
		groups = len(r.groups)
		for _, g := range r.groups {
			bytesHeld += g.size
		}
		return groups, bytesHeld
	}
	t.Run("total<=1 returns immediately", func(t *testing.T) {
		r := newReassembler()
		for _, tc := range []*pb.NoiseTransportFrame{
			{Payload: []byte("abc")},
			framePtrs(7, 0, 1, []byte("one")),
			framePtrs(7, 0, 0, []byte("zero-total")),
		} {
			got, ok, err := r.feed(tc)
			if err != nil {
				t.Fatalf("feed total<=1: %v", err)
			}
			if !ok {
				t.Fatalf("feed total<=1: ok=false")
			}
			if string(got) != string(tc.GetPayload()) {
				t.Fatalf("feed = %q, want %q", got, tc.GetPayload())
			}
		}
		if len(r.groups) != 0 || len(r.rejected) != 0 {
			t.Fatalf("accumulator touched for total<=1: groups=%d rejected=%d", len(r.groups), len(r.rejected))
		}
	})
	t.Run("joins by chunk_index out of order", func(t *testing.T) {
		r := newReassembler()
		frames := []*pb.NoiseTransportFrame{
			framePtrs(99, 2, 3, []byte("C")),
			framePtrs(99, 0, 3, []byte("A")),
			framePtrs(99, 1, 3, []byte("B")),
		}
		for i, f := range frames[:2] {
			if _, ok, err := r.feed(f); err != nil || ok {
				t.Fatalf("frame %d: complete early (ok=%v err=%v)", i, ok, err)
			}
		}
		got, ok, err := r.feed(frames[2])
		if err != nil || !ok || string(got) != "ABC" {
			t.Fatalf("join = %q ok=%v err=%v, want ABC true nil", got, ok, err)
		}
		if len(r.groups) != 0 {
			t.Fatalf("group not cleaned: %d left", len(r.groups))
		}
	})
	t.Run("different chunk ids do not mix", func(t *testing.T) {
		r := newReassembler()
		if _, ok, err := r.feed(framePtrs(1, 0, 2, []byte("x"))); err != nil || ok {
			t.Fatal("complete with one of two pieces")
		}
		if _, ok, err := r.feed(framePtrs(2, 1, 2, []byte("y"))); err != nil || ok {
			t.Fatal("complete across chunk ids")
		}
		got, ok, err := r.feed(framePtrs(1, 1, 2, []byte("z")))
		if err != nil || !ok || string(got) != "xz" {
			t.Fatalf("join = %q ok=%v err=%v, want xz", got, ok, err)
		}
	})
	t.Run("payload is copied", func(t *testing.T) {
		r := newReassembler()
		payload := []byte("mutable")
		got, ok, err := r.feed(&pb.NoiseTransportFrame{Payload: payload})
		if err != nil || !ok {
			t.Fatal("not complete")
		}
		payload[0] = 'X'
		if got[0] == 'X' {
			t.Fatal("returned payload aliases input")
		}
	})
	t.Run("out of range indices are kept in sorted order", func(t *testing.T) {
		// Python join_chunks joins sorted(parts), including
		// indices >= total_chunks; it never inserts empty
		// bytes for missing slots.
		r := newReassembler()
		if _, ok, err := r.feed(framePtrs(5, 5, 3, []byte("C"))); err != nil || ok {
			t.Fatal("complete with one of three pieces")
		}
		if _, ok, err := r.feed(framePtrs(5, 0, 3, []byte("A"))); err != nil || ok {
			t.Fatal("complete with two of three pieces")
		}
		got, ok, err := r.feed(framePtrs(5, 1, 3, []byte("B")))
		if err != nil || !ok || string(got) != "ABC" {
			t.Fatalf("join indices {0,1,5} total=3 = %q ok=%v err=%v, want ABC true", got, ok, err)
		}
	})
	t.Run("all indices out of range are joined", func(t *testing.T) {
		r := newReassembler()
		if _, ok, err := r.feed(framePtrs(6, 6, 2, []byte("B"))); err != nil || ok {
			t.Fatal("complete with one of two pieces")
		}
		got, ok, err := r.feed(framePtrs(6, 5, 2, []byte("A")))
		if err != nil || !ok || string(got) != "AB" {
			t.Fatalf("join indices {5,6} total=2 = %q ok=%v err=%v, want AB true", got, ok, err)
		}
	})
	t.Run("duplicate index overwrites", func(t *testing.T) {
		// Same-group overwrite before completion: feed index
		// 1 twice, then index 0 completes the group; the
		// second piece for index 1 wins.
		r := newReassembler()
		if _, ok, err := r.feed(framePtrs(8, 1, 2, []byte("stale"))); err != nil || ok {
			t.Fatal("complete with one of two pieces")
		}
		if _, ok, err := r.feed(framePtrs(8, 1, 2, []byte("B"))); err != nil || ok {
			t.Fatal("complete with one distinct index")
		}
		got, ok, err := r.feed(framePtrs(8, 0, 2, []byte("A")))
		if err != nil || !ok || string(got) != "AB" {
			t.Fatalf("join with overwritten index 1 = %q ok=%v err=%v, want AB true", got, ok, err)
		}
	})
	t.Run("duplicate overwrite adjusts held size", func(t *testing.T) {
		// Overwriting an index with a shorter piece shrinks
		// the held size: a 4-byte piece at the 4-byte cap,
		// overwritten by 1 byte, leaves room for the 2-byte
		// completing piece (total 3).
		r := newReassemblerWithLimits(4, 4)
		if _, ok, err := r.feed(framePtrs(40, 1, 2, []byte("ABCD"))); err != nil || ok {
			t.Fatalf("first piece: ok=%v err=%v", ok, err)
		}
		if _, ok, err := r.feed(framePtrs(40, 1, 2, []byte("X"))); err != nil || ok {
			t.Fatalf("overwrite: ok=%v err=%v", ok, err)
		}
		got, ok, err := r.feed(framePtrs(40, 0, 2, []byte("YZ")))
		if err != nil || !ok || string(got) != "YZX" {
			t.Fatalf("join after overwrite = %q ok=%v err=%v, want YZX true", got, ok, err)
		}
	})
	t.Run("empty payload pieces complete empty", func(t *testing.T) {
		r := newReassembler()
		if _, ok, err := r.feed(framePtrs(9, 0, 2, []byte{})); err != nil || ok {
			t.Fatal("complete with one of two pieces")
		}
		got, ok, err := r.feed(framePtrs(9, 1, 2, nil))
		if err != nil || !ok || len(got) != 0 {
			t.Fatalf("join empty pieces = %q ok=%v err=%v, want empty true", got, ok, err)
		}
	})
	t.Run("boundary splits round trip", func(t *testing.T) {
		for _, size := range []int{60000, 60001, 120001} {
			data := make([]byte, size)
			for i := range data {
				data[i] = byte(i % 251)
			}
			pieces := splitPieces(data)
			r := newReassembler()
			var got []byte
			var ok bool
			var err error
			for i, p := range pieces {
				got, ok, err = r.feed(framePtrs(10, uint32(i), uint32(len(pieces)), p))
				if err != nil {
					t.Fatalf("round trip size %d: %v", size, err)
				}
			}
			if !ok || !bytes.Equal(got, data) {
				t.Fatalf("round trip size %d: ok=%v len=%d, want %d", size, ok, len(got), size)
			}
		}
	})
	t.Run("exactly at size cap passes", func(t *testing.T) {
		r := newReassemblerWithLimits(3, 4)
		if _, ok, err := r.feed(framePtrs(20, 0, 2, []byte("AB"))); err != nil || ok {
			t.Fatalf("first piece: ok=%v err=%v", ok, err)
		}
		got, ok, err := r.feed(framePtrs(20, 1, 2, []byte("C")))
		if err != nil || !ok || string(got) != "ABC" {
			t.Fatalf("at-cap join = %q ok=%v err=%v, want ABC", got, ok, err)
		}
		// Completion removes the entry: no leak.
		if groups, bytesHeld := heldState(r); groups != 0 || bytesHeld != 0 {
			t.Errorf("held state after at-cap completion = (%d groups, %d bytes), want (0, 0)", groups, bytesHeld)
		}
	})
	t.Run("one byte over size cap fails typed and isolates other groups", func(t *testing.T) {
		r := newReassemblerWithLimits(3, 4)
		if _, ok, err := r.feed(framePtrs(20, 0, 2, []byte("AB"))); err != nil || ok {
			t.Fatalf("first piece: ok=%v err=%v", ok, err)
		}
		got, ok, err := r.feed(framePtrs(20, 1, 2, []byte("CD")))
		if err == nil || ok {
			t.Fatalf("over-cap feed: ok=%v err=%v, want a typed error", ok, err)
		}
		if got != nil {
			t.Errorf("over-cap feed returned %d bytes, want no partial delivery", len(got))
		}
		var sizeErr *ReassemblySizeError
		if !errors.As(err, &sizeErr) || sizeErr.Limit != 3 || sizeErr.Size != 4 || sizeErr.ChunkID != 20 {
			t.Errorf("error = %T (%v), want *ReassemblySizeError{ChunkID:20, Size:4, Limit:3}", err, err)
		}
		// Distinct type per cap: the size error must NOT
		// match the groups error type.
		var groupsErr *TooManyUnfinishedGroupsError
		if errors.As(err, &groupsErr) {
			t.Errorf("size-cap error also matches *TooManyUnfinishedGroupsError: the two cap types must stay distinct")
		}
		// The failed group's state is released (no group
		// entry, no retained bytes).
		if groups, bytesHeld := heldState(r); groups != 0 || bytesHeld != 0 {
			t.Errorf("held state after size-cap failure = (%d groups, %d bytes), want (0, 0)", groups, bytesHeld)
		}
		if len(r.rejected) > 4 {
			t.Errorf("rejected set = %d entries, want <= 4 (the groups limit)", len(r.rejected))
		}
		// The failed group is gone; its later pieces are
		// dropped silently, and an unrelated group still
		// completes from the same accumulator.
		if _, ok, err := r.feed(framePtrs(20, 0, 2, []byte("ZZ"))); err != nil || ok {
			t.Fatalf("rejected-group piece: ok=%v err=%v, want dropped silently", ok, err)
		}
		if _, ok, err := r.feed(framePtrs(21, 0, 2, []byte("x"))); err != nil || ok {
			t.Fatalf("other group first piece: ok=%v err=%v", ok, err)
		}
		got, ok, err = r.feed(framePtrs(21, 1, 2, []byte("y")))
		if err != nil || !ok || string(got) != "xy" {
			t.Fatalf("other group join = %q ok=%v err=%v, want xy", got, ok, err)
		}
		if len(r.groups) != 0 {
			t.Fatalf("groups left = %d, want 0", len(r.groups))
		}
	})
	t.Run("single piece over size cap fails typed", func(t *testing.T) {
		r := newReassemblerWithLimits(3, 4)
		got, ok, err := r.feed(&pb.NoiseTransportFrame{Payload: []byte("ABCD")})
		if err == nil || ok {
			t.Fatalf("single-piece over-cap: ok=%v err=%v, want a typed error", ok, err)
		}
		if got != nil {
			t.Errorf("single-piece over-cap returned %d bytes, want no partial delivery", len(got))
		}
		var sizeErr *ReassemblySizeError
		if !errors.As(err, &sizeErr) || sizeErr.Size != 4 || sizeErr.Limit != 3 {
			t.Errorf("error = %T (%v), want *ReassemblySizeError{Size:4, Limit:3}", err, err)
		}
		var groupsErr *TooManyUnfinishedGroupsError
		if errors.As(err, &groupsErr) {
			t.Errorf("size-cap error also matches *TooManyUnfinishedGroupsError")
		}
		if groups, bytesHeld := heldState(r); groups != 0 || bytesHeld != 0 {
			t.Errorf("held state after single-piece cap failure = (%d groups, %d bytes), want (0, 0)", groups, bytesHeld)
		}
	})
	t.Run("unfinished groups limit rejects newest, existing complete", func(t *testing.T) {
		r := newReassemblerWithLimits(100, 2)
		if _, ok, err := r.feed(framePtrs(30, 0, 2, []byte("a"))); err != nil || ok {
			t.Fatalf("group A: ok=%v err=%v", ok, err)
		}
		if _, ok, err := r.feed(framePtrs(31, 0, 2, []byte("b"))); err != nil || ok {
			t.Fatalf("group B: ok=%v err=%v", ok, err)
		}
		got, ok, err := r.feed(framePtrs(32, 0, 2, []byte("c")))
		if err == nil || ok {
			t.Fatalf("third group: ok=%v err=%v, want a typed error", ok, err)
		}
		if got != nil {
			t.Errorf("groups-cap feed returned %d bytes, want no partial delivery", len(got))
		}
		var groupsErr *TooManyUnfinishedGroupsError
		if !errors.As(err, &groupsErr) || groupsErr.Held != 2 || groupsErr.Limit != 2 || groupsErr.ChunkID != 32 {
			t.Errorf("error = %T (%v), want *TooManyUnfinishedGroupsError{ChunkID:32, Held:2, Limit:2}", err, err)
		}
		// Distinct type per cap: the groups error must NOT
		// match the size error type.
		var sizeErr *ReassemblySizeError
		if errors.As(err, &sizeErr) {
			t.Errorf("groups-cap error also matches *ReassemblySizeError: the two cap types must stay distinct")
		}
		// The rejected group holds no state; the two
		// existing groups are untouched.
		if groups, bytesHeld := heldState(r); groups != 2 || bytesHeld != 2 {
			t.Errorf("held state after groups-cap rejection = (%d groups, %d bytes), want (2, 2)", groups, bytesHeld)
		}
		// The rejected group's later pieces are dropped;
		// the two existing groups still complete, and the
		// freed slot admits a new group afterwards.
		if _, ok, err := r.feed(framePtrs(32, 1, 2, []byte("c2"))); err != nil || ok {
			t.Fatalf("rejected-group piece: ok=%v err=%v, want dropped silently", ok, err)
		}
		got, ok, err = r.feed(framePtrs(30, 1, 2, []byte("A")))
		if err != nil || !ok || string(got) != "aA" {
			t.Fatalf("group A join = %q ok=%v err=%v, want aA", got, ok, err)
		}
		got, ok, err = r.feed(framePtrs(31, 1, 2, []byte("B")))
		if err != nil || !ok || string(got) != "bB" {
			t.Fatalf("group B join = %q ok=%v err=%v, want bB", got, ok, err)
		}
		// Completion removes the entry: after every group
		// completes, no unfinished state leaks.
		if groups, bytesHeld := heldState(r); groups != 0 || bytesHeld != 0 {
			t.Errorf("held state after all groups complete = (%d groups, %d bytes), want (0, 0)", groups, bytesHeld)
		}
		_, ok, err = r.feed(framePtrs(33, 0, 2, []byte("d")))
		if err != nil || ok {
			t.Fatalf("new group after slots freed: ok=%v err=%v", ok, err)
		}
		got, ok, err = r.feed(framePtrs(33, 1, 2, []byte("D")))
		if err != nil || !ok || string(got) != "dD" {
			t.Fatalf("new group join = %q ok=%v err=%v, want dD", got, ok, err)
		}
		if groups, bytesHeld := heldState(r); groups != 0 || bytesHeld != 0 {
			t.Errorf("held state after final completion = (%d groups, %d bytes), want (0, 0)", groups, bytesHeld)
		}
	})
	t.Run("empty pieces past piece limit fail typed and isolate other groups", func(t *testing.T) {
		// RT-3: empty pieces carry 0 bytes, so only the
		// piece-count cap can stop the parts map growing.
		// Limit 3: three distinct empty indices are fine;
		// the fourth distinct index fails typed.
		r := newReassemblerWithPieceLimit(100, 4, 3)
		for _, idx := range []uint32{0, 1, 2} {
			if _, ok, err := r.feed(framePtrs(60, idx, 10, []byte{})); err != nil || ok {
				t.Fatalf("piece %d: ok=%v err=%v, want incomplete, no error", idx, ok, err)
			}
		}
		got, ok, err := r.feed(framePtrs(60, 3, 10, []byte{}))
		if err == nil || ok {
			t.Fatalf("fourth distinct piece: ok=%v err=%v, want a typed error", ok, err)
		}
		if got != nil {
			t.Errorf("piece-cap feed returned %d bytes, want no partial delivery", len(got))
		}
		var piecesErr *TooManyPiecesError
		if !errors.As(err, &piecesErr) || piecesErr.Pieces != 4 || piecesErr.Limit != 3 || piecesErr.ChunkID != 60 {
			t.Errorf("error = %T (%v), want *TooManyPiecesError{ChunkID:60, Pieces:4, Limit:3}", err, err)
		}
		// Distinct type per cap: the piece error must NOT
		// match either of the other two cap types.
		var sizeErr *ReassemblySizeError
		if errors.As(err, &sizeErr) {
			t.Errorf("piece-cap error also matches *ReassemblySizeError")
		}
		var groupsErr *TooManyUnfinishedGroupsError
		if errors.As(err, &groupsErr) {
			t.Errorf("piece-cap error also matches *TooManyUnfinishedGroupsError")
		}
		// The failed group is gone (no entry, no buffers);
		// the reader-survival contract holds through
		// isReassemblyCapError.
		if !isReassemblyCapError(err) {
			t.Errorf("piece-cap error is not recognised by isReassemblyCapError; the reader would die on it")
		}
		if groups, bytesHeld := heldState(r); groups != 0 || bytesHeld != 0 {
			t.Errorf("held state after piece-cap failure = (%d groups, %d bytes), want (0, 0)", groups, bytesHeld)
		}
		// The failed group's later pieces are dropped
		// silently, and an unrelated group still completes.
		if _, ok, err := r.feed(framePtrs(60, 4, 10, []byte{})); err != nil || ok {
			t.Fatalf("rejected-group piece: ok=%v err=%v, want dropped silently", ok, err)
		}
		if _, ok, err := r.feed(framePtrs(61, 0, 2, []byte("x"))); err != nil || ok {
			t.Fatalf("other group first piece: ok=%v err=%v", ok, err)
		}
		got, ok, err = r.feed(framePtrs(61, 1, 2, []byte("y")))
		if err != nil || !ok || string(got) != "xy" {
			t.Fatalf("other group join = %q ok=%v err=%v, want xy", got, ok, err)
		}
	})
	t.Run("exactly at piece limit passes", func(t *testing.T) {
		r := newReassemblerWithPieceLimit(100, 4, 3)
		for _, idx := range []uint32{0, 1} {
			if _, ok, err := r.feed(framePtrs(62, idx, 3, []byte{})); err != nil || ok {
				t.Fatalf("piece %d: ok=%v err=%v", idx, ok, err)
			}
		}
		got, ok, err := r.feed(framePtrs(62, 2, 3, []byte{}))
		if err != nil || !ok || len(got) != 0 {
			t.Fatalf("at-limit join = %q ok=%v err=%v, want empty true nil", got, ok, err)
		}
		if groups, bytesHeld := heldState(r); groups != 0 || bytesHeld != 0 {
			t.Errorf("held state after at-limit completion = (%d groups, %d bytes), want (0, 0)", groups, bytesHeld)
		}
	})
	t.Run("duplicate index overwrite does not count toward piece limit", func(t *testing.T) {
		// Overwriting an existing index grows nothing, so
		// repeated overwrites at the limit must not trip
		// the cap; the next DISTINCT index completes.
		r := newReassemblerWithPieceLimit(100, 4, 2)
		if _, ok, err := r.feed(framePtrs(63, 0, 2, []byte("a"))); err != nil || ok {
			t.Fatalf("first piece: ok=%v err=%v", ok, err)
		}
		if _, ok, err := r.feed(framePtrs(63, 0, 2, []byte("A"))); err != nil || ok {
			t.Fatalf("overwrite: ok=%v err=%v, want incomplete, no error", ok, err)
		}
		if _, ok, err := r.feed(framePtrs(63, 0, 2, []byte("B"))); err != nil || ok {
			t.Fatalf("second overwrite: ok=%v err=%v, want incomplete, no error", ok, err)
		}
		got, ok, err := r.feed(framePtrs(63, 1, 2, []byte("C")))
		if err != nil || !ok || string(got) != "BC" {
			t.Fatalf("join after overwrites = %q ok=%v err=%v, want BC", got, ok, err)
		}
	})
	t.Run("exactly at groups limit passes, limit plus one fails", func(t *testing.T) {
		// Boundary for the unfinished-groups cap: with
		// limit 3, opening exactly 3 groups is fine; the
		// 4th is rejected typed.
		r := newReassemblerWithLimits(100, 3)
		for _, id := range []int64{50, 51, 52} {
			if _, ok, err := r.feed(framePtrs(id, 0, 2, []byte("x"))); err != nil || ok {
				t.Fatalf("group %d at limit: ok=%v err=%v, want incomplete, no error", id, ok, err)
			}
		}
		if groups, _ := heldState(r); groups != 3 {
			t.Fatalf("held groups = %d, want exactly 3 at the limit", groups)
		}
		_, ok, err := r.feed(framePtrs(53, 0, 2, []byte("x")))
		if err == nil || ok {
			t.Fatalf("group past limit: ok=%v err=%v, want a typed error", ok, err)
		}
		var groupsErr *TooManyUnfinishedGroupsError
		if !errors.As(err, &groupsErr) || groupsErr.Held != 3 || groupsErr.Limit != 3 {
			t.Errorf("error = %T (%v), want *TooManyUnfinishedGroupsError{Held:3, Limit:3}", err, err)
		}
		// Completing all three removes every entry.
		for _, id := range []int64{50, 51, 52} {
			if _, ok, err := r.feed(framePtrs(id, 1, 2, []byte("y"))); err != nil || !ok {
				t.Fatalf("group %d completion: ok=%v err=%v", id, ok, err)
			}
		}
		if groups, bytesHeld := heldState(r); groups != 0 || bytesHeld != 0 {
			t.Errorf("held state after boundary completions = (%d groups, %d bytes), want (0, 0)", groups, bytesHeld)
		}
	})
}

// TestReassemblerLargeTotalSmallHeap (F1): a server-controlled
// total_chunks must never preallocate total*SendPiece bytes.
// 20000 empty pieces (old code: 1.2GB capacity for 0 payload bytes)
// must complete with small allocation. HeapAlloc does NOT count
// very large backing arrays on this runtime (measured: a 300MB
// make() left HeapAlloc unchanged), so the assertion uses
// cumulative TotalAlloc plus the returned slice's capacity, both
// of which separate the old 1.2GB preallocation from the new
// payload-sized join by orders of magnitude.
func TestReassemblerLargeTotalSmallHeap(t *testing.T) {
	const total = 20000
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	r := newReassembler()
	var got []byte
	var ok bool
	var err error
	for i := uint32(0); i < total; i++ {
		got, ok, err = r.feed(framePtrs(11, i, total, []byte{}))
		if err != nil {
			t.Fatalf("piece %d: %v", i, err)
		}
		if ok && i != total-1 {
			t.Fatalf("complete early at piece %d", i)
		}
	}
	if !ok {
		t.Fatal("large-total group never completed")
	}
	if len(got) != 0 {
		t.Fatalf("joined output len = %d, want 0", len(got))
	}
	if len(r.groups) != 0 {
		t.Fatalf("groups not cleaned: %d left", len(r.groups))
	}
	if cap(got) > 1<<20 {
		t.Errorf("joined capacity = %d, want < 1MB for 0 payload bytes (capacity must not scale with total_chunks)", cap(got))
	}
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	// Generous bound: the accumulator holds 20000 map entries of
	// empty slices (~a few MB at most). The old preallocation was
	// 1.2GB; anything under 100MB proves capacity is not sized by
	// total*SendPiece.
	delta := int64(after.TotalAlloc) - int64(before.TotalAlloc)
	if delta > 100<<20 {
		t.Errorf("allocated bytes = %d, want < 100MB for 20000 empty pieces", delta)
	}
}

// TestReassemblerProductionPieceLimit pins the production
// piece-count cap: MaxPiecesPerGroup empty pieces are held
// without error, and the (MaxPiecesPerGroup+1)th distinct empty
// piece fails with *TooManyPiecesError. This is the RT-3
// bypass at production scale (200,000 empty pieces).
func TestReassemblerProductionPieceLimit(t *testing.T) {
	r := newReassembler()
	const total = MaxPiecesPerGroup + 10
	for i := uint32(0); i < MaxPiecesPerGroup; i++ {
		if _, ok, err := r.feed(framePtrs(70, i, total, []byte{})); err != nil || ok {
			t.Fatalf("piece %d: ok=%v err=%v, want incomplete, no error", i, ok, err)
		}
	}
	got, ok, err := r.feed(framePtrs(70, MaxPiecesPerGroup, total, []byte{}))
	if err == nil || ok {
		t.Fatalf("piece %d: ok=%v err=%v, want *TooManyPiecesError", MaxPiecesPerGroup, ok, err)
	}
	if got != nil {
		t.Errorf("piece-cap feed returned %d bytes, want no partial delivery", len(got))
	}
	var piecesErr *TooManyPiecesError
	if !errors.As(err, &piecesErr) || piecesErr.Pieces != MaxPiecesPerGroup+1 || piecesErr.Limit != MaxPiecesPerGroup {
		t.Errorf("error = %T (%v), want *TooManyPiecesError{Pieces:%d, Limit:%d}", err, err, MaxPiecesPerGroup+1, MaxPiecesPerGroup)
	}
	if len(r.groups) != 0 {
		t.Errorf("groups left = %d, want 0 (failed group discarded)", len(r.groups))
	}
}

func TestSplitPieces(t *testing.T) {
	cases := []struct {
		size  int
		wantN int
	}{
		{0, 1}, {1, 1}, {60000, 1}, {60001, 2}, {120000, 2}, {120001, 3},
	}
	for _, tc := range cases {
		data := make([]byte, tc.size)
		pieces := splitPieces(data)
		if len(pieces) != tc.wantN {
			t.Errorf("splitPieces(%d): %d pieces, want %d", tc.size, len(pieces), tc.wantN)
		}
		total := 0
		for _, p := range pieces {
			if len(p) > SendPiece {
				t.Errorf("splitPieces(%d): piece %d > %d", tc.size, len(p), SendPiece)
			}
			total += len(p)
		}
		if total != tc.size {
			t.Errorf("splitPieces(%d): total %d", tc.size, total)
		}
	}
}

func TestMarshalTransportFramePresence(t *testing.T) {
	// Chunk id 0 present must serialize (field 1, varint 0) and
	// round-trip with Has() true; an absent id must not.
	b, err := marshalTransportFrame(0, 0, 1, []byte("x"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var fr pb.NoiseTransportFrame
	if err := proto.Unmarshal(b, &fr); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	fd := fr.ProtoReflect().Descriptor().Fields()
	for _, name := range []string{"chunk_id", "chunk_index", "total_chunks", "payload"} {
		if !fr.ProtoReflect().Has(fd.ByName(protoreflect.Name(name))) {
			t.Errorf("field %s not present after marshal", name)
		}
	}
	if fr.GetChunkId() != 0 || fr.GetTotalChunks() != 1 {
		t.Errorf("round-trip values: id=%d total=%d", fr.GetChunkId(), fr.GetTotalChunks())
	}
}

// TestGoldenVectorsSubset re-runs the PR0 proto-probe golden
// checks against the gateway's framing helpers: messages built
// with the generated code must marshal byte-identically to the
// bytes Python produced (vectors/*.bin in internal/proto).
func TestGoldenVectorsSubset(t *testing.T) {
	uni := "café ☃ — lý do"
	builders := map[string]func() proto.Message{
		"ntf_all": func() proto.Message {
			return &pb.NoiseTransportFrame{ChunkId: proto.Int64(1234567890123), ChunkIndex: proto.Uint32(2), TotalChunks: proto.Uint32(5), Payload: []byte("hello\xff\xfe\x00\x80\xc3\xa9")}
		},
		"ntf_chunk_id_zero_present": func() proto.Message {
			return &pb.NoiseTransportFrame{ChunkId: proto.Int64(0)}
		},
		"ntf_payload_empty_present": func() proto.Message {
			return &pb.NoiseTransportFrame{Payload: []byte{}}
		},
		"sr_daemon": func() proto.Message {
			return &pb.ServiceRequest{Service: pb.ServiceType_SERVICE_DAEMON, Payload: []byte("frame-bytes-\xff")}
		},
		"sr_sentinel": func() proto.Message {
			return &pb.ServiceRequest{Service: pb.ServiceType_SERVICE_SENTINEL, Payload: []byte{}}
		},
		"sf_request": func() proto.Message {
			return &pb.ServiceFrame{StreamId: 1, Kind: &pb.ServiceFrame_Request{Request: &pb.ApplicationRequest{Verb: "GET", Path: "/x", Headers: []*pb.Header{{Key: "k", Value: "v"}}, Body: []byte("hi"), EndBody: true}}}
		},
		"ar_full": func() proto.Message {
			return &pb.ApplicationRequest{Verb: "POST", Path: "/api/test?q=café", Headers: []*pb.Header{{Key: "content-type", Value: "application/json"}, {Key: "x-request-id", Value: "abc-123"}, {Key: "", Value: ""}, {Key: "x-unicode", Value: uni}}, Body: []byte("\x00\xff\xfe binary \x80"), EndBody: true}
		},
		"aresp_full": func() proto.Message {
			return &pb.ApplicationResponse{Status: 200, Headers: []*pb.Header{{Key: "content-type", Value: "text/plain"}, {Key: "x-u", Value: uni}}, Body: []byte("body\xff\x00end"), EndBody: true}
		},
		"reset_cancelled": func() proto.Message {
			return &pb.Reset{Code: pb.Reset_CANCELLED, Reason: uni}
		},
	}
	for name, build := range builders {
		t.Run(name, func(t *testing.T) {
			pyBytes, err := os.ReadFile(filepath.Join("..", "proto", "testdata", "vectors", name+".bin"))
			if err != nil {
				t.Fatalf("read vector: %v", err)
			}
			goBytes, err := proto.Marshal(build())
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if !bytes.Equal(goBytes, pyBytes) {
				t.Fatalf("go bytes != python bytes:\n go: %x\n py: %x", goBytes, pyBytes)
			}
			parsed := build().ProtoReflect().New().Interface()
			if err := proto.Unmarshal(pyBytes, parsed); err != nil {
				t.Fatalf("unmarshal python bytes: %v", err)
			}
			if !proto.Equal(build(), parsed) {
				t.Fatalf("proto.Equal(go-built, parsed) = false")
			}
		})
	}
}
