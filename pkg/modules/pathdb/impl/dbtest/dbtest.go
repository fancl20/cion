// Package dbtest implements the shared contract tests for path database
// implementations, following the trust DB's testing harness
// (pkg/modules/trustdb/impl/dbtest).
package dbtest

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/scionproto/scion/pkg/addr"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	cryptopb "github.com/scionproto/scion/pkg/proto/crypto"
	"google.golang.org/protobuf/proto"

	"github.com/fancl20/cion/pkg/modules/pathdb"
)

// TestableDB extends the path DB interface with the reset the harness needs.
type TestableDB interface {
	pathdb.DB
	// Prepare resets the internal state so the DB is empty and ready to be
	// tested.
	Prepare(*testing.T, context.Context)
	// Reopen closes and reopens the database at the same location.
	Reopen(*testing.T, context.Context)
}

// Run tests an implementation of the pathdb.DB interface; an implementation
// has at least one test that calls this suite.
func Run(t *testing.T, db TestableDB) {
	tests := map[string]func(*testing.T, TestableDB){
		"insert and get":       testInsertGet,
		"one segment by route": testOneSegmentByRoute,
		"types keep apart":     testTypesKeepApart,
		"evict expired":        testEvictExpired,
		"persist across open":  testPersist,
	}
	for name, test := range tests {
		t.Run("DB: "+name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			db.Prepare(t, ctx)
			test(t, db)
			_ = db.Close()
		})
	}
}

// segment builds a terminated down segment fixture crossing the given ASes
// in order, each entry's ingress interface 1 and egress interface 2 but the
// segment's ends', whose outer interface is zero. Its segment ID derives
// from the timestamp, so fixtures of one route at different instants differ
// in both, as two originations do. The signed bodies are well-formed but
// cryptographically meaningless: the database stores parsed segments, it
// does not verify them.
func segment(t *testing.T, ts time.Time, route ...addr.IA) *pathdb.Segment {
	t.Helper()
	pcb := &cppb.PathSegment{}
	info := &cppb.SegmentInformation{Timestamp: ts.Unix(), SegmentId: uint32(ts.Unix() & 0xffff)}
	raw, err := proto.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	pcb.SegmentInfo = raw
	for i, ia := range route {
		var next addr.IA
		hop := &cppb.HopField{ExpTime: 10}
		if i > 0 {
			hop.Ingress = 1
		}
		if i < len(route)-1 {
			next = route[i+1]
			hop.Egress = 2
		}
		body := &cppb.ASEntrySignedBody{
			IsdAs:     uint64(ia),
			NextIsdAs: uint64(next),
			HopEntry:  &cppb.HopEntry{HopField: hop},
		}
		rawBody, err := proto.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		hb, err := proto.Marshal(&cryptopb.HeaderAndBody{Body: rawBody})
		if err != nil {
			t.Fatal(err)
		}
		pcb.AsEntries = append(pcb.AsEntries, &cppb.ASEntry{
			Signed: &cryptopb.SignedMessage{HeaderAndBody: hb, Signature: []byte("sig")},
		})
	}
	seg, err := pathdb.NewSegment(pathdb.SegmentTypeDown, pcb)
	if err != nil {
		t.Fatal(err)
	}
	return seg
}

var (
	iaCore    = addr.MustIAFrom(20, 0xff0000000001)
	iaCoreB   = addr.MustIAFrom(20, 0xff0000000009)
	iaMiddle  = addr.MustIAFrom(20, 0xff0000000002)
	iaMiddleB = addr.MustIAFrom(20, 0xff0000000004)
	iaEnd     = addr.MustIAFrom(20, 0xff0000000003)
)

func testInsertGet(t *testing.T, db TestableDB) {
	ctx := context.Background()
	seg := segment(t, time.Now(), iaCore, iaMiddle, iaEnd)

	if in, err := db.Insert(ctx, seg); err != nil || !in {
		t.Fatalf("Insert = (%v, %v), want (true, nil)", in, err)
	}
	segs, err := db.Get(ctx, pathdb.Query{})
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) != 1 {
		t.Fatalf("Get all = %d segments, want 1", len(segs))
	}
	if got := segs[0].LastIA(); !got.Equal(iaEnd) {
		t.Errorf("last IA = %v, want %v", got, iaEnd)
	}
	if got := segs[0].Type; got != pathdb.SegmentTypeDown {
		t.Errorf("type = %v, want down", got)
	}

	segs, err = db.Get(ctx, pathdb.Query{Type: pathdb.SegmentTypeDown, DstIA: iaEnd})
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) != 1 {
		t.Fatalf("Get by destination = %d, want 1", len(segs))
	}
	segs, err = db.Get(ctx, pathdb.Query{SrcIA: iaCore})
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) != 1 {
		t.Fatalf("Get by origin = %d, want 1", len(segs))
	}
	for _, q := range []pathdb.Query{
		{DstIA: iaMiddle},
		{Type: pathdb.SegmentTypeUp},
		{SrcIA: iaCoreB},
	} {
		segs, err = db.Get(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		if len(segs) != 0 {
			t.Errorf("Get %+v = %d segments, want 0", q, len(segs))
		}
	}
}

// testOneSegmentByRoute checks the identity: the originations of one route
// share one slot, which holds the freshest of them, and another route is
// another slot.
func testOneSegmentByRoute(t *testing.T, db TestableDB) {
	ctx := context.Background()
	now := time.Now()
	only := func(want *pathdb.Segment) {
		t.Helper()
		segs, err := db.Get(ctx, pathdb.Query{DstIA: iaEnd})
		if err != nil {
			t.Fatal(err)
		}
		if len(segs) != 1 {
			t.Fatalf("Get = %d segments, want the route's one", len(segs))
		}
		if got := segs[0].PCB.Timestamp(); !got.Equal(want.PCB.Timestamp()) {
			t.Errorf("stored origination = %v, want %v", got, want.PCB.Timestamp())
		}
	}

	first := segment(t, now, iaCore, iaMiddle, iaEnd)
	if in, err := db.Insert(ctx, first); err != nil || !in {
		t.Fatalf("first Insert = (%v, %v), want (true, nil)", in, err)
	}
	// The same origination registered again changes nothing.
	if in, err := db.Insert(ctx, segment(t, now, iaCore, iaMiddle, iaEnd)); err != nil || in {
		t.Fatalf("repeated Insert = (%v, %v), want (false, nil)", in, err)
	}
	only(first)
	// A fresher origination of the route takes the slot.
	fresher := segment(t, now.Add(time.Minute), iaCore, iaMiddle, iaEnd)
	if in, err := db.Insert(ctx, fresher); err != nil || !in {
		t.Fatalf("fresher Insert = (%v, %v), want (true, nil)", in, err)
	}
	only(fresher)
	// A staler one arriving late leaves the slot alone.
	if in, err := db.Insert(ctx, segment(t, now.Add(-time.Minute), iaCore, iaMiddle, iaEnd)); err != nil || in {
		t.Fatalf("staler Insert = (%v, %v), want (false, nil)", in, err)
	}
	only(fresher)

	// Another route to the same end is a slot of its own.
	other := segment(t, now, iaCore, iaMiddleB, iaEnd)
	if in, err := db.Insert(ctx, other); err != nil || !in {
		t.Fatalf("other route's Insert = (%v, %v), want (true, nil)", in, err)
	}
	segs, err := db.Get(ctx, pathdb.Query{DstIA: iaEnd})
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) != 2 {
		t.Fatalf("Get = %d segments, want one per route", len(segs))
	}
}

// testTypesKeepApart checks that one route stored as two types holds two
// slots: the type is part of the identity.
func testTypesKeepApart(t *testing.T, db TestableDB) {
	ctx := context.Background()
	down := segment(t, time.Now(), iaCore, iaEnd)
	up := segment(t, time.Now(), iaCore, iaEnd)
	up.Type = pathdb.SegmentTypeUp
	for _, seg := range []*pathdb.Segment{down, up} {
		if in, err := db.Insert(ctx, seg); err != nil || !in {
			t.Fatalf("Insert %v = (%v, %v), want (true, nil)", seg.Type, in, err)
		}
	}
	for _, typ := range []pathdb.SegmentType{pathdb.SegmentTypeDown, pathdb.SegmentTypeUp} {
		segs, err := db.Get(ctx, pathdb.Query{Type: typ})
		if err != nil {
			t.Fatal(err)
		}
		if len(segs) != 1 {
			t.Errorf("Get type %v = %d segments, want 1", typ, len(segs))
		}
	}
}

func testEvictExpired(t *testing.T, db TestableDB) {
	ctx := context.Background()
	now := time.Now()
	fresh := segment(t, now, iaCore, iaMiddle, iaEnd)
	// ExpTime 10 → expiration ~56 minutes after the timestamp.
	stale := segment(t, now.Add(-2*time.Hour), iaCore, iaMiddleB, iaEnd)

	for _, seg := range []*pathdb.Segment{fresh, stale} {
		if _, err := db.Insert(ctx, seg); err != nil {
			t.Fatal(err)
		}
	}
	// On access, the expired segment is not served.
	segs, err := db.Get(ctx, pathdb.Query{})
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) != 1 || !segs[0].PCB.Timestamp().Equal(fresh.PCB.Timestamp()) {
		t.Fatalf("Get = %v segments, want only the fresh one", len(segs))
	}
	// The sweep removes it for good.
	n, err := db.DeleteExpired(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("DeleteExpired = %d, want 1", n)
	}
	segs, err = db.Get(ctx, pathdb.Query{Type: pathdb.SegmentTypeDown, DstIA: iaEnd})
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) != 1 {
		t.Fatalf("Get after sweep = %d, want 1 (fresh kept)", len(segs))
	}
}

// testPersist checks that segments survive closing and reopening the
// database: a restarted node serves up segments before the next beaconing
// period.
func testPersist(t *testing.T, db TestableDB) {
	ctx := context.Background()
	seg := segment(t, time.Now(), iaCore, iaMiddle, iaEnd)
	if _, err := db.Insert(ctx, seg); err != nil {
		t.Fatal(err)
	}
	db.Reopen(t, ctx)
	segs, err := db.Get(ctx, pathdb.Query{})
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) != 1 {
		t.Fatalf("Get after reopen = %d segments, want 1", len(segs))
	}
	if diff := cmp.Diff(seg.Key(), segs[0].Key()); diff != "" {
		t.Errorf("segment key after reopen (-want +got):\n%s", diff)
	}
	if got := segs[0].PCB.Timestamp(); !got.Equal(seg.PCB.Timestamp()) {
		t.Errorf("segment timestamp after reopen = %v, want %v", got, seg.PCB.Timestamp())
	}
}
