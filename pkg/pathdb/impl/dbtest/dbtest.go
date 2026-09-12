// Package dbtest implements the shared contract tests for path database
// implementations, following the trust DB's testing harness
// (pkg/trust/impl/dbtest).
package dbtest

import (
	"context"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	cryptopb "github.com/scionproto/scion/pkg/proto/crypto"
	"google.golang.org/protobuf/proto"

	"github.com/fancl20/cion/pkg/pathdb"
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
		"insert and get":      testInsertGet,
		"replace by identity": testReplaceByIdentity,
		"evict expired":       testEvictExpired,
		"persist across open": testPersist,
	}
	for name, test := range tests {
		t.Run("DB: "+name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			db.Prepare(t, ctx)
			test(t, db)
			db.Close() //nolint:errcheck
		})
	}
}

// segment builds a terminated segment fixture: entries [core, middle, end],
// signed bodies well-formed but cryptographically meaningless — the database
// stores parsed segments, it does not verify them.
func segment(t *testing.T, core, middle, end addr.IA, ts time.Time) *pathdb.Segment {
	t.Helper()
	pcb := &cppb.PathSegment{}
	info := &cppb.SegmentInformation{Timestamp: ts.Unix(), SegmentId: 4242}
	raw, err := proto.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	pcb.SegmentInfo = raw
	for _, e := range []struct {
		ia, next addr.IA
	}{
		{core, middle},
		{middle, end},
		{end, 0},
	} {
		body := &cppb.ASEntrySignedBody{
			IsdAs:     uint64(e.ia),
			NextIsdAs: uint64(e.next),
			HopEntry: &cppb.HopEntry{
				HopField: &cppb.HopField{
					Ingress: 1,
					Egress:  2,
					ExpTime: 10,
				},
			},
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
	iaCore   = addr.MustIAFrom(20, 0xff0000000001)
	iaCoreB  = addr.MustIAFrom(20, 0xff0000000009)
	iaMiddle = addr.MustIAFrom(20, 0xff0000000002)
	iaEnd    = addr.MustIAFrom(20, 0xff0000000003)
)

func testInsertGet(t *testing.T, db TestableDB) {
	ctx := context.Background()
	seg := segment(t, iaCore, iaMiddle, iaEnd, time.Now())

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

func testReplaceByIdentity(t *testing.T, db TestableDB) {
	ctx := context.Background()
	now := time.Now()
	first := segment(t, iaCore, iaMiddle, iaEnd, now)
	second := segment(t, iaCore, iaMiddle, iaEnd, now) // same origin, ID, timestamp

	if in, err := db.Insert(ctx, first); err != nil || !in {
		t.Fatalf("first Insert = (%v, %v), want (true, nil)", in, err)
	}
	if in, err := db.Insert(ctx, second); err != nil || in {
		t.Fatalf("second Insert = (%v, %v), want (false, nil)", in, err)
	}
	segs, err := db.Get(ctx, pathdb.Query{})
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) != 1 {
		t.Fatalf("Get = %d segments, want 1 after replacement", len(segs))
	}
	// A different creation timestamp is a different segment.
	third := segment(t, iaCore, iaMiddle, iaEnd, now.Add(time.Second))
	if in, err := db.Insert(ctx, third); err != nil || !in {
		t.Fatalf("third Insert = (%v, %v), want (true, nil)", in, err)
	}
	segs, err = db.Get(ctx, pathdb.Query{})
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) != 2 {
		t.Fatalf("Get = %d segments, want 2", len(segs))
	}
}

func testEvictExpired(t *testing.T, db TestableDB) {
	ctx := context.Background()
	now := time.Now()
	fresh := segment(t, iaCore, iaMiddle, iaEnd, now)
	// ExpTime 10 → expiration ~56 minutes after the timestamp.
	stale := segment(t, iaCore, iaMiddle, iaEnd, now.Add(-2*time.Hour))

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
	if len(segs) != 1 || !segs[0].Key().Timestamp.Equal(fresh.Key().Timestamp) {
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
	seg := segment(t, iaCore, iaMiddle, iaEnd, time.Now())
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
	if got := segs[0].Key(); got != seg.Key() {
		t.Errorf("segment key = %v, want %v", got, seg.Key())
	}
}
