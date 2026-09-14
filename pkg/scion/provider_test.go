package scion

import (
	"context"
	"hash"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/scrypto"

	"github.com/fancl20/cion/pkg/pathdb"
	"github.com/fancl20/cion/pkg/segment"
)

var (
	iaCore = addr.MustIAFrom(20, 0xff0000000001)
	iaMid  = addr.MustIAFrom(20, 0xff0000000002)
	iaLeaf = addr.MustIAFrom(20, 0xff0000000003)
)

// fakePathDB is an in-memory path database.
type fakePathDB struct{ segs []*pathdb.Segment }

func (d *fakePathDB) Insert(_ context.Context, seg *pathdb.Segment) (bool, error) {
	d.segs = append(d.segs, seg)
	return true, nil
}

func (d *fakePathDB) Get(_ context.Context, q pathdb.Query) ([]*pathdb.Segment, error) {
	var out []*pathdb.Segment
	for _, s := range d.segs {
		if q.Type != pathdb.SegmentTypeUnspecified && q.Type != s.Type {
			continue
		}
		if !q.SrcIA.IsZero() && !q.SrcIA.Equal(s.FirstIA()) {
			continue
		}
		if !q.DstIA.IsZero() && !q.DstIA.Equal(s.LastIA()) {
			continue
		}
		out = append(out, s)
	}
	return out, nil
}

func (d *fakePathDB) DeleteExpired(context.Context, time.Time) (int, error) { return 0, nil }
func (d *fakePathDB) Close() error                                          { return nil }

// linePCB builds the unsigned route form of a segment crossing the given
// ASes in order, MACed with the test forwarding key.
func linePCB(t *testing.T, now time.Time, ias ...addr.IA) *segment.PCB {
	t.Helper()
	pcb, err := segment.PCBWithID(now, 0x111)
	if err != nil {
		t.Fatal(err)
	}
	for i, ia := range ias {
		opts := segment.EntryOptions{}
		if i > 0 {
			opts.IngressIfID = testIfID
		}
		if i < len(ias)-1 {
			opts.EgressIfID = testIfID
		}
		if _, err := pcb.AppendRouteHop(ia, opts, testMACHasher); err != nil {
			t.Fatal(err)
		}
	}
	return pcb
}

func testMACHasher() hash.Hash {
	h, _ := scrypto.InitMac(testMACKeyBytes)
	return h
}

// TestProviderLocalPath checks the local-only resolution: a core destination
// resolves to the reversed freshest up segment, without any fetch.
func TestProviderLocalPath(t *testing.T) {
	db := &fakePathDB{}
	if _, err := db.Insert(context.Background(), &pathdb.Segment{
		Type: pathdb.SegmentTypeUp,
		PCB:  linePCB(t, time.Now(), iaCore, iaMid, iaLeaf),
	}); err != nil {
		t.Fatal(err)
	}
	fetched := false
	p := &PathProvider{
		IA: iaLeaf,
		DB: db,
		Lookup: func(context.Context, addr.IA) []*pathdb.Segment {
			fetched = true
			return nil
		},
	}

	path, err := p.LocalPath(iaCore)
	if err != nil {
		t.Fatal(err)
	}
	if len(path.HopFields) != 3 {
		t.Fatalf("route to the core = %d hops, want 3", len(path.HopFields))
	}
	if path.InfoFields[0].ConsDir {
		t.Error("route to the core is not reversed")
	}
	if fetched {
		t.Error("LocalPath fetched down segments, want local state only")
	}
}

// TestProviderComposedPath checks the composed resolution from a leaf: the
// reversed up segment to the core the down segment starts at, composed
// before the down segment's forward path.
func TestProviderComposedPath(t *testing.T) {
	db := &fakePathDB{}
	if _, err := db.Insert(context.Background(), &pathdb.Segment{
		Type: pathdb.SegmentTypeUp,
		PCB:  linePCB(t, time.Now(), iaCore, iaMid, iaLeaf),
	}); err != nil {
		t.Fatal(err)
	}
	lookups := 0
	p := &PathProvider{
		IA: iaLeaf,
		DB: db,
		Lookup: func(_ context.Context, dst addr.IA) []*pathdb.Segment {
			lookups++
			if !dst.Equal(iaMid) {
				t.Errorf("looked up %v, want %v", dst, iaMid)
			}
			return []*pathdb.Segment{{
				Type: pathdb.SegmentTypeDown,
				PCB:  linePCB(t, time.Now(), iaCore, iaMid),
			}}
		},
	}

	path, err := p.Path(context.Background(), iaMid)
	if err != nil {
		t.Fatal(err)
	}
	if lookups != 1 {
		t.Errorf("down-segment lookups = %d, want 1", lookups)
	}
	// Reversed up [leaf, mid, core] composed before the forward down
	// [core, mid]: five hops in two segments.
	if len(path.HopFields) != 5 {
		t.Fatalf("composed path = %d hops, want 5", len(path.HopFields))
	}
	if len(path.InfoFields) != 2 {
		t.Fatalf("composed path = %d segments, want 2", len(path.InfoFields))
	}
}

// TestProviderCorePath checks the resolution on the core a down segment
// starts at: the segment alone is the complete route.
func TestProviderCorePath(t *testing.T) {
	db := &fakePathDB{}
	p := &PathProvider{
		IA: iaCore,
		DB: db,
		Lookup: func(context.Context, addr.IA) []*pathdb.Segment {
			return []*pathdb.Segment{{
				Type: pathdb.SegmentTypeDown,
				PCB:  linePCB(t, time.Now(), iaCore, iaMid, iaLeaf),
			}}
		},
	}

	path, err := p.Path(context.Background(), iaLeaf)
	if err != nil {
		t.Fatal(err)
	}
	if len(path.HopFields) != 3 {
		t.Fatalf("route from the core = %d hops, want the down segment's 3",
			len(path.HopFields))
	}
	if !path.InfoFields[0].ConsDir {
		t.Error("route from the core is reversed, want the forward down segment")
	}
}

// TestProviderNoPath checks that a destination nothing resolves to is an
// error, not a hang.
func TestProviderNoPath(t *testing.T) {
	p := &PathProvider{
		IA:     iaLeaf,
		DB:     &fakePathDB{},
		Lookup: func(context.Context, addr.IA) []*pathdb.Segment { return nil },
	}
	if _, err := p.Path(context.Background(), iaMid); err == nil {
		t.Error("resolving a destination without segments succeeded, want error")
	}
}

// TestPathExpiry checks the send-side expiry of a composed path: the
// earliest hop-field expiration across both segments.
func TestPathExpiry(t *testing.T) {
	now := time.Now()
	db := &fakePathDB{}
	if _, err := db.Insert(context.Background(), &pathdb.Segment{
		Type: pathdb.SegmentTypeUp,
		PCB:  linePCB(t, now, iaCore, iaMid, iaLeaf),
	}); err != nil {
		t.Fatal(err)
	}
	p := &PathProvider{
		IA: iaLeaf,
		DB: db,
		Lookup: func(context.Context, addr.IA) []*pathdb.Segment {
			return []*pathdb.Segment{{
				Type: pathdb.SegmentTypeDown,
				PCB: linePCB(t, now.Add(-time.Hour),
					iaCore, iaMid),
			}}
		},
	}
	path, err := p.Path(context.Background(), iaMid)
	if err != nil {
		t.Fatal(err)
	}

	segTTL := time.Duration(segment.HopExpTime+1) * (24 * time.Hour / 256)
	want := util.SecsToTime(util.TimeToSecs(now.Add(-time.Hour))).Add(segTTL)
	if got := PathExpiry(path); !got.Equal(want) {
		t.Errorf("path expiry = %v, want the older segment's %v", got, want)
	}
}
