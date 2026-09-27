package scion

import (
	"context"
	"hash"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/scrypto"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/pathdb"
	"github.com/fancl20/cion/pkg/segment"
)

var (
	iaCore  = addr.MustIAFrom(20, 0xff0000000001)
	iaMid   = addr.MustIAFrom(20, 0xff0000000002)
	iaLeaf  = addr.MustIAFrom(20, 0xff0000000003)
	iaDest  = addr.MustIAFrom(20, 0xff0000000004)
	iaCore2 = addr.MustIAFrom(20, 0xff0000000005)
	iaBelow = addr.MustIAFrom(20, 0xff0000000006)
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

// checkHops fails the test unless the path's hop fields run exactly the
// given entries' hop fields in order.
func checkHops(t *testing.T, path *spath.Decoded, entries ...segment.ASEntry) {
	t.Helper()
	if len(path.HopFields) != len(entries) {
		t.Fatalf("path = %d hops, want the entries' %d", len(path.HopFields), len(entries))
	}
	for i, e := range entries {
		if path.HopFields[i] != e.Hop {
			t.Fatalf("hop %d = %+v, want entry %d's %+v", i, path.HopFields[i], i, e.Hop)
		}
	}
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

// TestProviderLocalPathOnPath checks the on-path resolution of proposal 0025:
// a destination an up segment already contains mid-segment resolves to the
// truncated reversed path, still without any fetch.
func TestProviderLocalPathOnPath(t *testing.T) {
	up := linePCB(t, time.Now(), iaCore, iaMid, iaLeaf)
	db := &fakePathDB{}
	if _, err := db.Insert(context.Background(), &pathdb.Segment{
		Type: pathdb.SegmentTypeUp,
		PCB:  up,
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

	path, err := p.LocalPath(iaMid)
	if err != nil {
		t.Fatal(err)
	}
	if len(path.HopFields) != 2 || len(path.InfoFields) != 1 {
		t.Fatalf("route to the middle = %d hops / %d segments, want 2/1",
			len(path.HopFields), len(path.InfoFields))
	}
	if path.InfoFields[0].ConsDir {
		t.Error("route to the middle is not reversed")
	}
	checkHops(t, path, up.Entries[2], up.Entries[1])
	if fetched {
		t.Error("LocalPath fetched down segments, want local state only")
	}
}

// TestProviderLocalISDAS checks that the local ISD-AS errors rather than
// composing — in both variants, whatever down segments a fetch would find.
func TestProviderLocalISDAS(t *testing.T) {
	db := &fakePathDB{}
	if _, err := db.Insert(context.Background(), &pathdb.Segment{
		Type: pathdb.SegmentTypeUp,
		PCB:  linePCB(t, time.Now(), iaCore, iaLeaf),
	}); err != nil {
		t.Fatal(err)
	}
	p := &PathProvider{
		IA: iaLeaf,
		DB: db,
		// A down segment whose terminator is the local node: the meeting
		// rule must not turn it into a route to self.
		Lookup: func(context.Context, addr.IA) []*pathdb.Segment {
			return []*pathdb.Segment{{
				Type: pathdb.SegmentTypeDown,
				PCB:  linePCB(t, time.Now(), iaCore, iaLeaf),
			}}
		},
	}
	if _, err := p.LocalPath(iaLeaf); err == nil {
		t.Error("LocalPath of the local ISD-AS succeeded, want error")
	}
	if _, err := p.Path(context.Background(), iaLeaf); err == nil {
		t.Error("Path of the local ISD-AS succeeded, want error")
	}
}

// TestProviderComposedPath checks the composed resolution from a leaf, the
// draft's Case 2: the up and down segments share only their core, and the
// join is the full reversed up segment composed before the full forward down
// segment.
func TestProviderComposedPath(t *testing.T) {
	up := linePCB(t, time.Now(), iaCore, iaMid, iaLeaf)
	down := linePCB(t, time.Now(), iaCore, iaDest)
	db := &fakePathDB{}
	if _, err := db.Insert(context.Background(), &pathdb.Segment{
		Type: pathdb.SegmentTypeUp,
		PCB:  up,
	}); err != nil {
		t.Fatal(err)
	}
	lookups := 0
	p := &PathProvider{
		IA: iaLeaf,
		DB: db,
		Lookup: func(_ context.Context, dst addr.IA) []*pathdb.Segment {
			lookups++
			if !dst.Equal(iaDest) {
				t.Errorf("looked up %v, want %v", dst, iaDest)
			}
			return []*pathdb.Segment{{Type: pathdb.SegmentTypeDown, PCB: down}}
		},
	}

	path, err := p.Path(context.Background(), iaDest)
	if err != nil {
		t.Fatal(err)
	}
	if lookups != 1 {
		t.Errorf("down-segment lookups = %d, want 1", lookups)
	}
	// Reversed up [leaf, mid, core] composed before the forward down
	// [core, dest]: five hops in two segments.
	if len(path.HopFields) != 5 || len(path.InfoFields) != 2 {
		t.Fatalf("composed path = %d hops / %d segments, want 5/2",
			len(path.HopFields), len(path.InfoFields))
	}
	if path.InfoFields[0].ConsDir || !path.InfoFields[1].ConsDir {
		t.Error("composed directions are not reversed-then-forward")
	}
	checkHops(t, path, up.Entries[2], up.Entries[1], up.Entries[0],
		down.Entries[0], down.Entries[1])
}

// TestProviderCommonAncestorPath checks the draft's Case 4: the up and down
// segments share an ancestor below the core, and the join truncates both at
// it.
func TestProviderCommonAncestorPath(t *testing.T) {
	up := linePCB(t, time.Now(), iaCore, iaMid, iaLeaf)
	down := linePCB(t, time.Now(), iaCore, iaMid, iaDest)
	db := &fakePathDB{}
	if _, err := db.Insert(context.Background(), &pathdb.Segment{
		Type: pathdb.SegmentTypeUp,
		PCB:  up,
	}); err != nil {
		t.Fatal(err)
	}
	p := &PathProvider{
		IA: iaLeaf,
		DB: db,
		Lookup: func(context.Context, addr.IA) []*pathdb.Segment {
			return []*pathdb.Segment{{Type: pathdb.SegmentTypeDown, PCB: down}}
		},
	}

	path, err := p.Path(context.Background(), iaDest)
	if err != nil {
		t.Fatal(err)
	}
	if len(path.HopFields) != 4 || len(path.InfoFields) != 2 {
		t.Fatalf("joined path = %d hops / %d segments, want 4/2",
			len(path.HopFields), len(path.InfoFields))
	}
	if path.InfoFields[0].ConsDir || !path.InfoFields[1].ConsDir {
		t.Error("joined directions are not reversed-then-forward")
	}
	// Truncated at the shared middle: [leaf, mid] then [mid, dest], the
	// core's hops absent from both parts.
	checkHops(t, path, up.Entries[2], up.Entries[1], down.Entries[1], down.Entries[2])
}

// TestProviderMeetingAtLocalNode checks the draft's Case 5 on the down side:
// the local node sits on the down segment, and the truncated forward down
// segment alone carries the travel.
func TestProviderMeetingAtLocalNode(t *testing.T) {
	up := linePCB(t, time.Now(), iaCore, iaMid)
	down := linePCB(t, time.Now(), iaCore, iaMid, iaDest)
	db := &fakePathDB{}
	if _, err := db.Insert(context.Background(), &pathdb.Segment{
		Type: pathdb.SegmentTypeUp,
		PCB:  up,
	}); err != nil {
		t.Fatal(err)
	}
	p := &PathProvider{
		IA: iaMid,
		DB: db,
		Lookup: func(context.Context, addr.IA) []*pathdb.Segment {
			return []*pathdb.Segment{{Type: pathdb.SegmentTypeDown, PCB: down}}
		},
	}

	path, err := p.Path(context.Background(), iaDest)
	if err != nil {
		t.Fatal(err)
	}
	if len(path.HopFields) != 2 || len(path.InfoFields) != 1 {
		t.Fatalf("route from the middle = %d hops / %d segments, want 2/1",
			len(path.HopFields), len(path.InfoFields))
	}
	if !path.InfoFields[0].ConsDir {
		t.Error("route from the middle is reversed, want the forward down segment")
	}
	checkHops(t, path, down.Entries[1], down.Entries[2])
}

// TestProviderCorePath checks the resolution on the core a down segment
// starts at: the segment alone is the complete route — the local-node
// meeting's shallowest case.
func TestProviderCorePath(t *testing.T) {
	down := linePCB(t, time.Now(), iaCore, iaMid, iaLeaf)
	p := &PathProvider{
		IA:   iaCore,
		DB:   &fakePathDB{},
		Lookup: func(context.Context, addr.IA) []*pathdb.Segment {
			return []*pathdb.Segment{{Type: pathdb.SegmentTypeDown, PCB: down}}
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
	checkHops(t, path, down.Entries...)
}

// TestProviderPrefersFewestHops checks the selection order: a staler up
// segment through a deeper parent wins on hops — the reason every candidate
// enters the computation, not the freshest per core.
func TestProviderPrefersFewestHops(t *testing.T) {
	fresh := linePCB(t, time.Now(), iaCore, iaLeaf)
	stale := linePCB(t, time.Now().Add(-10*time.Minute), iaCore, iaMid, iaLeaf)
	down := linePCB(t, time.Now(), iaCore, iaMid, iaDest)
	db := &fakePathDB{}
	for _, up := range []*segment.PCB{fresh, stale} {
		if _, err := db.Insert(context.Background(), &pathdb.Segment{
			Type: pathdb.SegmentTypeUp,
			PCB:  up,
		}); err != nil {
			t.Fatal(err)
		}
	}
	p := &PathProvider{
		IA: iaLeaf,
		DB: db,
		Lookup: func(context.Context, addr.IA) []*pathdb.Segment {
			return []*pathdb.Segment{{Type: pathdb.SegmentTypeDown, PCB: down}}
		},
	}

	path, err := p.Path(context.Background(), iaDest)
	if err != nil {
		t.Fatal(err)
	}
	// The deeper meeting through the stale segment joins at the middle in
	// four hops; the fresh segment meets only at the core in five.
	if len(path.HopFields) != 4 {
		t.Fatalf("joined path = %d hops, want the shorter join's 4", len(path.HopFields))
	}
	checkHops(t, path, stale.Entries[2], stale.Entries[1], down.Entries[1], down.Entries[2])
}

// TestProviderPrefersFresherPair checks the tiebreak behind hop count: joins
// of equal hops resolve to the fresher pair, the meeting's own rule carried
// from segments to pairs.
func TestProviderPrefersFresherPair(t *testing.T) {
	staleUp := linePCB(t, time.Now().Add(-10*time.Minute), iaCore, iaLeaf)
	freshUp := linePCB(t, time.Now(), iaCore2, iaLeaf)
	db := &fakePathDB{}
	for _, up := range []*segment.PCB{staleUp, freshUp} {
		if _, err := db.Insert(context.Background(), &pathdb.Segment{
			Type: pathdb.SegmentTypeUp,
			PCB:  up,
		}); err != nil {
			t.Fatal(err)
		}
	}
	p := &PathProvider{
		IA: iaLeaf,
		DB: db,
		Lookup: func(context.Context, addr.IA) []*pathdb.Segment {
			return []*pathdb.Segment{
				{Type: pathdb.SegmentTypeDown, PCB: linePCB(t, time.Now(), iaCore, iaDest)},
				{Type: pathdb.SegmentTypeDown, PCB: linePCB(t, time.Now(), iaCore2, iaDest)},
			}
		},
	}

	path, err := p.Path(context.Background(), iaDest)
	if err != nil {
		t.Fatal(err)
	}
	if len(path.HopFields) != 4 {
		t.Fatalf("joined path = %d hops, want either pair's 4", len(path.HopFields))
	}
	if got, want := path.InfoFields[0].Timestamp, util.TimeToSecs(freshUp.Timestamp()); got != want {
		t.Errorf("fresher pair's segment = timestamp %d, want the fresh up's %d", got, want)
	}
}

// TestProviderFilterCountsTraversedHopsOnly checks the interface-down filter
// against the meeting rule: a signal on a stretch the join drops no longer
// disqualifies it, and a signal on the traversed stretch keeps the join only
// as the last resort behind every clean one.
func TestProviderFilterCountsTraversedHopsOnly(t *testing.T) {
	upMid := linePCB(t, time.Now(), iaCore, iaMid, iaLeaf)
	upOther := linePCB(t, time.Now(), iaCore2, iaLeaf)
	downMid := linePCB(t, time.Now(), iaCore, iaMid, iaDest)
	downOther := linePCB(t, time.Now(), iaCore2, iaBelow, iaDest)
	newProvider := func() *PathProvider {
		db := &fakePathDB{}
		for _, up := range []*segment.PCB{upMid, upOther} {
			if _, err := db.Insert(context.Background(), &pathdb.Segment{
				Type: pathdb.SegmentTypeUp,
				PCB:  up,
			}); err != nil {
				t.Fatal(err)
			}
		}
		return &PathProvider{
			IA: iaLeaf,
			DB: db,
			InterfaceDown: NewInterfaceDownCache(),
			Lookup: func(context.Context, addr.IA) []*pathdb.Segment {
				return []*pathdb.Segment{
					{Type: pathdb.SegmentTypeDown, PCB: downMid},
					{Type: pathdb.SegmentTypeDown, PCB: downOther},
				}
			},
		}
	}

	// The middle join crosses the signaled interface on its traversed
	// stretch: the clean join through the other core wins even though it is
	// the longer one.
	p := newProvider()
	p.InterfaceDown.Record(InterfaceDownSignal{IA: iaMid, IfID: testIfID})
	path, err := p.Path(context.Background(), iaDest)
	if err != nil {
		t.Fatal(err)
	}
	if len(path.HopFields) != 5 {
		t.Fatalf("joined path = %d hops, want the clean join's 5", len(path.HopFields))
	}
	checkHops(t, path, upOther.Entries[1], upOther.Entries[0],
		downOther.Entries[0], downOther.Entries[1], downOther.Entries[2])

	// The signal on the other core's stretch — traversed only by the join
	// through it — leaves the middle join clean and shorter.
	p = newProvider()
	p.InterfaceDown.Record(InterfaceDownSignal{IA: iaCore2, IfID: testIfID})
	path, err = p.Path(context.Background(), iaDest)
	if err != nil {
		t.Fatal(err)
	}
	if len(path.HopFields) != 4 {
		t.Fatalf("joined path = %d hops, want the middle join's 4", len(path.HopFields))
	}
	checkHops(t, path, upMid.Entries[2], upMid.Entries[1], downMid.Entries[1], downMid.Entries[2])

	// A signal on the dropped core-ward stretch of the up segment — the
	// entry above the meeting — leaves its join clean.
	p = newProvider()
	p.InterfaceDown.Record(InterfaceDownSignal{IA: iaCore, IfID: testIfID})
	path, err = p.Path(context.Background(), iaDest)
	if err != nil {
		t.Fatal(err)
	}
	if len(path.HopFields) != 4 {
		t.Fatalf("joined path = %d hops, want the middle join's 4 past the dropped stretch",
			len(path.HopFields))
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
	if _, err := p.Path(context.Background(), iaDest); err == nil {
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
					iaCore, iaDest),
			}}
		},
	}
	path, err := p.Path(context.Background(), iaDest)
	if err != nil {
		t.Fatal(err)
	}

	segTTL := time.Duration(segment.HopExpTime+1) * (24 * time.Hour / 256)
	want := util.SecsToTime(util.TimeToSecs(now.Add(-time.Hour))).Add(segTTL)
	if got := PathExpiry(path); !got.Equal(want) {
		t.Errorf("path expiry = %v, want the older segment's %v", got, want)
	}
}
