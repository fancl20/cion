package scion

import (
	"context"
	"hash"
	"slices"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/util"
	cryptopb "github.com/scionproto/scion/pkg/proto/crypto"
	"github.com/scionproto/scion/pkg/scrypto"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/modules/pathdb"
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

// TestProviderLocalPathOnPath checks the on-path resolution: a destination
// an up segment already contains mid-segment resolves to the
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
		IA: iaCore,
		DB: &fakePathDB{},
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
			IA:            iaLeaf,
			DB:            db,
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

// TestProviderBootstrapRoute checks the enrollment fallback: before any up
// segment is verified, the reversed unverified beacon — the node's own hop
// already extended — serves the core route in both resolution variants,
// with no fetch, and a verified up segment takes over the moment one
// exists.
func TestProviderBootstrapRoute(t *testing.T) {
	beacon := linePCB(t, time.Now(), iaCore, iaLeaf)
	route := beacon.ReversePath()
	fetched := false
	db := &fakePathDB{}
	p := &PathProvider{
		IA: iaLeaf,
		DB: db,
		Lookup: func(context.Context, addr.IA) []*pathdb.Segment {
			fetched = true
			return nil
		},
		Bootstrap: func(core addr.IA) *spath.Decoded {
			if !core.Equal(iaCore) {
				return nil
			}
			return route
		},
	}

	for _, resolve := range []struct {
		name string
		call func() (*spath.Decoded, error)
	}{
		{"LocalPath", func() (*spath.Decoded, error) { return p.LocalPath(iaCore) }},
		{"Path", func() (*spath.Decoded, error) {
			return p.Path(context.Background(), iaCore)
		}},
	} {
		path, err := resolve.call()
		if err != nil {
			t.Fatalf("%s over the bootstrap route: %v", resolve.name, err)
		}
		if len(path.HopFields) != 2 || len(path.InfoFields) != 1 {
			t.Errorf("%s = %d hops / %d segments, want the beacon's 2/1",
				resolve.name, len(path.HopFields), len(path.InfoFields))
		}
		if path.InfoFields[0].ConsDir {
			t.Errorf("%s is forward, want the reversed beacon", resolve.name)
		}
	}
	if fetched {
		t.Error("the bootstrap route fetched down segments, want local state only")
	}

	// A verified up segment takes over the moment one exists: the route
	// grows the middle hop the stored segment carries.
	up := linePCB(t, time.Now(), iaCore, iaMid, iaLeaf)
	if _, err := db.Insert(context.Background(), &pathdb.Segment{
		Type: pathdb.SegmentTypeUp,
		PCB:  up,
	}); err != nil {
		t.Fatal(err)
	}
	path, err := p.LocalPath(iaCore)
	if err != nil {
		t.Fatal(err)
	}
	if len(path.HopFields) != 3 {
		t.Fatalf("route with a stored up segment = %d hops, want its 3",
			len(path.HopFields))
	}
	checkHops(t, path, up.Entries[2], up.Entries[1], up.Entries[0])
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

// testSigner signs by wrapping the body unsigned — the enumeration tests
// read entries, never verify them.
type testSigner struct{}

func (testSigner) Sign(
	_ context.Context, msg []byte, _ ...[]byte,
) (*cryptopb.SignedMessage, error) {

	return &cryptopb.SignedMessage{HeaderAndBody: msg}, nil
}

// linkHop names one AS entry of a test segment: the AS, its construction
// ingress and egress interface IDs — distinct, so a link-set reading can
// drop no pair unnoticed — and its egress link's declared one-way delay.
type linkHop struct {
	ia      addr.IA
	in, eg  uint16
	latency time.Duration
}

// signedLine builds a signed-entry segment crossing the given hops.
func signedLine(t *testing.T, now time.Time, hops ...linkHop) *segment.PCB {
	t.Helper()
	pcb, err := segment.PCBWithID(now, 0x111)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hops {
		if err := pcb.AppendEntry(context.Background(), h.ia, segment.EntryOptions{
			IngressIfID:   h.in,
			EgressIfID:    h.eg,
			EgressLatency: h.latency,
		}, testMACHasher, testSigner{}); err != nil {
			t.Fatal(err)
		}
	}
	return pcb
}

// TestEnumerateFacts checks the candidate's facts against hand-computed
// values: the link pairs of the traversed stretch alone — both interface
// IDs of each entry — the staler piece's timestamp as Fresh, and the rank
// fields the wrapper sorts by.
func TestEnumerateFacts(t *testing.T) {
	up := signedLine(t, time.Now(),
		linkHop{ia: iaCore, eg: 11},
		linkHop{ia: iaMid, in: 12, eg: 13},
		linkHop{ia: iaLeaf, in: 14},
	)
	stale := time.Now().Add(-time.Hour)
	down := signedLine(t, stale,
		linkHop{ia: iaCore, eg: 21},
		linkHop{ia: iaDest, in: 22},
	)
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

	candidates, err := p.Enumerate(context.Background(), iaDest)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 {
		t.Fatalf("candidates = %d, want the single join", len(candidates))
	}
	c := candidates[0]
	if c.Hops != 5 || len(c.Path.HopFields) != 5 || len(c.Path.InfoFields) != 2 {
		t.Fatalf("candidate = %d hops / %d segments, want the join's 5/2",
			c.Hops, len(c.Path.InfoFields))
	}
	if !c.Fresh.Equal(down.Timestamp()) {
		t.Errorf("candidate freshness = %v, want the staler down piece's %v",
			c.Fresh, down.Timestamp())
	}
	if c.Entries != 5 {
		t.Errorf("candidate entries = %d, want the pair's 5", c.Entries)
	}
	if c.Crossing {
		t.Error("candidate crosses a signaled interface, want clean")
	}
	// The traversed stretch alone: both of the middle entry's interface IDs
	// present, the zero interfaces of the segment ends absent, the dropped
	// core-ward stretch of the up segment contributing nothing (there is
	// none here — the meeting is the core — so the down core's egress
	// beside the up's own).
	want := []segment.LinkID{
		{IA: iaCore, IfID: 11},
		{IA: iaMid, IfID: 12},
		{IA: iaMid, IfID: 13},
		{IA: iaLeaf, IfID: 14},
		{IA: iaCore, IfID: 21},
		{IA: iaDest, IfID: 22},
	}
	if !slices.Equal(c.Links, want) {
		t.Errorf("candidate links = %v, want %v", c.Links, want)
	}
}

// TestEnumerateTruncatedFacts checks truncation against the facts: entries
// above the meeting on the up side and beyond it on the down side cross
// nothing the candidate travels, and Fresh still reads the staler piece.
func TestEnumerateTruncatedFacts(t *testing.T) {
	up := signedLine(t, time.Now(),
		linkHop{ia: iaCore, eg: 11},
		linkHop{ia: iaMid, in: 12, eg: 13},
		linkHop{ia: iaLeaf, in: 14},
	)
	stale := time.Now().Add(-time.Hour)
	down := signedLine(t, stale,
		linkHop{ia: iaCore, eg: 21},
		linkHop{ia: iaMid, in: 22, eg: 23},
		linkHop{ia: iaDest, in: 24},
	)
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

	candidates, err := p.Enumerate(context.Background(), iaDest)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 {
		t.Fatalf("candidates = %d, want the single join at the middle", len(candidates))
	}
	c := candidates[0]
	if c.Hops != 4 {
		t.Fatalf("candidate = %d hops, want the truncated join's 4", c.Hops)
	}
	// The core's entries — the up's origin above the meeting, the down's
	// origin beyond it — cross nothing the candidate travels; the meeting
	// contributes its entry on each side, both interface IDs of each.
	want := []segment.LinkID{
		{IA: iaMid, IfID: 12},
		{IA: iaMid, IfID: 13},
		{IA: iaLeaf, IfID: 14},
		{IA: iaMid, IfID: 22},
		{IA: iaMid, IfID: 23},
		{IA: iaDest, IfID: 24},
	}
	if !slices.Equal(c.Links, want) {
		t.Errorf("candidate links = %v, want %v", c.Links, want)
	}
	if !c.Fresh.Equal(down.Timestamp()) {
		t.Errorf("candidate freshness = %v, want the staler down piece's %v",
			c.Fresh, down.Timestamp())
	}
}

// TestEnumerateCoverage checks the containing branch beside the joins: a
// destination both serve yields the joins and one candidate per containing
// up segment, exclusion filtering both kinds identically.
func TestEnumerateCoverage(t *testing.T) {
	up := linePCB(t, time.Now(), iaCore, iaMid, iaLeaf)
	down := linePCB(t, time.Now(), iaCore, iaMid)
	db := &fakePathDB{}
	if _, err := db.Insert(context.Background(), &pathdb.Segment{
		Type: pathdb.SegmentTypeUp,
		PCB:  up,
	}); err != nil {
		t.Fatal(err)
	}
	newProvider := func() *PathProvider {
		return &PathProvider{
			IA: iaLeaf,
			DB: db,
			Lookup: func(context.Context, addr.IA) []*pathdb.Segment {
				return []*pathdb.Segment{{Type: pathdb.SegmentTypeDown, PCB: down}}
			},
		}
	}

	// The join at the middle and the containing up segment's truncated
	// reversal beside it.
	candidates, err := newProvider().Enumerate(context.Background(), iaMid)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 2 {
		t.Fatalf("candidates = %d, want the join and the containing reversal", len(candidates))
	}
	for i, c := range candidates {
		if c.Hops != 2 || len(c.Path.HopFields) != 2 {
			t.Errorf("candidate %d = %d hops, want the truncated 2", i, c.Hops)
		}
	}

	// Excluding the middle's interface drops both kinds; excluding an
	// interface no traversed hop names drops neither.
	mid := segment.LinkID{IA: iaMid, IfID: testIfID}
	candidates, err = newProvider().Enumerate(context.Background(), iaMid, mid)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 0 {
		t.Errorf("candidates past the exclusion = %d, want 0", len(candidates))
	}
	candidates, err = newProvider().Enumerate(context.Background(), iaMid,
		segment.LinkID{IA: iaMid, IfID: testIfID + 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 2 {
		t.Errorf("candidates past the absent exclusion = %d, want 2", len(candidates))
	}
}

// TestEnumerateExclusion checks the exclusion's semantics against the
// signaled-down skip's: an excluded link never yields a candidate — no last
// resort — while a signaled interface still yields a flagged one; either of
// a hop's two interface IDs suffices; the local ISD-AS errors and the
// unreachable destination enumerates empty.
func TestEnumerateExclusion(t *testing.T) {
	up := linePCB(t, time.Now(), iaCore, iaMid, iaLeaf)
	down := linePCB(t, time.Now(), iaCore, iaDest)
	db := &fakePathDB{}
	if _, err := db.Insert(context.Background(), &pathdb.Segment{
		Type: pathdb.SegmentTypeUp,
		PCB:  up,
	}); err != nil {
		t.Fatal(err)
	}
	newProvider := func() *PathProvider {
		return &PathProvider{
			IA:            iaLeaf,
			DB:            db,
			InterfaceDown: NewInterfaceDownCache(),
			Lookup: func(context.Context, addr.IA) []*pathdb.Segment {
				return []*pathdb.Segment{{Type: pathdb.SegmentTypeDown, PCB: down}}
			},
		}
	}

	// A signaled interface on the traversed stretch yields a flagged
	// candidate, never a filtered one.
	p := newProvider()
	p.InterfaceDown.Record(InterfaceDownSignal{IA: iaMid, IfID: testIfID})
	candidates, err := p.Enumerate(context.Background(), iaDest)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 || !candidates[0].Crossing {
		t.Fatalf("candidates past the signal = %d (crossing %v), want one flagged",
			len(candidates), len(candidates) == 1 && candidates[0].Crossing)
	}

	// Excluding the signaled link drops the candidate outright: exclusion
	// hard-filters, no last resort. Excluding by the destination's ingress
	// end — the other interface ID of the same hop — drops it too.
	for _, link := range []segment.LinkID{
		{IA: iaMid, IfID: testIfID},
		{IA: iaDest, IfID: testIfID},
	} {
		candidates, err = p.Enumerate(context.Background(), iaDest, link)
		if err != nil {
			t.Fatal(err)
		}
		if len(candidates) != 0 {
			t.Errorf("candidates past excluding %v = %d, want 0", link, len(candidates))
		}
	}

	// The local ISD-AS errors; an unreachable destination is empty.
	if _, err := newProvider().Enumerate(context.Background(), iaLeaf); err == nil {
		t.Error("enumerating to the local ISD-AS succeeded, want error")
	}
	empty := &PathProvider{
		IA:     iaLeaf,
		DB:     &fakePathDB{},
		Lookup: func(context.Context, addr.IA) []*pathdb.Segment { return nil },
	}
	candidates, err = empty.Enumerate(context.Background(), iaDest)
	if err != nil || len(candidates) != 0 {
		t.Errorf("enumerating an unreachable destination = %d, %v, want empty", len(candidates), err)
	}
}

// TestEnumerateDeclaredLatency checks the one-way sum: the traversed
// inter-AS edges' declarations added, an up part's edges priced from the
// upstream entries' declarations — a per-hop-field reading keys the wrong
// entry's map there — both ends of an edge declaring resolving to the
// higher, and one undeclared edge making the fact absent.
func TestEnumerateDeclaredLatency(t *testing.T) {
	up := signedLine(t, time.Now(),
		linkHop{ia: iaCore, eg: 11, latency: 5 * time.Millisecond},
		linkHop{ia: iaMid, in: 12, eg: 13, latency: 7 * time.Millisecond},
		linkHop{ia: iaLeaf, in: 14},
	)
	down := signedLine(t, time.Now(),
		linkHop{ia: iaCore, eg: 21, latency: 11 * time.Millisecond},
		linkHop{ia: iaDest, in: 22},
	)
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

	candidates, err := p.Enumerate(context.Background(), iaDest)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 || candidates[0].Latency == nil {
		t.Fatalf("candidates = %d, want one with a declared sum", len(candidates))
	}
	// The up part's core-to-middle edge is declared on the core entry's
	// egress — the adjacent upstream entry — which a reading keyed on the
	// hop field at hand would miss.
	if got := *candidates[0].Latency; got != 23*time.Millisecond {
		t.Errorf("declared sum = %v, want the traversed edges' 23ms", got)
	}

	// The destination declaring its ingress end of the same edge — the
	// richer instance another implementation speaks — loses to the core's
	// higher declaration and displaces a lower one.
	down.Entries[1].Latency = map[segment.LinkID]time.Duration{
		{IA: iaDest, IfID: 22}: 4 * time.Millisecond,
	}
	candidates, err = p.Enumerate(context.Background(), iaDest)
	if err != nil {
		t.Fatal(err)
	}
	if got := *candidates[0].Latency; got != 23*time.Millisecond {
		t.Errorf("declared sum with the lower conflict = %v, want 23ms", got)
	}
	down.Entries[1].Latency = map[segment.LinkID]time.Duration{
		{IA: iaDest, IfID: 22}: 20 * time.Millisecond,
	}
	candidates, err = p.Enumerate(context.Background(), iaDest)
	if err != nil {
		t.Fatal(err)
	}
	if got := *candidates[0].Latency; got != 32*time.Millisecond {
		t.Errorf("declared sum with the higher conflict = %v, want 32ms", got)
	}

	// One undeclared edge makes the fact absent: unknown, not free.
	undeclared := signedLine(t, time.Now(),
		linkHop{ia: iaCore, eg: 11, latency: 5 * time.Millisecond},
		linkHop{ia: iaMid, in: 12, eg: 13},
		linkHop{ia: iaLeaf, in: 14},
	)
	db = &fakePathDB{}
	if _, err := db.Insert(context.Background(), &pathdb.Segment{
		Type: pathdb.SegmentTypeUp,
		PCB:  undeclared,
	}); err != nil {
		t.Fatal(err)
	}
	p.DB = db
	candidates, err = p.Enumerate(context.Background(), iaDest)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 || candidates[0].Latency != nil {
		t.Errorf("declared sum over an undeclared edge = %v, want absent",
			candidates[0].Latency)
	}
}

// TestProviderEntriesTiebreak checks the rank's third tiebreak: two joins
// tied on hops and timestamp resolve to the pair with fewer entries.
func TestProviderEntriesTiebreak(t *testing.T) {
	ts := time.Now()
	upShort := linePCB(t, ts, iaCore, iaLeaf)
	downShort := linePCB(t, ts, iaCore, iaDest)
	upLong := linePCB(t, ts, iaCore2, iaMid, iaLeaf)
	downLong := linePCB(t, ts, iaCore2, iaMid, iaDest)
	db := &fakePathDB{}
	for _, up := range []*segment.PCB{upShort, upLong} {
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
				{Type: pathdb.SegmentTypeDown, PCB: downShort},
				{Type: pathdb.SegmentTypeDown, PCB: downLong},
			}
		},
	}

	path, err := p.Path(context.Background(), iaDest)
	if err != nil {
		t.Fatal(err)
	}
	// Both joins tie on four hops and one timestamp; the shorter pair's
	// four entries beat the deeper meeting's six.
	if len(path.HopFields) != 4 {
		t.Fatalf("joined path = %d hops, want either tie's 4", len(path.HopFields))
	}
	checkHops(t, path, upShort.Entries[1], upShort.Entries[0],
		downShort.Entries[0], downShort.Entries[1])
}

// TestProviderLastResortFirstCrossing checks the last resort's own rule:
// with nothing clean, the first crossing candidate in emission order
// serves, not the best-ranked crossing one.
func TestProviderLastResortFirstCrossing(t *testing.T) {
	up := linePCB(t, time.Now(), iaCore, iaLeaf)
	downLong := linePCB(t, time.Now(), iaCore, iaMid, iaDest)
	downShort := linePCB(t, time.Now(), iaCore, iaDest)
	db := &fakePathDB{}
	if _, err := db.Insert(context.Background(), &pathdb.Segment{
		Type: pathdb.SegmentTypeUp,
		PCB:  up,
	}); err != nil {
		t.Fatal(err)
	}
	p := &PathProvider{
		IA:            iaLeaf,
		DB:            db,
		InterfaceDown: NewInterfaceDownCache(),
		Lookup: func(context.Context, addr.IA) []*pathdb.Segment {
			return []*pathdb.Segment{
				{Type: pathdb.SegmentTypeDown, PCB: downLong},
				{Type: pathdb.SegmentTypeDown, PCB: downShort},
			}
		},
	}
	// Every join leaves through the signaled core interface, so every
	// candidate crosses; the shorter join would win a rank the last resort
	// never holds.
	p.InterfaceDown.Record(InterfaceDownSignal{IA: iaCore, IfID: testIfID})

	path, err := p.Path(context.Background(), iaDest)
	if err != nil {
		t.Fatal(err)
	}
	if len(path.HopFields) != 5 {
		t.Fatalf("last-resort path = %d hops, want the emitted-first join's 5",
			len(path.HopFields))
	}
	checkHops(t, path, up.Entries[1], up.Entries[0],
		downLong.Entries[0], downLong.Entries[1], downLong.Entries[2])
}
