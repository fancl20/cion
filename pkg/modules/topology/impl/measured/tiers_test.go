package measured

import (
	"context"
	"hash"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto"

	"github.com/fancl20/cion/pkg/modules/links"
	"github.com/fancl20/cion/pkg/modules/pathdb"
	"github.com/fancl20/cion/pkg/scion"
	"github.com/fancl20/cion/pkg/segment"
)

// queriesMACHasher builds the test forwarding key's MAC hashers the line
// segments below hop with.
func queriesMACHasher() hash.Hash {
	h, _ := scrypto.InitMac([]byte("0123456789abcdef"))
	return h
}

// lineSegment builds an unsigned route-form segment crossing the given ASes
// in order, every hop on the one test interface.
func lineSegment(
	t *testing.T,
	segType pathdb.SegmentType,
	now time.Time,
	ias ...addr.IA,
) *pathdb.Segment {

	t.Helper()
	pcb, err := segment.PCBWithID(now, 0x111)
	if err != nil {
		t.Fatal(err)
	}
	for i, ia := range ias {
		opts := segment.EntryOptions{}
		if i > 0 {
			opts.IngressIfID = 1
		}
		if i < len(ias)-1 {
			opts.EgressIfID = 1
		}
		if _, err := pcb.AppendRouteHop(ia, opts, queriesMACHasher); err != nil {
			t.Fatal(err)
		}
	}
	return &pathdb.Segment{Type: segType, PCB: pcb}
}

// enumPathDB is an in-memory path database for the enumeration fixtures.
type enumPathDB struct{ segs []*pathdb.Segment }

func (d *enumPathDB) Insert(_ context.Context, seg *pathdb.Segment) (bool, error) {
	d.segs = append(d.segs, seg)
	return true, nil
}

func (d *enumPathDB) Get(_ context.Context, q pathdb.Query) ([]*pathdb.Segment, error) {
	var out []*pathdb.Segment
	for _, s := range d.segs {
		if q.Type != pathdb.SegmentTypeUnspecified && q.Type != s.Type {
			continue
		}
		out = append(out, s)
	}
	return out, nil
}

func (d *enumPathDB) DeleteExpired(context.Context, time.Time) (int, error) { return 0, nil }
func (d *enumPathDB) Close() error                                          { return nil }

// enumSelection builds a selection whose provider serves the given up and
// down segments.
func enumSelection(ups, downs []*pathdb.Segment) *selection {
	db := &enumPathDB{segs: ups}
	return &selection{cfg: SelectionConfig{
		IA: selIA,
		Provider: &scion.PathProvider{
			IA:     selIA,
			DB:     db,
			Lookup: func(context.Context, addr.IA) []*pathdb.Segment { return downs },
		},
	}}
}

// sm builds a window sample of the given round trips and enumerated routes.
func sm(direct, path time.Duration, candidates ...scion.Candidate) sample {
	return sample{m: measurement{direct: direct, path: path}, candidates: candidates}
}

// TestDeriveTiers checks the sorted walk: a peer within the gap joins, one
// past twice the median opens a new tier, the median recomputes as a tier
// grows, an unmeasured peer classes into none, and equal samples are stable
// across recomputation.
func TestDeriveTiers(t *testing.T) {
	samples := map[addr.IA]sample{
		selA: sm(5, 0),
		selB: sm(6, 0),
		selC: sm(7, 0),
		selD: sm(9, 0),
		// Unmeasured, however favorable its path baseline: not placed.
		selE: sm(0, 4),
	}
	// The median recomputes as the tier grows — {5} then {5,6} then
	// {5,6,7} then {5,6,7,9} — and every peer stays within the gap.
	ts := deriveTiers(samples)
	if len(ts) != 1 || len(ts[0].members) != 4 {
		t.Fatalf("tiers = %d of %d members, want one of four", len(ts), len(ts[0].members))
	}
	want := []addr.IA{selA, selB, selC, selD}
	for i, m := range ts[0].members {
		if !m.ia.Equal(want[i]) {
			t.Errorf("member %d = %s, want %s", i, m.ia, want[i])
		}
	}

	// A peer past twice the median opens the next tier.
	samples[selE] = sm(30, 0)
	ts = deriveTiers(samples)
	if len(ts) != 2 {
		t.Fatalf("tiers = %d, want two", len(ts))
	}
	if len(ts[1].members) != 1 || !ts[1].members[0].ia.Equal(selE) {
		t.Errorf("the second tier = %v, want the slow peer alone", ts[1].members)
	}

	// The walk is order-stable among equals: recomputation derives the same
	// classes, equal samples holding their order.
	equal := map[addr.IA]sample{
		selA: sm(10, 0), selB: sm(10, 0), selC: sm(10, 0), selD: sm(10, 0),
	}
	for range 3 {
		ts = deriveTiers(equal)
		if len(ts) != 1 {
			t.Fatalf("tiers of equal samples = %d, want one", len(ts))
		}
		for i, m := range ts[0].members {
			if !m.ia.Equal(want[i]) {
				t.Errorf("equal samples ordered %s before %s", m.ia, want[i])
			}
		}
	}
}

// TestWindowTierFacts checks what one helper turns a tier into: up links
// from the verdicts alone, the baseline the fastest member echo takes, the
// price the measured baseline fixes over declared sums, the route count
// reading the clean candidates alone — a crossing candidate and one over a
// local verdict-down interface counting as no route — and strandedness over
// live routes alone.
func TestWindowTierFacts(t *testing.T) {
	verdicts := map[uint16]bool{4: false, 7: false} // the down link and the node's own dead interface
	up := &links.Link{NeighborIA: selA, IfID: 3, State: links.StateEstablished}
	dead := &links.Link{NeighborIA: selB, IfID: 4, State: links.StateEstablished}
	neighbors := map[addr.IA]*links.Link{selA: up, selB: dead}
	entries := map[addr.IA]DirectoryEntry{
		selA: entryOf(selA), selB: entryOf(selB), selC: entryOf(selC),
	}
	s := &selection{
		cfg: SelectionConfig{
			IA:       selIA,
			Verdicts: func() map[uint16]bool { return verdicts },
		},
		excludedFn: func(context.Context, []addr.IA, segment.LinkID) excludedSample {
			return excludedSample{survived: true}
		},
	}
	// One fast tier of three measured peers: A up with a path baseline and
	// a declared route beside it, B verdict-down, C a candidate whose
	// enumerated routes are all the ones the comparator refuses — a
	// crossing candidate, one over the node's own dead interface — beside
	// one clean route; and a slow stranded tier of one.
	samples := map[addr.IA]sample{
		selA: sm(5, 20*time.Millisecond, declared(1*time.Millisecond)),
		selB: sm(6, 30*time.Millisecond),
		selC: sm(7, 0,
			scion.Candidate{Crossing: true},
			cand(segment.LinkID{IA: selIA, IfID: 7}),
			cand(link(selX)),
		),
		selD: sm(50, 0),
	}
	ts := s.windowTiers(context.Background(), neighbors, entries, samples)
	if len(ts) != 2 {
		t.Fatalf("tiers = %d, want the fast one and the slow one", len(ts))
	}
	fast, slow := &ts[0], &ts[1]

	// The fast tier's up links: A's alone, the verdict-down B no
	// redundancy. Its baseline is the fastest member echo, and the price
	// the measured baseline fixes over the misstated declaration.
	if len(fast.upLinks) != 1 || fast.upLinks[0].IfID != up.IfID {
		t.Errorf("up links = %v, want the verdict-up link alone", fast.upLinks)
	}
	if fast.baseline != 20*time.Millisecond {
		t.Errorf("baseline = %v, want the fastest member echo 20ms", fast.baseline)
	}
	if fast.price != 20*time.Millisecond {
		t.Errorf("price = %v, want the measured baseline over the declared 2ms",
			fast.price)
	}
	// The route count reads the clean candidates alone, and the excluded
	// measurements cover the established members.
	if fast.routes != 2 {
		t.Errorf("routes = %d, want the up link beside the one clean route", fast.routes)
	}
	for _, ia := range []addr.IA{selA, selB} {
		if _, ok := fast.excluded[ia]; !ok {
			t.Errorf("no excluded measurement for the established %s", ia)
		}
	}

	// The slow tier holds no live route: no up links, no clean candidate —
	// stranded.
	if slow.routes != 0 || !slow.stranded {
		t.Error("the tier of a stranded peer is not stranded")
	}
	if slow.price != 0 {
		t.Errorf("the stranded tier's price = %v, want nothing pricing it", slow.price)
	}
}
