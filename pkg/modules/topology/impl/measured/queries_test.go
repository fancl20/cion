package measured

import (
	"context"
	"hash"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto"

	"github.com/fancl20/cion/pkg/modules/pathdb"
	"github.com/fancl20/cion/pkg/scion"
	"github.com/fancl20/cion/pkg/segment"
)

var (
	selCore = addr.MustIAFrom(20, 0xfd0000000021)
	selX    = addr.MustIAFrom(20, 0xfd0000000031)
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

// TestFreshestBaseline checks the baseline carrier and the excluded
// baseline: freshness picks the route the echo measures, the exclusion
// takes the freshest survivor, and excluding what every route crosses
// leaves none — the cut-critical reading.
func TestFreshestBaseline(t *testing.T) {
	now := time.Now()
	up := lineSegment(t, pathdb.SegmentTypeUp, now, selCore, selIA)
	freshDown := lineSegment(t, pathdb.SegmentTypeDown, now, selCore, selX, selPeer)
	staleDown := lineSegment(t, pathdb.SegmentTypeDown,
		now.Add(-time.Hour), selCore, selPeer)
	s := enumSelection([]*pathdb.Segment{up},
		[]*pathdb.Segment{freshDown, staleDown})

	// The freshest candidate carries the baseline, the longer route
	// included: freshness decides, not hops.
	c := s.freshest(context.Background(), selPeer)
	if c == nil {
		t.Fatal("freshest = nil, want the fresh join")
	}
	if !c.Fresh.Equal(freshDown.PCB.Timestamp()) {
		t.Errorf("freshest = %v, want the fresh down's %v",
			c.Fresh, freshDown.PCB.Timestamp())
	}

	// The excluded baseline enumerates minus the link: the fresh route
	// crosses it, so the stale survivor carries the excluded baseline.
	c = s.freshest(context.Background(), selPeer, segment.LinkID{IA: selX, IfID: 1})
	if c == nil {
		t.Fatal("excluded baseline = nil, want the stale survivor")
	}
	if !c.Fresh.Equal(staleDown.PCB.Timestamp()) {
		t.Errorf("excluded baseline = %v, want the stale down's %v",
			c.Fresh, staleDown.PCB.Timestamp())
	}

	// Excluding a link every route crosses — the up's core egress — leaves
	// no route into the tier: the link is cut-critical.
	if c := s.freshest(context.Background(), selPeer,
		segment.LinkID{IA: selCore, IfID: 1}); c != nil {

		t.Errorf("excluded baseline over a cut-critical link = %v, want none", c.Fresh)
	}
}

// cand builds a candidate of the given links, for the pure queries' tests.
func cand(links ...segment.LinkID) scion.Candidate {
	return scion.Candidate{Links: links}
}

func link(ia addr.IA) segment.LinkID { return segment.LinkID{IA: ia, IfID: 1} }

// TestRouteCount checks the tier's route count: the up links beside the
// composed paths traversing none of them, the second path counting only
// when edge-disjoint — checked over all pairs, so the pair a greedy first
// pick misses still counts — and the count saturating at two.
func TestRouteCount(t *testing.T) {
	// No up links. The first candidate shares an edge with each of the
	// others, but a different pair is disjoint: the greedy miss.
	crossing := []scion.Candidate{
		cand(link(selA), link(selB)),
		cand(link(selA), link(selC)),
		cand(link(selB), link(selD)),
	}
	if got := routeCount(nil, crossing); got != 2 {
		t.Errorf("route count = %d, want the disjoint pair's 2", got)
	}

	// A single candidate alone counts one.
	if got := routeCount(nil, crossing[:1]); got != 1 {
		t.Errorf("route count = %d, want 1", got)
	}

	// Saturation: however many pairwise-disjoint routes, the count stops
	// at two.
	disjoint := []scion.Candidate{
		cand(link(selA)),
		cand(link(selB)),
		cand(link(selC)),
	}
	if got := routeCount(nil, disjoint); got != 2 {
		t.Errorf("route count = %d, want the saturated 2", got)
	}

	// One up link: a candidate traversing it never counts — the link is
	// already the route — and one avoiding it adds the second.
	up := []segment.LinkID{link(selA)}
	over := []scion.Candidate{
		cand(link(selA), link(selB)),
		cand(link(selA), link(selC)),
	}
	if got := routeCount(up, over); got != 1 {
		t.Errorf("route count over the up link = %d, want 1", got)
	}
	avoiding := []scion.Candidate{cand(link(selA), link(selB)), cand(link(selC))}
	if got := routeCount(up, avoiding); got != 2 {
		t.Errorf("route count beside the up link = %d, want 2", got)
	}

	// Two up links saturate the count whatever the candidates.
	if got := routeCount([]segment.LinkID{link(selA), link(selB)}, avoiding); got != 2 {
		t.Errorf("route count of two up links = %d, want 2", got)
	}
}

// TestTierPrice checks the promotion estimate's pricing: the declared
// one-way sums doubled to meet the round trips they are judged against,
// the measured baseline beside them, an undeclared route pricing nothing.
func TestTierPrice(t *testing.T) {
	declared := 8 * time.Millisecond
	pricier := 20 * time.Millisecond
	routes := []scion.Candidate{
		{Latency: &declared},
		{Latency: nil}, // an undeclared edge is unknown, not free
		{Latency: &pricier},
	}
	if got := tierPrice(0, routes); got != 16*time.Millisecond {
		t.Errorf("tier price = %v, want the doubled cheapest 16ms", got)
	}
	if got := tierPrice(12*time.Millisecond, routes); got != 12*time.Millisecond {
		t.Errorf("tier price beside the measured baseline = %v, want 12ms", got)
	}
	if got := tierPrice(30*time.Millisecond, routes); got != 16*time.Millisecond {
		t.Errorf("tier price past the measured baseline = %v, want 16ms", got)
	}
	if got := tierPrice(0, routes[1:2]); got != 0 {
		t.Errorf("tier price of undeclared routes = %v, want 0", got)
	}
}
