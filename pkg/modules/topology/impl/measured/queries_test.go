package measured

import (
	"context"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/modules/pathdb"
	"github.com/fancl20/cion/pkg/scion"
	"github.com/fancl20/cion/pkg/segment"
)

var (
	selCore = addr.MustIAFrom(20, 0xfd0000000021)
	selX    = addr.MustIAFrom(20, 0xfd0000000031)
)

// lineSegments builds the enumeration fixtures' up and down segments: an up
// segment the local node terminates and two downs to the peer, the fresh one
// a hop longer, every hop on the one test interface.
func lineSegments(t *testing.T, now time.Time) (up, freshDown, staleDown *pathdb.Segment) {
	t.Helper()
	up = lineSegment(t, pathdb.SegmentTypeUp, now, selCore, selIA)
	freshDown = lineSegment(t, pathdb.SegmentTypeDown, now, selCore, selX, selPeer)
	staleDown = lineSegment(t, pathdb.SegmentTypeDown,
		now.Add(-time.Hour), selCore, selPeer)
	return
}

// TestFreshestClean checks the baseline's carrier: the freshest clean
// candidate carries it, a crossing candidate — the wrapper's last resort —
// never, and a candidate over one of the node's own verdict-down links
// neither. All dirty leaves it unmeasured rather than served over a route
// the network would not.
func TestFreshestClean(t *testing.T) {
	verdicts := map[uint16]bool{7: false} // the node's own dead interface
	s := &selection{cfg: SelectionConfig{
		IA:       selIA,
		Verdicts: func() map[uint16]bool { return verdicts },
	}}
	now := time.Now()
	dirty := []scion.Candidate{
		{Fresh: now, Crossing: true},                                // flagged
		{Fresh: now, Links: []segment.LinkID{{IA: selIA, IfID: 7}}}, // over the dead interface
	}
	if c := s.freshest(dirty); c != nil {
		t.Errorf("freshest over the dirty pair = %v, want none", c.Fresh)
	}
	// The dirty pair beside one clean candidate however stale: the clean
	// one carries the baseline.
	stale := append(dirty, scion.Candidate{
		Fresh: now.Add(-time.Hour), Links: []segment.LinkID{link(selX)},
	})
	if c := s.freshest(stale); c == nil || !c.Fresh.Equal(now.Add(-time.Hour)) {
		t.Errorf("freshest = %v, want the stale clean one", c)
	}
	// A clean candidate at the head outranks them all.
	fresh := append(stale, scion.Candidate{Fresh: now})
	if c := s.freshest(fresh); c == nil || !c.Fresh.Equal(now) {
		t.Errorf("freshest over the clean set = %v, want the fresh clean one", c)
	}
}

// TestMeasureExcluded checks the excluded measurement: the enumeration to
// the tier's members with the link excluded takes the freshest clean
// survivor, and excluding what every route crosses leaves none — the
// cut-critical reading. No probe conn resolves a survivor the echo cannot
// answer: unmeasured, never cut-critical.
func TestMeasureExcluded(t *testing.T) {
	now := time.Now()
	up, freshDown, staleDown := lineSegments(t, now)
	s := enumSelection([]*pathdb.Segment{up},
		[]*pathdb.Segment{freshDown, staleDown})
	entries := map[addr.IA]DirectoryEntry{selPeer: entryOf(selPeer)}
	tr := &tier{members: []member{{ia: selPeer}}}

	// The excluded enumeration takes the freshest survivor: the fresh route
	// crosses the excluded link, the stale one carries it.
	ex := s.measureExcluded(context.Background(), tr, entries,
		segment.LinkID{IA: selX, IfID: 1})
	if !ex.survived {
		t.Error("excluded measurement = none, want the stale survivor")
	}
	if ex.echo != 0 {
		t.Errorf("excluded echo without a probe conn = %v, want the unanswered 0", ex.echo)
	}

	// Excluding a link every route crosses — the up's core egress — leaves
	// no route into the tier: the link is cut-critical.
	ex = s.measureExcluded(context.Background(), tr, entries,
		segment.LinkID{IA: selCore, IfID: 1})
	if ex.survived {
		t.Error("excluded measurement over a cut-critical link survived")
	}
}

// cand builds a candidate of the given links, for the pure queries' tests.
func cand(links ...segment.LinkID) scion.Candidate {
	return scion.Candidate{Links: links}
}

func link(ia addr.IA) segment.LinkID { return segment.LinkID{IA: ia, IfID: 1} }

// declared builds an enumerated route declaring its one-way latency.
func declared(oneWay time.Duration) scion.Candidate {
	return scion.Candidate{Latency: &oneWay}
}

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

// TestTierPrice checks the promotion estimate's pricing: the measured
// baseline is the authority wherever an echo exists — a misstated
// declaration moves no measured baseline — the declared one-way sums
// doubled to meet the round trips they are judged against where none does,
// and an undeclared edge prices nothing.
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
	if got := tierPrice(30*time.Millisecond, routes); got != 30*time.Millisecond {
		t.Errorf("tier price past a misstated declaration = %v, want the measured 30ms", got)
	}
	if got := tierPrice(0, routes[1:2]); got != 0 {
		t.Errorf("tier price of undeclared routes = %v, want 0", got)
	}
}
