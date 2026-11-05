package measured

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/libs/bus"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/segment"
	"github.com/fancl20/cion/pkg/modules/links"
)

var selX = addr.MustIAFrom(20, 0xfd0000000031)

// TestFreshestClean checks the baseline: the freshest clean candidate,
// never an ejected one nor one over one of the node's own verdict-down
// links, while a suspect one serves. All dirty leaves no baseline.
func TestFreshestClean(t *testing.T) {
	verdicts := map[uint16]bool{7: false} // the node's own dead interface
	s := &selection{cfg: SelectionConfig{
		IA:    selIA,
		Links: verdictTopic(verdicts),
	}}
	now := time.Now()
	dirty := []scion.Candidate{
		{Fresh: now, Health: scion.HealthEjected},
		{Fresh: now, Links: []segment.LinkID{{IA: selIA, IfID: 7}}}, // over the dead interface
	}
	if c := s.freshest(dirty); c != nil {
		t.Errorf("freshest over the dirty ones = %v, want none", c.Fresh)
	}
	// The dirty ones beside one clean candidate however stale: the clean
	// one is the baseline.
	stale := append(dirty, scion.Candidate{
		Fresh: now.Add(-time.Hour), Links: []segment.LinkID{link(selX)},
	})
	if c := s.freshest(stale); c == nil || !c.Fresh.Equal(now.Add(-time.Hour)) {
		t.Errorf("freshest = %v, want the stale clean one", c)
	}
	// A clean candidate at the head outranks them all, suspect though it is.
	fresh := append(stale, scion.Candidate{Fresh: now, Health: scion.HealthSuspect})
	if c := s.freshest(fresh); c == nil || !c.Fresh.Equal(now) {
		t.Errorf("freshest over the clean set = %v, want the fresh clean one", c)
	}
}

// cand builds a candidate of the given links, for the pure queries' tests.
func cand(links ...segment.LinkID) scion.Candidate {
	return scion.Candidate{Links: links}
}

func link(ia addr.IA) segment.LinkID { return segment.LinkID{IA: ia, IfID: 1} }

// local names one of the node's own interfaces.
func local(ifID uint16) segment.LinkID { return segment.LinkID{IA: selIA, IfID: ifID} }

// route builds an enumerated route over the links, fresh at the given
// offset, as composition returns one nothing measured: unknown, its cost
// twice the one-way latency it declares when that is nonzero.
func route(fresh time.Duration, oneWay time.Duration, links ...segment.LinkID) scion.Candidate {
	c := scion.Candidate{
		Links: links, Crossed: links, ID: bus.PathIDOf(links),
		Fresh: time.Unix(1<<30, 0).Add(fresh),
	}
	if oneWay > 0 {
		prior := 2 * oneWay
		c.Latency, c.Cost = &oneWay, &prior
	}
	return c
}

// measured returns the route as the measurements leave it: healthy, at the
// measured cost.
func measured(c scion.Candidate, cost time.Duration) scion.Candidate {
	c.Health, c.Cost = scion.HealthHealthy, &cost
	return c
}

// with returns the route in the given health.
func with(c scion.Candidate, h scion.Health) scion.Candidate {
	c.Health = h
	return c
}

// ptrs points at the candidates, the form the tier's routes take.
func ptrs(cs ...scion.Candidate) []*scion.Candidate {
	out := make([]*scion.Candidate, len(cs))
	for i := range cs {
		out[i] = &cs[i]
	}
	return out
}

// TestRouteCount checks the tier's route count: the up links beside the
// composed paths traversing none of them, the second path counting only
// when edge-disjoint — checked over all pairs, so the pair a greedy first
// pick misses still counts — and the count saturating at two.
func TestRouteCount(t *testing.T) {
	// No up links. The first candidate shares an edge with each of the
	// others, but a different pair is disjoint: the greedy miss.
	crossing := ptrs(
		cand(link(selA), link(selB)),
		cand(link(selA), link(selC)),
		cand(link(selB), link(selD)),
	)
	if got := routeCount(nil, crossing); got != 2 {
		t.Errorf("route count = %d, want the disjoint pair's 2", got)
	}

	// A single candidate alone counts one.
	if got := routeCount(nil, crossing[:1]); got != 1 {
		t.Errorf("route count = %d, want 1", got)
	}

	// Saturation: however many pairwise-disjoint routes, the count stops
	// at two.
	disjoint := ptrs(cand(link(selA)), cand(link(selB)), cand(link(selC)))
	if got := routeCount(nil, disjoint); got != 2 {
		t.Errorf("route count = %d, want the saturated 2", got)
	}

	// One up link: a candidate traversing it never counts — the link is
	// already the route — and one avoiding it adds the second.
	up := []segment.LinkID{link(selA)}
	over := ptrs(cand(link(selA), link(selB)), cand(link(selA), link(selC)))
	if got := routeCount(up, over); got != 1 {
		t.Errorf("route count over the up link = %d, want 1", got)
	}
	avoiding := ptrs(cand(link(selA), link(selB)), cand(link(selC)))
	if got := routeCount(up, avoiding); got != 2 {
		t.Errorf("route count beside the up link = %d, want 2", got)
	}

	// Two up links saturate the count whatever the candidates.
	if got := routeCount([]segment.LinkID{link(selA), link(selB)}, avoiding); got != 2 {
		t.Errorf("route count of two up links = %d, want 2", got)
	}
}

// TestCheapest checks the price of a set of routes: each at its cost, the
// measured round trip or else the declared sum doubled, a route with neither
// pricing nothing, and the cheapest winning.
func TestCheapest(t *testing.T) {
	ms := time.Millisecond
	slow := measured(cand(), 30*ms)
	fast := measured(cand(), 12*ms)
	declared := route(0, 8*ms)
	for _, tc := range []struct {
		name   string
		routes []*scion.Candidate
		want   time.Duration
	}{
		{"a declaration under a measurement", ptrs(slow, declared, cand()), 16 * ms},
		{"a measurement under a declaration", ptrs(fast, declared), 12 * ms},
		{"routes without a cost", ptrs(cand(), cand()), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := cheapest(tc.routes); got != tc.want {
				t.Errorf("price = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestMeasureExcluded checks each up link's excluded measurement over the
// window's candidates: the survivors are the clean candidates that traverse
// the link nowhere, the freshest of them the window's survivor, answered
// when healthy; the price is the cheapest survivor at its cost; each
// member's price is the same over its own survivors, each route charged the
// transit penalty per AS it crosses, beside the survivor it is priced by;
// the route count reads the tier's other up links beside the survivors; a
// link every route crosses leaves no survivor and no price; and a down link
// takes no measurement.
func TestMeasureExcluded(t *testing.T) {
	verdicts := map[uint16]bool{1: true, 2: true, 4: false, 5: true}
	neighbors := map[addr.IA]*links.Link{
		selA: {NeighborIA: selA, IfID: 1, State: links.StateEstablished},
		selB: {NeighborIA: selB, IfID: 2, State: links.StateEstablished},
		selD: {NeighborIA: selD, IfID: 4, State: links.StateEstablished},
		selE: {NeighborIA: selE, IfID: 5, State: links.StateEstablished},
	}
	// A's measured route leaves through B's link; A's other route, unknown,
	// through its own. B's measured route leaves through its own link; B's
	// other route through a third, declaring.
	a := sm(10*time.Millisecond,
		measured(route(-time.Minute, 0, local(2), link(selB), link(selA)), 22*time.Millisecond),
		route(-2*time.Minute, 0, local(1), link(selA)),
	)
	b := sm(12*time.Millisecond,
		measured(route(-30*time.Second, 0, local(2), link(selB)), 26*time.Millisecond),
		route(-3*time.Minute, 30*time.Millisecond, local(3), link(selC), link(selB)),
	)
	// E, alone in a slow tier, reached only over its own link.
	e := sm(100*time.Millisecond, route(0, 0, local(5), link(selE)))
	samples := map[addr.IA]sample{
		selA: a, selB: b, selD: sm(11 * time.Millisecond), selE: e,
	}
	s := &selection{cfg: SelectionConfig{
		IA:    selIA,
		Links: verdictTopic(verdicts),
	}}
	ts := s.windowTiers(neighbors, samples)
	if len(ts) != 2 {
		t.Fatalf("tiers = %d, want the fast one and E's", len(ts))
	}
	fast, slow := &ts[0], &ts[1]

	opts := []cmp.Option{cmp.AllowUnexported(excludedSample{}), cmpopts.EquateEmpty()}
	// Excluding A's link: B's measured route is the freshest survivor,
	// answered, and A's surviving route at 22ms the price. B's link and the
	// declared third route keep two routes. A's own price rides B's link,
	// one transit: 22ms and 10ms more.
	want := excludedSample{
		survivor: &b.candidates[0],
		dst:      selB,
		answered: true,
		price:    22 * time.Millisecond,
		routes:   2,
		prices:   map[addr.IA]time.Duration{selA: 32 * time.Millisecond, selB: 26 * time.Millisecond},
		cheapest: map[addr.IA]*scion.Candidate{selA: &a.candidates[0], selB: &b.candidates[0]},
	}
	if diff := cmp.Diff(want, fast.excluded[selA], opts...); diff != "" {
		t.Errorf("A's excluded measurement (-want +got):\n%s", diff)
	}
	// Excluding B's link: A's own route is the freshest survivor, unknown,
	// so the window decides nothing; the declared route prices at 60ms, and
	// B at 70ms with its one transit.
	want = excludedSample{
		survivor: &a.candidates[1],
		dst:      selA,
		price:    60 * time.Millisecond,
		routes:   2,
		prices:   map[addr.IA]time.Duration{selB: 70 * time.Millisecond},
		cheapest: map[addr.IA]*scion.Candidate{selB: &b.candidates[1]},
	}
	if diff := cmp.Diff(want, fast.excluded[selB], opts...); diff != "" {
		t.Errorf("B's excluded measurement (-want +got):\n%s", diff)
	}
	if _, ok := fast.excluded[selD]; ok {
		t.Error("the down link took an excluded measurement")
	}
	// E's link is crossed by every route into its tier.
	if diff := cmp.Diff(excludedSample{}, slow.excluded[selE], opts...); diff != "" {
		t.Errorf("E's excluded measurement (-want +got):\n%s", diff)
	}
}
