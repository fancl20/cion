package measured

import (
	"fmt"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/modules/links"
	"github.com/fancl20/cion/pkg/scion"
	"github.com/fancl20/cion/pkg/segment"
)

var selX = addr.MustIAFrom(20, 0xfd0000000031)

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

// cand builds a candidate of the given links, for the pure queries' tests.
func cand(links ...segment.LinkID) scion.Candidate {
	return scion.Candidate{Links: links}
}

func link(ia addr.IA) segment.LinkID { return segment.LinkID{IA: ia, IfID: 1} }

// local names one of the node's own interfaces.
func local(ifID uint16) segment.LinkID { return segment.LinkID{IA: selIA, IfID: ifID} }

// declared builds an enumerated route declaring its one-way latency.
func declared(oneWay time.Duration) scion.Candidate {
	return scion.Candidate{Latency: &oneWay}
}

// route builds an enumerated route over the links, fresh at the given
// offset from now, declaring the one-way latency when it is nonzero.
func route(fresh time.Duration, oneWay time.Duration, links ...segment.LinkID) scion.Candidate {
	c := scion.Candidate{Links: links, Fresh: time.Unix(1<<30, 0).Add(fresh)}
	if oneWay > 0 {
		c.Latency = &oneWay
	}
	return c
}

// routeKey names a route by its links, the key the path echo seam's
// answers are given by.
func routeKey(c *scion.Candidate) string { return fmt.Sprint(c.Links) }

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

// TestCheapest checks the price of a set of routes: a probed route by its
// echo, an unanswered one pricing nothing whatever it declares, every other
// route by its declared one-way sum doubled, an undeclared one pricing
// nothing — and the cheapest wins, a declaration under the echoes included.
func TestCheapest(t *testing.T) {
	probedRoute := declared(time.Millisecond) // its declaration never prices
	cheap := declared(8 * time.Millisecond)
	pricier := declared(20 * time.Millisecond)
	routes := ptrs(probedRoute, cheap, cand(), pricier)
	probed := map[*scion.Candidate]bool{routes[0]: true}

	for _, tc := range []struct {
		name   string
		echoes []time.Duration
		routes []*scion.Candidate
		want   time.Duration
	}{
		{"a declaration under the echo", []time.Duration{30 * time.Millisecond}, routes, 16 * time.Millisecond},
		{"an echo under the declarations", []time.Duration{12 * time.Millisecond}, routes, 12 * time.Millisecond},
		{"an unanswered echo", []time.Duration{0}, routes, 16 * time.Millisecond},
		{"the probed route alone, unanswered", []time.Duration{0}, routes[:1], 0},
		{"undeclared routes", nil, routes[2:3], 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := cheapest(tc.echoes, tc.routes, probed); got != tc.want {
				t.Errorf("price = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestMeasureExcluded checks each up link's excluded measurement over the
// window's candidates: the survivors are the clean candidates that traverse
// the link nowhere, the freshest of them echoed; the price is the cheapest
// survivor — the echoed one by its new echo, unanswered pricing nothing, a
// surviving carrier by its baseline echo, any other by its declaration;
// the route count reads the tier's other up links beside the survivors; a
// link every route crosses leaves no survivor, no echo, and no price; and a
// down link takes no measurement.
func TestMeasureExcluded(t *testing.T) {
	verdicts := map[uint16]bool{1: true, 2: true, 4: false, 5: true}
	neighbors := map[addr.IA]*links.Link{
		selA: {NeighborIA: selA, IfID: 1, State: links.StateEstablished},
		selB: {NeighborIA: selB, IfID: 2, State: links.StateEstablished},
		selD: {NeighborIA: selD, IfID: 4, State: links.StateEstablished},
		selE: {NeighborIA: selE, IfID: 5, State: links.StateEstablished},
	}
	entries := map[addr.IA]DirectoryEntry{
		selA: entryOf(selA), selB: entryOf(selB), selD: entryOf(selD), selE: entryOf(selE),
	}
	// A's carrier leaves through B's link; A's other route through its own.
	// B's carrier leaves through its own link; B's other route through a
	// third, declaring.
	a := sm(10*time.Millisecond, 22*time.Millisecond,
		route(-time.Minute, 0, local(2), link(selB), link(selA)),
		route(-2*time.Minute, 0, local(1), link(selA)),
	)
	a.carrier = &a.candidates[0]
	b := sm(12*time.Millisecond, 18*time.Millisecond,
		route(-30*time.Second, 0, local(2), link(selB)),
		route(-3*time.Minute, 30*time.Millisecond, local(3), link(selC), link(selB)),
	)
	b.carrier = &b.candidates[0]
	// E, alone in a slow tier, reached only over its own link.
	e := sm(100*time.Millisecond, 0, route(0, 0, local(5), link(selE)))
	samples := map[addr.IA]sample{
		selA: a, selB: b, selD: sm(11*time.Millisecond, 0), selE: e,
	}
	echoes := map[string]time.Duration{
		routeKey(&b.candidates[0]): 26 * time.Millisecond, // B's carrier, echoed anew
	}
	s := &selection{
		cfg: SelectionConfig{
			IA:       selIA,
			Verdicts: func() map[uint16]bool { return verdicts },
		},
		pathEchoFn: func(_ addr.IA, c *scion.Candidate) time.Duration {
			return echoes[routeKey(c)]
		},
	}
	ts := s.windowTiers(t.Context(), neighbors, entries, samples)
	if len(ts) != 2 {
		t.Fatalf("tiers = %d, want the fast one and E's", len(ts))
	}
	fast, slow := &ts[0], &ts[1]

	// Excluding A's link: B's carrier is the freshest survivor, priced by
	// its new 26ms echo, and A's surviving carrier by its 22ms baseline —
	// the price. B's link and the declared third route keep two routes.
	want := excludedSample{echo: 26 * time.Millisecond, price: 22 * time.Millisecond, routes: 2}
	if got := fast.excluded[selA]; got != want {
		t.Errorf("A's excluded measurement = %+v, want %+v", got, want)
	}
	// Excluding B's link: A's own route is the freshest survivor and goes
	// unanswered, pricing nothing; the declared route prices at 60ms.
	want = excludedSample{price: 60 * time.Millisecond, routes: 2}
	if got := fast.excluded[selB]; got != want {
		t.Errorf("B's excluded measurement = %+v, want %+v", got, want)
	}
	if _, ok := fast.excluded[selD]; ok {
		t.Error("the down link took an excluded measurement")
	}
	// E's link is crossed by every route into its tier.
	if got := slow.excluded[selE]; got != (excludedSample{}) {
		t.Errorf("E's excluded measurement = %+v, want none", got)
	}
}
