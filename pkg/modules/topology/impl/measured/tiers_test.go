package measured

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/modules/links"
)

// sm builds a window sample of the given direct round trip and enumerated
// routes.
func sm(direct time.Duration, candidates ...scion.Candidate) sample {
	return sample{direct: direct, candidates: candidates}
}

// TestDeriveTiers checks the sorted walk: a peer within the gap joins, one
// past twice the median opens a new tier, the median recomputes as a tier
// grows, an unmeasured peer classes into none, and equal samples are stable
// across recomputation.
func TestDeriveTiers(t *testing.T) {
	samples := map[addr.IA]sample{
		selA: sm(5),
		selB: sm(6),
		selC: sm(7),
		selD: sm(9),
		// Unmeasured, however favorable its route: not placed.
		selE: sm(0, measured(route(0, 0, link(selE)), 4)),
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
	samples[selE] = sm(30)
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
		selA: sm(10), selB: sm(10), selC: sm(10), selD: sm(10),
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
// from the verdicts alone; the price of the cheapest clean route at its cost
// — a declared route under a measured one sets it, while a crossing route,
// an ejected one, and one over a local down interface price nothing; each
// member's own price over its own routes, a member no route prices absent;
// the route count reading the clean candidates alone; and strandedness, once
// no up link reaches a tier and the measurements doubt every route into it.
func TestWindowTierFacts(t *testing.T) {
	verdicts := map[uint16]bool{3: true, 4: false, 7: false} // B's link down, the node's own 7 dead
	up := &links.Link{NeighborIA: selA, IfID: 3, State: links.StateEstablished}
	dead := &links.Link{NeighborIA: selB, IfID: 4, State: links.StateEstablished}
	neighbors := map[addr.IA]*links.Link{selA: up, selB: dead}
	s := &selection{cfg: SelectionConfig{
		IA:    selIA,
		Links: verdictTopic(verdicts),
	}}
	// One fast tier of three measured peers: A up, its route measured at
	// 20ms beside a clean route declaring 8ms one way; B verdict-down, its
	// route over the down link; C a candidate whose routes are a crossing
	// one and one over the node's own dead interface, both declaring 1ms,
	// beside one clean undeclared route. And a slow tier of two: D, whose
	// one route declares 2ms but was ejected, and E, whose one route is
	// suspect.
	a := sm(5,
		measured(route(0, 0, local(3), link(selA)), 20*time.Millisecond),
		route(-time.Minute, 8*time.Millisecond, link(selX), link(selA)),
	)
	b := sm(6, route(0, time.Millisecond, local(4), link(selB)))
	crossing := route(0, time.Millisecond, link(selC))
	crossing.Crossing = true
	c := sm(7,
		crossing,
		route(0, time.Millisecond, local(7), link(selC)),
		route(0, 0, link(selX), link(selC)),
	)
	d := sm(50, with(route(0, 2*time.Millisecond, link(selX), link(selD)), scion.HealthEjected))
	e := sm(60, with(route(0, 3*time.Millisecond, link(selX), link(selE)), scion.HealthSuspect))
	samples := map[addr.IA]sample{selA: a, selB: b, selC: c, selD: d, selE: e}

	ts := s.windowTiers(neighbors, samples)
	if len(ts) != 2 {
		t.Fatalf("tiers = %d, want the fast one and the slow one", len(ts))
	}
	fast, slow := &ts[0], &ts[1]

	if len(fast.upLinks) != 1 || fast.upLinks[0] != local(3) {
		t.Errorf("up links = %v, want the verdict-up link alone", fast.upLinks)
	}
	if fast.price != 16*time.Millisecond {
		t.Errorf("price = %v, want the declared route's doubled 16ms", fast.price)
	}
	// A's declared route undercuts its measured 20ms route; B's and C's
	// routes are dirty or undeclared.
	wantPrices := map[addr.IA]time.Duration{selA: 16 * time.Millisecond}
	if diff := cmp.Diff(wantPrices, fast.prices); diff != "" {
		t.Errorf("member prices (-want +got):\n%s", diff)
	}
	// The up link beside a clean route that avoids it: the declared route
	// and C's clean route share no link with the up link.
	if fast.routes != 2 {
		t.Errorf("routes = %d, want the up link beside a clean route", fast.routes)
	}
	if fast.stranded {
		t.Error("a tier with an up link is stranded")
	}
	if _, ok := fast.excluded[selA]; !ok {
		t.Error("no excluded measurement for the up link")
	}

	// The slow tier: D's one route was ejected, and E's suspect one counts
	// and prices, but no up link reaches the tier and the measurements doubt
	// its one route — stranded.
	if slow.routes != 1 || !slow.stranded {
		t.Errorf("the slow tier = %d routes, stranded %v; want E's one and stranded",
			slow.routes, slow.stranded)
	}
	if slow.price != 6*time.Millisecond {
		t.Errorf("the stranded tier's price = %v, want E's declared 6ms", slow.price)
	}

	// An up link to D: the slow tier is not stranded, though the
	// measurements still doubt every route into it.
	verdicts[9] = true
	s.cfg.Links = verdictTopic(verdicts)
	neighbors[selD] = &links.Link{NeighborIA: selD, IfID: 9, State: links.StateEstablished}
	if ts := s.windowTiers(neighbors, samples); len(ts) != 2 || ts[1].stranded {
		t.Error("a tier an up link reaches is stranded")
	}
}

// TestExcludedCutsOffTheLinksOwnNeighbor checks the excluded measurement of
// a link whose neighbor no composed route reaches — a fellow core, which
// only their link routes a core to: without the link the neighbor is cut
// off, and the window decides the link useful however well the survivors
// serve the rest of its tier.
func TestExcludedCutsOffTheLinksOwnNeighbor(t *testing.T) {
	ms := time.Millisecond
	verdicts := map[uint16]bool{3: true, 5: true}
	neighbors := map[addr.IA]*links.Link{
		selA: {NeighborIA: selA, IfID: 3, State: links.StateEstablished},
		selB: {NeighborIA: selB, IfID: 5, State: links.StateEstablished},
	}
	s := &selection{cfg: SelectionConfig{
		IA:    selIA,
		Links: verdictTopic(verdicts),
	}}
	// A answers its direct echo, and no route composes into it. B's measured
	// route rides B's own link, and a second route reaches B around it.
	b := sm(10*ms,
		measured(route(0, 0, local(5), link(selB)), 20*ms),
		route(0, 12*ms, link(selX), link(selB)),
	)
	ts := s.windowTiers(neighbors, map[addr.IA]sample{selA: sm(10 * ms), selB: b})
	if len(ts) != 1 {
		t.Fatalf("tiers = %d, want one", len(ts))
	}
	if !ts[0].excluded[selA].cutOff[selA] {
		t.Error("excluding A's link left A uncut, though no survivor reaches it")
	}
	if decided, useless := judge(&ts[0], selA); !decided || useless {
		t.Errorf("judge = (%v, %v), want (true, false): the link is A's only route",
			decided, useless)
	}
}

// TestWindowTiersWithoutMeasurements checks a window nothing measured, every
// route unknown, as on a node without the ping application: routes price by
// their declarations, a tier with no up link is not stranded while a clean
// route composes into it, and no up link's useless test decides.
func TestWindowTiersWithoutMeasurements(t *testing.T) {
	ms := time.Millisecond
	verdicts := map[uint16]bool{3: true, 5: true}
	neighbors := map[addr.IA]*links.Link{
		selA: {NeighborIA: selA, IfID: 3, State: links.StateEstablished},
		selB: {NeighborIA: selB, IfID: 5, State: links.StateEstablished},
	}
	s := &selection{cfg: SelectionConfig{
		IA:    selIA,
		Links: verdictTopic(verdicts),
	}}
	ts := s.windowTiers(neighbors, map[addr.IA]sample{
		selA: sm(10*ms, route(0, 6*ms, local(3), link(selA)), route(0, 7*ms, local(5), link(selB), link(selA))),
		selB: sm(11*ms, route(0, 6*ms, local(5), link(selB)), route(0, 7*ms, local(3), link(selA), link(selB))),
		selC: sm(100*ms, route(0, 30*ms, local(3), link(selA), link(selC))),
	})
	if len(ts) != 2 {
		t.Fatalf("tiers = %d, want A's and B's, and C's", len(ts))
	}
	fast, slow := &ts[0], &ts[1]
	if fast.price != 12*ms || slow.price != 60*ms {
		t.Errorf("prices = %v and %v, want the declared 12ms and 60ms", fast.price, slow.price)
	}
	if slow.stranded {
		t.Error("a tier a clean route reaches is stranded")
	}
	for _, ia := range []addr.IA{selA, selB} {
		if decided, _ := judge(fast, ia); decided {
			t.Errorf("a window nothing measured decided %s's link", ia)
		}
	}
}

// TestMemberPrice checks a member's price: each route at its cost, the
// measured round trip or else the declared sum doubled, an undeclared and
// unmeasured one pricing nothing; each route charged the transit penalty for
// every AS it crosses between its ends, each way; the cheapest winning.
func TestMemberPrice(t *testing.T) {
	ms := time.Millisecond
	direct := measured(route(0, ms, local(1), link(selA)), 20*ms)
	oneTransit := route(0, 9*ms, local(2), link(selB), link(selA))
	twoTransits := route(0, 3*ms, local(2), link(selB), link(selC), link(selA))
	undeclared := route(0, 0, local(3), link(selC), link(selA))

	for _, tc := range []struct {
		name   string
		routes []*scion.Candidate
		want   time.Duration
	}{
		{"a measured route at its cost", ptrs(direct), 20 * ms},
		{"a measured route's transit charged", ptrs(measured(oneTransit, 20*ms)), 30 * ms},
		{"a declared route, its transit charged", ptrs(oneTransit), 28 * ms},
		{"two transits charged", ptrs(twoTransits), 26 * ms},
		{"an undeclared route", ptrs(undeclared), 0},
		{"the cheapest", ptrs(measured(direct, 30*ms), oneTransit, twoTransits, undeclared), 26 * ms},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := memberPrice(tc.routes); got != tc.want {
				t.Errorf("price = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestTierQualifies checks the priced admission cases: a direct round trip
// beating the member's own price by the promotion ratio qualifies however
// cheap the tier's price, one short of the ratio or beating the price by
// less than the margin floor does not, a member no route prices takes the
// tier's price, a single-route tier admits within the demotion ratio of its
// price, and an unpriced tier qualifies nothing.
func TestTierQualifies(t *testing.T) {
	ms := time.Millisecond
	priced := tier{
		price:  10 * ms,
		prices: map[addr.IA]time.Duration{selA: 30 * ms, selB: 9 * ms},
		routes: 2,
	}
	single := tier{price: 10 * ms, routes: 1}

	for _, tc := range []struct {
		name   string
		tier   tier
		ia     addr.IA
		direct time.Duration
		want   bool
	}{
		{"beating its own price", priced, selA, 20 * ms, true},
		{"short of the promotion ratio", priced, selA, 25 * ms, false},
		{"within the margin floor", priced, selB, 7100 * time.Microsecond, false},
		{"past the margin floor", priced, selB, 6900 * time.Microsecond, true},
		{"beating the tier's price", priced, selC, 7 * ms, true},
		{"short of the tier's price", priced, selC, 9 * ms, false},
		{"a second route within the demotion ratio", single, selC, 12 * ms, true},
		{"a second route past it", single, selC, 13 * ms, false},
		{"an unpriced tier", tier{routes: 1}, selC, ms, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.tier.qualifies(tc.ia, tc.direct); got != tc.want {
				t.Errorf("qualifies = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestJudge checks the useless test: with the tier's route count and price
// held, a link is useless only while every member keeps a route within the
// demotion ratio of its own price — the link's own neighbor of its direct
// round trip. A priced member the survivors reach but none prices leaves the
// window undecided, unless another member decides the link useful; a
// survivor of a member no route prices counts for nothing, and a member cut
// off, priced or not, decides the link useful. A tier nothing prices, or a
// survivor that did not answer, decides nothing.
func TestJudge(t *testing.T) {
	ms := time.Millisecond
	type prices = map[addr.IA]time.Duration
	// The link is A's, its round trip 10ms and its own price 16ms. B prices
	// at 20ms, and no route prices C.
	tierWith := func(ex excludedSample) *tier {
		return &tier{
			members: []member{
				{ia: selA, direct: 10 * ms},
				{ia: selB, direct: 12 * ms},
				{ia: selC, direct: 14 * ms},
			},
			price:    20 * ms,
			prices:   prices{selA: 16 * ms, selB: 20 * ms},
			routes:   2,
			excluded: map[addr.IA]excludedSample{selA: ex},
		}
	}
	// held is an excluded measurement that holds the tier's route count and
	// price, the members given cut off.
	held := func(p prices, cutOff ...addr.IA) excludedSample {
		ex := excludedSample{
			answered: true,
			price:    22 * ms,
			routes:   2,
			prices:   p,
			cutOff:   make(map[addr.IA]bool),
		}
		for _, ia := range cutOff {
			ex.cutOff[ia] = true
		}
		return ex
	}
	within := prices{selA: 12 * ms, selB: 24 * ms}

	for _, tc := range []struct {
		name    string
		ex      excludedSample
		decided bool
		useless bool
	}{
		{"every member within the ratio", held(within), true, true},
		{"the neighbor past the ratio of its round trip",
			held(prices{selA: 13 * ms, selB: 24 * ms}), true, false},
		{"another member past the ratio of its price",
			held(prices{selA: 12 * ms, selB: 26 * ms}), true, false},
		{"a member no survivor prices", held(prices{selA: 12 * ms}), false, false},
		{"the neighbor no survivor prices", held(prices{selB: 24 * ms}), false, false},
		{"a member no survivor prices, another past the ratio",
			held(prices{selA: 13 * ms}), true, false},
		{"a member cut off", held(prices{selA: 12 * ms}, selB), true, false},
		{"a member no route prices, cut off", held(within, selC), true, false},
		{"a survivor of a member no route prices",
			held(prices{selA: 12 * ms, selB: 24 * ms, selC: 100 * ms}), true, true},
		{"the tier's price past the ratio",
			excludedSample{answered: true, price: 26 * ms, routes: 2, prices: within}, true, false},
		{"a route lost",
			excludedSample{answered: true, price: 22 * ms, routes: 1, prices: within}, true, false},
		{"the survivor unanswered",
			excludedSample{price: 22 * ms, routes: 2, prices: within}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			decided, useless := judge(tierWith(tc.ex), selA)
			if decided != tc.decided || useless != tc.useless {
				t.Errorf("judge = (%v, %v), want (%v, %v)",
					decided, useless, tc.decided, tc.useless)
			}
		})
	}

	unpriced := tierWith(held(within))
	unpriced.price = 0
	if decided, _ := judge(unpriced, selA); decided {
		t.Error("a tier nothing prices decided a link")
	}
}
