package measured

import (
	"maps"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/libs/bus"
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
// from the verdicts alone; the price of the cheapest clean read route at
// its cost — a declared route under a measured one prices nothing, nor do an
// ejected route and one over a local down interface; each member's own price
// over its own read routes, beside its cheapest route, read or not, which
// the window requests; the lowest lower bound of the read routes, the tier's
// at their costs and each member's at their prices; the route count reading
// the clean candidates alone; and strandedness, once no up link reaches a
// tier and the measurements doubt every route into it.
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
	// 20ms, bounded below at 18ms, beside a clean route declaring 8ms one
	// way, bounded below at 5ms by too few probes to read, and a measured
	// route through D at 30ms, bounded below at 14ms; B verdict-down, its
	// route over the down link; C a candidate whose route over the node's
	// own dead interface declares 1ms, beside one clean undeclared route.
	// And a slow tier of two: D, whose one route declares 2ms but was
	// ejected, and E, whose one route is suspect.
	bounded := func(c scion.Candidate, low time.Duration) scion.Candidate {
		c.Low = &low
		return c
	}
	a := sm(5,
		bounded(measured(route(0, 0, local(3), link(selA)), 20*time.Millisecond), 18*time.Millisecond),
		bounded(route(-time.Minute, 8*time.Millisecond, link(selX), link(selA)), 5*time.Millisecond),
		bounded(measured(route(0, 0, local(3), link(selD), link(selA)), 30*time.Millisecond), 14*time.Millisecond),
	)
	b := sm(6, route(0, time.Millisecond, local(4), link(selB)))
	c := sm(7,
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
	if fast.price != 20*time.Millisecond {
		t.Errorf("price = %v, want the measured route's 20ms", fast.price)
	}
	// A's declared route undercuts its measured 20ms route but is read by
	// nothing; B's and C's routes are dirty or undeclared.
	wantPrices := map[addr.IA]time.Duration{selA: 20 * time.Millisecond}
	if diff := cmp.Diff(wantPrices, fast.prices); diff != "" {
		t.Errorf("member prices (-want +got):\n%s", diff)
	}
	if len(fast.cheapest) != 1 || fast.cheapest[selA].ID != a.candidates[1].ID {
		t.Errorf("the members' cheapest routes = %v, want A's declared route", fast.cheapest)
	}
	// The route through D bounds the tier at its cost, 14ms, but A at its
	// price, 24ms with its transit, above the direct route's 18ms; the
	// declared route bounds nothing.
	if fast.low != 14*time.Millisecond {
		t.Errorf("low = %v, want the route through D's 14ms", fast.low)
	}
	if diff := cmp.Diff(map[addr.IA]time.Duration{selA: 18 * time.Millisecond}, fast.lows); diff != "" {
		t.Errorf("member lows (-want +got):\n%s", diff)
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
	// though its declaration prices nothing, but no up link reaches the tier
	// and the measurements doubt its one route — stranded.
	if slow.routes != 1 || !slow.stranded {
		t.Errorf("the slow tier = %d routes, stranded %v; want E's one and stranded",
			slow.routes, slow.stranded)
	}
	if slow.price != 0 {
		t.Errorf("the stranded tier's price = %v, want none: E's route is declared alone", slow.price)
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

// TestExcludedCheapestSurvivors checks the survivor the excluded
// measurement prices each member by: the cheapest at its price, transits
// charged, not the cheapest at its cost; none for a member whose survivors
// price nothing or that no survivor reaches.
func TestExcludedCheapestSurvivors(t *testing.T) {
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
	// A's own link at 20ms; around it, through B at 15ms, 25ms with its
	// transit, and through B and X at 12ms, 32ms with its two. B rides its
	// own link alone. C's routes declare nothing.
	aOwn := measured(route(0, 0, local(3), link(selA)), 20*ms)
	aViaB := measured(route(-time.Minute, 0, local(5), link(selB), link(selA)), 15*ms)
	aViaBX := measured(route(-time.Minute, 0, local(5), link(selB), link(selX), link(selA)), 12*ms)
	bOwn := measured(route(0, 0, local(5), link(selB)), 20*ms)
	ts := s.windowTiers(neighbors, map[addr.IA]sample{
		selA: sm(10*ms, aOwn, aViaB, aViaBX),
		selB: sm(10*ms, bOwn),
		selC: sm(10*ms, route(0, 0, local(3), link(selA), link(selC)), route(0, 0, local(5), link(selB), link(selC))),
	})
	if len(ts) != 1 {
		t.Fatalf("tiers = %d, want one", len(ts))
	}
	ids := func(cheapest map[addr.IA]*scion.Candidate) map[addr.IA]bus.PathID {
		out := make(map[addr.IA]bus.PathID, len(cheapest))
		for ia, c := range cheapest {
			out[ia] = c.ID
		}
		return out
	}
	for _, tc := range []struct {
		name string
		link addr.IA
		want map[addr.IA]bus.PathID
	}{
		{"around A's link", selA, map[addr.IA]bus.PathID{selA: aViaB.ID, selB: bOwn.ID}},
		{"around B's link", selB, map[addr.IA]bus.PathID{selA: aOwn.ID}},
	} {
		if diff := cmp.Diff(tc.want, ids(ts[0].excluded[tc.link].cheapest)); diff != "" {
			t.Errorf("%s: cheapest survivors (-want +got):\n%s", tc.name, diff)
		}
	}
}

// TestWindowTiersWithoutMeasurements checks a window nothing measured, every
// route unknown, as on a node without the ping application: no route
// prices, though each member's cheapest by its declaration is requested, a
// tier with no up link is not stranded while a clean route composes into it,
// and no up link's useless test decides.
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
	if fast.price != 0 || slow.price != 0 {
		t.Errorf("prices = %v and %v, want none", fast.price, slow.price)
	}
	if c := slow.cheapest[selC]; c == nil || *c.Cost != 60*ms {
		t.Errorf("C's cheapest route = %v, want its declared 60ms one", c)
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

// TestMemberRoute checks the route a member is priced by: each route at its
// cost, the measured round trip or else the declared sum doubled, an
// undeclared and unmeasured one, or one measured at zero, pricing nothing;
// each route charged the transit penalty for every AS it crosses between its
// ends, each way; the cheapest winning.
func TestMemberRoute(t *testing.T) {
	ms := time.Millisecond
	direct := measured(route(0, ms, local(1), link(selA)), 20*ms)
	oneTransit := route(0, 9*ms, local(2), link(selB), link(selA))
	twoTransits := route(0, 3*ms, local(2), link(selB), link(selC), link(selA))
	undeclared := route(0, 0, local(3), link(selC), link(selA))

	for _, tc := range []struct {
		name      string
		routes    []*scion.Candidate
		want      time.Duration
		wantRoute bus.PathID
	}{
		{"a measured route at its cost", ptrs(direct), 20 * ms, direct.ID},
		{"a measured route's transit charged", ptrs(measured(oneTransit, 20*ms)), 30 * ms, oneTransit.ID},
		{"a declared route, its transit charged", ptrs(oneTransit), 28 * ms, oneTransit.ID},
		{"two transits charged", ptrs(twoTransits), 26 * ms, twoTransits.ID},
		{"an undeclared route", ptrs(undeclared), 0, ""},
		{"a zero cost, its transit uncharged", ptrs(measured(oneTransit, 0)), 0, ""},
		{"the cheapest", ptrs(measured(direct, 30*ms), oneTransit, twoTransits, undeclared), 26 * ms, twoTransits.ID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, price := memberRoute(tc.routes)
			var got bus.PathID
			if c != nil {
				got = c.ID
			}
			if price != tc.want || got != tc.wantRoute {
				t.Errorf("route %v at %v, want %v at %v", got, price, tc.wantRoute, tc.want)
			}
		})
	}
}

// TestTierQualifies checks the priced admission cases. On the readings, a
// direct round trip beating the member's own price by the promotion ratio
// qualifies however cheap the tier's price, one short of the ratio or
// beating the price by less than the margin floor does not, a member no
// route prices takes the tier's price, and one whose routes none read beats
// nothing. Confirmed, a round trip short of the ratio qualifies where it and
// its upper bound both gain on the price and on its lower bound by the band
// the path policy moves a lease for: a fifth of the smaller below the cap,
// the cap itself on a long path. A single-route tier admits within
// SecondRouteRatio of its price, and an unpriced tier qualifies nothing.
func TestTierQualifies(t *testing.T) {
	ms := time.Millisecond
	unread := route(0, 30*ms, link(selX), link(selD))
	priced := tier{
		price:    10 * ms,
		prices:   map[addr.IA]time.Duration{selA: 30 * ms, selB: 9 * ms, selE: 200 * ms},
		low:      9 * ms,
		lows:     map[addr.IA]time.Duration{selA: 29600 * time.Microsecond, selB: 8 * ms, selE: 199 * ms},
		cheapest: map[addr.IA]*scion.Candidate{selD: &unread},
		routes:   2,
	}
	single := tier{price: 10 * ms, routes: 1}
	long := tier{price: 200 * ms, low: 199 * ms, routes: 2}

	for _, tc := range []struct {
		name         string
		tier         tier
		ia           addr.IA
		direct, high time.Duration
		want         bool
	}{
		{"beating its own price", priced, selA, 20 * ms, 0, true},
		{"short of the promotion ratio", priced, selA, 25 * ms, 26 * ms, false},
		{"within the margin floor", priced, selB, 7100 * time.Microsecond, 7100 * time.Microsecond, false},
		{"past the margin floor", priced, selB, 6900 * time.Microsecond, 0, true},
		{"beating the tier's price", priced, selC, 7 * ms, 0, true},
		{"short of the tier's price", priced, selC, 9 * ms, 9 * ms, false},
		{"its routes none read", priced, selD, ms, ms, false},
		{"short of the ratio, confirmed past the band", priced, selA, 24500 * time.Microsecond, 24600 * time.Microsecond, true},
		{"short of the ratio, its bound within the band", priced, selA, 24500 * time.Microsecond, 25 * ms, false},
		{"short of the ratio, unbounded", priced, selA, 24500 * time.Microsecond, 0, false},
		{"a long path, confirmed past the cap", priced, selE, 185 * ms, 187 * ms, true},
		{"a long path, its bound within the cap", priced, selE, 185 * ms, 190 * ms, false},
		{"a long path, its reading within the cap", priced, selE, 191 * ms, 185 * ms, false},
		{"no route pricing the member, confirmed against a long tier's", long, selC, 185 * ms, 187 * ms, true},
		{"a second route within SecondRouteRatio", single, selC, 12 * ms, 0, true},
		{"a second route past it", single, selC, 13 * ms, 0, false},
		{"an unpriced tier", tier{routes: 1}, selC, ms, ms, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.tier.qualifies(tc.ia, tc.direct, tc.high); got != tc.want {
				t.Errorf("qualifies = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestTierGain checks what a candidate's direct round trip gains: its own
// price less the round trip, the tier's price when no route prices the
// member, and sure on the lower of the price and its lower bound; zero for
// a member whose routes none read, for an unpriced tier, and for a round
// trip that saves nothing, and the sure gain zero for a price no bound
// bounds.
func TestTierGain(t *testing.T) {
	ms := time.Millisecond
	unread := route(0, 30*ms, link(selX), link(selD))
	priced := tier{
		price:    10 * ms,
		prices:   map[addr.IA]time.Duration{selA: 30 * ms, selB: 9 * ms, selE: 30 * ms, selPeer: 20 * ms},
		low:      9 * ms,
		lows:     map[addr.IA]time.Duration{selA: 24 * ms, selB: 8 * ms, selPeer: 26 * ms},
		cheapest: map[addr.IA]*scion.Candidate{selD: &unread},
	}
	for _, tc := range []struct {
		name       string
		tier       tier
		ia         addr.IA
		direct     time.Duration
		gain, sure time.Duration
	}{
		{"its own price", priced, selA, 20 * ms, 10 * ms, 4 * ms},
		{"a round trip saving nothing", priced, selB, 12 * ms, 0, 0},
		{"the tier's price", priced, selC, 7 * ms, 3 * ms, 2 * ms},
		{"a price no bound bounds", priced, selE, 20 * ms, 10 * ms, 0},
		{"a lower bound above the price", priced, selPeer, 10 * ms, 10 * ms, 10 * ms},
		{"its routes none read", priced, selD, ms, 0, 0},
		{"an unpriced tier", tier{}, selC, ms, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if gain, sure := tc.tier.gain(tc.ia, tc.direct); gain != tc.gain || sure != tc.sure {
				t.Errorf("gain = %v, %v, want %v, %v", gain, sure, tc.gain, tc.sure)
			}
		})
	}
}

// TestJudgeOutside checks the useless test of a link the clustering does
// not allow: decided once a survivor answered, whatever the prices; useful
// while the exclusion would drop the route count or cut a member off, or no
// chosen pair links the units; useless otherwise.
func TestJudgeOutside(t *testing.T) {
	ms := time.Millisecond
	tierWith := func(ex excludedSample) *tier {
		return &tier{
			members:  []member{{ia: selA, direct: 10 * ms}, {ia: selB, direct: 12 * ms}},
			price:    20 * ms,
			prices:   map[addr.IA]time.Duration{selA: 16 * ms, selB: 20 * ms},
			routes:   2,
			excluded: map[addr.IA]excludedSample{selA: ex},
		}
	}
	// held keeps the routes and cuts nobody off, at prices far above the
	// link's: a priced test would keep the link.
	held := excludedSample{answered: true, price: 90 * ms, routes: 2, cutOff: map[addr.IA]bool{}}
	unanswered := held
	unanswered.answered = false
	fewer := held
	fewer.routes = 1
	cut := held
	cut.cutOff = map[addr.IA]bool{selB: true}
	for _, tc := range []struct {
		name             string
		ex               excludedSample
		joined           bool
		decided, useless bool
	}{
		{"covered", held, true, true, true},
		{"no survivor answered", unanswered, true, false, false},
		{"a route lost", fewer, true, true, false},
		{"a member cut off", cut, true, true, false},
		{"no chosen pair linked", held, false, true, false},
	} {
		decided, useless := judgeOutside(tierWith(tc.ex), selA, tc.joined)
		if decided != tc.decided || useless != tc.useless {
			t.Errorf("%s: judgeOutside = %v, %v, want %v, %v", tc.name, decided, useless, tc.decided, tc.useless)
		}
	}
	if decided, _ := judgeOutside(nil, selA, true); decided {
		t.Error("an unclassed link decided")
	}
}

// TestJudge checks the useless test and the eviction's. With the tier's
// route count held, the useless test finds a link useless only while its
// exclusion raises no price — the tier's, each priced member's, the link's
// own neighbor's against its direct round trip — and the bounds confirm it:
// for the tier and for each member a route over the link reaches, the
// survivors' upper bound no higher than the link's lower bound, the
// neighbor's by its direct side's. The eviction's finds a link weak while
// its exclusion raises no price by promotion's fifth and its floor, and the
// bounds confirm it gains no one the band. A member the survivors reach but
// no read survivor prices, or one whose routes none read, leaves the window
// undecided, unless another member decides the link useful; a survivor of a
// member no route prices counts for nothing, and a member cut off, priced or
// not, decides the link useful, as does a bound missing. A tier no read
// route prices, or a survivor that did not answer, decides nothing.
func TestJudge(t *testing.T) {
	ms := time.Millisecond
	type prices = map[addr.IA]time.Duration
	// The link is A's, its round trip 10ms and its own price 16ms. B prices
	// at 20ms over a route crossing the link, and no route reaches C.
	tierWith := func(ex excludedSample) *tier {
		return &tier{
			members: []member{
				{ia: selA, direct: 10 * ms, low: 10 * ms},
				{ia: selB, direct: 12 * ms},
				{ia: selC, direct: 14 * ms},
			},
			price:    20 * ms,
			prices:   prices{selA: 16 * ms, selB: 20 * ms},
			cheapest: make(map[addr.IA]*scion.Candidate),
			routes:   2,
			excluded: map[addr.IA]excludedSample{selA: ex},
		}
	}
	// held is an excluded measurement of the tier's route count, priced as
	// given, the members given cut off, its bounds those of steady routes:
	// the tier's and B's routes over the link at 20ms, the survivors at
	// their prices.
	held := func(price time.Duration, p prices, cutOff ...addr.IA) excludedSample {
		ex := excludedSample{
			answered: true,
			price:    price,
			routes:   2,
			prices:   p,
			cutOff:   make(map[addr.IA]bool),
			crossed:  true,
			low:      20 * ms,
			high:     price,
			lows:     prices{selB: 20 * ms},
			highs:    maps.Clone(p),
		}
		for _, ia := range cutOff {
			ex.cutOff[ia] = true
		}
		return ex
	}
	// bounded returns the measurement with its bounds changed.
	bounded := func(ex excludedSample, change func(ex *excludedSample)) excludedSample {
		ex.lows, ex.highs = maps.Clone(ex.lows), maps.Clone(ex.highs)
		change(&ex)
		return ex
	}
	none := prices{selA: 10 * ms, selB: 20 * ms}
	band := prices{selA: 11900 * time.Microsecond, selB: 23900 * time.Microsecond}
	fifth := prices{selA: 12 * ms, selB: 25 * ms}

	for _, tc := range []struct {
		name          string
		ex            excludedSample
		decided, idle bool
		yields        bool
	}{
		{"no price rises", held(20*ms, none), true, true, true},
		{"the neighbor's survivors slower than its round trip",
			held(20*ms, prices{selA: 11 * ms, selB: 20 * ms}), true, false, true},
		{"another member's price rises", held(20*ms, prices{selA: 10 * ms, selB: 21 * ms}), true, false, true},
		{"the tier's price rises", held(21*ms, none), true, false, true},
		{"every price within the band", held(23900*time.Microsecond, band), true, false, true},
		{"every price within the fifth, past the band", held(25*ms, fifth), true, false, false},
		{"the neighbor's past the fifth", held(25*ms, prices{selA: 13 * ms, selB: 25 * ms}), true, false, false},
		{"another member's past the fifth", held(25*ms, prices{selA: 12 * ms, selB: 26 * ms}), true, false, false},
		{"the tier's past the fifth", held(26*ms, fifth), true, false, false},
		{"a member no survivor prices", held(20*ms, prices{selA: 10 * ms}), false, false, false},
		{"the neighbor no survivor prices", held(20*ms, prices{selB: 20 * ms}), false, false, false},
		{"a member no survivor prices, another past the fifth",
			held(20*ms, prices{selA: 13 * ms}), true, false, false},
		{"a member cut off", held(20*ms, none, selB), true, false, false},
		{"a member no route reaches, cut off", held(20*ms, none, selC), true, false, false},
		{"a survivor of a member no route reaches",
			held(20*ms, prices{selA: 10 * ms, selB: 20 * ms, selC: 100 * ms}), true, true, true},
		{"a route lost", excludedSample{answered: true, price: 20 * ms, routes: 1, prices: none}, true, false, false},
		{"the survivor unanswered", excludedSample{price: 20 * ms, routes: 2, prices: none}, false, false, false},
		{"a member's survivors bounded above the link's routes",
			bounded(held(20*ms, none), func(ex *excludedSample) { ex.highs[selB] = 22 * ms }), true, false, true},
		{"a member's survivors bounded past the band",
			bounded(held(20*ms, none), func(ex *excludedSample) { ex.highs[selB] = 25 * ms }), true, false, false},
		{"the tier's survivors bounded above its routes",
			bounded(held(20*ms, none), func(ex *excludedSample) { ex.high = 22 * ms }), true, false, true},
		{"the neighbor's survivors bounded above its round trip",
			bounded(held(20*ms, none), func(ex *excludedSample) { ex.highs[selA] = 11 * ms }), true, false, true},
		{"a member's survivors unbounded",
			bounded(held(20*ms, none), func(ex *excludedSample) { delete(ex.highs, selB) }), true, false, false},
		{"the tier's survivors unbounded",
			bounded(held(20*ms, none), func(ex *excludedSample) { ex.high = 0 }), true, false, false},
		{"the readings showing a rise the history does not",
			bounded(held(20*ms, prices{selA: 11 * ms, selB: 20 * ms}), func(ex *excludedSample) { ex.highs[selA] = 10 * ms }),
			true, false, true},
		{"the tier's price rising on the readings alone",
			bounded(held(21*ms, none), func(ex *excludedSample) { ex.high = 20 * ms }), true, false, true},
		{"no route crossing the link but the neighbor's",
			bounded(held(20*ms, none), func(ex *excludedSample) {
				ex.crossed, ex.low, ex.high = false, 0, 0
				delete(ex.lows, selB)
				delete(ex.highs, selB)
			}), true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			decided, useless := judge(tierWith(tc.ex), selA)
			if decided != tc.decided || useless != tc.idle {
				t.Errorf("judge = (%v, %v), want (%v, %v)", decided, useless, tc.decided, tc.idle)
			}
			decided, weak := yields(tierWith(tc.ex), selA)
			if want := tc.decided || tc.yields; decided != want || weak != tc.yields {
				t.Errorf("yields = (%v, %v), want (%v, %v)", decided, weak, want, tc.yields)
			}
		})
	}

	// A fast neighbor's survivor past the fifth of its 4ms round trip by less
	// than the margin floor: its link would not earn its place.
	fast := tierWith(held(20*ms, prices{selA: 5200 * time.Microsecond, selB: 20 * ms}))
	fast.members[0].direct, fast.members[0].low = 4*ms, 4*ms
	if decided, weak := yields(fast, selA); !decided || !weak {
		t.Errorf("yields within the margin floor = (%v, %v), want (true, true)", decided, weak)
	}
	unbounded := tierWith(held(20*ms, none))
	unbounded.members[0].low = 0
	if decided, useless := judge(unbounded, selA); !decided || useless {
		t.Errorf("judge without the neighbor's bound = (%v, %v), want (true, false)", decided, useless)
	}

	unread := route(-time.Hour, 10*ms, link(selX), link(selC))
	readless := tierWith(held(20*ms, none))
	readless.cheapest[selC] = &unread
	if decided, _ := judge(readless, selA); decided {
		t.Error("the useless test decided while C's routes none read")
	}
	if decided, _ := yields(readless, selA); decided {
		t.Error("the eviction's test decided while C's routes none read")
	}
	unpriced := tierWith(held(20*ms, none))
	unpriced.price = 0
	if decided, _ := judge(unpriced, selA); decided {
		t.Error("a tier no read route prices decided a link")
	}
}

// TestOutgained checks the eviction's test against a candidate's gain: a
// link yields its slot while every price it holds down — the tier's, each
// priced member's, its own neighbor's against its direct round trip — saves
// less than the gain by the promotion ratio and the margin floor, and the
// bounds confirm it: the survivors' upper bound less the link's lower bound
// beaten by the sure gain as well. A member cut off, a route lost, a bound
// missing, or a gain the history does not confirm keeps the link its slot;
// a member no survivor prices, or a survivor that did not answer, decides
// nothing.
func TestOutgained(t *testing.T) {
	ms := time.Millisecond
	type prices = map[addr.IA]time.Duration
	// The link is A's, its round trip 10ms. B prices at 20ms over a route
	// crossing the link, and so does the tier.
	tierWith := func(ex excludedSample) *tier {
		return &tier{
			members:  []member{{ia: selA, direct: 10 * ms, low: 10 * ms}, {ia: selB, direct: 12 * ms}},
			price:    20 * ms,
			prices:   prices{selA: 16 * ms, selB: 20 * ms},
			cheapest: make(map[addr.IA]*scion.Candidate),
			routes:   2,
			excluded: map[addr.IA]excludedSample{selA: ex},
		}
	}
	// held is an excluded measurement saving the tier 5ms, A 8ms on its
	// round trip, and B 6ms, its bounds those of steady routes; changed
	// returns it changed.
	held := func() excludedSample {
		return excludedSample{
			answered: true,
			price:    25 * ms,
			routes:   2,
			prices:   prices{selA: 18 * ms, selB: 26 * ms},
			cutOff:   make(map[addr.IA]bool),
			crossed:  true,
			low:      20 * ms,
			high:     25 * ms,
			lows:     prices{selB: 20 * ms},
			highs:    prices{selA: 18 * ms, selB: 26 * ms},
		}
	}
	changed := func(change func(ex *excludedSample)) excludedSample {
		ex := held()
		change(&ex)
		return ex
	}
	// small saves A 2.5ms and nothing else.
	small := changed(func(ex *excludedSample) {
		ex.price, ex.high = 20*ms, 20*ms
		ex.prices = prices{selA: 12500 * time.Microsecond, selB: 20 * ms}
		ex.highs = maps.Clone(ex.prices)
	})

	for _, tc := range []struct {
		name          string
		ex            excludedSample
		gain, sure    time.Duration
		decided, weak bool
	}{
		{"every saving beaten", held(), 15 * ms, 15 * ms, true, true},
		{"a gain the history does not confirm", held(), 15 * ms, 9 * ms, true, false},
		{"a gain no bound confirms", held(), 15 * ms, 0, true, false},
		{"the neighbor's saving within the ratio", held(), 9 * ms, 9 * ms, true, false},
		{"the tier's saving within the ratio",
			changed(func(ex *excludedSample) { ex.price, ex.high = 33*ms, 33*ms }), 15 * ms, 15 * ms, true, false},
		{"another member's saving within the ratio",
			changed(func(ex *excludedSample) { ex.prices[selB], ex.highs[selB] = 33*ms, 33*ms }), 15 * ms, 15 * ms, true, false},
		{"past the margin floor", small, 5 * ms, 5 * ms, true, true},
		{"within the margin floor", small, 4 * ms, 4 * ms, true, false},
		{"no gain", held(), 0, 0, true, false},
		{"the tier's saving bounded near the gain",
			changed(func(ex *excludedSample) { ex.high = 33 * ms }), 15 * ms, 15 * ms, true, false},
		{"a member's saving bounded near the gain",
			changed(func(ex *excludedSample) { ex.highs[selB] = 33 * ms }), 15 * ms, 15 * ms, true, false},
		{"the neighbor's saving bounded near the gain",
			changed(func(ex *excludedSample) { ex.highs[selA] = 23 * ms }), 15 * ms, 15 * ms, true, false},
		{"a saving the readings show and the history does not",
			changed(func(ex *excludedSample) { ex.prices[selB] = 33 * ms }), 15 * ms, 15 * ms, true, false},
		{"a bound missing", changed(func(ex *excludedSample) { delete(ex.highs, selB) }), 15 * ms, 15 * ms, true, false},
		{"a member cut off", changed(func(ex *excludedSample) { ex.cutOff[selB] = true }), 15 * ms, 15 * ms, true, false},
		{"a route lost", changed(func(ex *excludedSample) { ex.routes = 1 }), 15 * ms, 15 * ms, true, false},
		{"a member no survivor prices",
			changed(func(ex *excludedSample) { delete(ex.prices, selB) }), 15 * ms, 15 * ms, false, false},
		{"the survivor unanswered", changed(func(ex *excludedSample) { ex.answered = false }), 15 * ms, 15 * ms, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			decided, weak := outgained(tierWith(tc.ex), selA, tc.gain, tc.sure)
			if decided != tc.decided || weak != tc.weak {
				t.Errorf("outgained = (%v, %v), want (%v, %v)", decided, weak, tc.decided, tc.weak)
			}
		})
	}
}
