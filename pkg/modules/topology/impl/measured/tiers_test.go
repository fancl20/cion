package measured

import (
	"maps"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/libs/bus"
	"github.com/fancl20/cion/pkg/libs/evidence"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/modules/links"
)

// sm builds a window sample of the given direct round trip and enumerated
// routes.
func sm(direct time.Duration, candidates ...scion.Candidate) sample {
	return sample{direct: direct, candidates: candidates}
}

// boundedSm builds a window sample of the given direct round trip whose
// bounds estimate reads it between lo and hi.
func boundedSm(direct, lo, hi time.Duration) sample {
	return sample{direct: direct, bounds: scion.PublishedEstimate(direct, lo, hi)}
}

// lastTiers builds the last window's tiers of the peers given, a tier per
// group, in order.
func lastTiers(groups ...[]addr.IA) []tier {
	ts := make([]tier, len(groups))
	for i, g := range groups {
		for _, ia := range g {
			ts[i].members = append(ts[i].members, member{ia: ia})
		}
	}
	return ts
}

// classes returns each tier's members, in the walk's order.
func classes(ts []tier) [][]addr.IA {
	var out [][]addr.IA
	for _, t := range ts {
		var ias []addr.IA
		for _, m := range t.members {
			ias = append(ias, m.ia)
		}
		out = append(out, ias)
	}
	return out
}

// TestDeriveTiers checks the sorted walk of a first window, which places
// every peer by its value: a peer within the gap joins, one past twice the
// median opens a new tier, the median recomputes as a tier grows, an
// unmeasured peer classes into none, and equal samples are stable across
// recomputation.
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
	ts := deriveTiers(samples, nil)
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
	ts = deriveTiers(samples, nil)
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
		ts = deriveTiers(equal, nil)
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

// TestDeriveTiersKeepsSides checks the walk against the last window's
// tiers: a peer crosses the line only once its bounds and the median's lie
// apart by it, an undecided one keeping the side the last window held it
// on, and a peer the last window did not class is placed by its value.
func TestDeriveTiersKeepsSides(t *testing.T) {
	ms := time.Millisecond
	// A and B sit steady at 8ms and 10ms: a third peer weighs against B,
	// the median as walked, whose line lies at 20ms.
	a, b := boundedSm(8*ms, 8*ms, 8*ms), boundedSm(10*ms, 10*ms, 10*ms)
	straddling, past := boundedSm(25*ms, 15*ms, 30*ms), boundedSm(25*ms, 20*ms, 30*ms)
	for _, tc := range []struct {
		name    string
		samples map[addr.IA]sample
		last    [][]addr.IA
		want    [][]addr.IA
	}{{
		name:    "a peer past the line by its value but not its bounds keeps its tier",
		samples: map[addr.IA]sample{selA: a, selB: b, selC: straddling},
		last:    [][]addr.IA{{selA, selB, selC}},
		want:    [][]addr.IA{{selA, selB, selC}},
	}, {
		name:    "a peer whose lower bound clears the line opens the next tier",
		samples: map[addr.IA]sample{selA: a, selB: b, selC: past},
		last:    [][]addr.IA{{selA, selB, selC}},
		want:    [][]addr.IA{{selA, selB}, {selC}},
	}, {
		// B's upper bound at 11ms puts twice it at 22ms.
		name:    "the median's bounds count",
		samples: map[addr.IA]sample{selA: a, selB: boundedSm(10*ms, 9*ms, 11*ms), selC: past},
		last:    [][]addr.IA{{selA, selB, selC}},
		want:    [][]addr.IA{{selA, selB, selC}},
	}, {
		// Twice B's bounds run from 18ms to 22ms.
		name: "a peer within twice the median's bounds keeps its tier",
		samples: map[addr.IA]sample{selA: a, selB: boundedSm(10*ms, 9*ms, 11*ms),
			selC: boundedSm(25*ms, 21500*time.Microsecond, 30*ms)},
		last: [][]addr.IA{{selA, selB, selC}},
		want: [][]addr.IA{{selA, selB, selC}},
	}, {
		name: "a peer past twice the median's upper bound opens the next tier",
		samples: map[addr.IA]sample{selA: a, selB: boundedSm(10*ms, 9*ms, 11*ms),
			selC: boundedSm(25*ms, 22*ms, 30*ms)},
		last: [][]addr.IA{{selA, selB, selC}},
		want: [][]addr.IA{{selA, selB}, {selC}},
	}, {
		name:    "a peer from above keeps out while its bounds straddle the line",
		samples: map[addr.IA]sample{selA: a, selB: b, selC: boundedSm(15*ms, 12*ms, 25*ms)},
		last:    [][]addr.IA{{selA, selB}, {selC}},
		want:    [][]addr.IA{{selA, selB}, {selC}},
	}, {
		name:    "a peer from above joins once its upper bound lies within the line",
		samples: map[addr.IA]sample{selA: a, selB: b, selC: boundedSm(15*ms, 12*ms, 19*ms)},
		last:    [][]addr.IA{{selA, selB}, {selC}},
		want:    [][]addr.IA{{selA, selB, selC}},
	}, {
		name:    "a peer the last window did not class opens by its value",
		samples: map[addr.IA]sample{selA: a, selB: b, selC: straddling},
		last:    [][]addr.IA{{selA, selB}},
		want:    [][]addr.IA{{selA, selB}, {selC}},
	}, {
		name:    "a peer the last window did not class joins by its value",
		samples: map[addr.IA]sample{selA: a, selB: b, selC: boundedSm(15*ms, 12*ms, 25*ms)},
		last:    [][]addr.IA{{selA, selB}},
		want:    [][]addr.IA{{selA, selB, selC}},
	}, {
		// A and C shared the last window's second tier — E, gone, held its
		// first — and the first tier continues A's: C, straddling A's line
		// at 16ms, joins it.
		name:    "the first tier continues its first peer's tier",
		samples: map[addr.IA]sample{selA: a, selC: straddling},
		last:    [][]addr.IA{{selE}, {selA, selC}},
		want:    [][]addr.IA{{selA, selC}},
	}, {
		// C, from the tier above A's, fell to 9ms, its bounds straddling A's
		// line at 16ms; B and D, which the tier held, lie within it.
		name: "a peer whose round trip fell into the tier below joins it whole",
		samples: map[addr.IA]sample{selA: a, selB: b, selC: boundedSm(9*ms, 5*ms, 25*ms),
			selD: boundedSm(11*ms, 10*ms, 12*ms)},
		last: [][]addr.IA{{selA, selB, selD}, {selC}},
		want: [][]addr.IA{{selA, selC, selB, selD}},
	}, {
		// C's lower bound clears B's line, and the tier it opens continues
		// the one after the first: D, from that tier and undecided against
		// C, whose bounds run from 20ms to 30ms, joins it.
		name: "a tier a peer of the tier opens continues the one after",
		samples: map[addr.IA]sample{selA: a, selB: b, selC: past,
			selD: boundedSm(40*ms, 30*ms, 60*ms)},
		last: [][]addr.IA{{selA, selB, selC}, {selD}},
		want: [][]addr.IA{{selA, selB}, {selC, selD}},
	}, {
		// C, from two tiers above A's — E, gone, held the one between —
		// straddles A's line, and D lies past it: C opens the tier, which
		// continues C's, so D, from that tier and undecided against C, whose
		// bounds run from 12ms to 30ms, joins it.
		name: "a tier a peer from above opens continues that peer's tier",
		samples: map[addr.IA]sample{selA: a, selC: boundedSm(20*ms, 12*ms, 30*ms),
			selD: boundedSm(50*ms, 45*ms, 55*ms)},
		last: [][]addr.IA{{selA}, {selE}, {selC, selD}},
		want: [][]addr.IA{{selA}, {selC, selD}},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			if diff := cmp.Diff(tc.want, classes(deriveTiers(tc.samples, lastTiers(tc.last...)))); diff != "" {
				t.Errorf("tiers (-want +got):\n%s", diff)
			}
		})
	}
}

// TestWindowTiersCarryTheSides checks that the selection carries each
// peer's tier from window to window: a peer keeps its tier while its bounds
// straddle the line, whichever side its value lies on, and two peers
// trading places at the line settle in one window and stay.
func TestWindowTiersCarryTheSides(t *testing.T) {
	ms := time.Millisecond
	a, b := boundedSm(8*ms, 8*ms, 8*ms), boundedSm(10*ms, 10*ms, 10*ms)
	t.Run("one peer", func(t *testing.T) {
		s := &selection{cfg: SelectionConfig{IA: selIA}}
		// C joins by its value in the first window, keeps its tier past the
		// line, leaves once its lower bound clears it, and keeps out once
		// back within it by its value.
		for i, w := range []struct {
			c    sample
			want [][]addr.IA
		}{
			{boundedSm(15*ms, 12*ms, 25*ms), [][]addr.IA{{selA, selB, selC}}},
			{boundedSm(25*ms, 15*ms, 30*ms), [][]addr.IA{{selA, selB, selC}}},
			{boundedSm(25*ms, 20*ms, 30*ms), [][]addr.IA{{selA, selB}, {selC}}},
			{boundedSm(15*ms, 12*ms, 25*ms), [][]addr.IA{{selA, selB}, {selC}}},
		} {
			ts := s.windowTiers(nil, map[addr.IA]sample{selA: a, selB: b, selC: w.c})
			if diff := cmp.Diff(w.want, classes(ts)); diff != "" {
				t.Errorf("window %d tiers (-want +got):\n%s", i+1, diff)
			}
		}
	})
	t.Run("two peers trading places", func(t *testing.T) {
		// C, from the tier above, walks below D, which the tier held, both
		// straddling the line: C joins with D. Traded back, both stay.
		s := &selection{cfg: SelectionConfig{IA: selIA},
			tiers: lastTiers([]addr.IA{selA, selB, selD}, []addr.IA{selC})}
		low, high := boundedSm(19*ms, 15*ms, 25*ms), boundedSm(21*ms, 15*ms, 25*ms)
		ts := s.windowTiers(nil, map[addr.IA]sample{selA: a, selB: b, selC: low, selD: high})
		if diff := cmp.Diff([][]addr.IA{{selA, selB, selC, selD}}, classes(ts)); diff != "" {
			t.Errorf("tiers (-want +got):\n%s", diff)
		}
		ts = s.windowTiers(nil, map[addr.IA]sample{selA: a, selB: b, selC: high, selD: low})
		if diff := cmp.Diff([][]addr.IA{{selA, selB, selD, selC}}, classes(ts)); diff != "" {
			t.Errorf("tiers traded back (-want +got):\n%s", diff)
		}
	})
}

// TestWindowTierFacts checks what one helper turns a tier into: up links
// from the verdicts alone; the price of the cheapest clean read route at
// its price — a declared route under a measured one prices nothing, nor do
// an ejected route and one over a local down interface — and the least of
// the read routes' price estimates, the tier's and each member's over its
// own, beside each member's cheapest route, read or not, which the window
// requests; the route count reading the clean candidates alone; and
// strandedness, once no up link reaches a tier and the measurements doubt
// every route into it.
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
	// route through D at 17ms, bounded below at 14ms — 21ms and 18ms with
	// its transit; B verdict-down, its route over the down link; C a
	// candidate whose route over the node's own dead interface declares 1ms,
	// beside one clean undeclared route.
	// And a slow tier of two: D, whose one route declares 2ms but was
	// ejected, and E, whose one route is suspect.
	bounded := func(c scion.Candidate, low time.Duration) scion.Candidate {
		c.Low = &low
		c.BoundsEvidence.Lo, c.BoundsEvidence.HasLo = low, c.BoundsEvidence.Answered > 0
		return c
	}
	a := sm(5,
		bounded(measured(route(0, 0, local(3), link(selA)), 20*time.Millisecond), 18*time.Millisecond),
		bounded(route(-time.Minute, 8*time.Millisecond, link(selX), link(selA)), 5*time.Millisecond),
		bounded(measured(route(0, 0, local(3), link(selD), link(selA)), 17*time.Millisecond), 14*time.Millisecond),
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
	// The route through D, cheaper at its cost, is dearer at its price.
	if fast.price != 20*time.Millisecond {
		t.Errorf("price = %v, want A's own route's 20ms", fast.price)
	}
	// The tier's price as the comparisons weigh it, and A's, is the least
	// of A's two read routes' estimates at their prices: A's own 20ms, its
	// lower bound 18ms, as low as the route through D's at its price. A's
	// declared route undercuts its measured 20ms route but is read by
	// nothing; B's and C's routes are dirty or undeclared.
	price := evidence.Min(priceBounds(&a.candidates[0]), priceBounds(&a.candidates[2]))
	if price.Value != 20*time.Millisecond || price.Lo != 18*time.Millisecond {
		t.Errorf("the least of A's routes = %+v, want 20ms bounded below at 18ms", price)
	}
	if diff := cmp.Diff(price, fast.estimate); diff != "" {
		t.Errorf("the tier's price (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(map[addr.IA]evidence.Estimate{selA: price}, fast.prices); diff != "" {
		t.Errorf("member prices (-want +got):\n%s", diff)
	}
	if len(fast.cheapest) != 1 || fast.cheapest[selA].ID != a.candidates[1].ID {
		t.Errorf("the members' cheapest routes = %v, want A's declared route", fast.cheapest)
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
	if got := judge(&ts[0], selA, steadyAt(10*ms)); got != evidence.NotBetter {
		t.Errorf("judge = %v, want not better: the link is A's only route", got)
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
		if got := judge(fast, ia, steadyAt(10*ms)); got != evidence.Undecided {
			t.Errorf("a window nothing measured decided %s's link: %v", ia, got)
		}
	}
}

// TestCheapest checks the route a set of routes is priced by: each route at
// its cost, the measured round trip or else the declared sum doubled, an
// undeclared and unmeasured one, or one measured at zero, pricing nothing;
// each route charged the transit penalty for every AS it crosses between its
// ends, each way; the cheapest winning.
func TestCheapest(t *testing.T) {
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
		{"a measured route's transit charged", ptrs(measured(oneTransit, 20*ms)), 20*ms + transitCost, oneTransit.ID},
		{"a declared route, its transit charged", ptrs(oneTransit), 18*ms + transitCost, oneTransit.ID},
		{"two transits charged", ptrs(twoTransits), 6*ms + 2*transitCost, twoTransits.ID},
		{"an undeclared route", ptrs(undeclared), 0, ""},
		{"a zero cost, its transit uncharged", ptrs(measured(oneTransit, 0)), 0, ""},
		{"the cheapest", ptrs(measured(direct, 30*ms), oneTransit, twoTransits, undeclared),
			6*ms + 2*transitCost, twoTransits.ID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, price := cheapest(tc.routes)
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

// boundsKind is the kind of the estimates the comparisons weigh.
var boundsKind = scion.BoundsEstimate(nil, time.Time{}).Kind

// estimateOf returns an estimate of the bounds' kind at the value, bounded at
// lo and hi, resting on a route's steady probes; a zero bound is none.
func estimateOf(value, lo, hi time.Duration) evidence.Estimate {
	return evidence.Estimate{Kind: boundsKind, Value: value, Lo: lo, Hi: hi, HasLo: lo > 0, HasHi: hi > 0,
		Answered: steadyBounds, Sent: steadyBounds, Newest: time.Now()}
}

// steadyAt returns the estimate of a round trip that holds steady: bounded
// at its value.
func steadyAt(rtt time.Duration) evidence.Estimate {
	return estimateOf(rtt, rtt, rtt)
}

// TestTierBeats checks the priced cases' comparisons. A member's direct side
// beats its own price by the band: better once its upper bound and the band
// lie at or below the price's lower bound, not better once its lower bound
// and the band pass the price's upper bound, undecided between and without
// a bound it needs — at most one transit's charge on a long path. A member
// no route prices weighs the tier's price, one whose routes none read
// weighs nothing, and an unpriced tier weighs nothing. A tier of one route
// takes a second under its ceiling, its price scaled by SecondRouteRatio,
// undecided within the ceiling's bounds.
func TestTierBeats(t *testing.T) {
	ms := time.Millisecond
	unread := route(0, 30*ms, link(selX), link(selD))
	priced := tier{
		estimate: steadyAt(10 * ms),
		prices: map[addr.IA]evidence.Estimate{
			selA: steadyAt(30 * ms), selB: steadyAt(9 * ms), selE: steadyAt(200 * ms)},
		cheapest: map[addr.IA]*scion.Candidate{selD: &unread},
		routes:   2,
	}
	single := tier{estimate: steadyAt(20 * ms), routes: 1}
	spread := tier{estimate: estimateOf(20*ms, 18*ms, 22*ms), routes: 1}
	for _, tc := range []struct {
		name          string
		tier          tier
		ia            addr.IA
		direct        evidence.Estimate
		beats, second evidence.Verdict
		price         evidence.Estimate
	}{
		{"beating its own price", priced, selA, steadyAt(20 * ms), evidence.Better, evidence.Undecided,
			priced.prices[selA]},
		{"at the band", priced, selA, steadyAt(26 * ms), evidence.Better, evidence.Undecided, priced.prices[selA]},
		{"within the band", priced, selA, steadyAt(27 * ms), evidence.NotBetter, evidence.Undecided,
			priced.prices[selA]},
		{"bounds straddling the band", priced, selA, estimateOf(20*ms, 18*ms, 28*ms), evidence.Undecided,
			evidence.Undecided, priced.prices[selA]},
		{"no upper bound", priced, selA, estimateOf(20*ms, 18*ms, 0), evidence.Undecided, evidence.Undecided,
			priced.prices[selA]},
		{"a fast price within the floor", priced, selB, steadyAt(7100 * time.Microsecond), evidence.NotBetter,
			evidence.Undecided, priced.prices[selB]},
		{"a fast price past the floor", priced, selB, steadyAt(6900 * time.Microsecond), evidence.Better,
			evidence.Undecided, priced.prices[selB]},
		{"the tier's price", priced, selC, steadyAt(7 * ms), evidence.Better, evidence.Undecided, priced.estimate},
		{"its routes none read", priced, selD, steadyAt(ms), evidence.Undecided, evidence.Undecided,
			evidence.Estimate{}},
		{"a long path past the cap", priced, selE, steadyAt(195 * ms), evidence.Better, evidence.Undecided,
			priced.prices[selE]},
		{"a long path within the cap", priced, selE, steadyAt(197 * ms), evidence.NotBetter, evidence.Undecided,
			priced.prices[selE]},
		{"an unpriced tier", tier{routes: 1}, selC, steadyAt(ms), evidence.Undecided, evidence.Undecided,
			evidence.Estimate{}},
		{"a second route within the room", single, selC, steadyAt(25 * ms), evidence.NotBetter, evidence.Better,
			single.estimate},
		{"a second route past it", single, selC, steadyAt(26 * ms), evidence.NotBetter, evidence.NotBetter,
			single.estimate},
		{"a second route under the ceiling's lower bound", spread, selC, steadyAt(22500 * time.Microsecond),
			evidence.NotBetter, evidence.Better, spread.estimate},
		{"a second route within the ceiling's bounds", spread, selC, steadyAt(23 * ms), evidence.NotBetter,
			evidence.Undecided, spread.estimate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			beats, price := tc.tier.beats(tc.ia, tc.direct)
			if beats != tc.beats || tc.tier.secondRoute(tc.direct) != tc.second {
				t.Errorf("beats = %v, second route = %v, want %v and %v", beats,
					tc.tier.secondRoute(tc.direct), tc.beats, tc.second)
			}
			if diff := cmp.Diff(tc.price, price); diff != "" {
				t.Errorf("the price weighed (-want +got):\n%s", diff)
			}
		})
	}
}

// TestTierGain checks what a candidate's direct side gains: the price beats
// weighs less the direct side, each bound against the other side's opposite
// bound; nothing for a member whose routes none read and for an unpriced
// tier.
func TestTierGain(t *testing.T) {
	ms := time.Millisecond
	unread := route(0, 30*ms, link(selX), link(selD))
	priced := tier{
		estimate: estimateOf(10*ms, 9*ms, 11*ms),
		prices:   map[addr.IA]evidence.Estimate{selA: estimateOf(30*ms, 28*ms, 31*ms)},
		cheapest: map[addr.IA]*scion.Candidate{selD: &unread},
	}
	for _, tc := range []struct {
		name               string
		tier               tier
		ia                 addr.IA
		direct             evidence.Estimate
		value, lo, hi      time.Duration
		answered, unpriced bool
	}{
		{"its own price", priced, selA, estimateOf(20*ms, 19*ms, 22*ms), 10 * ms, 6 * ms, 12 * ms, true, false},
		{"the tier's price", priced, selC, estimateOf(7*ms, 6*ms, 8*ms), 3 * ms, ms, 5 * ms, true, false},
		{"its routes none read", priced, selD, steadyAt(ms), 0, 0, 0, false, true},
		{"an unpriced tier", tier{}, selC, steadyAt(ms), 0, 0, 0, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.tier.gain(tc.ia, tc.direct)
			if tc.unpriced {
				if got.Answered != 0 {
					t.Errorf("gain = %+v, want none", got)
				}
				return
			}
			if got.Value != tc.value || got.Lo != tc.lo || got.Hi != tc.hi || !got.HasLo || !got.HasHi {
				t.Errorf("gain = %+v, want %v within %v..%v", got, tc.value, tc.lo, tc.hi)
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
			estimate: steadyAt(20 * ms),
			routes:   2,
			excluded: map[addr.IA]excludedSample{selA: ex},
		}
	}
	// held keeps the routes and cuts nobody off, at prices far above the
	// link's: a priced test would keep the link.
	held := excludedSample{answered: true, price: 90 * ms, survivors: steadyAt(90 * ms), routes: 2,
		cutOff: map[addr.IA]bool{}}
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

// TestJudge checks the useless test and whether a link would not earn its
// place. With the tier's route count held and no member cut off, the useless
// test finds a link useless once the survivors beat the routes crossing it
// by no line — for the tier, for each member those routes reach, and for
// the link's own neighbor against its direct side — useful once one of them
// does not, and undecided while one lacks its evidence. A link would not
// earn its place once the routes crossing it, and the neighbor's direct
// side, beat the survivors by the band for none of them. A member the
// survivors reach but no read survivor prices, or one whose routes none
// read, leaves the window undecided; a survivor of a member no route over
// the link reaches counts for nothing, and a member cut off, priced or not,
// decides the link useful. A tier no read route prices, or a survivor that
// did not answer, decides nothing.
func TestJudge(t *testing.T) {
	ms := time.Millisecond
	type prices = map[addr.IA]evidence.Estimate
	direct := steadyAt(10 * ms)
	// The link is A's, its direct side 10ms. B prices at 20ms over a route
	// crossing the link, as the tier does, and no route reaches C.
	tierWith := func(ex excludedSample) *tier {
		return &tier{
			members: []member{
				{ia: selA, direct: 10 * ms},
				{ia: selB, direct: 12 * ms},
				{ia: selC, direct: 14 * ms},
			},
			price:    20 * ms,
			estimate: steadyAt(20 * ms),
			prices:   prices{selA: steadyAt(16 * ms), selB: steadyAt(20 * ms)},
			cheapest: make(map[addr.IA]*scion.Candidate),
			routes:   2,
			excluded: map[addr.IA]excludedSample{selA: ex},
		}
	}
	// held is an excluded measurement of the tier's route count, the
	// survivors at the tier's price and each member's given, the members
	// given cut off, and the routes over the link at 20ms.
	held := func(survivors time.Duration, of prices, cutOff ...addr.IA) excludedSample {
		ex := excludedSample{
			answered:    true,
			price:       survivors,
			routes:      2,
			survivors:   steadyAt(survivors),
			crossing:    steadyAt(20 * ms),
			survivorsOf: of,
			crossingOf:  prices{selB: steadyAt(20 * ms)},
			cutOff:      make(map[addr.IA]bool),
		}
		for _, ia := range cutOff {
			ex.cutOff[ia] = true
		}
		return ex
	}
	at := func(a, b time.Duration) prices { return prices{selA: steadyAt(a), selB: steadyAt(b)} }
	// changed returns the measurement held at no rise with a change made.
	changed := func(change func(ex *excludedSample)) excludedSample {
		ex := held(20*ms, at(10*ms, 20*ms))
		ex.survivorsOf = maps.Clone(ex.survivorsOf)
		change(&ex)
		return ex
	}
	us := time.Microsecond
	for _, tc := range []struct {
		name   string
		ex     excludedSample
		judge  evidence.Verdict
		yields bool
	}{
		{"no price rises", held(20*ms, at(10*ms, 20*ms)), evidence.Better, true},
		{"the neighbor's survivors slower than its direct side", held(20*ms, at(11*ms, 20*ms)),
			evidence.NotBetter, true},
		{"another member's price rises", held(20*ms, at(10*ms, 21*ms)), evidence.NotBetter, true},
		{"the tier's price rises", held(21*ms, at(10*ms, 20*ms)), evidence.NotBetter, true},
		{"every price within the band", held(23900*us, at(11900*us, 23900*us)), evidence.NotBetter, true},
		{"the tier's past the band", held(24*ms, at(11900*us, 23900*us)), evidence.NotBetter, false},
		{"the neighbor's past the band", held(23900*us, at(12*ms, 23900*us)), evidence.NotBetter, false},
		{"another member's past the band", held(23900*us, at(11900*us, 24*ms)), evidence.NotBetter, false},
		{"a member no survivor prices", held(20*ms, prices{selA: steadyAt(10 * ms)}), evidence.Undecided, false},
		{"the neighbor no survivor prices", held(20*ms, prices{selB: steadyAt(20 * ms)}), evidence.Undecided, false},
		{"a member no survivor prices, the neighbor's price risen", held(20*ms, prices{selA: steadyAt(13 * ms)}),
			evidence.NotBetter, false},
		{"a member cut off", held(20*ms, at(10*ms, 20*ms), selB), evidence.NotBetter, false},
		{"a member no route reaches, cut off", held(20*ms, at(10*ms, 20*ms), selC), evidence.NotBetter, false},
		{"a survivor of a member no route over the link reaches",
			changed(func(ex *excludedSample) { ex.survivorsOf[selC] = steadyAt(100 * ms) }), evidence.Better, true},
		{"a route lost", changed(func(ex *excludedSample) { ex.routes = 1 }), evidence.NotBetter, false},
		{"the survivor unanswered", changed(func(ex *excludedSample) { ex.answered = false }), evidence.Undecided,
			false},
		{"a member's survivors bounded above the link's routes",
			changed(func(ex *excludedSample) { ex.survivorsOf[selB] = estimateOf(20*ms, 18*ms, 22*ms) }),
			evidence.Undecided, true},
		{"a member's survivors bounded past the band",
			changed(func(ex *excludedSample) { ex.survivorsOf[selB] = estimateOf(20*ms, 18*ms, 25*ms) }),
			evidence.Undecided, false},
		{"the tier's survivors bounded above its routes",
			changed(func(ex *excludedSample) { ex.survivors = estimateOf(20*ms, 18*ms, 22*ms) }),
			evidence.Undecided, true},
		{"the neighbor's survivors bounded above its direct side",
			changed(func(ex *excludedSample) { ex.survivorsOf[selA] = estimateOf(10*ms, 9*ms, 11*ms) }),
			evidence.Undecided, true},
		{"the neighbor's survivors unbounded",
			changed(func(ex *excludedSample) { ex.survivorsOf[selA] = estimateOf(10*ms, 0, 0) }),
			evidence.Undecided, false},
		{"no route crossing the link but the neighbor's",
			changed(func(ex *excludedSample) { ex.crossing, ex.crossingOf = evidence.Estimate{}, nil }),
			evidence.Better, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := judge(tierWith(tc.ex), selA, direct); got != tc.judge {
				t.Errorf("judge = %v, want %v", got, tc.judge)
			}
			if got := yields(tierWith(tc.ex), selA, direct); got != tc.yields {
				t.Errorf("yields = %v, want %v", got, tc.yields)
			}
		})
	}

	unread := route(-time.Hour, 10*ms, link(selX), link(selC))
	readless := tierWith(held(20*ms, at(10*ms, 20*ms)))
	readless.cheapest[selC] = &unread
	if got := judge(readless, selA, direct); got != evidence.Undecided {
		t.Errorf("the useless test decided %v while C's routes none read", got)
	}
	if yields(readless, selA, direct) {
		t.Error("the link yields while C's routes none read")
	}
	unpriced := tierWith(held(20*ms, at(10*ms, 20*ms)))
	unpriced.estimate = evidence.Estimate{}
	if got := judge(unpriced, selA, direct); got != evidence.Undecided {
		t.Errorf("a tier no read route prices decided a link: %v", got)
	}
}

// TestOutgained checks the eviction's test against a candidate's gain: a
// link yields its slot once the gain beats what the link saves every price
// it reaches by the band — the survivors' less the crossing routes', for the
// tier and each member those routes reach, and the neighbor's survivors
// less its direct side — each comparison better. A saving the gain does not
// beat, one undecided, a member cut off, a route lost, a member whose routes
// none read, or a survivor that did not answer keeps the link its slot.
func TestOutgained(t *testing.T) {
	ms := time.Millisecond
	type prices = map[addr.IA]evidence.Estimate
	direct := steadyAt(10 * ms)
	// The link is A's, its direct side 10ms. B prices at 20ms over a route
	// crossing the link, as the tier does.
	tierWith := func(ex excludedSample) *tier {
		return &tier{
			members:  []member{{ia: selA, direct: 10 * ms}, {ia: selB, direct: 12 * ms}},
			price:    20 * ms,
			estimate: steadyAt(20 * ms),
			prices:   prices{selA: steadyAt(16 * ms), selB: steadyAt(20 * ms)},
			cheapest: make(map[addr.IA]*scion.Candidate),
			routes:   2,
			excluded: map[addr.IA]excludedSample{selA: ex},
		}
	}
	// changed returns an excluded measurement saving the tier 5ms, A 8ms on
	// its direct side, and B 6ms, with a change made.
	changed := func(change func(ex *excludedSample)) excludedSample {
		ex := excludedSample{
			answered:    true,
			price:       25 * ms,
			routes:      2,
			survivors:   steadyAt(25 * ms),
			crossing:    steadyAt(20 * ms),
			survivorsOf: prices{selA: steadyAt(18 * ms), selB: steadyAt(26 * ms)},
			crossingOf:  prices{selB: steadyAt(20 * ms)},
			cutOff:      make(map[addr.IA]bool),
		}
		change(&ex)
		return ex
	}
	held := changed(func(*excludedSample) {})
	for _, tc := range []struct {
		name string
		ex   excludedSample
		gain evidence.Estimate
		want bool
	}{
		{"every saving beaten", held, steadyAt(15 * ms), true},
		{"a gain the history does not confirm", held, estimateOf(15*ms, 9*ms, 16*ms), false},
		{"a gain no bound confirms", held, estimateOf(15*ms, 0, 0), false},
		{"the neighbor's saving within the band", held, steadyAt(9 * ms), false},
		{"the tier's saving near the gain",
			changed(func(ex *excludedSample) { ex.survivors = steadyAt(33 * ms) }), steadyAt(15 * ms), false},
		{"another member's saving near the gain",
			changed(func(ex *excludedSample) { ex.survivorsOf[selB] = steadyAt(33 * ms) }), steadyAt(15 * ms), false},
		{"a member's saving bounded near the gain",
			changed(func(ex *excludedSample) { ex.survivorsOf[selB] = estimateOf(26*ms, 24*ms, 34*ms) }),
			steadyAt(15 * ms), false},
		{"no gain", held, evidence.Estimate{}, false},
		{"a member cut off", changed(func(ex *excludedSample) { ex.cutOff[selB] = true }), steadyAt(15 * ms), false},
		{"a route lost", changed(func(ex *excludedSample) { ex.routes = 1 }), steadyAt(15 * ms), false},
		{"a member no survivor prices",
			changed(func(ex *excludedSample) { delete(ex.survivorsOf, selB) }), steadyAt(15 * ms), false},
		{"the survivor unanswered", changed(func(ex *excludedSample) { ex.answered = false }), steadyAt(15 * ms),
			false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := outgained(tierWith(tc.ex), selA, direct, tc.gain); got != tc.want {
				t.Errorf("outgained = %v, want %v", got, tc.want)
			}
		})
	}
	unread := route(-time.Hour, 10*ms, link(selX), link(selC))
	readless := tierWith(held)
	readless.members = append(readless.members, member{ia: selC, direct: 14 * ms})
	readless.cheapest[selC] = &unread
	if outgained(readless, selA, direct, steadyAt(15*ms)) {
		t.Error("the gain outgained the link while C's routes none read")
	}
}
