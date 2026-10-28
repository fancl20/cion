package measured

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/modules/links"
)

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
// from the verdicts alone; the baseline the fastest answered echo takes;
// the price of the cheapest route — a declared route under the echoed
// carrier sets it, while an unanswered carrier, a crossing candidate, and
// one over a local down interface price nothing; each member's own price
// over its own routes, a member no route prices absent; the route count
// reading the clean candidates alone; and strandedness on the echoes,
// however many clean candidates compose into a tier none of whose echoes
// answered.
func TestWindowTierFacts(t *testing.T) {
	verdicts := map[uint16]bool{3: true, 4: false, 7: false} // B's link down, the node's own 7 dead
	up := &links.Link{NeighborIA: selA, IfID: 3, State: links.StateEstablished}
	dead := &links.Link{NeighborIA: selB, IfID: 4, State: links.StateEstablished}
	neighbors := map[addr.IA]*links.Link{selA: up, selB: dead}
	s := &selection{
		cfg: SelectionConfig{
			IA:    selIA,
			Links: verdictTopic(verdicts),
		},
		pathEchoFn: func(addr.IA, *scion.Candidate) time.Duration { return 0 },
	}
	// One fast tier of three measured peers: A up, its echoed carrier at
	// 20ms beside a clean route declaring 8ms one way; B verdict-down, its
	// carrier over the down link; C a candidate whose routes are a crossing
	// one and one over the node's own dead interface, both declaring 1ms,
	// beside one clean undeclared route. And a slow tier of one, D, whose
	// clean carrier declares 2ms but went unanswered.
	a := sm(5, 20*time.Millisecond,
		route(0, 0, local(3), link(selA)),
		route(-time.Minute, 8*time.Millisecond, link(selX), link(selA)),
	)
	a.carrier = &a.candidates[0]
	b := sm(6, 0, route(0, time.Millisecond, local(4), link(selB)))
	b.carrier = &b.candidates[0]
	crossing := route(0, time.Millisecond, link(selC))
	crossing.Crossing = true
	c := sm(7, 0,
		crossing,
		route(0, time.Millisecond, local(7), link(selC)),
		route(0, 0, link(selX), link(selC)),
	)
	d := sm(50, 0, route(0, 2*time.Millisecond, link(selX), link(selD)))
	d.carrier = &d.candidates[0]
	samples := map[addr.IA]sample{selA: a, selB: b, selC: c, selD: d}

	ts := s.windowTiers(t.Context(), neighbors, samples)
	if len(ts) != 2 {
		t.Fatalf("tiers = %d, want the fast one and the slow one", len(ts))
	}
	fast, slow := &ts[0], &ts[1]

	if len(fast.upLinks) != 1 || fast.upLinks[0] != local(3) {
		t.Errorf("up links = %v, want the verdict-up link alone", fast.upLinks)
	}
	if fast.baseline != 20*time.Millisecond {
		t.Errorf("baseline = %v, want the answered echo 20ms", fast.baseline)
	}
	if fast.price != 16*time.Millisecond {
		t.Errorf("price = %v, want the declared route's doubled 16ms", fast.price)
	}
	// A's declared route undercuts its carrier's 20ms echo; B's and C's
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

	// D's tier: a clean route composes into it, but no up link and no
	// answered echo reach it — stranded, and unpriced.
	if slow.routes != 1 || !slow.stranded {
		t.Errorf("the slow tier = %d routes, stranded %v; want 1 and stranded",
			slow.routes, slow.stranded)
	}
	if slow.price != 0 {
		t.Errorf("the stranded tier's price = %v, want nothing pricing it", slow.price)
	}
	if len(slow.prices) != 0 {
		t.Errorf("the stranded tier's member prices = %v, want none", slow.prices)
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
	s := &selection{
		cfg: SelectionConfig{
			IA:    selIA,
			Links: verdictTopic(verdicts),
		},
		pathEchoFn: func(addr.IA, *scion.Candidate) time.Duration { return 20 * ms },
	}
	// A answers its direct echo, and no route composes into it. B's carrier
	// rides B's own link, and a second route reaches B around it.
	b := sm(10*ms, 20*ms,
		route(0, 0, local(5), link(selB)),
		route(0, 12*ms, link(selX), link(selB)),
	)
	b.carrier = &b.candidates[0]
	ts := s.windowTiers(t.Context(), neighbors, map[addr.IA]sample{selA: sm(10*ms, 0), selB: b})
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

// TestMemberPrice checks a member's price: the carrier by its echo, an
// unanswered one pricing nothing; every other route the window did not probe
// by its declared sum doubled, an undeclared one pricing nothing; each route
// charged the transit penalty for every AS it crosses between its ends, each
// way; the cheapest winning.
func TestMemberPrice(t *testing.T) {
	ms := time.Millisecond
	routes := ptrs(
		route(0, ms, local(1), link(selA)),
		route(0, 9*ms, local(2), link(selB), link(selA)),
		route(0, 3*ms, local(2), link(selB), link(selC), link(selA)),
		route(0, 0, local(3), link(selC), link(selA)),
	)
	direct, oneTransit, twoTransits, undeclared := routes[0], routes[1], routes[2], routes[3]
	probed := map[*scion.Candidate]bool{direct: true}

	for _, tc := range []struct {
		name    string
		carrier *scion.Candidate
		echo    time.Duration
		routes  []*scion.Candidate
		want    time.Duration
	}{
		{"the carrier by its echo", direct, 20 * ms, nil, 20 * ms},
		{"an unanswered carrier", direct, 0, nil, 0},
		{"the carrier's transit charged", oneTransit, 20 * ms, nil, 30 * ms},
		{"a declared route, its transit charged", nil, 0, []*scion.Candidate{oneTransit}, 28 * ms},
		{"two transits charged", nil, 0, []*scion.Candidate{twoTransits}, 26 * ms},
		{"an undeclared route", nil, 0, []*scion.Candidate{undeclared}, 0},
		{"a probed route's declaration", nil, 0, []*scion.Candidate{direct}, 0},
		{"the cheapest", direct, 30 * ms, routes, 26 * ms},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := memberPrice(tc.carrier, tc.echo, tc.routes, probed); got != tc.want {
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
// round trip. A survivor of a member no route prices counts for nothing, and
// a member cut off, priced or not, decides the link useful. A tier nothing
// prices, or a survivor that went unanswered, decides nothing.
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
			echo:   20 * ms,
			price:  22 * ms,
			routes: 2,
			prices: p,
			cutOff: make(map[addr.IA]bool),
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
		{"a member no survivor prices", held(prices{selA: 12 * ms}), true, true},
		{"a member cut off", held(prices{selA: 12 * ms}, selB), true, false},
		{"a member no route prices, cut off", held(within, selC), true, false},
		{"a survivor of a member no route prices",
			held(prices{selA: 12 * ms, selB: 24 * ms, selC: 100 * ms}), true, true},
		{"the tier's price past the ratio",
			excludedSample{echo: 20 * ms, price: 26 * ms, routes: 2, prices: within}, true, false},
		{"a route lost",
			excludedSample{echo: 20 * ms, price: 22 * ms, routes: 1, prices: within}, true, false},
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
