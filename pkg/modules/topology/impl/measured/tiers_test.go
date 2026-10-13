package measured

import (
	"testing"
	"time"

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
// one over a local down interface price nothing; the route count reading
// the clean candidates alone; and strandedness on the echoes, however many
// clean candidates compose into a tier none of whose echoes answered.
func TestWindowTierFacts(t *testing.T) {
	verdicts := map[uint16]bool{3: true, 4: false, 7: false} // B's link down, the node's own 7 dead
	up := &links.Link{NeighborIA: selA, IfID: 3, State: links.StateEstablished}
	dead := &links.Link{NeighborIA: selB, IfID: 4, State: links.StateEstablished}
	neighbors := map[addr.IA]*links.Link{selA: up, selB: dead}
	entries := map[addr.IA]DirectoryEntry{
		selA: entryOf(selA), selB: entryOf(selB), selC: entryOf(selC), selD: entryOf(selD),
	}
	s := &selection{
		cfg: SelectionConfig{
			IA:       selIA,
			Verdicts: func() map[uint16]bool { return verdicts },
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

	ts := s.windowTiers(t.Context(), neighbors, entries, samples)
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
}
