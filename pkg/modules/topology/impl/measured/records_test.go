package measured

import (
	"context"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/libs/bus"
	"github.com/fancl20/cion/pkg/libs/evidence"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/segment"
	"github.com/fancl20/cion/pkg/modules/links"
)

// recorded is a record as the tests compare it: all but its instant, each
// estimate it weighed by its name, value, bounds, and answered samples.
type recorded struct {
	Change, Subject, From, To, Why string
	Line                           time.Duration
	Weighed                        []weighedAt
}

// weighedAt is an estimate a record weighed as the tests compare it, the
// span its kind reads telling a reading's from the bounds'.
type weighedAt struct {
	Name          string
	Span          time.Duration
	Value, Lo, Hi time.Duration
	Answered      int
}

// records returns the records the selection appended, as the tests compare
// them.
func (f *selFixture) records(t *testing.T) []recorded {
	t.Helper()
	changes, dropped := f.sel.cfg.Changes.Since(0)
	if dropped != 0 {
		t.Fatalf("the journal dropped %d changes", dropped)
	}
	var out []recorded
	for _, c := range changes {
		r, ok := c.(evidence.Record)
		if !ok {
			t.Fatalf("change %+v is no record", c)
		}
		rec := recorded{Change: r.Change, Subject: r.Subject, From: r.From, To: r.To, Why: r.Why, Line: r.Line}
		for _, w := range r.Weighed {
			rec.Weighed = append(rec.Weighed, weighedAt{Name: w.Name, Span: w.Span,
				Value: w.Value, Lo: w.Lo, Hi: w.Hi, Answered: w.Answered})
		}
		out = append(out, rec)
	}
	return out
}

// steady returns the weighed estimate of a round trip that holds steady,
// read over the span: its value, its lower bound from two samples on, and
// its upper bound from fourteen on.
func steady(name string, span, rtt time.Duration, answered int) weighedAt {
	w := weighedAt{Name: name, Span: span, Value: rtt, Answered: answered}
	if answered >= 2 {
		w.Lo = rtt
	}
	if answered >= 14 {
		w.Hi = rtt
	}
	return w
}

// readingAt returns the weighed estimate a steady round trip's reading
// comes from.
func readingAt(name string, rtt time.Duration, answered int) weighedAt {
	return steady(name, scion.ReadingSpan, rtt, answered)
}

// boundsAt returns the weighed estimate a steady round trip's bounds come
// from.
func boundsAt(name string, rtt time.Duration, answered int) weighedAt {
	return steady(name, scion.BoundSpan, rtt, answered)
}

// TestSelectionRecordsPromotions checks the record of each promotion: the
// link promoted for each reason, at the interface it took, beside what its
// decision weighed — the direct side's reading alone where reaching the
// peer decides, the price's reading beside it where a price does, and both
// sides' bounds where the history confirms — and an announcement before a
// beaten price's promotion, which landing ends without a withdrawal.
func TestSelectionRecordsPromotions(t *testing.T) {
	ms := time.Millisecond
	onReadings := "its direct link beats its own price on its readings"
	confirming := "its direct link beats its own price, its history confirming"
	for _, tc := range []struct {
		name      string
		neighbors []addr.IA
		// run runs the fixture's windows, returning the peer promoted.
		run  func(t *testing.T, f *selFixture) addr.IA
		want func(promoted string) []recorded
	}{{
		name:      "the redundancy floor",
		neighbors: []addr.IA{selPeer},
		run: func(t *testing.T, f *selFixture) addr.IA {
			f.candidate(selA, 30*ms, 10*ms)
			f.candidate(selB, 0, 10*ms)
			f.pass(t)
			return selA
		},
		want: func(promoted string) []recorded {
			return []recorded{{Change: LinkPromoted, Subject: selA.String(), To: promoted,
				Why: "the redundancy floor", Weighed: []weighedAt{readingAt("direct", 30*ms, 1)}}}
		},
	}, {
		name:      "its stranded tier",
		neighbors: []addr.IA{selPeer, selA},
		run: func(t *testing.T, f *selFixture) addr.IA {
			f.candidate(selB, 22*ms, 0)
			f.candidate(selC, 30*ms, 0)
			f.pass(t)
			return selB
		},
		want: func(promoted string) []recorded {
			return []recorded{{Change: LinkPromoted, Subject: selB.String(), To: promoted,
				Why: "its stranded tier", Weighed: []weighedAt{readingAt("direct", 22*ms, 1)}}}
		},
	}, {
		name:      "a second route for its tier",
		neighbors: []addr.IA{selPeer, selA},
		run: func(t *testing.T, f *selFixture) addr.IA {
			f.candidate(selB, 22*ms, 20*ms, cand(link(selX)))
			f.candidate(selC, 26*ms, 20*ms, cand(link(selX)))
			for range promoteWindows(selIA, selB) {
				f.pass(t)
			}
			return selB
		},
		want: func(promoted string) []recorded {
			// The ratio leaves 5ms above the tier's 20ms price.
			return []recorded{{Change: LinkPromoted, Subject: selB.String(), To: promoted,
				Why: "a second route for its tier", Line: 5 * ms, Weighed: []weighedAt{
					readingAt("direct", 22*ms, promoteWindows(selIA, selB)),
					readingAt("price", 20*ms, scion.ReadingSamples),
				}}}
		},
	}, {
		name:      "a price beaten on the readings",
		neighbors: []addr.IA{selPeer, selA},
		run: func(t *testing.T, f *selFixture) addr.IA {
			f.candidate(selB, 8*ms, 20*ms)
			f.candidate(selC, 18*ms, 20*ms)
			for range PromoteWindows + 1 {
				f.pass(t)
			}
			return selB
		},
		want: func(promoted string) []recorded {
			// The ratio asks the 20ms price a gain of 4ms.
			price := readingAt("price", 20*ms, scion.ReadingSamples)
			return []recorded{
				{Change: PromotionAnnounced, Subject: selB.String(), Why: onReadings, Line: 4 * ms,
					Weighed: []weighedAt{readingAt("direct", 8*ms, 1), price}},
				{Change: LinkPromoted, Subject: selB.String(), To: promoted, Why: onReadings, Line: 4 * ms,
					Weighed: []weighedAt{readingAt("direct", 8*ms, 2), price}},
			}
		},
	}, {
		name:      "the tier's price beaten by a candidate no route prices",
		neighbors: []addr.IA{selPeer, selA},
		run: func(t *testing.T, f *selFixture) addr.IA {
			// Peer's route over A's link prices the tier at 16ms, its
			// transit uncharged at the tier's level.
			f.carried(selPeer, 10*ms, 16*ms, f.via(t, selA, 0, selA, selPeer))
			f.candidate(selB, 8*ms, 0)
			for range PromoteWindows {
				f.pass(t)
			}
			return selB
		},
		want: func(promoted string) []recorded {
			price := readingAt("price", 16*ms, scion.ReadingSamples)
			line := 3200 * time.Microsecond
			return []recorded{
				{Change: PromotionAnnounced, Subject: selB.String(), Why: onReadings, Line: line,
					Weighed: []weighedAt{readingAt("direct", 8*ms, 1), price}},
				{Change: LinkPromoted, Subject: selB.String(), To: promoted, Why: onReadings, Line: line,
					Weighed: []weighedAt{readingAt("direct", 8*ms, 2), price}},
			}
		},
	}, {
		name:      "a fast price beaten by the margin floor",
		neighbors: []addr.IA{selPeer, selA},
		run: func(t *testing.T, f *selFixture) addr.IA {
			f.candidate(selB, 6*ms, 9*ms)
			for range PromoteWindows {
				f.pass(t)
			}
			return selB
		},
		want: func(promoted string) []recorded {
			// The ratio asks the 9ms price a gain of 1.8ms, short of the
			// margin floor.
			price := readingAt("price", 9*ms, scion.ReadingSamples)
			return []recorded{
				{Change: PromotionAnnounced, Subject: selB.String(), Why: onReadings, Line: MarginFloor,
					Weighed: []weighedAt{readingAt("direct", 6*ms, 1), price}},
				{Change: LinkPromoted, Subject: selB.String(), To: promoted, Why: onReadings, Line: MarginFloor,
					Weighed: []weighedAt{readingAt("direct", 6*ms, 2), price}},
			}
		},
	}, {
		name:      "a price beaten as the history confirms",
		neighbors: []addr.IA{selPeer, selA},
		run: func(t *testing.T, f *selFixture) addr.IA {
			// D's two disjoint routes price it at 204ms, the cheaper with
			// its transit charged.
			f.candidate(selD, 185*ms, 200*ms,
				route(-time.Hour, 0, link(selX), link(selC), link(selD)),
				measured(route(-time.Hour, 0, link(selE), segment.LinkID{IA: selD, IfID: 2}), 210*ms))
			for range 15 {
				f.pass(t)
			}
			return selD
		},
		want: func(promoted string) []recorded {
			// The history's bounds confirm the price beaten once fourteen
			// samples bound the direct side from above.
			line := scion.Band(185*ms, 204*ms)
			price := boundsAt("price", 204*ms, steadyBounds)
			return []recorded{
				{Change: PromotionAnnounced, Subject: selD.String(), Why: confirming, Line: line,
					Weighed: []weighedAt{boundsAt("direct", 185*ms, 14), price}},
				{Change: LinkPromoted, Subject: selD.String(), To: promoted, Why: confirming, Line: line,
					Weighed: []weighedAt{boundsAt("direct", 185*ms, 15), price}},
			}
		},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSelFixture(t, tc.neighbors...)
			promoted := tc.run(t, f)
			if diff := cmp.Diff(tc.want(linkName(f.ifID(t, promoted))), f.records(t)); diff != "" {
				t.Errorf("records (-want +got):\n%s", diff)
			}
		})
	}
}

// TestSelectionRecordsRetirements checks the record of each retirement: the
// link retired by each rule, from its interface, beside what its decision
// weighed — the eviction the candidate's estimates and its tier's price with
// and without the link, the useless test the direct side's bounds and the
// survivors' — and an announcement before a useless retirement, which the
// retirement ends without a withdrawal.
func TestSelectionRecordsRetirements(t *testing.T) {
	ms := time.Millisecond
	useless := "a window found its link useless"
	for _, tc := range []struct {
		name    string
		bubbled bool
		run     func(t *testing.T) *selFixture
		// want returns the records wanted, the fixture naming the links'
		// interfaces.
		want func(t *testing.T, f *selFixture) []recorded
	}{{
		name:    "the candidate window",
		bubbled: true,
		run: func(t *testing.T) *selFixture {
			f := newSelFixture(t)
			f.sel.cfg.Window = 10 * ms
			if err := f.store.Insert(context.Background(), &links.Link{
				NeighborIA: selPeer,
				Local:      netip.MustParseAddrPort("127.0.0.1:40003"),
				Remote:     netip.MustParseAddrPort("127.0.0.1:40004"),
				State:      links.StateCandidate,
			}); err != nil {
				t.Fatal(err)
			}
			time.Sleep(20 * ms)
			f.pass(t)
			return f
		},
		want: func(t *testing.T, f *selFixture) []recorded {
			return []recorded{{Change: LinkRetired, Subject: selPeer.String(), From: linkName(f.ifID(t, selPeer)),
				Why: "candidate window elapsed without a confirmed link"}}
		},
	}, {
		name: "the cap's eviction",
		run: func(t *testing.T) *selFixture {
			f := capFixture(t)
			f.pass(t)
			f.pass(t)
			return f
		},
		want: func(t *testing.T, f *selFixture) []recorded {
			// D's one route prices it at 44ms with its transit, the ratio
			// asking a gain of 8.8ms; B's exclusion leaves its tier's 16ms
			// price.
			beaten := "its direct link beats its own price on its readings"
			price := readingAt("price", 44*ms, scion.ReadingSamples)
			return []recorded{
				{Change: PromotionAnnounced, Subject: selD.String(), Why: beaten, Line: 8800 * time.Microsecond,
					Weighed: []weighedAt{readingAt("direct", 24*ms, 1), price}},
				{Change: LinkRetired, Subject: selB.String(), From: linkName(f.ifID(t, selB)),
					Why: "displaced by the least-harm eviction for " + selD.String(),
					Weighed: []weighedAt{readingAt("direct", 24*ms, 2), price,
						readingAt("with", 16*ms, scion.ReadingSamples),
						readingAt("without", 16*ms, scion.ReadingSamples)}},
				{Change: LinkPromoted, Subject: selD.String(), To: linkName(f.ifID(t, selD)), Why: beaten,
					Line: 8800 * time.Microsecond, Weighed: []weighedAt{readingAt("direct", 24*ms, 2), price}},
				// C reaches over A's link at 16ms, 20ms with the transit,
				// below its own 30ms: useless once the history bounds its
				// direct side.
				{Change: RetirementAnnounced, Subject: selC.String(), Why: useless,
					Weighed: []weighedAt{boundsAt("direct", 30*ms, 2), boundsAt("survivors", 16*ms, steadyBounds)}},
			}
		},
	}, {
		name: "its verdict stayed down",
		run: func(t *testing.T) *selFixture {
			f := newSelFixture(t, selPeer, selA, selB)
			f.down[selB] = true
			for range DemoteWindows {
				f.pass(t)
			}
			return f
		},
		want: func(t *testing.T, f *selFixture) []recorded {
			return []recorded{{Change: LinkRetired, Subject: selB.String(), From: linkName(f.ifID(t, selB)),
				Why: "its verdict stayed down"}}
		},
	}, {
		name: "its tier served no worse without it",
		run: func(t *testing.T) *selFixture {
			f := newSelFixture(t, selPeer, selA, selB)
			// A's baseline rides Peer's link at 8ms, below its 18ms round
			// trip with the transit charged; B reaches over A's link at
			// 30ms, dearer than over its own.
			f.carried(selA, 18*ms, 8*ms, f.via(t, selPeer, 0, selPeer, selA))
			f.carried(selB, 10*ms, 20*ms, f.via(t, selB, -time.Hour, selB),
				measured(f.via(t, selA, 0, selA, selB), 30*ms))
			for range 5 {
				f.pass(t)
			}
			return f
		},
		want: func(t *testing.T, f *selFixture) []recorded {
			crossing := boundsAt("crossing", 30*ms, steadyBounds)
			survivors := boundsAt("survivors", 8*ms, steadyBounds)
			return []recorded{
				{Change: RetirementAnnounced, Subject: selA.String(), Why: useless,
					Weighed: []weighedAt{boundsAt("direct", 18*ms, 2), crossing, survivors}},
				{Change: LinkRetired, Subject: selA.String(), From: linkName(f.ifID(t, selA)),
					Why:     "its tier served no worse without it",
					Weighed: []weighedAt{boundsAt("direct", 18*ms, 4), crossing, survivors}},
			}
		},
	}, {
		name: "the clusters link its units elsewhere",
		run: func(t *testing.T) *selFixture {
			f := newSelFixture(t, selPeer, selA, selB)
			f.carried(selA, 18*ms, 10*ms, f.via(t, selPeer, 0, selPeer, selA))
			f.clustered(true)
			for range 2 * DemoteWindows {
				f.pass(t)
			}
			return f
		},
		want: func(t *testing.T, f *selFixture) []recorded {
			return []recorded{
				{Change: RetirementAnnounced, Subject: selA.String(), Why: useless,
					Weighed: []weighedAt{boundsAt("direct", 18*ms, 1), boundsAt("survivors", 10*ms, steadyBounds)}},
				{Change: LinkRetired, Subject: selA.String(), From: linkName(f.ifID(t, selA)),
					Why: "the clusters link its units elsewhere"},
			}
		},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			check := func(t *testing.T) {
				f := tc.run(t)
				if diff := cmp.Diff(tc.want(t, f), f.records(t)); diff != "" {
					t.Errorf("records (-want +got):\n%s", diff)
				}
			}
			if tc.bubbled {
				// The sweep reads the clock: the window's passage is a
				// fake-time sleep.
				synctest.Test(t, check)
				return
			}
			check(t)
		})
	}
}

// TestSelectionRecordsWithdrawals checks the record of each withdrawn
// announcement beside what ended it: a promotion's peer silent, its link no
// longer allowed, its price no longer beaten, a wait on another node's
// change, or a faster candidate; a retirement's link found useful, or the
// dialed links at the floor.
func TestSelectionRecordsWithdrawals(t *testing.T) {
	ms := time.Millisecond
	beaten := "its direct link beats its own price on its readings"
	// announcedB is the announcement of B's 8ms beating its 20ms price.
	announcedB := recorded{Change: PromotionAnnounced, Subject: selB.String(), Why: beaten, Line: 4 * ms,
		Weighed: []weighedAt{readingAt("direct", 8*ms, 1), readingAt("price", 20*ms, scion.ReadingSamples)}}
	// announcedA is the announcement of A's useless link.
	announcedA := recorded{Change: RetirementAnnounced, Subject: selA.String(),
		Why: "a window found its link useless", Weighed: []weighedAt{
			boundsAt("direct", 18*ms, 2), boundsAt("survivors", 8*ms, steadyBounds)}}
	withdrawn := func(change string, ia addr.IA, why string) recorded {
		return recorded{Change: change, Subject: ia.String(), Why: why}
	}
	// promoting returns a fixture at the floor whose first window announced
	// B's promotion, the establishments failing.
	promoting := func(t *testing.T) *selFixture {
		f := newSelFixture(t, selPeer, selA)
		f.sel.establishFn = func(context.Context, target, string) *links.Link { return nil }
		f.candidate(selB, 8*ms, 20*ms)
		f.pass(t)
		return f
	}
	// retiring returns a fixture above the floor whose second window
	// announced the retirement of A's useless link.
	retiring := func(t *testing.T) *selFixture {
		f := newSelFixture(t, selPeer, selA, selB)
		f.carried(selA, 18*ms, 8*ms, f.via(t, selPeer, 0, selPeer, selA))
		f.pass(t)
		f.pass(t)
		return f
	}
	for _, tc := range []struct {
		name string
		run  func(t *testing.T) *selFixture
		want []recorded
	}{{
		name: "a silent peer",
		run: func(t *testing.T) *selFixture {
			f := promoting(t)
			f.samples[selB] = sm(0)
			f.pass(t)
			return f
		},
		want: []recorded{announcedB,
			withdrawn(PromotionWithdrawn, selB, "its peer is no longer a reachable candidate")},
	}, {
		name: "a link the clusters no longer allow",
		run: func(t *testing.T) *selFixture {
			f := newSelFixture(t, selPeer, selB)
			f.sel.establishFn = func(context.Context, target, string) *links.Link { return nil }
			f.candidate(selA, 5*ms, 20*ms)
			f.pass(t)
			f.clustered(false)
			f.pass(t)
			return f
		},
		want: []recorded{
			{Change: PromotionAnnounced, Subject: selA.String(), Why: beaten, Line: 4 * ms,
				Weighed: []weighedAt{readingAt("direct", 5*ms, 1), readingAt("price", 20*ms, scion.ReadingSamples)}},
			withdrawn(PromotionWithdrawn, selA, "the clusters no longer allow its link"),
		},
	}, {
		name: "a price no longer beaten",
		run: func(t *testing.T) *selFixture {
			f := promoting(t)
			f.carried(selB, 30*ms, 20*ms)
			f.pass(t)
			return f
		},
		want: []recorded{announcedB,
			withdrawn(PromotionWithdrawn, selB, "its direct link no longer beats its own price")},
	}, {
		name: "a wait on another node's change",
		run: func(t *testing.T) *selFixture {
			f := promoting(t)
			// Peer, linked to the node at 1ms, announces its promotion of B
			// at 5ms: B over Peer would cost the node 10ms with Peer's
			// transit, which B's 8ms does not beat by the promotion ratio.
			f.report(selPeer, bus.PeerReport{IA: selIA, RTT: ms, IfID: 1},
				bus.PeerReport{IA: selB, RTT: 5 * ms, Promoting: true})
			f.report(selB, bus.PeerReport{IA: selIA, RTT: 8 * ms})
			f.pass(t)
			return f
		},
		want: []recorded{announcedB,
			withdrawn(PromotionWithdrawn, selB, "it waits on another node's change")},
	}, {
		name: "a faster candidate",
		run: func(t *testing.T) *selFixture {
			f := promoting(t)
			f.candidate(selD, 5*ms, 20*ms)
			f.pass(t)
			return f
		},
		want: []recorded{announcedB,
			withdrawn(PromotionWithdrawn, selB, "a faster candidate beats its own price"),
			{Change: PromotionAnnounced, Subject: selD.String(), Why: beaten, Line: 4 * ms,
				Weighed: []weighedAt{readingAt("direct", 5*ms, 1), readingAt("price", 20*ms, scion.ReadingSamples)}},
		},
	}, {
		name: "a link found useful",
		run: func(t *testing.T) *selFixture {
			f := retiring(t)
			// The route around A's link now prices A past its round trip.
			f.carried(selA, 18*ms, 30*ms, f.via(t, selPeer, 0, selPeer, selA))
			f.pass(t)
			return f
		},
		want: []recorded{announcedA,
			withdrawn(RetirementWithdrawn, selA, "a window found its link useful")},
	}, {
		name: "the dialed links at the floor",
		run: func(t *testing.T) *selFixture {
			f := retiring(t)
			f.down[selB] = true
			f.pass(t)
			return f
		},
		want: []recorded{announcedA,
			withdrawn(RetirementWithdrawn, selA, "the dialed links stand at the floor")},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			if diff := cmp.Diff(tc.want, tc.run(t).records(t)); diff != "" {
				t.Errorf("records (-want +got):\n%s", diff)
			}
		})
	}
}

// TestSelectionRecordsClusterChanges checks the records of the cluster the
// node joins: the natural cluster of its metro, named by its least ISD-AS,
// and once no report holds the cluster together and no other node names it,
// none.
func TestSelectionRecordsClusterChanges(t *testing.T) {
	f := newSelFixture(t, selPeer, selB)
	f.metros()
	f.pass(t)
	for i := range f.directory {
		f.directory[i].Peers = nil
	}
	f.pass(t)
	cluster := selPeer.String()
	want := []recorded{
		{Change: ClusterJoined, Subject: selIA.String(), To: cluster, Why: "a natural cluster holds the node"},
		{Change: ClusterLeft, Subject: selIA.String(), From: cluster, Why: "its unit fell below two members"},
	}
	if diff := cmp.Diff(want, f.records(t)); diff != "" {
		t.Errorf("records (-want +got):\n%s", diff)
	}
}

// metros has the nodes of two metros, the node's of Peer and B and that of
// A, C, and D, report their round trips to every node after them: 2ms
// within a metro and 40ms across, each bounded a twentieth around, so that
// a natural cluster holds the node's metro. The other metro's nodes answer
// no probe.
func (f *selFixture) metros() {
	metros := [][]addr.IA{{selIA, selPeer, selB}, {selA, selC, selD}}
	var nodes []addr.IA
	metro := make(map[addr.IA]int)
	for i, m := range metros {
		nodes = append(nodes, m...)
		for _, ia := range m {
			metro[ia] = i
		}
	}
	f.directory = append(f.directory, bus.DirectoryEntry{IA: selIA},
		entryOf(selA), entryOf(selC), entryOf(selD))
	for i, a := range nodes {
		var reports []bus.PeerReport
		for _, b := range nodes[i+1:] {
			rtt := 40 * time.Millisecond
			if metro[a] == metro[b] {
				rtt = 2 * time.Millisecond
			}
			reports = append(reports, bus.PeerReport{IA: b, RTT: rtt, Low: rtt - rtt/20, High: rtt + rtt/20})
		}
		f.report(a, reports...)
	}
}

// TestSelectionRecordsNothingUnchanged checks that windows changing nothing
// record nothing.
func TestSelectionRecordsNothingUnchanged(t *testing.T) {
	f := newSelFixture(t, selPeer, selA)
	f.samples[selPeer] = f.priced(selPeer, 20*time.Millisecond, 20*time.Millisecond)
	f.candidate(selB, 20*time.Millisecond, 20*time.Millisecond)
	for range 4 {
		f.pass(t)
	}
	if got := f.records(t); len(got) != 0 {
		t.Errorf("windows changing nothing recorded %+v", got)
	}
}
