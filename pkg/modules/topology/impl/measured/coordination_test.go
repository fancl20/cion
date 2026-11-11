package measured

import (
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/libs/bus"
	"github.com/fancl20/cion/pkg/libs/evidence"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/segment"
)

// The nodes of the coordination's tests: S the node deciding, T its
// candidate peer, O another node, M and P on the way.
var (
	coS = addr.MustIAFrom(20, 0xfd0000000101)
	coT = addr.MustIAFrom(20, 0xfd0000000102)
	coO = addr.MustIAFrom(20, 0xfd0000000103)
	coM = addr.MustIAFrom(20, 0xfd0000000104)
	coP = addr.MustIAFrom(20, 0xfd0000000105)
)

// coReports builds a directory of one scope from each node's reports, its
// entries ordered by ISD-AS.
func coReports(reports map[addr.IA][]bus.PeerReport) bus.Directory {
	var entries []bus.DirectoryEntry
	for _, ia := range slices.Sorted(maps.Keys(reports)) {
		entries = append(entries, bus.DirectoryEntry{IA: ia, Peers: reports[ia]})
	}
	return bus.NewDirectory(nil, bus.NewScope(bus.DirectoryID{1}, entries...))
}

// coTight returns a report of the peer at a round trip, its bounds a
// twentieth around it.
func coTight(ia addr.IA, rtt time.Duration) bus.PeerReport {
	return bus.PeerReport{IA: ia, RTT: rtt, Low: rtt - rtt/20, High: rtt + rtt/20}
}

// coLink returns the reports of a link between two nodes at a round trip,
// bounded tightly, each end on the given interface.
func coLink(reports map[addr.IA][]bus.PeerReport, a addr.IA, ai uint16, b addr.IA, bi uint16,
	rtt time.Duration) {

	ra, rb := coTight(b, rtt), coTight(a, rtt)
	ra.IfID, rb.IfID = ai, bi
	reports[a] = append(reports[a], ra)
	reports[b] = append(reports[b], rb)
}

// coHerd returns the reports of the herd the coordination exists for: S
// reaches T over O and M, at 5, 50, and 5 ms, so its path to T costs 60 ms
// beside two transits; S measures T at 30 ms and O measures T at 20 ms, so
// both pairs violate, and O's link to T would serve S at 25 ms beside a
// transit. Every round trip is bounded tightly.
func coHerd() map[addr.IA][]bus.PeerReport {
	reports := make(map[addr.IA][]bus.PeerReport)
	coLink(reports, coS, 1, coO, 1, 5*time.Millisecond)
	coLink(reports, coO, 2, coM, 1, 50*time.Millisecond)
	coLink(reports, coM, 2, coT, 1, 5*time.Millisecond)
	reports[coS] = append(reports[coS], coTight(coT, 30*time.Millisecond))
	reports[coO] = append(reports[coO], coTight(coT, 20*time.Millisecond))
	return reports
}

// TestCoordViewReadsReports checks the view: a pair's estimate is the
// larger of its ends' round trips, of their lower bounds, and of their upper
// bounds; it is linked when an end reports a link and none reports none,
// the paths charge each transit, the announcements read as reported, and
// each signer's cluster is its latest entry's.
func TestCoordViewReadsReports(t *testing.T) {
	reports := make(map[addr.IA][]bus.PeerReport)
	coLink(reports, coS, 1, coM, 1, 10*time.Millisecond)
	coLink(reports, coM, 2, coT, 1, 20*time.Millisecond)
	reports[coS] = append(reports[coS], bus.PeerReport{IA: coT, RTT: 25 * time.Millisecond,
		Low: 22 * time.Millisecond, High: 26 * time.Millisecond, Promoting: true})
	reports[coT] = append(reports[coT], bus.PeerReport{IA: coS, RTT: 27 * time.Millisecond,
		Low: 21 * time.Millisecond, High: 30 * time.Millisecond})
	// O reports a link to P, which reports none: the link is down.
	reports[coO] = append(reports[coO], bus.PeerReport{IA: coP, RTT: 3 * time.Millisecond, IfID: 4})
	reports[coP] = append(reports[coP], bus.PeerReport{IA: coO, RTT: 3 * time.Millisecond,
		Retiring: true, Relies: []segment.LinkID{{IA: coM, IfID: 2}}})
	v := newCoordView(coReports(reports))

	if diff := cmp.Diff(scion.PublishedEstimate(27*time.Millisecond, 22*time.Millisecond, 30*time.Millisecond),
		v.rtts[pairOf(coS, coT)]); diff != "" {
		t.Errorf("S-T, want the larger ends' 27ms, 22ms, and 30ms (-want +got):\n%s", diff)
	}
	want := map[pair]bool{pairOf(coS, coM): true, pairOf(coM, coT): true}
	if diff := cmp.Diff(want, v.linked, cmp.AllowUnexported(pair{})); diff != "" {
		t.Errorf("linked (-want +got):\n%s", diff)
	}
	// S-M 10ms and M-T 20ms, each bounded a twentieth around.
	want30 := scion.PublishedEstimate(30*time.Millisecond+transitCost, 28500*time.Microsecond+transitCost,
		31500*time.Microsecond+transitCost)
	if got, ok := v.cost(coS, coT); !ok || !cmp.Equal(got, want30) {
		t.Errorf("cost S-T = %+v, %v; want %+v, the transit at M charged", got, ok, want30)
	}
	if _, ok := v.cost(coS, coO); ok {
		t.Error("S joined to O, which no up link reaches")
	}
	if by := v.promoting[pairOf(coS, coT)]; by != coS {
		t.Errorf("promotion of S-T announced by %v, want S", by)
	}
	if r := v.retiring[pairOf(coO, coP)]; r.by != coP || len(r.relies) != 1 {
		t.Errorf("retirement of O-P = %+v, want P's with its reliance", r)
	}

	// A pair without an upper bound leaves every path across it none.
	open := make(map[addr.IA][]bus.PeerReport)
	coLink(open, coS, 1, coM, 1, 10*time.Millisecond)
	open[coM] = append(open[coM], bus.PeerReport{IA: coT, RTT: 20 * time.Millisecond,
		Low: 19 * time.Millisecond, IfID: 2})
	open[coT] = append(open[coT], bus.PeerReport{IA: coM, RTT: 20 * time.Millisecond,
		Low: 19 * time.Millisecond, IfID: 1})
	if got, ok := newCoordView(coReports(open)).cost(coS, coT); !ok || got.HasHi {
		t.Errorf("cost S-T across a pair without an upper bound = %+v, %v; want no upper bound", got, ok)
	}

	// S's later entry, in another scope, names its cluster.
	early := bus.DirectoryEntry{IA: coS, Published: time.Unix(1, 0)}
	late := bus.DirectoryEntry{IA: coS, Cluster: coM, Published: time.Unix(2, 0)}
	for _, order := range [][2]bus.DirectoryEntry{{early, late}, {late, early}} {
		d := bus.NewDirectory(nil, bus.NewScope(bus.DirectoryID{1}, order[0]),
			bus.NewScope(bus.DirectoryID{2}, order[1]))
		if got := newCoordView(d).clusters[coS]; got != coM {
			t.Errorf("S's cluster = %v, want its latest entry's %v", got, coM)
		}
	}
}

// TestCoordViewViolates checks the violation test over the published links:
// a pair violates when it beats the cheapest path between its ends by the
// line to buy, or when no path joins them, and costWith prices the path
// were a pair linked.
func TestCoordViewViolates(t *testing.T) {
	v := newCoordView(coReports(coHerd()))
	if !v.violates(pairOf(coS, coT)) || !v.violates(pairOf(coO, coT)) {
		t.Error("S-T and O-T beat their paths, want both violating")
	}
	if v.violates(pairOf(coS, coO)) {
		t.Error("the linked S-O violates")
	}
	if got, ok := v.costWith(coS, coT, pairOf(coO, coT)); !ok || got.Value != 25*time.Millisecond+transitCost {
		t.Errorf("cost S-T with O-T linked = %v, %v; want 25ms and the transit at O charged", got.Value, ok)
	}
	if got, ok := v.costWith(coS, coM, pairOf(coO, coT)); !ok || got.Value != 30*time.Millisecond+2*transitCost {
		t.Errorf("cost S-M with O-T linked = %v, %v; want 30ms and the transits at O and T charged", got.Value, ok)
	}
	// Without its bounds, S-T decides nothing against its path.
	unbounded := coHerd()
	for i, r := range unbounded[coS] {
		if r.IA == coT {
			unbounded[coS][i].Low, unbounded[coS][i].High = 0, 0
		}
	}
	if newCoordView(coReports(unbounded)).violates(pairOf(coS, coT)) {
		t.Error("S-T without bounds violates")
	}
	// S, O, and M name one cluster and T stands alone: M's 5ms and O's
	// 20ms choose the pairs to T, so S-T is not a pair the clustering
	// allows, and O-T is.
	clustered := newCoordView(coReports(coHerd()))
	clustered.clusters[coO], clustered.clusters[coM] = coS, coS
	clustered.units = newUnits(clustered, coS, coS)
	if clustered.violates(pairOf(coS, coT)) {
		t.Error("S-T violates, though the clustering does not allow it")
	}
	if !clustered.violates(pairOf(coO, coT)) {
		t.Error("O-T does not violate, though the clustering chose it")
	}
}

// TestBeatsPath checks the comparison against a path at its edges: the
// pair's upper bound under the path's lower bound scaled by the promotion
// ratio, and under the path's lower bound by the margin floor, both of which
// must hold; undecided where the bounds overlap; better where no path joins.
func TestBeatsPath(t *testing.T) {
	ms := time.Millisecond
	point := func(d time.Duration) evidence.Estimate { return scion.PublishedEstimate(d, d, d) }
	for _, tc := range []struct {
		name    string
		w, path evidence.Estimate
		want    evidence.Verdict
	}{
		{"by the floor", point(7 * ms), point(9 * ms), evidence.Better},
		{"short of the floor", point(7100 * time.Microsecond), point(9 * ms), evidence.NotBetter},
		{"past the floor, short of the ratio", point(17 * ms), point(20 * ms), evidence.NotBetter},
		{"by the ratio", point(16 * ms), point(20 * ms), evidence.Better},
		{"overlapping", scion.PublishedEstimate(16*ms, 15*ms, 17*ms),
			scion.PublishedEstimate(20*ms, 19*ms, 21*ms), evidence.Undecided},
		{"by the ratio within the path's spread", point(14400 * time.Microsecond),
			scion.PublishedEstimate(20*ms, 18*ms, 22*ms), evidence.Better},
		{"past the ratio within the path's spread", point(14500 * time.Microsecond),
			scion.PublishedEstimate(20*ms, 18*ms, 22*ms), evidence.Undecided},
		{"no upper bound", scion.PublishedEstimate(10*ms, 9*ms, 0), point(20 * ms), evidence.Undecided},
	} {
		if got := beatsPath(tc.w, tc.path, true); got != tc.want {
			t.Errorf("%s: beatsPath = %v, want %v", tc.name, got, tc.want)
		}
	}
	if got := beatsPath(point(time.Second), evidence.Estimate{}, false); got != evidence.Better {
		t.Errorf("a pair no path joins: beatsPath = %v, want better", got)
	}
}

// TestObserveRestartsPredictions checks the prediction's first window: a
// pair that stops violating loses it, and violating again starts anew.
func TestObserveRestartsPredictions(t *testing.T) {
	now := time.Now()
	herd := newCoordView(coReports(coHerd()))
	served := coHerd()
	served[coO] = slices.DeleteFunc(served[coO], func(r bus.PeerReport) bool { return r.IA == coT })
	coLink(served, coO, 3, coT, 2, 20*time.Millisecond)
	c := &coordState{}
	c.observe(herd, now)
	c.observe(newCoordView(coReports(served)), now)
	if _, ok := c.predicted[pairOf(coS, coT)]; ok {
		t.Error("S-T, served over O's link, kept its prediction")
	}
	c.observe(herd, now)
	if got := c.predicted[pairOf(coS, coT)]; got != c.window {
		t.Errorf("S-T violating again was first predicted in window %d, want %d", got, c.window)
	}
}

// coAnnounce marks the node's report of the peer as an announced promotion.
func coAnnounce(reports map[addr.IA][]bus.PeerReport, by, peer addr.IA) map[addr.IA][]bus.PeerReport {
	for i, r := range reports[by] {
		if r.IA == peer {
			reports[by][i].Promoting = true
		}
	}
	return reports
}

// TestWaitsToPromote checks the node's waits on another node's lighter pair
// that would serve it: a predicted pair holds it for runnerUpWindows
// windows after its prediction, an announced one as long after its
// announcement first shows, and a pair that serves it not, or that is
// heavier, or that the node's pair, undecided against its path, would not
// wait for, holds nothing.
func TestWaitsToPromote(t *testing.T) {
	now := time.Now()
	c := &coordState{}
	predicted := newCoordView(coReports(coHerd()))
	for window := 1; window <= runnerUpWindows+2; window++ {
		c.observe(predicted, now)
		want := window <= runnerUpWindows+1
		if got := c.waitsToPromote(predicted, coS, coT, nil, now); got != want {
			t.Errorf("predicted, window %d: waits = %v, want %v", window, got, want)
		}
	}
	// O announces past its prediction's windows: S waits as long again.
	announced := newCoordView(coReports(coAnnounce(coHerd(), coO, coT)))
	for window := 1; window <= runnerUpWindows+2; window++ {
		c.observe(announced, now)
		want := window <= runnerUpWindows+1
		if got := c.waitsToPromote(announced, coS, coT, nil, now); got != want {
			t.Errorf("announced, window %d: waits = %v, want %v", window, got, want)
		}
	}

	// S's own lighter candidate holds nothing back: with O measuring T no
	// longer, S measures M at 10ms, a link that would serve its pair to T
	// at 25ms, but the node orders its own promotions.
	own := coHerd()
	own[coO] = slices.DeleteFunc(own[coO], func(r bus.PeerReport) bool { return r.IA == coT })
	own[coS] = append(own[coS], coTight(coM, 10*time.Millisecond))
	c = &coordState{}
	ownView := newCoordView(coReports(own))
	c.observe(ownView, now)
	if c.waitsToPromote(ownView, coS, coT, nil, now) {
		t.Error("S's promotion of T waits on S's own lighter candidate")
	}

	// A heavier pair holds nothing back, though linked it would serve S's:
	// S measures T at 100ms over a 230ms path, and O measures T at 110ms,
	// which would bring S's path to 125ms.
	heavy := make(map[addr.IA][]bus.PeerReport)
	coLink(heavy, coS, 1, coO, 1, 5*time.Millisecond)
	coLink(heavy, coO, 2, coM, 1, 200*time.Millisecond)
	coLink(heavy, coM, 2, coT, 1, 5*time.Millisecond)
	heavy[coS] = append(heavy[coS], coTight(coT, 100*time.Millisecond))
	heavy[coO] = append(heavy[coO], coTight(coT, 110*time.Millisecond))
	c = &coordState{}
	heavyView := newCoordView(coReports(heavy))
	c.observe(heavyView, now)
	if c.waitsToPromote(heavyView, coS, coT, nil, now) {
		t.Error("S's promotion of T waits on O's heavier one")
	}

	// O's promotion of T waits on nothing: S's candidate is heavier.
	c = &coordState{}
	c.observe(predicted, now)
	if c.waitsToPromote(predicted, coO, coT, nil, now) {
		t.Error("O's lighter promotion waits on S's heavier one")
	}

	// S's pair without bounds decides nothing against the published path:
	// it waits on no lighter pair, only on a link its routes do not see,
	// and its routes cross every one.
	unbounded := coHerd()
	for i, r := range unbounded[coS] {
		if r.IA == coT {
			unbounded[coS][i].Low, unbounded[coS][i].High = 0, 0
		}
	}
	c = &coordState{}
	uv := newCoordView(coReports(unbounded))
	c.observe(uv, now)
	seen := scion.Candidate{Links: []segment.LinkID{{IA: coS, IfID: 1}, {IA: coO, IfID: 1},
		{IA: coO, IfID: 2}, {IA: coM, IfID: 1}, {IA: coM, IfID: 2}, {IA: coT, IfID: 1}}}
	if c.waitsToPromote(uv, coS, coT, []scion.Candidate{seen}, now) {
		t.Error("S's undecided pair waits on O's lighter one")
	}

	// A lighter candidate that serves S not holds nothing back: P–M, far
	// from S's path, linking nothing S needs.
	far := coHerd()
	for i, r := range far[coO] {
		if r.IA == coT {
			far[coO] = append(far[coO][:i], far[coO][i+1:]...)
			break
		}
	}
	coLink(far, coP, 1, coT, 3, 40*time.Millisecond)
	far[coP] = append(far[coP], coTight(coM, time.Millisecond))
	c = &coordState{}
	v := newCoordView(coReports(far))
	c.observe(v, now)
	if c.waitsToPromote(v, coS, coT, nil, now) {
		t.Error("S waits on a promotion that would not serve it")
	}
}

// TestWaitsToPromoteLagging checks the wait on a link the node's prices
// cannot see yet: the published links serve S's pair through O's new link to
// T, and S waits while none of its routes crosses that link, until one does
// or scion.StaleAfter passes.
func TestWaitsToPromoteLagging(t *testing.T) {
	now := time.Now()
	reports := coHerd()
	for i, r := range reports[coO] {
		if r.IA == coT {
			reports[coO] = append(reports[coO][:i], reports[coO][i+1:]...)
			break
		}
	}
	coLink(reports, coO, 3, coT, 2, 20*time.Millisecond)
	v := newCoordView(coReports(reports))
	c := &coordState{}
	c.observe(v, now)
	old := scion.Candidate{Links: []segment.LinkID{{IA: coS, IfID: 1}, {IA: coO, IfID: 1},
		{IA: coO, IfID: 2}, {IA: coM, IfID: 1}, {IA: coM, IfID: 2}, {IA: coT, IfID: 1}}}
	if !c.waitsToPromote(v, coS, coT, []scion.Candidate{old}, now) {
		t.Error("S promotes past a link its routes do not cross yet")
	}
	// A route across O's new link ends the wait, though the links off the
	// cheapest path, as new to S, cross none of its routes.
	fresh := scion.Candidate{Links: []segment.LinkID{{IA: coS, IfID: 1}, {IA: coO, IfID: 1},
		{IA: coO, IfID: 3}, {IA: coT, IfID: 2}}}
	if c.waitsToPromote(v, coS, coT, []scion.Candidate{fresh}, now) {
		t.Error("S waits though a route crosses the new link")
	}
	later := now.Add(scion.StaleAfter + time.Second)
	c.observe(v, later)
	if c.waitsToPromote(v, coS, coT, []scion.Candidate{old}, later) {
		t.Error("S waits on a link seen more than StaleAfter ago")
	}
}

// TestWaitsToRetire checks the retirement waits: on an announced retirement
// of a link the node's routes rely on, unless the two rest on each other,
// directly or through a third, and the node's link is the cycle's heaviest;
// on a retired link the routes still cross; and on nothing else.
func TestWaitsToRetire(t *testing.T) {
	now := time.Now()
	// S retires its link to M (10 ms); O announces retiring its link to P.
	base := func(oRelies []segment.LinkID, opRTT time.Duration) map[addr.IA][]bus.PeerReport {
		reports := make(map[addr.IA][]bus.PeerReport)
		coLink(reports, coS, 1, coM, 1, 10*time.Millisecond)
		coLink(reports, coO, 2, coP, 2, opRTT)
		for i, r := range reports[coO] {
			if r.IA == coP {
				reports[coO][i].Retiring, reports[coO][i].Relies = true, oRelies
			}
		}
		return reports
	}
	relies := []segment.LinkID{{IA: coO, IfID: 2}}
	mineCrossed := []segment.LinkID{{IA: coS, IfID: 1}}
	for _, tc := range []struct {
		name    string
		reports map[addr.IA][]bus.PeerReport
		relies  []segment.LinkID
		want    bool
	}{
		{"relies on it", base(nil, 5*time.Millisecond), relies, true},
		{"relies on nothing it retires", base(nil, 5*time.Millisecond), nil, false},
		{"mutual, its link the lighter", base(mineCrossed, 5*time.Millisecond), relies, false},
		{"mutual, its link the heavier", base(mineCrossed, 20*time.Millisecond), relies, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &coordState{}
			v := newCoordView(coReports(tc.reports))
			c.observe(v, now)
			if got := c.waitsToRetire(v, coS, coM, tc.relies); got != tc.want {
				t.Errorf("waits = %v, want %v", got, tc.want)
			}
		})
	}

	// A cycle of three: S rests on O's retirement, O on T's, and T, at the
	// round trip given, on S's; or T on nothing, a chain.
	cycle := func(tpRTT time.Duration, tRestsOnS bool) map[addr.IA][]bus.PeerReport {
		reports := make(map[addr.IA][]bus.PeerReport)
		coLink(reports, coS, 1, coM, 1, 10*time.Millisecond)
		coLink(reports, coO, 2, coP, 2, 5*time.Millisecond)
		coLink(reports, coT, 3, coP, 3, tpRTT)
		announce := func(by, peer addr.IA, relies []segment.LinkID) {
			for i, r := range reports[by] {
				if r.IA == peer {
					reports[by][i].Retiring, reports[by][i].Relies = true, relies
				}
			}
		}
		announce(coO, coP, []segment.LinkID{{IA: coT, IfID: 3}})
		var tRelies []segment.LinkID
		if tRestsOnS {
			tRelies = mineCrossed
		}
		announce(coT, coP, tRelies)
		return reports
	}
	for _, tc := range []struct {
		name    string
		reports map[addr.IA][]bus.PeerReport
		want    bool
	}{
		{"a cycle, its link the heaviest", cycle(7*time.Millisecond, true), false},
		{"a cycle, another link heavier", cycle(20*time.Millisecond, true), true},
		{"a chain, its link the heaviest", cycle(7*time.Millisecond, false), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &coordState{}
			v := newCoordView(coReports(tc.reports))
			c.observe(v, now)
			if got := c.waitsToRetire(v, coS, coM, relies); got != tc.want {
				t.Errorf("waits = %v, want %v", got, tc.want)
			}
		})
	}

	// O's link left after its announcement: S waits while its routes cross
	// it, up to StaleAfter.
	c := &coordState{}
	v := newCoordView(coReports(base(nil, 5*time.Millisecond)))
	c.observe(v, now)
	gone := make(map[addr.IA][]bus.PeerReport)
	coLink(gone, coS, 1, coM, 1, 10*time.Millisecond)
	v = newCoordView(coReports(gone))
	c.observe(v, now)
	if !c.waitsToRetire(v, coS, coM, relies) {
		t.Error("S retires while its routes cross a link that just left")
	}
	later := now.Add(scion.StaleAfter + time.Second)
	c.observe(v, later)
	if c.waitsToRetire(v, coS, coM, relies) {
		t.Error("S waits on a link gone more than StaleAfter")
	}

	// The link left while O's announcement lingers a window: the departure
	// keeps the interfaces the link had.
	c = &coordState{}
	c.observe(newCoordView(coReports(base(nil, 5*time.Millisecond))), now)
	lingering := make(map[addr.IA][]bus.PeerReport)
	coLink(lingering, coS, 1, coM, 1, 10*time.Millisecond)
	lingering[coO] = []bus.PeerReport{{IA: coP, RTT: 5 * time.Millisecond, Retiring: true}}
	c.observe(newCoordView(coReports(lingering)), now)
	c.observe(v, now)
	if !c.waitsToRetire(v, coS, coM, relies) {
		t.Error("S retires while its routes cross a link that left a window ago")
	}

	// S's own other announced retirement holds nothing back.
	ownRet := base(nil, 5*time.Millisecond)
	coLink(ownRet, coS, 2, coP, 3, 7*time.Millisecond)
	for i, r := range ownRet[coS] {
		if r.IA == coP {
			ownRet[coS][i].Retiring = true
		}
	}
	c = &coordState{}
	v = newCoordView(coReports(ownRet))
	c.observe(v, now)
	if c.waitsToRetire(v, coS, coM, []segment.LinkID{{IA: coS, IfID: 2}}) {
		t.Error("S's retirement waits on S's own other announced retirement")
	}
}

// TestReportRTT checks the reported round trip's hysteresis: the first
// measurement reports, and one within rttStep and rttFloor of the reported
// one keeps it.
func TestReportRTT(t *testing.T) {
	c := &coordState{rtts: make(map[addr.IA]time.Duration)}
	for _, tc := range []struct{ measured, want time.Duration }{
		{20 * time.Millisecond, 20 * time.Millisecond},
		{21 * time.Millisecond, 20 * time.Millisecond},
		{23 * time.Millisecond, 23 * time.Millisecond},
		{2 * time.Millisecond, 2 * time.Millisecond},
		{2400 * time.Microsecond, 2 * time.Millisecond},
		{2600 * time.Microsecond, 2600 * time.Microsecond},
	} {
		if got := c.reportRTT(coT, tc.measured); got != tc.want {
			t.Errorf("reportRTT(%v) = %v, want %v", tc.measured, got, tc.want)
		}
	}
}

// TestReportBounds checks the reported bounds' hysteresis: each steps as a
// round trip does, apart.
func TestReportBounds(t *testing.T) {
	c := &coordState{lows: make(map[addr.IA]time.Duration), highs: make(map[addr.IA]time.Duration)}
	for _, tc := range []struct{ low, high, wantLow, wantHigh time.Duration }{
		{18 * time.Millisecond, 22 * time.Millisecond, 18 * time.Millisecond, 22 * time.Millisecond},
		{19 * time.Millisecond, 26 * time.Millisecond, 18 * time.Millisecond, 26 * time.Millisecond},
		{0, 26 * time.Millisecond, 0, 26 * time.Millisecond},
	} {
		if low, high := c.reportBounds(coT, tc.low, tc.high); low != tc.wantLow || high != tc.wantHigh {
			t.Errorf("reportBounds(%v, %v) = %v, %v, want %v, %v",
				tc.low, tc.high, low, high, tc.wantLow, tc.wantHigh)
		}
	}
}

// TestReliance checks the links a retirement relies on: the freshest
// survivor's and each member's cheapest survivor's, once each, in order.
func TestReliance(t *testing.T) {
	a := &scion.Candidate{Links: []segment.LinkID{{IA: coO, IfID: 2}, {IA: coM, IfID: 1}}}
	b := &scion.Candidate{Links: []segment.LinkID{{IA: coM, IfID: 1}, {IA: coP, IfID: 3}}}
	ex := excludedSample{survivor: a, cheapest: map[addr.IA]*scion.Candidate{coT: b}}
	want := []segment.LinkID{{IA: coO, IfID: 2}, {IA: coM, IfID: 1}, {IA: coP, IfID: 3}}
	if diff := cmp.Diff(want, reliance(ex)); diff != "" {
		t.Errorf("reliance (-want +got):\n%s", diff)
	}
}
