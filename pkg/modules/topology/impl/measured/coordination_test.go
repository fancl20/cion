package measured

import (
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/libs/bus"
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

// coLink returns the reports of a link between two nodes at a round trip,
// each end on the given interface.
func coLink(reports map[addr.IA][]bus.PeerReport, a addr.IA, ai uint16, b addr.IA, bi uint16,
	rtt time.Duration) {

	reports[a] = append(reports[a], bus.PeerReport{IA: b, RTT: rtt, IfID: ai})
	reports[b] = append(reports[b], bus.PeerReport{IA: a, RTT: rtt, IfID: bi})
}

// coHerd returns the reports of the herd the coordination exists for: S
// reaches T over O and M, at 5, 50, and 5 ms, so its path to T costs 80 ms
// with two transits; S measures T at 30 ms and O measures T at 20 ms, so
// both pairs violate, and O's link to T would serve S at 35 ms.
func coHerd() map[addr.IA][]bus.PeerReport {
	reports := make(map[addr.IA][]bus.PeerReport)
	coLink(reports, coS, 1, coO, 1, 5*time.Millisecond)
	coLink(reports, coO, 2, coM, 1, 50*time.Millisecond)
	coLink(reports, coM, 2, coT, 1, 5*time.Millisecond)
	reports[coS] = append(reports[coS], bus.PeerReport{IA: coT, RTT: 30 * time.Millisecond})
	reports[coO] = append(reports[coO], bus.PeerReport{IA: coT, RTT: 20 * time.Millisecond})
	return reports
}

// TestCoordViewReadsReports checks the view: a pair weighs the larger of its
// ends' round trips, and is bounded by the larger of their lower and of
// their upper bounds; it is linked when an end reports a link and none
// reports none, the paths charge each transit, the announcements read as
// reported, and each signer's cluster is its latest entry's.
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

	if got := v.weight[pairOf(coS, coT)]; got != 27*time.Millisecond {
		t.Errorf("weight of S-T = %v, want the larger end's 27ms", got)
	}
	want := map[pair]bool{pairOf(coS, coM): true, pairOf(coM, coT): true}
	if diff := cmp.Diff(want, v.linked, cmp.AllowUnexported(pair{})); diff != "" {
		t.Errorf("linked (-want +got):\n%s", diff)
	}
	if got, ok := v.cost(coS, coT); !ok || got != 40*time.Millisecond {
		t.Errorf("cost S-T = %v, %v; want 40ms, the transit at M charged", got, ok)
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
	if low, high := v.low[pairOf(coS, coT)], v.high[pairOf(coS, coT)]; low != 22*time.Millisecond ||
		high != 30*time.Millisecond {
		t.Errorf("bounds of S-T = %v, %v; want the larger ends' 22ms and 30ms", low, high)
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
// a pair violates when its weight beats the path between its ends by the
// promotion ratio and the margin floor, or when no path joins them, and
// costWith prices the path were a pair linked.
func TestCoordViewViolates(t *testing.T) {
	v := newCoordView(coReports(coHerd()))
	if !v.violates(pairOf(coS, coT)) || !v.violates(pairOf(coO, coT)) {
		t.Error("S-T and O-T beat their 80 and 65 ms paths, want both violating")
	}
	if v.violates(pairOf(coS, coO)) {
		t.Error("the linked S-O violates")
	}
	if got, ok := v.costWith(coS, coT, pairOf(coO, coT)); !ok || got != 35*time.Millisecond {
		t.Errorf("cost S-T with O-T linked = %v, %v; want 35ms", got, ok)
	}
	if got, ok := v.costWith(coS, coM, pairOf(coO, coT)); !ok || got != 50*time.Millisecond {
		t.Errorf("cost S-M with O-T linked = %v, %v; want 50ms, the transits at O and T charged", got, ok)
	}
	if !violatesAt(time.Second, 0, false) {
		t.Error("a pair no path joins does not violate")
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
	for _, tc := range []struct {
		w, path time.Duration
		want    bool
	}{
		{7 * time.Millisecond, 9 * time.Millisecond, true},      // within the ratio by the floor
		{7100 * time.Microsecond, 9 * time.Millisecond, false},  // within the ratio, short of the floor
		{17 * time.Millisecond, 20 * time.Millisecond, false},   // past the floor, short of the ratio
		{15900 * time.Microsecond, 20 * time.Millisecond, true}, // within both
	} {
		if got := violatesAt(tc.w, tc.path, true); got != tc.want {
			t.Errorf("violatesAt(%v, %v) = %v, want %v", tc.w, tc.path, got, tc.want)
		}
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
// heavier, holds nothing.
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
	own[coS] = append(own[coS], bus.PeerReport{IA: coM, RTT: 10 * time.Millisecond})
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
	heavy[coS] = append(heavy[coS], bus.PeerReport{IA: coT, RTT: 100 * time.Millisecond})
	heavy[coO] = append(heavy[coO], bus.PeerReport{IA: coT, RTT: 110 * time.Millisecond})
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
	far[coP] = append(far[coP], bus.PeerReport{IA: coM, RTT: time.Millisecond})
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
// of a link the node's routes rely on, unless that node relies on the node's
// link too and that link is the lighter; on a retired link the routes still
// cross; and on nothing else.
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
