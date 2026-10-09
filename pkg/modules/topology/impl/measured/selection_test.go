package measured

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/controlplane"
	"github.com/fancl20/cion/pkg/modules/links"
	"github.com/fancl20/cion/pkg/modules/links/impl/memory"
	"github.com/fancl20/cion/pkg/scion"
	"github.com/fancl20/cion/pkg/segment"
)

// selFixture is the selection loop's test harness: a memory link store, a
// directory snapshot, the monitor's verdicts, injected measurements and path
// echoes, and injected candidate-grace probes. The establishment is
// recorded rather than performed; the promotion and retirement rules are
// what the tests assert.
type selFixture struct {
	store     *memory.DB
	directory []DirectoryEntry
	samples   map[addr.IA]sample
	verdicts  map[uint16]bool
	down      map[addr.IA]bool // neighbors whose verdict is down
	// alive holds the candidates whose rendezvous socket answers the
	// sweep's probe, keyed by neighbor ISD-AS.
	alive map[addr.IA]bool
	// probed holds the directory entries the last pass measured, the scope
	// filter's own record.
	probed map[addr.IA]bool
	// echoes holds the excluded measurements' path echoes by route key; an
	// unset route goes unanswered.
	echoes      map[string]time.Duration
	established []addr.IA // the promoted candidates, in order
	changed     int
	sel         *selection
}

var (
	selIA   = addr.MustIAFrom(20, 0xfd0000000001)
	selPeer = addr.MustIAFrom(20, 0xfd0000000002)
	selA    = addr.MustIAFrom(20, 0xfd0000000011)
	selB    = addr.MustIAFrom(20, 0xfd0000000012)
	selC    = addr.MustIAFrom(20, 0xfd0000000013)
	selD    = addr.MustIAFrom(20, 0xfd0000000014)
	selE    = addr.MustIAFrom(20, 0xfd0000000015)
)

func entryOf(ia addr.IA) DirectoryEntry {
	return DirectoryEntry{
		IA:             ia,
		ControlAddr:    netip.MustParseAddrPort("127.0.0.1:30042"),
		RendezvousAddr: netip.MustParseAddrPort("127.0.0.1:30043"),
	}
}

// scopedEntry builds a directory entry whose published rendezvous address
// sits at the given scope's address.
func scopedEntry(ia addr.IA, rendezvous string) DirectoryEntry {
	return DirectoryEntry{
		IA:             ia,
		ControlAddr:    netip.MustParseAddrPort("127.0.0.1:30042"),
		RendezvousAddr: netip.MustParseAddrPort(rendezvous),
	}
}

func newSelFixture(t *testing.T, neighbors ...addr.IA) *selFixture {
	t.Helper()
	f := &selFixture{
		store:    memory.New(),
		samples:  make(map[addr.IA]sample),
		verdicts: make(map[uint16]bool),
		down:     make(map[addr.IA]bool),
		alive:    make(map[addr.IA]bool),
		probed:   make(map[addr.IA]bool),
		echoes:   make(map[string]time.Duration),
	}
	for _, ia := range neighbors {
		if err := f.store.Insert(context.Background(), &links.Link{
			NeighborIA: ia,
			Local:      netip.MustParseAddrPort("127.0.0.1:40001"),
			Remote:     netip.MustParseAddrPort("127.0.0.1:40002"),
			State:      links.StateEstablished,
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, ia := range neighbors {
		f.directory = append(f.directory, entryOf(ia))
		f.samples[ia] = sm(10*time.Millisecond, 20*time.Millisecond)
	}
	f.sel = &selection{
		cfg: SelectionConfig{
			IA:      selIA,
			Store:   f.store,
			Changed: func() { f.changed++ },
			Window:  time.Hour, // the candidate sweep never retires in these
			// The viewer sits on loopback, so the loopback entries below
			// share its scope and pass the loop's filter.
			ControlAddr: netip.MustParseAddrPort("127.0.0.1:30042"),
		},
		streaks: make(map[addr.IA]*peerStreak),
		probeFn: func(_ context.Context, e DirectoryEntry, _ *links.Link) sample {
			f.probed[e.IA] = true
			return f.samples[e.IA]
		},
		pathEchoFn: func(_ addr.IA, c *scion.Candidate) time.Duration {
			return f.echoes[routeKey(c)]
		},
		establishFn: func(_ context.Context, e DirectoryEntry, _ string) bool {
			if err := f.store.Insert(context.Background(), &links.Link{
				NeighborIA: e.IA,
				Local:      netip.MustParseAddrPort("127.0.0.1:40001"),
				Remote:     netip.MustParseAddrPort("127.0.0.1:40002"),
				State:      links.StateEstablished,
			}); err != nil {
				t.Error(err)
				return false
			}
			f.established = append(f.established, e.IA)
			return true
		},
	}
	f.sel.cfg.Directory = func() []DirectoryEntry { return f.directory }
	f.sel.cfg.Verdicts = func() map[uint16]bool { return f.verdicts }
	// Every established neighbor holds its verdict up unless a test says
	// otherwise.
	f.sel.cfg.Evidence = func(*links.Link) bool { return false }
	f.sel.aliveFn = func(l *links.Link) bool { return f.alive[l.NeighborIA] }
	f.refresh()
	return f
}

// refresh rebuilds the verdict map from the established entries, minus the
// down ones.
func (f *selFixture) refresh() {
	entries, err := f.store.All(context.Background())
	if err != nil {
		return
	}
	f.verdicts = make(map[uint16]bool)
	for _, l := range entries {
		if l.State != links.StateEstablished {
			continue
		}
		f.verdicts[l.IfID] = !f.down[l.NeighborIA]
	}
}

// pass runs one evaluation window, refreshing liveness first.
func (f *selFixture) pass(t *testing.T) {
	t.Helper()
	f.refresh()
	f.sel.pass(context.Background())
}

// state returns the entry's state of a neighbor, retired ones included.
func (f *selFixture) state(t *testing.T, ia addr.IA) links.State {
	t.Helper()
	entries, err := f.store.All(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range entries {
		if l.NeighborIA.Equal(ia) {
			return l.State
		}
	}
	t.Fatalf("no entry for %s", ia)
	return 0
}

// hasEntry reports whether an entry of the neighbor exists.
func (f *selFixture) hasEntry(t *testing.T, ia addr.IA) bool {
	t.Helper()
	entries, err := f.store.All(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range entries {
		if l.NeighborIA.Equal(ia) {
			return true
		}
	}
	return false
}

// candidate adds a directory candidate with the given sample.
func (f *selFixture) candidate(ia addr.IA, direct, path time.Duration, routes ...scion.Candidate) {
	f.directory = append(f.directory, entryOf(ia))
	f.samples[ia] = sample{m: measurement{direct: direct, path: path}, candidates: routes}
}

// via builds a route that leaves through the neighbor's link and crosses
// the remote ASes, fresh at the offset.
func (f *selFixture) via(t *testing.T, through addr.IA, fresh time.Duration, remote ...addr.IA) scion.Candidate {
	t.Helper()
	path := []segment.LinkID{local(f.ifID(t, through))}
	for _, ia := range remote {
		path = append(path, link(ia))
	}
	return route(fresh, 0, path...)
}

// carried sets the peer's sample to the round trips and routes given, the
// first route the baseline's carrier: an excluded measurement echoing that
// route answers as the baseline did.
func (f *selFixture) carried(ia addr.IA, direct, path time.Duration, routes ...scion.Candidate) {
	s := sm(direct, path, routes...)
	s.carrier = &s.candidates[0]
	f.samples[ia] = s
	f.echoes[routeKey(s.carrier)] = path
}

// ifID returns the neighbor's entry's interface ID.
func (f *selFixture) ifID(t *testing.T, ia addr.IA) uint16 {
	t.Helper()
	entries, err := f.store.All(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range entries {
		if l.NeighborIA.Equal(ia) {
			return l.IfID
		}
	}
	t.Fatalf("no entry for %s", ia)
	return 0
}

// TestSelectionDeclaresLatency checks the window's declarations: each
// neighbor's echo round trip halved lands in the shared table the
// beaconer's entries read, and a link the next window does not measure
// declares nothing again.
func TestSelectionDeclaresLatency(t *testing.T) {
	f := newSelFixture(t, selPeer)
	latencies := controlplane.NewLinkLatency()
	f.sel.cfg.Latencies = latencies
	ifID := f.ifID(t, selPeer)

	f.samples[selPeer] = sm(10*time.Millisecond, 20*time.Millisecond)
	f.pass(t)
	if got := latencies.Sample(ifID); got != 5*time.Millisecond {
		t.Errorf("declared one-way delay = %v, want the halved round trip 5ms", got)
	}

	// A window the link goes unanswered declares nothing: the next entries
	// carry no stale sample.
	f.samples[selPeer] = sm(0, 0)
	f.pass(t)
	if got := latencies.Sample(ifID); got != 0 {
		t.Errorf("declared one-way delay past an unanswered window = %v, want 0", got)
	}
}

// TestSelectionFloorPromotion checks the redundancy floor: below it, any
// reachable candidate is promoted outright — reachability outranks latency —
// and the unreachable one is skipped.
func TestSelectionFloorPromotion(t *testing.T) {
	f := newSelFixture(t, selPeer)
	f.candidate(selA, 30*time.Millisecond, 10*time.Millisecond) // slow but reachable
	f.candidate(selB, 0, 10*time.Millisecond)                   // unreachable

	f.pass(t)
	if len(f.established) != 1 || !f.established[0].Equal(selA) {
		t.Fatalf("promoted %v, want the reachable %v", f.established, selA)
	}

	// Above the floor, the unreachable candidate stays out.
	f.pass(t)
	if f.hasEntry(t, selB) || len(f.established) != 1 {
		t.Error("an unreachable candidate was promoted above the floor")
	}
}

// TestSelectionStrandedPromotion checks the stranded clause: a tier no live
// route resolves into admits its fastest reachable member at once, no
// streak — the establishment riding the rendezvous path — and an
// unreachable member of the same tier is not that member.
func TestSelectionStrandedPromotion(t *testing.T) {
	f := newSelFixture(t, selPeer, selA) // at the floor
	// A slow tier of two: one member reachable over the rendezvous echo,
	// one silent. No up links and no clean candidates reach into it.
	f.candidate(selB, 22*time.Millisecond, 0)
	f.candidate(selC, 30*time.Millisecond, 0)

	f.pass(t) // the first window establishes: no streak for the stranded
	if len(f.established) != 1 || !f.established[0].Equal(selB) {
		t.Fatalf("promoted %v on the first window, want the stranded tier's fastest %v",
			f.established, selB)
	}
}

// TestSelectionPricedPromotion checks the beaten-baseline case: a candidate
// whose direct round trip beats its tier's price by the promotion ratio is
// promoted on the second consecutive good window, never on the first, and a
// candidate that beats no price never is — however cheap the declarations
// its unreachable self would price.
func TestSelectionPricedPromotion(t *testing.T) {
	f := newSelFixture(t, selPeer, selA)                        // at the floor
	f.candidate(selB, 8*time.Millisecond, 20*time.Millisecond)  // beats 0.8 of the 20ms price
	f.candidate(selC, 18*time.Millisecond, 20*time.Millisecond) // does not

	f.pass(t)
	if len(f.established) != 0 {
		t.Fatal("a candidate was promoted on a single good window")
	}
	f.pass(t)
	if len(f.established) != 1 || !f.established[0].Equal(selB) {
		t.Fatalf("promoted %v, want the sustained winner %v", f.established, selB)
	}
	if f.hasEntry(t, selC) {
		t.Error("a candidate that beats no price was promoted")
	}

	// A candidate that answers no probe is never promoted, however
	// favorable its tier's declared prices.
	f.candidate(selD, 0, 0, declared(1*time.Millisecond))
	for range 3 {
		f.pass(t)
	}
	if f.hasEntry(t, selD) {
		t.Error("an unreachable candidate was promoted")
	}
}

// TestSelectionSingleRoutePromotion checks the redundancy purchase: a
// single-route tier admits a second member within the demotion ratio of the
// price, sustained, and rejects one outside it.
func TestSelectionSingleRoutePromotion(t *testing.T) {
	f := newSelFixture(t, selPeer, selA) // at the floor
	// A slow tier of one member, its single route the clean path to it:
	// 22ms is within the demotion ratio of the 20ms price.
	f.candidate(selB, 22*time.Millisecond, 20*time.Millisecond, cand(link(selX)))
	f.candidate(selC, 26*time.Millisecond, 20*time.Millisecond, cand(link(selX)))

	f.pass(t)
	if len(f.established) != 0 {
		t.Fatal("the second route was purchased on a single window")
	}
	f.pass(t)
	if len(f.established) != 1 || !f.established[0].Equal(selB) {
		t.Fatalf("promoted %v, want the member within the ratio %v", f.established, selB)
	}
	if f.hasEntry(t, selC) {
		t.Error("a member outside the demotion ratio of the price was admitted")
	}
}

// TestSelectionUnpricedTier checks the unpriced reading: a tier nothing
// prices — its up link's echo unanswered and no edge declaring — promotes
// nothing, however many windows pass; the up link keeps it from stranding.
func TestSelectionUnpricedTier(t *testing.T) {
	f := newSelFixture(t, selPeer, selA)
	// A slow tier of A, up, and the candidate B, whose single route is
	// clean but undeclared.
	f.samples[selA] = sm(50*time.Millisecond, 0)
	f.candidate(selB, 55*time.Millisecond, 0, cand(link(selX)))

	for range 4 {
		f.pass(t)
	}
	if len(f.established) != 0 {
		t.Fatal("an unpriced tier promoted a candidate")
	}
}

// TestSelectionFlappingCandidate checks the damping: a candidate with a good
// window, a bad one, and a good one is never promoted — the streak resets on
// the bad window.
func TestSelectionFlappingCandidate(t *testing.T) {
	f := newSelFixture(t, selPeer, selA)
	f.candidate(selB, 8*time.Millisecond, 20*time.Millisecond)

	f.pass(t) // good: streak 1
	f.samples[selB] = sm(18*time.Millisecond, 20*time.Millisecond)
	f.pass(t) // bad: streak reset
	f.samples[selB] = sm(8*time.Millisecond, 20*time.Millisecond)
	f.pass(t) // good again: streak 1
	f.pass(t) // good: streak 2 — promoted now, four windows in
	if len(f.established) != 1 || !f.established[0].Equal(selB) {
		t.Fatalf("promoted %v, want the flapper only after sustained evidence", f.established)
	}
}

// TestSelectionOneEstablishment checks the window's budget: two stranded
// tiers' cases running together still establish one link, the fastest
// member of the strandedest the winner.
func TestSelectionOneEstablishment(t *testing.T) {
	f := newSelFixture(t, selPeer, selA) // at the floor
	// Two slow tiers, both stranded: the fastest reachable member of the
	// first wins the one establishment.
	f.candidate(selB, 22*time.Millisecond, 0)
	f.candidate(selC, 30*time.Millisecond, 0)
	f.candidate(selD, 80*time.Millisecond, 0)

	f.pass(t)
	if len(f.established) != 1 || !f.established[0].Equal(selB) {
		t.Fatalf("established %v, want the single fastest stranded member %v",
			f.established, selB)
	}
}

// TestSelectionUselessRetirement checks the useless rule: an up link whose
// exclusion leaves its tier's route count unchanged and its price within
// the demotion ratio retires on the third consecutive window decided
// useless — the survivor measured each window — and never at the floor of
// up links.
func TestSelectionUselessRetirement(t *testing.T) {
	f := newSelFixture(t, selPeer, selA, selB) // above the floor of two
	// A's baseline rides Peer's link: excluding A's link leaves the tier two
	// up links and the route through Peer answering at the price — useless —
	// and A's own round trip earns nothing.
	f.carried(selA, 18*time.Millisecond, 20*time.Millisecond, f.via(t, selPeer, 0, selPeer, selA))

	f.pass(t)
	f.pass(t)
	if f.state(t, selA) != links.StateEstablished {
		t.Fatal("a neighbor was retired before three useless windows")
	}
	f.pass(t)
	if f.state(t, selA) != links.StateRetired {
		t.Fatal("a durably useless neighbor was not retired")
	}

	// At the floor, the same useless evidence retires nothing: Peer's
	// baseline rides B's link, and a route through a third interface keeps
	// the tier's two routes without Peer's link.
	f.carried(selPeer, 10*time.Millisecond, 20*time.Millisecond,
		f.via(t, selB, 0, selB, selPeer),
		route(-time.Minute, 0, local(9), link(selX), link(selPeer)))
	for range 5 {
		f.pass(t)
	}
	if f.state(t, selPeer) != links.StateEstablished || f.state(t, selB) != links.StateEstablished {
		t.Error("an up link retired at the floor")
	}
}

// TestSelectionSecondRouteKept checks the route count's half of the useless
// test: a link bought as its tier's second route never decides useless
// while it is one of the tier's two routes, though its exclusion leaves the
// first route answering at the price — where latency alone would retire it.
func TestSelectionSecondRouteKept(t *testing.T) {
	f := newSelFixture(t, selPeer, selA, selB, selC)
	// A slow tier of B and C, both reached over B's link alone besides C's
	// own: excluding C's link leaves B's route at the price, and one route.
	f.carried(selB, 50*time.Millisecond, 60*time.Millisecond, f.via(t, selB, 0, selB))
	f.carried(selC, 55*time.Millisecond, 60*time.Millisecond, f.via(t, selB, 0, selB, selC))
	for range 5 {
		f.pass(t)
	}
	if f.state(t, selC) != links.StateEstablished {
		t.Error("the tier's second route retired as useless")
	}
}

// TestSelectionRetirementCounts checks that each rule counts its own
// windows: a down window holds the useless count, an up window resets the
// down count alone, an undecided window holds the useless count, and a
// count at DemoteWindows retires a link only in a window decided useless.
func TestSelectionRetirementCounts(t *testing.T) {
	// A down window between useless ones holds the useless count: the link
	// retires on the third useless window, not on the down one.
	f := newSelFixture(t, selPeer, selA, selB)
	f.carried(selA, 18*time.Millisecond, 20*time.Millisecond, f.via(t, selPeer, 0, selPeer, selA))
	f.pass(t)
	f.pass(t)
	f.down[selA] = true
	f.pass(t)
	if f.state(t, selA) != links.StateEstablished {
		t.Fatal("a down window added to the useless windows retired the link")
	}
	f.down[selA] = false
	f.pass(t)
	if f.state(t, selA) != links.StateRetired {
		t.Fatal("the third useless window did not retire the link")
	}

	// An up window resets the down count: two down windows, an up one, and
	// two down again retire nothing; the third consecutive one retires.
	f = newSelFixture(t, selPeer, selA, selB)
	f.down[selB] = true
	f.pass(t)
	f.pass(t)
	f.down[selB] = false
	f.pass(t)
	f.down[selB] = true
	f.pass(t)
	f.pass(t)
	if f.state(t, selB) != links.StateEstablished {
		t.Fatal("down windows on either side of an up one retired the link")
	}
	f.pass(t)
	if f.state(t, selB) != links.StateRetired {
		t.Fatal("the third consecutive down window did not retire the link")
	}

	// The floor holds A while its useless count passes the threshold; a
	// third up link lifts the floor in a window A's survivor goes
	// unanswered, which decides nothing; the next window decided useless
	// retires A.
	f = newSelFixture(t, selPeer, selA)
	carrier := f.via(t, selPeer, 0, selPeer, selA)
	f.carried(selA, 18*time.Millisecond, 20*time.Millisecond, carrier,
		route(-time.Minute, 0, local(9), link(selX), link(selA)))
	for range DemoteWindows + 1 {
		f.pass(t)
	}
	if f.state(t, selA) != links.StateEstablished {
		t.Fatal("an up link retired at the floor")
	}
	if err := f.store.Insert(context.Background(), &links.Link{
		NeighborIA: selB,
		Local:      netip.MustParseAddrPort("127.0.0.1:40001"),
		Remote:     netip.MustParseAddrPort("127.0.0.1:40002"),
		State:      links.StateEstablished,
	}); err != nil {
		t.Fatal(err)
	}
	f.directory = append(f.directory, entryOf(selB))
	f.samples[selB] = sm(10*time.Millisecond, 20*time.Millisecond)
	f.echoes[routeKey(&carrier)] = 0
	f.pass(t)
	if f.state(t, selA) != links.StateEstablished {
		t.Fatal("a count at the threshold retired the link in an undecided window")
	}
	f.echoes[routeKey(&carrier)] = 20 * time.Millisecond
	f.pass(t)
	if f.state(t, selA) != links.StateRetired {
		t.Fatal("a window decided useless past the threshold did not retire the link")
	}
}

// TestSelectionVerdictDownRetirement checks the liveness rule: a neighbor
// whose verdict stays down retires on the third window — its recovery path
// re-establishment, the peer remaining a candidate the window measures.
func TestSelectionVerdictDownRetirement(t *testing.T) {
	f := newSelFixture(t, selPeer, selA, selB)
	f.down[selB] = true

	f.pass(t)
	f.pass(t)
	if f.state(t, selB) != links.StateEstablished {
		t.Fatal("a down neighbor was retired before three windows")
	}
	f.pass(t)
	if f.state(t, selB) != links.StateRetired {
		t.Fatal("a durably down neighbor was not retired")
	}
	for _, ia := range []addr.IA{selPeer, selA} {
		if f.state(t, ia) != links.StateEstablished {
			t.Errorf("retirement took the up neighbor %s", ia)
		}
	}
}

// TestSelectionFloorCountsUpLinks checks the floor's arithmetic: it counts
// up links only, so a link the verdict marks down retires where the old
// established-entry floor would have held it, and never blocks another's
// retirement — while an up link never retires at the floor.
func TestSelectionFloorCountsUpLinks(t *testing.T) {
	// The down link retires at the up-link floor: it is no redundancy and
	// holds no floor of its own.
	f := newSelFixture(t, selPeer, selA)
	f.down[selPeer] = true
	for range DemoteWindows {
		f.pass(t)
	}
	if f.state(t, selPeer) != links.StateRetired {
		t.Fatal("the verdict-down link was held at the floor it does not count in")
	}
	if f.state(t, selA) != links.StateEstablished {
		t.Error("retirement took the up link beside it")
	}

	// The same node's promotion floor counts up links only: below it, a
	// reachable candidate is promoted outright.
	f = newSelFixture(t, selPeer, selA)
	f.down[selPeer] = true
	f.candidate(selB, 30*time.Millisecond, 10*time.Millisecond)
	f.pass(t)
	if len(f.established) != 1 || !f.established[0].Equal(selB) {
		t.Fatalf("promoted %v, want the reachable candidate below the up-link floor",
			f.established)
	}
}

// TestSelectionOneUpLinkPerWindow checks the departure budget: useless up
// links retire one per window, down to the floor — each departure changes
// the routes the others' exclusions were measured against.
func TestSelectionOneUpLinkPerWindow(t *testing.T) {
	f := newSelFixture(t, selPeer, selA, selB, selC, selD)
	// A, B, and C ride Peer's link: every exclusion but Peer's leaves the
	// tier two up links and an answered route at the price.
	for _, ia := range []addr.IA{selA, selB, selC} {
		f.carried(ia, 18*time.Millisecond, 20*time.Millisecond, f.via(t, selPeer, 0, selPeer, ia))
	}
	retired := func() int {
		n := 0
		for _, ia := range []addr.IA{selPeer, selA, selB, selC, selD} {
			if f.state(t, ia) == links.StateRetired {
				n++
			}
		}
		return n
	}
	for range DemoteWindows - 1 {
		f.pass(t)
	}
	for _, want := range []int{1, 2, 3, 3} {
		f.pass(t)
		if got := retired(); got != want {
			t.Fatalf("retired links = %d, want %d", got, want)
		}
	}
	if f.state(t, selPeer) != links.StateEstablished {
		t.Error("the link every other route rides retired")
	}
}

// TestSelectionEvictionBlocksPrune checks that an eviction spends the
// window's departure: the window whose eviction takes an up link retires
// no useless one, and the next window does.
func TestSelectionEvictionBlocksPrune(t *testing.T) {
	neighbors := []addr.IA{selPeer, selA, selB, selC}
	f := newSelFixture(t, neighbors...)
	f.sel.cfg.MaxLinks = len(neighbors)
	// A and B ride Peer's link, useless from the first window; B is the
	// slower direct sample.
	f.carried(selA, 18*time.Millisecond, 20*time.Millisecond, f.via(t, selPeer, 0, selPeer, selA))
	f.carried(selB, 19*time.Millisecond, 20*time.Millisecond, f.via(t, selPeer, 0, selPeer, selB))
	f.pass(t)
	// D beats the price, sustained from the second window: the third
	// window evicts at the cap while A's useless count reaches the
	// threshold.
	f.candidate(selD, 8*time.Millisecond, 20*time.Millisecond)
	f.pass(t)
	f.pass(t)
	if len(f.established) != 1 || !f.established[0].Equal(selD) {
		t.Fatalf("promoted %v, want the candidate", f.established)
	}
	if f.state(t, selB) != links.StateRetired {
		t.Fatal("the eviction took another link than the slowest least-harm one")
	}
	if f.state(t, selA) != links.StateEstablished {
		t.Fatal("the window of an eviction also retired a useless up link")
	}
	f.pass(t)
	if f.state(t, selA) != links.StateRetired {
		t.Fatal("the window after the eviction retired no useless up link")
	}
}

// TestSelectionCutCritical checks the guard the useless test holds by
// construction: the bridge, its tier's only route, decides nothing and never
// retires as useless, while the useless link beside it does; and once the
// bridge's verdict stays down it retires at its count, for no guard holds a
// link that carries no route.
func TestSelectionCutCritical(t *testing.T) {
	f := newSelFixture(t, selPeer, selA, selB, selC)
	// B is the slow tier's only link, and every route into the tier rides it.
	f.carried(selB, 50*time.Millisecond, 60*time.Millisecond, f.via(t, selB, 0, selB))
	// A is useless in the fast tier, its baseline riding Peer's link.
	f.carried(selA, 18*time.Millisecond, 20*time.Millisecond, f.via(t, selPeer, 0, selPeer, selA))

	for range 5 {
		f.pass(t)
	}
	if f.state(t, selB) != links.StateEstablished {
		t.Fatal("the bridge was retired as useless")
	}
	if f.state(t, selA) != links.StateRetired {
		t.Error("the useless link beside it kept its entry")
	}

	f.down[selB] = true
	for range DemoteWindows {
		f.pass(t)
	}
	if f.state(t, selB) != links.StateRetired {
		t.Fatal("a guard held the down bridge")
	}
}

// TestSelectionCapEviction checks the cap: at it, an admission evicts the
// retirement-qualified neighbor whose exclusion moves its tier's price
// least, ties to the slower direct sample; none qualifying means no
// promotion; the bridge, whose exclusion leaves no answered survivor, is
// never evicted and the promotion waits; and a down link whose count
// reached DemoteWindows goes at no harm.
func TestSelectionCapEviction(t *testing.T) {
	neighbors := []addr.IA{selPeer, selA, selB, selC}
	f := newSelFixture(t, neighbors...)
	f.sel.cfg.MaxLinks = len(neighbors)
	// C's baseline rides A's link and sets the price at 16ms: excluding A's
	// link raises it to 20ms, a harm of 4ms. Excluding B's or C's moves it
	// by nothing, and B is the slower direct sample.
	f.carried(selA, 10*time.Millisecond, 20*time.Millisecond, f.via(t, selPeer, 0, selPeer, selA))
	f.carried(selB, 12*time.Millisecond, 20*time.Millisecond, f.via(t, selPeer, 0, selPeer, selB))
	f.carried(selC, 10*time.Millisecond, 16*time.Millisecond, f.via(t, selA, 0, selA, selC))
	f.candidate(selD, 8*time.Millisecond, 20*time.Millisecond)

	f.pass(t) // streak 1
	f.pass(t) // streak 2: evicts B and admits D
	if len(f.established) != 1 || !f.established[0].Equal(selD) {
		t.Fatalf("promoted %v, want the displacing candidate", f.established)
	}
	if f.state(t, selB) != links.StateRetired {
		t.Error("the slower of the least-harm links was not displaced")
	}
	for _, ia := range []addr.IA{selPeer, selA, selC} {
		if f.state(t, ia) != links.StateEstablished {
			t.Errorf("displacement retired %s as well", ia)
		}
	}

	// None qualifying means no promotion: the cap stands.
	f = newSelFixture(t, neighbors...)
	f.sel.cfg.MaxLinks = len(neighbors)
	f.candidate(selD, 8*time.Millisecond, 20*time.Millisecond)
	f.pass(t)
	f.pass(t)
	if len(f.established) != 0 {
		t.Error("a candidate displaced a neighbor no retirement rule qualified")
	}

	// The bridge B, alone in a slow tier with no route around its link,
	// decides nothing: with nothing else qualifying, the promotion waits.
	// Then C's verdict stays down, and at its count C is the victim.
	f = newSelFixture(t, neighbors...)
	f.sel.cfg.MaxLinks = len(neighbors)
	f.carried(selB, 50*time.Millisecond, 60*time.Millisecond, f.via(t, selB, 0, selB))
	f.candidate(selD, 8*time.Millisecond, 20*time.Millisecond)
	f.pass(t)
	f.pass(t)
	if len(f.established) != 0 || f.state(t, selB) != links.StateEstablished {
		t.Fatal("the promotion evicted the bridge")
	}
	f.down[selC] = true
	for range DemoteWindows - 1 {
		f.pass(t)
	}
	if len(f.established) != 0 {
		t.Fatal("the eviction took the down link short of its count")
	}
	f.pass(t)
	if len(f.established) != 1 || !f.established[0].Equal(selD) {
		t.Fatalf("promoted %v, want the candidate once the down link reached its count",
			f.established)
	}
	if f.state(t, selC) != links.StateRetired || f.state(t, selB) != links.StateEstablished {
		t.Error("the eviction took the bridge, or left the down link")
	}
}

// TestSelectionEquilibrium plays regional meshes joined by a bridge at a cap
// of three: the regional links R1 and R2 and the bridge Z, a composed route
// through the bridge giving the region a third route. A faster regional
// candidate R3, sustained, evicts a regional link, never the bridge, whose
// exclusion leaves its tier no answered route. Then the bridge goes down
// while a far candidate W appears: the far tier strands, and its rescue
// waits — the regional links, the floor's two up links, qualify for
// nothing — until the bridge's down count reaches DemoteWindows and the
// eviction takes it at no harm.
func TestSelectionEquilibrium(t *testing.T) {
	r1, r2, z, r3, w := selA, selB, selC, selD, selE
	f := newSelFixture(t, r1, r2, z)
	f.sel.cfg.MaxLinks = 3
	// R1 and R2 reach each other over their own links, and both by the
	// round route through the bridge. R2 is the slower direct sample, so
	// the tie between the two regional evictions is decided.
	f.carried(r1, 10*time.Millisecond, 20*time.Millisecond,
		f.via(t, r2, 0, r2, r1), f.via(t, z, -time.Minute, z, selX, r1))
	f.carried(r2, 11*time.Millisecond, 20*time.Millisecond,
		f.via(t, r1, 0, r1, r2), f.via(t, z, -time.Minute, z, selX, r2))
	f.carried(z, 100*time.Millisecond, 200*time.Millisecond, f.via(t, z, 0, z))
	viaR1 := f.via(t, r1, 0, r1, r3)
	f.candidate(r3, 5*time.Millisecond, 20*time.Millisecond, viaR1)
	f.echoes[routeKey(&viaR1)] = 20 * time.Millisecond

	f.pass(t)
	f.pass(t)
	if len(f.established) != 1 || !f.established[0].Equal(r3) {
		t.Fatalf("promoted %v, want the faster regional candidate", f.established)
	}
	if f.state(t, r2) != links.StateRetired {
		t.Fatal("the eviction took another link than a regional one")
	}
	if f.state(t, r1) != links.StateEstablished || f.state(t, z) != links.StateEstablished {
		t.Fatal("the eviction took the bridge or both regional links")
	}

	// The bridge goes down: its one-hop echo and its routes fail. W, far,
	// answers its rendezvous echo, and its routes all ride the bridge.
	f.down[z] = true
	f.samples[z] = sm(0, 0, f.via(t, z, 0, z))
	f.carried(r1, 10*time.Millisecond, 20*time.Millisecond,
		f.via(t, r3, 0, r3, r1), f.via(t, z, -time.Minute, z, selX, r1))
	f.carried(r3, 5*time.Millisecond, 20*time.Millisecond, f.via(t, r1, 0, r1, r3))
	f.candidate(w, 100*time.Millisecond, 0, f.via(t, z, 0, z, w))
	for range DemoteWindows - 1 {
		f.pass(t)
	}
	if len(f.established) != 1 || f.state(t, z) != links.StateEstablished {
		t.Fatal("the rescue displaced a link short of the bridge's down count")
	}
	f.pass(t)
	if len(f.established) != 2 || !f.established[1].Equal(w) {
		t.Fatalf("promoted %v, want the stranded far candidate", f.established)
	}
	if f.state(t, z) != links.StateRetired {
		t.Error("the rescue did not take the down bridge")
	}
	for _, ia := range []addr.IA{r1, r3} {
		if f.state(t, ia) != links.StateEstablished {
			t.Errorf("the rescue took the regional link %s", ia)
		}
	}
}

// TestSelectionStrandedFlag checks the dialer's trigger: the window records
// the node stranded only while it holds fewer up links than the floor and
// no directory candidate answered its probe.
func TestSelectionStrandedFlag(t *testing.T) {
	f := newSelFixture(t, selPeer, selA)
	var stranded atomic.Bool
	f.sel.cfg.Stranded = &stranded
	// The establishments fail, so the windows below keep the table as set.
	f.sel.establishFn = func(context.Context, DirectoryEntry, string) bool { return false }

	// At the floor, every directory peer a neighbor: no candidate answers,
	// and still the node is not stranded.
	f.pass(t)
	if stranded.Load() {
		t.Error("a node at the floor recorded itself stranded")
	}

	// One up link short of the floor with no candidate: stranded.
	f.down[selA] = true
	f.pass(t)
	if !stranded.Load() {
		t.Error("a node below the floor with no candidate recorded itself unstranded")
	}

	// A candidate answers: not stranded.
	f.candidate(selB, 30*time.Millisecond, 0)
	f.pass(t)
	if stranded.Load() {
		t.Error("a window with a reachable candidate recorded the node stranded")
	}

	// The candidate goes silent: stranded again.
	f.samples[selB] = sm(0, 0)
	f.pass(t)
	if !stranded.Load() {
		t.Error("a window no candidate answered recorded the node unstranded")
	}
}

// TestSelectionCapCountsCandidates checks what the cap counts: the named
// live entries, so a named candidate in flight holds its place, and a
// promotion past it needs an eviction even while the established neighbors
// alone sit below the cap.
func TestSelectionCapCountsCandidates(t *testing.T) {
	neighbors := []addr.IA{selPeer, selA, selB}
	f := newSelFixture(t, neighbors...)
	f.sel.cfg.MaxLinks = len(neighbors) + 1
	// No route survives an exclusion, so none qualifies a neighbor for
	// eviction.
	// A peer's own dial minted a named candidate the sweep has not settled.
	if err := f.store.Insert(context.Background(), &links.Link{
		NeighborIA: selC,
		Local:      netip.MustParseAddrPort("127.0.0.1:40001"),
		Remote:     netip.MustParseAddrPort("127.0.0.1:40002"),
		State:      links.StateCandidate,
	}); err != nil {
		t.Fatal(err)
	}
	f.candidate(selD, 8*time.Millisecond, 20*time.Millisecond)

	f.pass(t) // streak 1
	f.pass(t) // streak 2: at the cap, nothing qualifies for eviction
	if len(f.established) != 0 {
		t.Errorf("promoted %v past the candidate holding the cap's last place", f.established)
	}
}

// TestSelectionSweepCandidateWindow checks the candidate sweep: an unproven
// candidate retires once the window passes, a proven one is established.
// The sweep reads the clock, so the test runs in a bubble: the window's
// passage is a fake-time sleep — instant, and never a real-time race.
func TestSelectionSweepCandidateWindow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newSelFixture(t)
		f.sel.cfg.Window = 10 * time.Millisecond
		unproven := &links.Link{
			Local:  netip.MustParseAddrPort("127.0.0.1:40001"),
			Remote: netip.MustParseAddrPort("127.0.0.1:40002"),
			State:  links.StateCandidate,
		}
		if err := f.store.Insert(context.Background(), unproven); err != nil {
			t.Fatal(err)
		}
		proven := &links.Link{
			NeighborIA: selPeer,
			Local:      netip.MustParseAddrPort("127.0.0.1:40003"),
			Remote:     netip.MustParseAddrPort("127.0.0.1:40004"),
			State:      links.StateCandidate,
		}
		if err := f.store.Insert(context.Background(), proven); err != nil {
			t.Fatal(err)
		}
		f.sel.cfg.Evidence = func(l *links.Link) bool { return l.IfID == proven.IfID }

		time.Sleep(20 * time.Millisecond)
		f.pass(t)
		if f.state(t, selPeer) != links.StateEstablished {
			t.Error("the proven candidate was not established")
		}
		entries, err := f.store.All(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, l := range entries {
			if l.IfID == unproven.IfID {
				found = true
				if l.State != links.StateRetired {
					t.Error("the unproven candidate outlived the window")
				}
			}
		}
		if !found {
			t.Error("the unproven candidate vanished instead of retiring")
		}
	})
}

// TestSelectionNoAction checks the comparator's quiet case: neutral
// evidence — no verdict edges, no streak thresholds met, no cap pressure —
// moves nothing.
func TestSelectionNoAction(t *testing.T) {
	f := newSelFixture(t, selPeer, selA)
	f.samples[selPeer] = sm(20*time.Millisecond, 20*time.Millisecond)
	f.candidate(selB, 20*time.Millisecond, 20*time.Millisecond)

	for range 4 {
		f.pass(t)
	}
	entries, err := f.store.All(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("the table changed on neutral evidence: %v", entries)
	}
	if f.changed != 0 {
		t.Errorf("change notifications = %d, want 0", f.changed)
	}
}

// TestSelectionSweepGrace checks the candidacy grace: the sweep's own probe
// is its only recency evidence — a named candidate whose rendezvous socket
// answers the window's probe is alive and trying, exactly the joiner whose
// enrollment is still in flight, and retires when it goes silent. The grace
// is spent on named candidates alone: the unnamed entries the probes
// themselves mint on their targets retire with the window. The test runs in
// a bubble: outliving the window is a fake-time sleep, instant and exact.
func TestSelectionSweepGrace(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newSelFixture(t)
		f.sel.cfg.Window = 50 * time.Millisecond
		insertCandidate := func(name addr.IA) *links.Link {
			l := &links.Link{
				NeighborIA: name,
				Local:      netip.MustParseAddrPort("127.0.0.1:40001"),
				Remote:     netip.MustParseAddrPort("127.0.0.1:40002"),
				State:      links.StateCandidate,
			}
			if err := f.store.Insert(context.Background(), l); err != nil {
				t.Fatal(err)
			}
			return l
		}
		answering := insertCandidate(selA)
		_ = insertCandidate(selB)
		unnamed := &links.Link{
			Local:  netip.MustParseAddrPort("127.0.0.1:40003"),
			Remote: netip.MustParseAddrPort("127.0.0.1:40004"),
			State:  links.StateCandidate,
		}
		if err := f.store.Insert(context.Background(), unnamed); err != nil {
			t.Fatal(err)
		}
		time.Sleep(60 * time.Millisecond) // the candidates outlive the window

		f.alive[selA] = true // the window's probe answers
		f.pass(t)
		if f.state(t, selA) != links.StateCandidate {
			t.Error("the answering candidate's grace did not hold")
		}
		if f.state(t, selB) != links.StateRetired {
			t.Error("the silent candidate outlived the window")
		}
		entries, err := f.store.All(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range entries {
			if l.IfID == unnamed.IfID && l.State != links.StateRetired {
				t.Error("the unnamed candidate outlived the window")
			}
		}

		// The grace reads probe outcomes, not identity: once the probe goes
		// unanswered, the entry retires on the next sweep.
		f.alive[selA] = false
		f.pass(t)
		if f.state(t, selA) != links.StateRetired {
			t.Error("the candidate kept its grace after going silent")
		}
		_ = answering
	})
}

// TestSelectionScopeFilter checks the candidate skip's scope filter: a
// loopback viewer probes loopback and global entries and skips the private,
// shared, and link-local ones; a global viewer probes the global entries
// alone. Every entry carries an unreachable sample, so the filter is the
// only thing that decides what the pass measures.
func TestSelectionScopeFilter(t *testing.T) {
	newDirectory := func() ([]addr.IA, map[addr.IA]string) {
		return []addr.IA{selA, selB, selC, selD, selE}, map[addr.IA]string{
			selA: "192.0.2.10:30043",  // global
			selB: "127.0.0.5:30043",   // loopback
			selC: "192.168.1.5:30043", // private
			selD: "100.64.0.5:30043",  // the CGNAT shared range
			selE: "169.254.0.5:30043", // link-local
		}
	}

	// The loopback viewer: loopback shares its scope, global is always
	// probeable, the rest skip.
	f := newSelFixture(t)
	ias, rendezvous := newDirectory()
	for _, ia := range ias {
		f.directory = append(f.directory, scopedEntry(ia, rendezvous[ia]))
		f.samples[ia] = sm(0, 10*time.Millisecond)
	}
	f.pass(t)
	for _, ia := range []addr.IA{selA, selB} {
		if !f.probed[ia] {
			t.Errorf("the loopback viewer skipped %v at %s, want it probed", ia,
				rendezvous[ia])
		}
	}
	for _, ia := range []addr.IA{selC, selD, selE} {
		if f.probed[ia] {
			t.Errorf("the loopback viewer probed %v at %s, want it skipped", ia,
				rendezvous[ia])
		}
	}

	// The global viewer: the global entries alone.
	f = newSelFixture(t)
	f.sel.cfg.ControlAddr = netip.MustParseAddrPort("203.0.113.7:30042")
	ias, rendezvous = newDirectory()
	for _, ia := range ias {
		f.directory = append(f.directory, scopedEntry(ia, rendezvous[ia]))
		f.samples[ia] = sm(0, 10*time.Millisecond)
	}
	f.pass(t)
	if !f.probed[selA] {
		t.Error("the global viewer skipped the global entry")
	}
	for _, ia := range []addr.IA{selB, selC, selD, selE} {
		if f.probed[ia] {
			t.Errorf("the global viewer probed %v at %s, want it skipped", ia,
				rendezvous[ia])
		}
	}
}

// TestSelectionRendezvousGuard checks the rendezvous establishment's guard:
// a reply naming the entry's ISD-AS records the link, one naming another
// ISD-AS — the answer of a colliding subnet's real peer at the published
// address — is refused, and the dial learns the reply's observed host.
func TestSelectionRendezvousGuard(t *testing.T) {
	f := newRendezvousFixture(t, func(cfg *RendezvousConfig) {
		cfg.IA = rendezvousIA
	})
	var learned []netip.Addr
	s := &selection{
		cfg: SelectionConfig{
			Store:    memory.New(),
			LinkHost: netip.MustParseAddr("127.0.0.1"),
			Learn:    func(host netip.Addr) { learned = append(learned, host) },
		},
	}
	entry := func(t *testing.T, claimed addr.IA) *links.Link {
		t.Helper()
		l := &links.Link{
			NeighborIA: claimed,
			Local:      netip.MustParseAddrPort("127.0.0.1:40001"),
			State:      links.StateCandidate,
		}
		if err := s.cfg.Store.Insert(context.Background(), l); err != nil {
			t.Fatal(err)
		}
		return l
	}

	// The matching reply records the link's remote side.
	l := entry(t, rendezvousIA)
	e := scopedEntry(rendezvousIA, f.addr.String())
	if !s.establishByRendezvous(context.Background(), e, l) {
		t.Fatal("the guarded establishment of the matching reply failed")
	}
	updated, err := s.cfg.Store.ByNeighbor(context.Background(), rendezvousIA)
	if err != nil || updated == nil {
		t.Fatalf("no recorded establishment (%v)", err)
	}
	if !updated.Remote.IsValid() || updated.RemoteIfID == 0 {
		t.Errorf("recorded remote = %v, interface %d, want the reply's side",
			updated.Remote, updated.RemoteIfID)
	}
	if len(learned) != 1 || learned[0] != netip.MustParseAddr("127.0.0.1") {
		t.Errorf("learned hosts = %v, want the dial's observed 127.0.0.1", learned)
	}

	// A reply naming another ISD-AS is refused: the entry keeps its side.
	l = entry(t, strangerKeyIA)
	e = scopedEntry(strangerKeyIA, f.addr.String())
	if s.establishByRendezvous(context.Background(), e, l) {
		t.Error("an establishment whose reply named another ISD-AS recorded")
	}
	updated, err = s.cfg.Store.ByNeighbor(context.Background(), strangerKeyIA)
	if err != nil || updated == nil {
		t.Fatalf("no entry of the refused establishment (%v)", err)
	}
	if updated.Remote.IsValid() {
		t.Errorf("the refused establishment recorded the remote %v", updated.Remote)
	}
}
