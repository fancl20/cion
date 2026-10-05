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
// directory snapshot, the monitor's verdicts, injected measurements and
// excluded measurements, and injected candidate-grace probes. The
// establishment is recorded rather than performed; the promotion and
// retirement rules are what the tests assert.
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
	// excluded holds the injected excluded measurements by the questioned
	// link's interface ID; an unset one resolves a survivor that answers
	// nothing — unmeasured, never cut-critical.
	excluded    map[uint16]*excludedSample
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
		excluded: make(map[uint16]*excludedSample),
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
		excludedFn: func(_ context.Context, _ []addr.IA, exclude segment.LinkID) excludedSample {
			if ex := f.excluded[exclude.IfID]; ex != nil {
				return *ex
			}
			return excludedSample{survived: true}
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

// setExcluded injects the excluded measurement of the neighbor's link.
func (f *selFixture) setExcluded(t *testing.T, ia addr.IA, ex excludedSample) {
	t.Helper()
	f.excluded[f.ifID(t, ia)] = &ex
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
// prices — no echo answered and no edge declares — promotes nothing,
// however many windows pass.
func TestSelectionUnpricedTier(t *testing.T) {
	f := newSelFixture(t, selPeer, selA)
	// A slow tier of one member whose single route is clean but undeclared.
	f.candidate(selB, 22*time.Millisecond, 0, cand(link(selX)))

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

// TestSelectionUselessRetirement checks the useless rule: a link whose
// excluded baseline serves its tier no worse than the demotion ratio above
// the price retires on the third consecutive bad window, the survivor is
// measured each window — an unanswered one extends no streak, a useful one
// resets it — and never below the floor of up links.
func TestSelectionUselessRetirement(t *testing.T) {
	f := newSelFixture(t, selPeer, selA, selB) // above the floor of two
	// A's exclusion leaves the tier served at the price — useless — and its
	// own direct round trip earns nothing: the retirement sticks.
	f.samples[selA] = sm(18*time.Millisecond, 20*time.Millisecond)
	f.setExcluded(t, selA, excludedSample{survived: true, echo: 20 * time.Millisecond})

	f.pass(t)
	f.pass(t)
	if f.state(t, selA) != links.StateEstablished {
		t.Fatal("a neighbor was retired before three bad windows")
	}
	f.pass(t)
	if f.state(t, selA) != links.StateRetired {
		t.Fatal("a durably useless neighbor was not retired")
	}

	// At the floor, the same useless evidence retires nothing.
	f.setExcluded(t, selPeer, excludedSample{survived: true, echo: 20 * time.Millisecond})
	for range 5 {
		f.pass(t)
	}
	if f.state(t, selPeer) != links.StateEstablished || f.state(t, selB) != links.StateEstablished {
		t.Error("an up link retired at the floor")
	}
}

// TestSelectionUselessStreak checks the measurement's own rules: a window
// the excluded enumeration resolves a survivor the echo cannot answer
// leaves the streak intact but unextended — no evidence, no retirement —
// and a window the survivor serves the tier usefully resets it.
func TestSelectionUselessStreak(t *testing.T) {
	// Unanswered: the streak survives a quiet window unextended.
	f := newSelFixture(t, selPeer, selA, selB)
	f.samples[selA] = sm(18*time.Millisecond, 20*time.Millisecond)
	f.setExcluded(t, selA, excludedSample{survived: true, echo: 20 * time.Millisecond})
	f.pass(t)                                              // bad: streak 1
	f.pass(t)                                              // bad: streak 2
	f.setExcluded(t, selA, excludedSample{survived: true}) // the echo went unanswered
	f.pass(t)                                              // unmeasured: streak 2 still
	f.setExcluded(t, selA, excludedSample{survived: true, echo: 20 * time.Millisecond})
	f.pass(t) // bad: streak 3 — retired now
	if f.state(t, selA) != links.StateRetired {
		t.Fatal("the unmeasured window extended the streak")
	}

	// Useful: the streak resets.
	f = newSelFixture(t, selPeer, selA, selB)
	f.samples[selA] = sm(18*time.Millisecond, 20*time.Millisecond)
	f.setExcluded(t, selA, excludedSample{survived: true, echo: 20 * time.Millisecond})
	f.pass(t) // bad: streak 1
	f.pass(t) // bad: streak 2
	f.setExcluded(t, selA, excludedSample{survived: true, echo: 40 * time.Millisecond})
	f.pass(t) // useful: reset
	f.setExcluded(t, selA, excludedSample{survived: true, echo: 20 * time.Millisecond})
	f.pass(t) // bad: streak 1
	if f.state(t, selA) != links.StateEstablished {
		t.Fatal("a neighbor was retired without three consecutive bad windows")
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

// TestSelectionCutCritical checks the guard: a link whose exclusion leaves
// its tier without a live route never retires, however slow its verdict or
// useless its exclusion — the bridge survives on measured merit, healing is
// promotion's work.
func TestSelectionCutCritical(t *testing.T) {
	f := newSelFixture(t, selPeer, selA, selB, selC)
	// B is the slow tier's only link, and its exclusion strands the tier:
	// no survivor, no other up link.
	f.samples[selB] = sm(50*time.Millisecond, 60*time.Millisecond)
	f.setExcluded(t, selB, excludedSample{})
	f.down[selB] = true
	// A is useless in the fast tier, its exclusion serving it no worse.
	f.samples[selA] = sm(18*time.Millisecond, 20*time.Millisecond)
	f.setExcluded(t, selA, excludedSample{survived: true, echo: 20 * time.Millisecond})

	for range 5 {
		f.pass(t)
	}
	if f.state(t, selB) != links.StateEstablished {
		t.Fatal("the cut-critical bridge was retired")
	}
	if f.state(t, selA) != links.StateRetired {
		t.Error("the useless link beside it kept its entry")
	}
}

// TestSelectionCapEviction checks the cap: at it, an admission evicts the
// retirement-qualified neighbor whose exclusion moves its tier's baseline
// least, ties to the slower direct sample; none qualifying means no
// promotion; and a bridge whose exclusion strands its tier is not eligible
// and blocks the promotion.
func TestSelectionCapEviction(t *testing.T) {
	neighbors := []addr.IA{selPeer, selA, selB, selC}
	f := newSelFixture(t, neighbors...)
	f.sel.cfg.MaxLinks = len(neighbors)
	// B is the slower direct sample of the two least-harm evictions; the
	// other two exclusions serve their tiers too well to qualify.
	f.setExcluded(t, selA, excludedSample{survived: true, echo: 20 * time.Millisecond})
	f.setExcluded(t, selB, excludedSample{survived: true, echo: 20 * time.Millisecond})
	f.setExcluded(t, selPeer, excludedSample{survived: true, echo: 40 * time.Millisecond})
	f.setExcluded(t, selC, excludedSample{survived: true, echo: 40 * time.Millisecond})
	f.samples[selB] = sm(12*time.Millisecond, 20*time.Millisecond)
	f.candidate(selD, 8*time.Millisecond, 20*time.Millisecond)

	f.pass(t) // streak 1
	f.pass(t) // streak 2: evicts B and admits D
	if len(f.established) != 1 || !f.established[0].Equal(selD) {
		t.Fatalf("promoted %v, want the displacing candidate", f.established)
	}
	if f.state(t, selB) != links.StateRetired {
		t.Error("the slower of the least-harm pair was not displaced")
	}
	for _, ia := range []addr.IA{selPeer, selA, selC} {
		if f.state(t, ia) != links.StateEstablished {
			t.Errorf("displacement retired %s as well", ia)
		}
	}

	// None qualifying means no promotion: the cap stands.
	f = newSelFixture(t, neighbors...)
	f.sel.cfg.MaxLinks = len(neighbors)
	for _, ia := range neighbors {
		f.setExcluded(t, ia, excludedSample{survived: true, echo: 40 * time.Millisecond})
	}
	f.candidate(selD, 8*time.Millisecond, 20*time.Millisecond)
	f.pass(t)
	f.pass(t)
	if len(f.established) != 0 {
		t.Error("a candidate displaced a neighbor no retirement rule qualified")
	}

	// The bridge is not eligible: its exclusion strands its tier, so the
	// promotion it alone could serve is blocked.
	f = newSelFixture(t, neighbors...)
	f.sel.cfg.MaxLinks = len(neighbors)
	f.samples[selB] = sm(50*time.Millisecond, 60*time.Millisecond)
	f.setExcluded(t, selB, excludedSample{})
	f.down[selB] = true
	for _, ia := range []addr.IA{selPeer, selA, selC} {
		f.setExcluded(t, ia, excludedSample{survived: true, echo: 40 * time.Millisecond})
	}
	// Three windows build the dead bridge's sustained-down streak — the
	// retirement test it would qualify under — while the candidate earns
	// none; then the candidate turns fast.
	f.candidate(selD, 18*time.Millisecond, 20*time.Millisecond)
	for range 3 {
		f.pass(t)
	}
	f.samples[selD] = sm(8*time.Millisecond, 20*time.Millisecond)
	f.pass(t) // streak 1
	f.pass(t) // streak 2: the eviction finds no eligible neighbor
	if len(f.established) != 0 {
		t.Fatal("the promotion evicted the bridge its exclusion strands")
	}
	if f.state(t, selB) != links.StateEstablished {
		t.Error("the bridge was retired at the cap")
	}
}

// TestSelectionStrandedFlag checks the dialer's trigger: the window records
// whether any directory candidate answered its probe — the flag the
// joiner's dial loop reads to re-dial what the table holds.
func TestSelectionStrandedFlag(t *testing.T) {
	f := newSelFixture(t, selPeer)
	var stranded atomic.Bool
	f.sel.cfg.Stranded = &stranded

	f.candidate(selA, 30*time.Millisecond, 0)
	f.pass(t)
	if stranded.Load() {
		t.Error("a window with a reachable candidate recorded the node stranded")
	}
	f.samples[selA] = sm(0, 0)
	f.pass(t)
	if !stranded.Load() {
		t.Error("a window no candidate answered recorded the node unstranded")
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
