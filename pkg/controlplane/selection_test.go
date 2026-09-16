package controlplane

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/links"
	"github.com/fancl20/cion/pkg/links/impl/memory"
)

// selFixture is the selection loop's test harness: a memory link store, a
// directory snapshot, greeting liveness, and injected measurements. The
// establishment is recorded rather than performed; the promotion and
// demotion rules are what the tests assert.
type selFixture struct {
	store       *memory.DB
	directory   []DirectoryEntry
	samples     map[addr.IA]measurement
	fresh       map[uint16]Neighbor
	silent      map[addr.IA]bool // neighbors whose greetings timed out
	established []addr.IA        // the promoted candidates, in order
	retired     []addr.IA        // the demoted neighbors, in order
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
)

func entryOf(ia addr.IA) DirectoryEntry {
	return DirectoryEntry{
		IA:             ia,
		ControlAddr:    netip.MustParseAddrPort("127.0.0.1:30043"),
		RendezvousAddr: netip.MustParseAddrPort("127.0.0.1:30045"),
	}
}

func newSelFixture(t *testing.T, neighbors ...addr.IA) *selFixture {
	t.Helper()
	f := &selFixture{
		store:   memory.New(),
		samples: make(map[addr.IA]measurement),
		fresh:   make(map[uint16]Neighbor),
		silent:  make(map[addr.IA]bool),
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
		f.samples[ia] = measurement{direct: 10 * time.Millisecond, path: 20 * time.Millisecond}
	}
	f.sel = &selection{
		cfg: SelectionConfig{
			IA:      selIA,
			Store:   f.store,
			Changed: func() { f.changed++ },
			Window:  time.Hour, // the candidate sweep never retires in these
		},
		streaks: make(map[addr.IA]*peerStreak),
		probeFn: func(_ context.Context, e DirectoryEntry) measurement {
			return f.samples[e.IA]
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
	f.sel.cfg.Neighbors = func() map[uint16]Neighbor { return f.fresh }
	// Every established neighbor is greeting-fresh unless a test says
	// otherwise.
	f.sel.cfg.Evidence = func(*links.Link) bool { return false }
	f.refresh()
	return f
}

// refresh rebuilds the greeting-fresh map from the established entries,
// minus the silent ones.
func (f *selFixture) refresh() {
	entries, err := f.store.All(context.Background())
	if err != nil {
		return
	}
	f.fresh = make(map[uint16]Neighbor)
	for _, l := range entries {
		if l.State == links.StateEstablished && !f.silent[l.NeighborIA] {
			f.fresh[l.IfID] = Neighbor{IA: l.NeighborIA, IfID: l.RemoteIfID}
		}
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
func (f *selFixture) candidate(ia addr.IA, direct, path time.Duration) {
	f.directory = append(f.directory, entryOf(ia))
	f.samples[ia] = measurement{direct: direct, path: path}
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

// TestSelectionRatioPromotion checks the sustained-evidence rule: a
// candidate whose direct link beats its path baseline by the promotion ratio
// is promoted on the second consecutive good window, never on the first,
// and a candidate that does not beat the baseline never is.
func TestSelectionRatioPromotion(t *testing.T) {
	f := newSelFixture(t, selPeer, selA)                        // at the floor
	f.candidate(selB, 8*time.Millisecond, 20*time.Millisecond)  // beats 0.8
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
		t.Error("a candidate that does not beat its baseline was promoted")
	}
}

// TestSelectionFlappingCandidate checks the damping: a candidate with a good
// window, a bad one, and a good one is never promoted — the streak resets on
// the bad window.
func TestSelectionFlappingCandidate(t *testing.T) {
	f := newSelFixture(t, selPeer, selA)
	f.candidate(selB, 8*time.Millisecond, 20*time.Millisecond)

	f.pass(t) // good: streak 1
	f.samples[selB] = measurement{direct: 18 * time.Millisecond, path: 20 * time.Millisecond}
	f.pass(t) // bad: streak reset
	f.samples[selB] = measurement{direct: 8 * time.Millisecond, path: 20 * time.Millisecond}
	f.pass(t) // good again: streak 1
	f.pass(t) // good: streak 2 — promoted now, four windows in
	if len(f.established) != 1 || !f.established[0].Equal(selB) {
		t.Fatalf("promoted %v, want the flapper only after sustained evidence", f.established)
	}
}

// TestSelectionDemotion checks the demotion rule: a neighbor whose direct
// link durably loses to its path baseline retires on the third consecutive
// bad window, and never below the floor.
func TestSelectionDemotion(t *testing.T) {
	f := newSelFixture(t, selPeer, selA, selB) // above the floor of two
	f.samples[selA] = measurement{direct: 30 * time.Millisecond, path: 20 * time.Millisecond}

	f.pass(t)
	f.pass(t)
	if f.state(t, selA) != links.StateEstablished {
		t.Fatal("a neighbor was demoted before three bad windows")
	}
	f.pass(t)
	if f.state(t, selA) != links.StateRetired {
		t.Fatal("a durably slow neighbor was not demoted")
	}
	if f.state(t, selPeer) != links.StateEstablished || f.state(t, selB) != links.StateEstablished {
		t.Error("demotion took neighbors other than the slow one")
	}

	// At the floor, the same bad evidence retires nothing.
	f.samples[selPeer] = measurement{direct: 30 * time.Millisecond, path: 20 * time.Millisecond}
	for range 5 {
		f.pass(t)
	}
	if f.state(t, selPeer) != links.StateEstablished || f.state(t, selB) != links.StateEstablished {
		t.Error("a demotion below the redundancy floor happened")
	}
}

// TestSelectionGreetingTimeout checks the liveness rule: a neighbor whose
// greetings have timed out counts as infinitely slow and retires on the
// third window — and the floor holds even when every neighbor goes silent
// in the same window.
func TestSelectionGreetingTimeout(t *testing.T) {
	f := newSelFixture(t, selPeer, selA, selB)
	f.silent[selPeer] = true
	f.silent[selA] = true
	f.silent[selB] = true // every greeting timed out

	f.pass(t)
	f.pass(t)
	if f.state(t, selPeer) != links.StateEstablished {
		t.Fatal("a silent neighbor was demoted before three windows")
	}
	f.pass(t)
	// Three silent neighbors above the floor of two retire down to it, no
	// further — the floor holds at every instant.
	retired := 0
	for _, ia := range []addr.IA{selPeer, selA, selB} {
		if f.state(t, ia) == links.StateRetired {
			retired++
		}
	}
	if retired != 1 {
		t.Fatalf("retired %d of three silent neighbors, want the one the floor allows", retired)
	}
	f.pass(t)
	retired = 0
	for _, ia := range []addr.IA{selPeer, selA, selB} {
		if f.state(t, ia) == links.StateRetired {
			retired++
		}
	}
	if retired != 1 {
		t.Errorf("retired %d of three silent neighbors after another window, want the floor to hold",
			retired)
	}
}

// TestSelectionCapDisplacement checks the cap: at it, a candidate that beats
// the worst neighbor by the promotion ratio with sustained evidence
// displaces it; one that does not beat it changes nothing.
func TestSelectionCapDisplacement(t *testing.T) {
	neighbors := []addr.IA{selPeer, selA, selB, selC}
	f := newSelFixture(t, neighbors...)
	f.sel.cfg.MaxLinks = len(neighbors)
	// B is the worst neighbor: slowest direct link.
	f.samples[selB] = measurement{direct: 40 * time.Millisecond, path: 10 * time.Millisecond}
	// The candidate beats B by the ratio, but not the others.
	f.candidate(selD, 25*time.Millisecond, 40*time.Millisecond)

	f.pass(t) // streak 1
	f.pass(t) // streak 2: displaces B
	if len(f.established) != 1 || !f.established[0].Equal(selD) {
		t.Fatalf("promoted %v, want the displacing candidate", f.established)
	}
	if f.state(t, selB) != links.StateRetired {
		t.Error("the worst neighbor was not displaced")
	}
	for _, ia := range []addr.IA{selPeer, selA, selC} {
		if f.state(t, ia) != links.StateEstablished {
			t.Errorf("displacement retired %s as well", ia)
		}
	}

	// A candidate that does not beat the worst neighbor changes nothing.
	f.candidate(selIA, 39*time.Millisecond, 40*time.Millisecond)
	f.pass(t)
	f.pass(t)
	if len(f.established) != 1 {
		t.Error("a candidate that beats no neighbor displaced one")
	}
}

// TestSelectionSweepCandidateWindow checks the candidate sweep: an unproven
// candidate retires once the window passes, a proven one is established.
func TestSelectionSweepCandidateWindow(t *testing.T) {
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
}

// TestSelectionNoAction checks the comparator's quiet case: neutral
// evidence — a direct link within the ratios — moves nothing.
func TestSelectionNoAction(t *testing.T) {
	f := newSelFixture(t, selPeer, selA)
	f.samples[selPeer] = measurement{direct: 20 * time.Millisecond, path: 20 * time.Millisecond}
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
