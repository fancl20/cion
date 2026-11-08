package measured

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/gopacket/gopacket"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path/empty"
	"google.golang.org/protobuf/proto"

	"github.com/fancl20/cion/pkg/core/dataplane/dataplanetest"
	"github.com/fancl20/cion/pkg/libs/bus"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/scionrpc"
	"github.com/fancl20/cion/pkg/libs/segment"
	"github.com/fancl20/cion/pkg/libs/underlay"
	"github.com/fancl20/cion/pkg/modules/links"
	"github.com/fancl20/cion/pkg/modules/links/impl/memory"
	"github.com/fancl20/cion/pkg/modules/pathdb"
	nodev1 "github.com/fancl20/cion/proto/node/v1"
)

// selFixture is the selection loop's test harness: a memory link store, the
// directory's entries and the monitor's verdicts, which each pass publishes
// first, injected samples, their routes' health and cost as the
// measurements leave them, and injected candidate-grace probes. The
// establishment is recorded rather than performed; the promotion and
// retirement rules are what the tests assert.
type selFixture struct {
	t              *testing.T
	store          *memory.DB
	directory      []bus.DirectoryEntry
	directoryTopic *bus.Topic[bus.Directory]
	samples        map[addr.IA]sample
	links          *bus.Topic[bus.LinkState]
	down           map[addr.IA]bool // neighbors whose verdict is down
	// alive holds the candidates whose rendezvous socket answers the
	// sweep's probe, keyed by neighbor ISD-AS.
	alive map[addr.IA]bool
	// probed holds the peers the last pass measured, and probedAt the
	// address each was measured at.
	probed      map[addr.IA]bool
	probedAt    map[addr.IA]netip.AddrPort
	established []addr.IA // the promoted candidates, in order
	// reports holds the last window's reports, by directory, and cluster
	// the cluster it named.
	reports map[bus.DirectoryID][]bus.PeerReport
	cluster addr.IA
	// writes counts the loop's own writes, signaled through its store as
	// the node's store signals them; the fixture's writes bypass it.
	writes int
	sel    *selection
}

// The fixture's ISD-ASes. The node's is picked so that its second-route
// promotion of D waits PromoteWindows, and of B the most,
// PromoteWindows+PromoteJitter (TestPromoteWindows).
var (
	selIA   = addr.MustIAFrom(20, 0xfd0000000041)
	selPeer = addr.MustIAFrom(20, 0xfd0000000002)
	selA    = addr.MustIAFrom(20, 0xfd0000000011)
	selB    = addr.MustIAFrom(20, 0xfd0000000012)
	selC    = addr.MustIAFrom(20, 0xfd0000000013)
	selD    = addr.MustIAFrom(20, 0xfd0000000014)
	selE    = addr.MustIAFrom(20, 0xfd0000000015)
)

// selScope is the directory the fixture's entries are published in.
var selScope = bus.DirectoryID{1}

func entryOf(ia addr.IA) bus.DirectoryEntry {
	return bus.DirectoryEntry{IA: ia, Addresses: []bus.Address{{
		ControlAddr:    netip.MustParseAddrPort("127.0.0.1:30042"),
		RendezvousAddr: netip.MustParseAddrPort("127.0.0.1:30043"),
	}}}
}

// targetOf builds a target whose rendezvous address is the given one, in the
// fixture's directory.
func targetOf(ia addr.IA, rendezvous string) target {
	return target{IA: ia, Scope: selScope,
		ControlAddr:    netip.MustParseAddrPort("127.0.0.1:30042"),
		RendezvousAddr: netip.MustParseAddrPort(rendezvous)}
}

// neighborLink builds an entry of the neighbor with link addresses no other
// ISD-AS of the tests holds: the store refuses two serving entries with one
// remote address. The entry records the directory's rendezvous address, as
// a link the loop dialed does.
func neighborLink(ia addr.IA, state links.State) *links.Link {
	l := liveLink(ia, uint16(41000+2*(uint64(ia.AS())&0xff)))
	l.Rendezvous = entryOf(ia).Addresses[0].RendezvousAddr
	l.State = state
	return l
}

// accept turns the neighbor's entry into one a peer's dial landed on: it
// records no rendezvous address.
func (f *selFixture) accept(t *testing.T, ia addr.IA) {
	t.Helper()
	l, err := f.store.ByNeighbor(context.Background(), ia)
	if err != nil || l == nil {
		t.Fatalf("no live entry for %s: %v", ia, err)
	}
	l.Rendezvous = netip.AddrPort{}
	if err := f.store.Update(context.Background(), l); err != nil {
		t.Fatal(err)
	}
}

func newSelFixture(t *testing.T, neighbors ...addr.IA) *selFixture {
	t.Helper()
	f := &selFixture{
		t:              t,
		store:          memory.New(),
		directoryTopic: new(bus.Topic[bus.Directory]),
		samples:        make(map[addr.IA]sample),
		links:          new(bus.Topic[bus.LinkState]),
		down:           make(map[addr.IA]bool),
		alive:          make(map[addr.IA]bool),
		probed:         make(map[addr.IA]bool),
		probedAt:       make(map[addr.IA]netip.AddrPort),
	}
	for _, ia := range neighbors {
		if err := f.store.Insert(context.Background(),
			neighborLink(ia, links.StateEstablished)); err != nil {
			t.Fatal(err)
		}
	}
	for _, ia := range neighbors {
		f.directory = append(f.directory, entryOf(ia))
		f.samples[ia] = f.priced(ia, 10*time.Millisecond, 20*time.Millisecond)
	}
	f.sel = &selection{
		cfg: SelectionConfig{
			IA:          selIA,
			Store:       links.Notifying(f.store, func() { f.writes++ }),
			Window:      time.Hour, // the candidate sweep never retires in these
			ControlHost: netip.MustParseAddr("127.0.0.1"),
		},
		streaks: make(map[addr.IA]*peerStreak),
		probeFn: func(_ context.Context, e target, _ *links.Link) sample {
			f.probed[e.IA] = true
			f.probedAt[e.IA] = e.RendezvousAddr
			sm := f.samples[e.IA]
			sm.baseline = f.sel.freshest(sm.candidates)
			return sm
		},
		establishFn: func(_ context.Context, e target, _ string) bool {
			if err := f.store.Insert(context.Background(),
				neighborLink(e.IA, links.StateEstablished)); err != nil {
				t.Error(err)
				return false
			}
			f.established = append(f.established, e.IA)
			return true
		},
	}
	f.sel.cfg.Directory = f.directoryTopic
	f.sel.cfg.Links = f.links
	f.sel.cfg.Report = func(c addr.IA, r map[bus.DirectoryID][]bus.PeerReport) { f.cluster, f.reports = c, r }
	f.sel.aliveFn = func(l *links.Link) bool { return f.alive[l.NeighborIA] }
	f.refresh()
	return f
}

// refresh publishes the directory's entries, and the link state of the
// established entries, the down ones' verdicts down.
func (f *selFixture) refresh() {
	f.directoryTopic.Publish(bus.NewDirectory(nil, bus.NewScope(selScope, slices.Clone(f.directory)...)))
	entries, err := f.store.All(context.Background())
	if err != nil {
		return
	}
	var ls []bus.Link
	for _, l := range entries {
		if l.State != links.StateEstablished {
			continue
		}
		ls = append(ls, bus.Link{Entry: *l, Down: f.down[l.NeighborIA]})
	}
	f.links.Publish(bus.NewLinkState(ls...))
}

// verdictState returns the link state of the verdicts' interfaces, each
// link down where its verdict is; an interface with no verdict is up.
func verdictState(verdicts map[uint16]bool) bus.LinkState {
	ls := make([]bus.Link, 0, len(verdicts))
	for ifID, up := range verdicts {
		ls = append(ls, bus.Link{Entry: links.Link{IfID: ifID}, Down: !up})
	}
	return bus.NewLinkState(ls...)
}

// verdictTopic returns a link state topic holding verdictState(verdicts).
func verdictTopic(verdicts map[uint16]bool) *bus.Topic[bus.LinkState] {
	t := new(bus.Topic[bus.LinkState])
	t.Publish(verdictState(verdicts))
	return t
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

// priced returns a sample of the direct round trip whose routes carry the
// price: the first route measured at it, else — none given — the stalest
// route measured at it, over the peer's own link for a neighbor and through
// X for a candidate. A zero price leaves the routes as given.
func (f *selFixture) priced(ia addr.IA, direct, price time.Duration, routes ...scion.Candidate) sample {
	f.t.Helper()
	if price == 0 {
		return sm(direct, routes...)
	}
	routes = slices.Clone(routes)
	if len(routes) == 0 {
		if f.hasEntry(f.t, ia) {
			routes = append(routes, f.via(f.t, ia, -time.Hour, ia))
		} else {
			routes = append(routes, route(-time.Hour, 0, link(selX), link(ia)))
		}
	}
	routes[0] = measured(routes[0], price)
	return sm(direct, routes...)
}

// candidate adds a directory candidate with the given sample, its routes
// carrying the price as priced has them.
func (f *selFixture) candidate(ia addr.IA, direct, price time.Duration, routes ...scion.Candidate) {
	f.directory = append(f.directory, entryOf(ia))
	f.samples[ia] = f.priced(ia, direct, price, routes...)
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

// carried sets the peer's sample to the round trip and routes given, the
// first route measured at the price.
func (f *selFixture) carried(ia addr.IA, direct, price time.Duration, routes ...scion.Candidate) {
	f.samples[ia] = f.priced(ia, direct, price, routes...)
}

// reported returns the last window's report of the peer, and whether the
// window reported it.
func (f *selFixture) reported(ia addr.IA) (bus.PeerReport, bool) {
	for _, reports := range f.reports {
		for _, r := range reports {
			if r.IA == ia {
				return r, true
			}
		}
	}
	return bus.PeerReport{}, false
}

// report sets the reports the peer's directory entry carries.
func (f *selFixture) report(ia addr.IA, reports ...bus.PeerReport) {
	for i := range f.directory {
		if f.directory[i].IA == ia {
			f.directory[i].Peers = reports
		}
	}
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
// neighbor's echo round trip halved lands in the latency topic the
// beaconer's entries read, and a link the next window does not measure
// declares nothing again.
func TestSelectionDeclaresLatency(t *testing.T) {
	f := newSelFixture(t, selPeer)
	latencies := new(bus.Topic[bus.LinkLatencies])
	f.sel.cfg.Latencies = latencies
	ifID := f.ifID(t, selPeer)

	f.samples[selPeer] = f.priced(selPeer, 10*time.Millisecond, 20*time.Millisecond)
	f.pass(t)
	if got := latencies.Latest().Of(ifID); got != 5*time.Millisecond {
		t.Errorf("declared one-way delay = %v, want the halved round trip 5ms", got)
	}

	// A window the link goes unanswered declares nothing: the next entries
	// carry no stale sample.
	f.samples[selPeer] = sm(0)
	f.pass(t)
	if got := latencies.Latest().Of(ifID); got != 0 {
		t.Errorf("declared one-way delay past an unanswered window = %v, want 0", got)
	}
}

// TestSelectionRequestsItsRoutes checks the routes a window requests
// measured: each peer's baseline and each up link's freshest clean survivor,
// priced, and a peer's freshest ejected route fresher than its baseline,
// half-open at its retry, never a staler one; the next window's requests
// replace them, a peer the directory no longer names requesting nothing.
func TestSelectionRequestsItsRoutes(t *testing.T) {
	ms := time.Millisecond
	f := newSelFixture(t, selPeer, selA, selB)
	requests := new(bus.Topic[bus.PathRequests])
	f.sel.cfg.Requests = requests
	viaPeer := f.via(t, selPeer, 0, selPeer, selA)
	f.carried(selA, 18*ms, 12*ms, viaPeer)
	// B's ejected route through Peer is staler than its baseline.
	bOwn := f.via(t, selB, -time.Hour, selB)
	f.carried(selB, 10*ms, 20*ms, bOwn,
		with(f.via(t, selPeer, -2*time.Hour, selPeer, selB), scion.HealthEjected))
	// C's baseline rides Peer's link; its route through B, older, is the
	// freshest route around Peer's link; and its freshest, through A, was
	// ejected.
	cViaPeer := f.via(t, selPeer, 0, selPeer, selC)
	cViaB := f.via(t, selB, -time.Minute, selB, selC)
	cViaA := with(f.via(t, selA, time.Minute, selA, selC), scion.HealthEjected)
	cViaA.Retry = time.Unix(1<<30, 0).Add(20 * time.Second)
	f.candidate(selC, 15*ms, 0, cViaPeer, cViaB, cViaA)

	type requested struct {
		Dst  addr.IA
		Role bus.PathRole
		Due  time.Time
	}
	got := func() map[bus.PathID]requested {
		out := make(map[bus.PathID]requested)
		for r := range requests.Latest().All() {
			out[r.ID] = requested{Dst: r.Dst, Role: r.Role, Due: r.Due}
		}
		return out
	}
	f.pass(t)
	want := map[bus.PathID]requested{
		f.samples[selPeer].candidates[0].ID: {Dst: selPeer, Role: bus.PathPriced},
		viaPeer.ID:                          {Dst: selA, Role: bus.PathPriced},
		bOwn.ID:                             {Dst: selB, Role: bus.PathPriced},
		cViaPeer.ID:                         {Dst: selC, Role: bus.PathPriced},
		cViaB.ID:                            {Dst: selC, Role: bus.PathPriced},
		cViaA.ID:                            {Dst: selC, Role: bus.PathHalfOpen, Due: cViaA.Retry},
	}
	if diff := cmp.Diff(want, got()); diff != "" {
		t.Errorf("the window's requests (-want +got):\n%s", diff)
	}

	f.directory = slices.DeleteFunc(f.directory, func(e bus.DirectoryEntry) bool { return e.IA.Equal(selC) })
	f.pass(t)
	for id := range got() {
		if id == cViaPeer.ID || id == cViaB.ID || id == cViaA.ID {
			t.Errorf("the next window still requests %s to a peer the directory dropped", id)
		}
	}
}

// TestSelectionRequestsEachMembersCheapest checks the routes the window
// requests beside each peer's baseline and each up link's freshest
// survivor: the route each member is priced by, with every link — in a tier
// no up link reaches as well — and without each up link, at its price,
// transits charged, not the one cheapest at its cost, whichever member the
// freshest survivor resolves into.
func TestSelectionRequestsEachMembersCheapest(t *testing.T) {
	ms := time.Millisecond
	f := newSelFixture(t, selPeer, selA)
	requests := new(bus.Topic[bus.PathRequests])
	f.sel.cfg.Requests = requests
	// B's freshest route rides Peer's link at 30ms, 40ms with its transit.
	// Around Peer's link: through A at 40ms, the freshest there; at 20ms,
	// 30ms with its transit, B's cheapest; and through A and X at 15ms, 35ms
	// with its two transits.
	viaPeer := measured(f.via(t, selPeer, 0, selPeer, selB), 30*ms)
	freshest := measured(f.via(t, selA, -time.Minute, selA, selB), 40*ms)
	cheapest := measured(f.via(t, selA, -2*time.Minute, selA, selB), 20*ms)
	viaAX := measured(f.via(t, selA, -3*time.Minute, selA, selX, selB), 15*ms)
	f.candidate(selB, 12*ms, 0, viaPeer, freshest, cheapest, viaAX)
	// C's cheapest route rides Peer's link at 20ms, 30ms with its transit;
	// around it, through A at 30ms, 40ms with its transit, staler than B's
	// routes there.
	cViaPeer := measured(f.via(t, selPeer, 0, selPeer, selC), 20*ms)
	cViaA := measured(f.via(t, selA, -5*time.Minute, selA, selC), 30*ms)
	f.candidate(selC, 12*ms, 0, cViaPeer, cViaA)
	// D, far, in a tier no up link reaches: its freshest route through Peer
	// at 80ms, its cheapest through A at 60ms.
	dViaPeer := measured(f.via(t, selPeer, 0, selPeer, selD), 80*ms)
	dViaA := measured(f.via(t, selA, -time.Minute, selA, selD), 60*ms)
	f.candidate(selD, 50*ms, 0, dViaPeer, dViaA)

	f.pass(t)
	got := make(map[bus.PathID]bool)
	for r := range requests.Latest().All() {
		got[r.ID] = true
	}
	want := map[bus.PathID]bool{
		f.samples[selPeer].candidates[0].ID: true,
		f.samples[selA].candidates[0].ID:    true,
		viaPeer.ID:                          true,
		freshest.ID:                         true,
		cheapest.ID:                         true,
		cViaPeer.ID:                         true,
		cViaA.ID:                            true,
		dViaPeer.ID:                         true,
		dViaA.ID:                            true,
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("the window's requests (-want +got):\n%s", diff)
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

// TestSelectionFloorWarning checks the floor's warning: a node below the
// floor linked to every peer its views name reports no shortfall, and one
// whose views name a peer it holds no link to, none of them answering,
// does.
func TestSelectionFloorWarning(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	warned := func() bool { return strings.Contains(logs.String(), "Redundancy floor unmet") }

	f := newSelFixture(t, selPeer)
	f.pass(t)
	if warned() {
		t.Errorf("a node linked to every peer its views name warned: %s", logs.String())
	}

	f.candidate(selB, 0, 10*time.Millisecond) // unreachable
	f.pass(t)
	if !warned() {
		t.Error("a node below the floor whose views name an unreachable candidate warned nothing")
	}
}

// TestSelectionEstablishFailedWarnsOnce checks the establishment's failure
// log: a warning for a candidate's first failure, for a different one, and
// for another candidate's, and none while the same failure repeats.
func TestSelectionEstablishFailedWarnsOnce(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	warnings := func() int { return strings.Count(logs.String(), "level=WARN") }

	f := newSelFixture(t)
	refused := errors.New("no rendezvous reply")
	const msg = "The rendezvous establishment failed"
	for _, step := range []struct {
		ia   addr.IA
		err  error
		want int
	}{
		{selA, refused, 1},
		{selA, refused, 1},
		{selA, errors.New("the reply names another ISD-AS"), 2},
		{selB, refused, 3},
	} {
		f.sel.establishFailed(step.ia, msg, step.err)
		if got := warnings(); got != step.want {
			t.Fatalf("after %v's %q: %d warnings, want %d", step.ia, step.err, got, step.want)
		}
	}
}

// TestSelectionStrandedPromotion checks the stranded clause: a tier no live
// route resolves into admits its fastest reachable member at once, no
// streak — the establishment riding the rendezvous path — though its pair
// waits the most windows a priced promotion can, and an unreachable member
// of the same tier is not that member.
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

// TestPromoteWindows checks each pair's wait: from PromoteWindows to
// PromoteWindows+PromoteJitter windows, and every value between drawn by a
// range of peers from one node and by a range of nodes from one peer.
func TestPromoteWindows(t *testing.T) {
	want := make(map[int]bool)
	for w := PromoteWindows; w <= PromoteWindows+PromoteJitter; w++ {
		want[w] = true
	}
	fromNode := make(map[int]bool)
	toPeer := make(map[int]bool)
	for as := range addr.AS(64) {
		other := addr.MustIAFrom(20, 0xfd0000000100|as)
		fromNode[promoteWindows(selIA, other)] = true
		toPeer[promoteWindows(other, selB)] = true
	}
	if diff := cmp.Diff(want, fromNode); diff != "" {
		t.Errorf("one node's waits for a range of peers (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(want, toPeer); diff != "" {
		t.Errorf("a range of nodes' waits for one peer (-want +got):\n%s", diff)
	}

	// The fixture's pairs wait what the tests below rely on.
	got := map[addr.IA]int{selB: promoteWindows(selIA, selB), selD: promoteWindows(selIA, selD)}
	fixture := map[addr.IA]int{selB: PromoteWindows + PromoteJitter, selD: PromoteWindows}
	if diff := cmp.Diff(fixture, got); diff != "" {
		t.Errorf("the fixture's waits (-want +got):\n%s", diff)
	}
}

// TestSelectionPricedPromotion checks the beaten-baseline case: a candidate
// no route prices, whose direct round trip beats its tier's price by the
// promotion ratio, is announced in its first window and promoted on the
// PromoteWindows-th, never before, and a candidate that beats no price never
// is — however cheap the declarations its unreachable self would price.
func TestSelectionPricedPromotion(t *testing.T) {
	f := newSelFixture(t, selPeer, selA)                        // at the floor
	f.candidate(selB, 8*time.Millisecond, 20*time.Millisecond)  // beats 0.8 of the 20ms price
	f.candidate(selC, 18*time.Millisecond, 20*time.Millisecond) // does not

	for range PromoteWindows - 1 {
		f.pass(t)
	}
	if len(f.established) != 0 {
		t.Fatal("a candidate was promoted short of its windows")
	}
	if r, ok := f.reported(selB); !ok || !r.Promoting {
		t.Fatalf("the report of %v = %+v, want its promotion announced", selB, r)
	}
	if r, _ := f.reported(selC); r.Promoting {
		t.Errorf("the report announces %v, which beats no price", selC)
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
	f.candidate(selD, 0, 0, route(0, time.Millisecond, link(selX), link(selD)))
	for range 3 {
		f.pass(t)
	}
	if f.hasEntry(t, selD) {
		t.Error("an unreachable candidate was promoted")
	}
}

// TestSelectionPromotionWaits checks the beaten price's coordination: a
// candidate another node's lighter announced promotion would serve is
// neither announced nor promoted while that announcement holds, then is
// announced, and promoted a window later.
func TestSelectionPromotionWaits(t *testing.T) {
	f := newSelFixture(t, selPeer, selA)                        // at the floor
	f.candidate(selB, 25*time.Millisecond, 40*time.Millisecond) // beats 0.8 of the 40ms price
	// Peer, linked to the node at 1ms, announces its promotion of B at 5ms:
	// the path to B over it would cost the node 16ms with Peer's transit,
	// against the 25ms B measures it at.
	f.report(selPeer, bus.PeerReport{IA: selIA, RTT: time.Millisecond, IfID: 1},
		bus.PeerReport{IA: selB, RTT: 5 * time.Millisecond, Promoting: true})
	f.report(selB, bus.PeerReport{IA: selIA, RTT: 25 * time.Millisecond})
	for window := 1; window <= runnerUpWindows+1; window++ {
		f.pass(t)
		if r, _ := f.reported(selB); r.Promoting || len(f.established) != 0 {
			t.Fatalf("window %d: B announced or promoted while Peer's announcement holds", window)
		}
	}
	f.pass(t)
	if r, _ := f.reported(selB); !r.Promoting || len(f.established) != 0 {
		t.Fatalf("once Peer's announcement lapsed: report %+v, established %v; want B announced alone",
			r, f.established)
	}
	f.pass(t)
	if len(f.established) != 1 || !f.established[0].Equal(selB) {
		t.Fatalf("established = %v, want B a window after its announcement", f.established)
	}
}

// TestSelectionReports checks the window's reports: every peer measured, in
// the directory that named it, at the round trip last reported unless the
// measurement moved past the step, naming no link.
func TestSelectionReports(t *testing.T) {
	f := newSelFixture(t, selPeer, selA)
	f.candidate(selB, 30*time.Millisecond, 0)
	f.candidate(selC, 0, 0) // unreachable
	f.pass(t)
	want := []bus.PeerReport{
		{IA: selPeer, RTT: 10 * time.Millisecond},
		{IA: selA, RTT: 10 * time.Millisecond},
		{IA: selB, RTT: 30 * time.Millisecond},
	}
	if diff := cmp.Diff(map[bus.DirectoryID][]bus.PeerReport{selScope: want}, f.reports); diff != "" {
		t.Fatalf("reports (-want +got):\n%s", diff)
	}
	f.samples[selB] = f.priced(selB, 31*time.Millisecond, 0)
	f.pass(t)
	if r, _ := f.reported(selB); r.RTT != 30*time.Millisecond {
		t.Errorf("a move within the step reports %v, want the 30ms reported", r.RTT)
	}
	f.samples[selB] = f.priced(selB, 34*time.Millisecond, 0)
	f.pass(t)
	if r, _ := f.reported(selB); r.RTT != 34*time.Millisecond {
		t.Errorf("a move past the step reports %v, want 34ms", r.RTT)
	}
}

// TestSelectionOwnPricePromotion checks promotion by a candidate's own
// price: a candidate whose one route detours through two transits promotes
// though a neighbor prices the tier below the candidate's round trip, while
// a faster candidate no route prices beats the tier's price by the promotion
// ratio but by less than the margin floor, and does not.
func TestSelectionOwnPricePromotion(t *testing.T) {
	f := newSelFixture(t, selPeer, selA) // at the floor
	// A's baseline over its own link prices the tier at 8ms.
	f.carried(selA, 10*time.Millisecond, 8*time.Millisecond, f.via(t, selA, 0, selA))
	// B's one route crosses A and X, measured at 24ms: 44ms with its
	// transits, which B's 16ms beats.
	f.candidate(selB, 16*time.Millisecond, 0,
		measured(route(0, 0, local(f.ifID(t, selA)), link(selA), link(selX), link(selB)), 24*time.Millisecond))
	// C's 6.3ms is within the ratio of the tier's 8ms, short of the floor.
	f.candidate(selC, 6300*time.Microsecond, 0)

	for range PromoteWindows {
		f.pass(t)
	}
	if len(f.established) != 1 || !f.established[0].Equal(selB) {
		t.Fatalf("promoted %v, want the candidate its own route detours %v", f.established, selB)
	}
	f.pass(t)
	if f.hasEntry(t, selC) {
		t.Error("a candidate within the margin floor of its price was promoted")
	}
}

// TestSelectionSingleRoutePromotion checks the redundancy purchase: a
// single-route tier admits a second member within SecondRouteRatio of the
// price, on the last of its pair's windows, and rejects one outside it.
func TestSelectionSingleRoutePromotion(t *testing.T) {
	f := newSelFixture(t, selPeer, selA) // at the floor
	// A slow tier of one member, its single route the clean path to it:
	// 22ms is within SecondRouteRatio of the 20ms price.
	f.candidate(selB, 22*time.Millisecond, 20*time.Millisecond, cand(link(selX)))
	f.candidate(selC, 26*time.Millisecond, 20*time.Millisecond, cand(link(selX)))

	for range promoteWindows(selIA, selB) - 1 {
		f.pass(t)
	}
	if len(f.established) != 0 {
		t.Fatal("the second route was purchased short of its pair's windows")
	}
	f.pass(t)
	if len(f.established) != 1 || !f.established[0].Equal(selB) {
		t.Fatalf("promoted %v, want the member within the ratio %v", f.established, selB)
	}
	if f.hasEntry(t, selC) {
		t.Error("a member outside SecondRouteRatio of the price was admitted")
	}
}

// TestSelectionSecondRouteFirst checks the priced cases' order: a second
// route for a single-route tier goes ahead of a faster candidate whose
// beaten price falls due in the same window.
func TestSelectionSecondRouteFirst(t *testing.T) {
	f := newSelFixture(t, selPeer, selA) // at the floor
	f.candidate(selB, 22*time.Millisecond, 20*time.Millisecond, cand(link(selX)))
	// D beats its price in the fast tier, its streak ending in B's last
	// window.
	for range promoteWindows(selIA, selB) - promoteWindows(selIA, selD) {
		f.pass(t)
	}
	f.candidate(selD, 8*time.Millisecond, 20*time.Millisecond)
	for range promoteWindows(selIA, selD) {
		f.pass(t)
	}
	if len(f.established) != 1 || !f.established[0].Equal(selB) {
		t.Fatalf("promoted %v, want the second route %v first", f.established, selB)
	}
}

// TestSelectionUnpricedTier checks the unpriced reading: a tier nothing
// prices — no route to its up link's neighbor, and no edge declaring —
// promotes nothing, however many windows pass; the up link keeps it from
// stranding.
func TestSelectionUnpricedTier(t *testing.T) {
	f := newSelFixture(t, selPeer, selA)
	// A slow tier of A, up, and the candidate B, whose single route is
	// clean but undeclared.
	f.samples[selA] = sm(50 * time.Millisecond)
	f.candidate(selB, 55*time.Millisecond, 0, cand(link(selX)))

	for range 4 {
		f.pass(t)
	}
	if len(f.established) != 0 {
		t.Fatal("an unpriced tier promoted a candidate")
	}
}

// TestSelectionFlappingCandidate checks the damping: a candidate whose good
// windows an unanswered one breaks short of PromoteWindows starts over, and
// is promoted once that many good windows run unbroken.
func TestSelectionFlappingCandidate(t *testing.T) {
	f := newSelFixture(t, selPeer, selA)
	f.candidate(selB, 8*time.Millisecond, 20*time.Millisecond)
	windows := PromoteWindows

	for range windows - 1 {
		f.pass(t) // good
	}
	f.samples[selB] = f.priced(selB, 0, 20*time.Millisecond)
	f.pass(t) // unanswered: the streak resets
	if r, _ := f.reported(selB); r.Promoting {
		t.Fatal("the bad window kept the flapper's promotion announced")
	}
	f.samples[selB] = f.priced(selB, 8*time.Millisecond, 20*time.Millisecond)
	for range windows - 1 {
		f.pass(t) // good again
	}
	if len(f.established) != 0 {
		t.Fatalf("promoted %v short of its windows since the bad one", f.established)
	}
	f.pass(t)
	if len(f.established) != 1 || !f.established[0].Equal(selB) {
		t.Fatalf("promoted %v, want the flapper only after sustained evidence", f.established)
	}
}

// TestSelectionReadingDamps checks the damping the readings add, the seam's
// direct side one sample a window: a slow window holds a candidate back
// while its round trip stands above four fifths of the samples, and the
// promotion's streak starts once it no longer does; fast windows among slow
// ones promote nothing.
func TestSelectionReadingDamps(t *testing.T) {
	fast, slow, price := 8*time.Millisecond, 18*time.Millisecond, 20*time.Millisecond
	t.Run("a slow window", func(t *testing.T) {
		f := newSelFixture(t, selPeer, selA)
		f.candidate(selB, fast, price)
		f.pass(t)
		f.carried(selB, slow, price)
		f.pass(t)
		f.carried(selB, fast, price)
		// The slow round trip stands above four fifths of up to four samples.
		for range 2 {
			f.pass(t)
			if r, _ := f.reported(selB); r.RTT != slow {
				t.Fatalf("reported %v, want the slow window's %v", r.RTT, slow)
			}
		}
		for range PromoteWindows {
			if len(f.established) != 0 {
				t.Fatalf("promoted %v short of its windows since the slow one", f.established)
			}
			f.pass(t)
			if r, _ := f.reported(selB); r.RTT != fast {
				t.Fatalf("reported %v, want %v once the slow window is a fifth", r.RTT, fast)
			}
		}
		if len(f.established) != 1 || !f.established[0].Equal(selB) {
			t.Fatalf("promoted %v, want the candidate once its readings run fast", f.established)
		}
	})
	t.Run("fast windows", func(t *testing.T) {
		f := newSelFixture(t, selPeer, selA)
		f.candidate(selB, slow, price)
		for range 4 {
			f.pass(t)
		}
		f.carried(selB, fast, price)
		for range PromoteWindows {
			f.pass(t)
		}
		if r, _ := f.reported(selB); r.RTT != slow {
			t.Errorf("reported %v, want the slow windows' %v", r.RTT, slow)
		}
		if len(f.established) != 0 {
			t.Errorf("promoted %v on fast windows among slow ones", f.established)
		}
	})
}

// TestSelectionRead checks the direct side's reading and bounds over an
// instrument's samples: each window's round trips join them; the reading is
// the 80th percentile of those taken within scion.ReadingSpan — the ones at
// its edge among them — and the bounds read every sample kept, those taken
// more than scion.BoundSpan before dropping out; a window of no round trip
// reads unreachable and keeps them; each peer's instruments keep their own;
// and the window forgets the instruments whose samples all lie past the
// bounds' span.
func TestSelectionRead(t *testing.T) {
	ms := time.Millisecond
	s := &selection{}
	link := instrument{ia: selPeer, ifID: 1}
	rendezvous := instrument{ia: selB, at: netip.MustParseAddrPort("192.0.2.1:30043")}
	start := time.Now()
	ten := slices.Repeat([]time.Duration{10 * ms}, 10)
	for i, step := range []struct {
		by      instrument
		rtts    []time.Duration
		after   time.Duration
		want    time.Duration
		bounded []time.Duration
	}{
		{link, []time.Duration{10 * ms, 12 * ms, 11 * ms}, 0, 12 * ms, []time.Duration{10 * ms, 12 * ms, 11 * ms}},
		{link, nil, 30 * time.Second, 0, nil},
		{link, []time.Duration{10 * ms, 10 * ms}, time.Minute, 11 * ms,
			[]time.Duration{10 * ms, 12 * ms, 11 * ms, 10 * ms, 10 * ms}},
		{rendezvous, []time.Duration{40 * ms}, time.Minute, 40 * ms, []time.Duration{40 * ms}},
		{link, []time.Duration{9 * ms}, scion.ReadingSpan, 11 * ms,
			[]time.Duration{10 * ms, 12 * ms, 11 * ms, 10 * ms, 10 * ms, 9 * ms}},
		{link, []time.Duration{9 * ms}, scion.ReadingSpan + time.Nanosecond, 10 * ms,
			[]time.Duration{10 * ms, 12 * ms, 11 * ms, 10 * ms, 10 * ms, 9 * ms, 9 * ms}},
		{link, ten, scion.BoundSpan, 10 * ms,
			slices.Concat([]time.Duration{10 * ms, 12 * ms, 11 * ms, 10 * ms, 10 * ms, 9 * ms, 9 * ms}, ten)},
		{link, []time.Duration{20 * ms}, scion.BoundSpan + time.Nanosecond, 10 * ms,
			slices.Concat([]time.Duration{10 * ms, 10 * ms, 9 * ms, 9 * ms}, ten, []time.Duration{20 * ms})},
	} {
		got, lo, hi := s.read(step.by, step.rtts, start.Add(step.after))
		wantLo, wantHi := scion.ReadingBounds(step.bounded)
		if got != step.want || lo != wantLo || hi != wantHi {
			t.Errorf("step %d: read %v within %v..%v, want %v within %v..%v", i, got, lo, hi, step.want, wantLo, wantHi)
		}
	}
	s.forget(start.Add(time.Minute + scion.BoundSpan + time.Nanosecond))
	if _, ok := s.history[rendezvous]; ok {
		t.Error("kept the instrument whose samples all lie past the span")
	}
	if _, ok := s.history[link]; !ok {
		t.Error("forgot the instrument with samples within the span")
	}
	later := start.Add(time.Hour)
	if got, lo, hi := s.read(link, nil, later); got != 0 || lo != 0 || hi != 0 {
		t.Errorf("an unanswered window past every sample read %v within %v..%v, want zeros", got, lo, hi)
	}
	if _, ok := s.history[link]; ok {
		t.Error("kept the instrument whose samples all dropped out")
	}
	s.forget(later)
}

// TestSelectionReadCarriesThePeer checks a change of instrument: one with
// no sample within the reading's span starts from those of the instrument
// that read the peer last — a link from its candidate's binding requests,
// the candidate again from the link's echoes — while one with samples keeps
// its own, and no peer starts from another's.
func TestSelectionReadCarriesThePeer(t *testing.T) {
	ms := time.Millisecond
	s := &selection{}
	rendezvous := instrument{ia: selPeer, at: netip.MustParseAddrPort("192.0.2.1:30043")}
	link := instrument{ia: selPeer, ifID: 1}
	other := instrument{ia: selB, ifID: 2}
	start := time.Now()
	for i, step := range []struct {
		by    instrument
		rtts  []time.Duration
		after time.Duration
		want  time.Duration
	}{
		{rendezvous, []time.Duration{10 * ms, 12 * ms, 30 * ms}, 0, 30 * ms},
		{other, []time.Duration{5 * ms}, 0, 5 * ms},
		{link, []time.Duration{11 * ms, 11 * ms}, time.Minute, 12 * ms},
		{link, []time.Duration{11 * ms}, 2 * time.Minute, 12 * ms},
		{rendezvous, []time.Duration{5 * ms}, scion.ReadingSpan + 30*time.Second, 11 * ms},
		{other, []time.Duration{50 * ms}, scion.ReadingSpan + 30*time.Second, 50 * ms},
	} {
		if got, _, _ := s.read(step.by, step.rtts, start.Add(step.after)); got != step.want {
			t.Errorf("step %d: read %v, want %v", i, got, step.want)
		}
	}
	s.forget(start.Add(time.Hour))
	if len(s.history) != 0 || len(s.last) != 0 {
		t.Errorf("past every sample the window keeps %d instruments and %d peers, want none",
			len(s.history), len(s.last))
	}
}

// TestSelectionForgetsUnprobedInstruments checks the window's upkeep of the
// samples: an instrument no window probes any longer goes once its samples
// all lie past scion.BoundSpan, and stays while one lies within it, past the
// reading's span or not.
func TestSelectionForgetsUnprobedInstruments(t *testing.T) {
	f := newSelFixture(t, selPeer)
	gone := instrument{ia: selX, ifID: 9}
	kept := instrument{ia: selD, ifID: 8}
	f.sel.history = map[instrument][]heard{
		gone: {{at: time.Now().Add(-scion.BoundSpan - time.Second), rtt: time.Millisecond}},
		kept: {{at: time.Now().Add(-scion.ReadingSpan - time.Second), rtt: time.Millisecond}},
	}
	f.sel.last = map[addr.IA]instrument{selX: gone, selD: kept}
	f.pass(t)
	if _, ok := f.sel.history[gone]; ok {
		t.Error("the window kept the samples of an instrument it no longer probes")
	}
	if _, ok := f.sel.last[selX]; ok {
		t.Error("the window kept the peer whose last instrument went")
	}
	if _, ok := f.sel.history[kept]; !ok {
		t.Error("the window forgot the samples the bounds still read")
	}
	if len(f.sel.history) != 2 {
		t.Errorf("the window keeps %d instruments, want the neighbor's link and the bounded one", len(f.sel.history))
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
// exclusion leaves its tier's route count and price unchanged, and every
// member a route no dearer than its own price, retires on the third
// consecutive window decided useless — the survivor answering each window,
// and the history confirming — and never at the floor of up links.
func TestSelectionUselessRetirement(t *testing.T) {
	f := newSelFixture(t, selPeer, selA, selB) // above the floor of two
	// A's baseline rides Peer's link at 8ms: excluding A's link leaves the
	// tier two up links, the route through Peer answering at the price, and
	// A a route as fast as its 18ms round trip, its one transit charged —
	// useless — and A's own round trip earns nothing.
	f.carried(selA, 18*time.Millisecond, 8*time.Millisecond, f.via(t, selPeer, 0, selPeer, selA))

	// The first window holds one sample of A's link, too few to bound it:
	// the history confirms nothing yet.
	f.pass(t)
	if r, _ := f.reported(selA); r.Retiring {
		t.Fatal("the report announces retiring A before its history confirms it")
	}
	f.pass(t)
	// The survivor through Peer and B's own route, each member's cheapest.
	want := []segment.LinkID{link(selPeer), link(selA), link(selB),
		local(f.ifID(t, selPeer)), local(f.ifID(t, selB))}
	if r, _ := f.reported(selA); !r.Retiring || !slices.Equal(r.Relies, want) {
		t.Fatalf("after the first useless window the report of A = %+v, want its retirement "+
			"announced relying on %v", r, want)
	}
	if r, _ := f.reported(selB); r.Retiring {
		t.Fatal("the report announces retiring B, which no window judged useless")
	}
	f.pass(t)
	if f.state(t, selA) != links.StateEstablished {
		t.Fatal("a neighbor was retired before three useless windows")
	}
	f.pass(t)
	if f.state(t, selA) != links.StateRetired {
		t.Fatal("a durably useless neighbor was not retired")
	}
	if r, _ := f.reported(selA); r.Retiring {
		t.Error("the retired link's retirement is still announced")
	}

	// At the floor, the same useless evidence retires nothing: B's baseline
	// rides Peer's link as A's did, and a route through a third interface
	// keeps the tier's two routes without B's link.
	f.carried(selB, 18*time.Millisecond, 8*time.Millisecond,
		f.via(t, selPeer, 0, selPeer, selB),
		route(-time.Minute, 0, local(9), link(selX), link(selB)))
	for range 5 {
		f.pass(t)
	}
	if f.state(t, selPeer) != links.StateEstablished || f.state(t, selB) != links.StateEstablished {
		t.Error("an up link retired at the floor")
	}
}

// TestSelectionStableState checks the state between the two lines: a link
// that helps its neighbor, though by less than promotion's fifth, never
// retires as useless, yet at the cap yields its slot to a candidate that
// earns one.
func TestSelectionStableState(t *testing.T) {
	neighbors := []addr.IA{selPeer, selA, selB}
	f := newSelFixture(t, neighbors...) // above the floor of two
	// A's route through Peer prices it at 20ms with its transit, slower than
	// its 18ms round trip by less than a fifth.
	f.carried(selA, 18*time.Millisecond, 10*time.Millisecond, f.via(t, selPeer, 0, selPeer, selA))
	for range 2 * DemoteWindows {
		f.pass(t)
	}
	if f.state(t, selA) != links.StateEstablished {
		t.Fatal("a link that helps its neighbor retired as useless")
	}
	if r, _ := f.reported(selA); r.Retiring {
		t.Fatal("a link that helps its neighbor was announced retiring")
	}

	// At a cap of three, D beats its price by more than a fifth and takes
	// A's slot: Peer's and B's links each carry their neighbor's one route.
	f.sel.cfg.MaxLinks = len(neighbors)
	f.candidate(selD, 8*time.Millisecond, 20*time.Millisecond)
	for range PromoteWindows {
		f.pass(t)
	}
	if len(f.established) != 1 || !f.established[0].Equal(selD) {
		t.Fatalf("promoted %v, want the candidate that earns a slot", f.established)
	}
	if f.state(t, selA) != links.StateRetired {
		t.Error("the cap's eviction passed over the link that helps by less than a fifth")
	}
}

// name sets the cluster the peer's directory entry names.
func (f *selFixture) name(ia, cluster addr.IA) {
	for i := range f.directory {
		if f.directory[i].IA == ia {
			f.directory[i].Cluster = cluster
		}
	}
}

// clustered puts the node in the cluster of Peer and B, named by Peer, and
// reports the round trips that choose the pairs linking it to A and to D,
// each a unit of one: Peer's 8ms and B's 12ms to A, beside the node's 18ms,
// choose Peer and B; the node's 9ms to D, beside Peer's 30ms and B's 31ms,
// chooses the node and Peer. Peer reports its link to A when linked is set.
func (f *selFixture) clustered(linked bool) {
	for _, ia := range []addr.IA{selPeer, selB, selA, selD} {
		if !slices.ContainsFunc(f.directory, func(e bus.DirectoryEntry) bool { return e.IA == ia }) {
			f.directory = append(f.directory, entryOf(ia))
		}
	}
	f.sel.cluster = selPeer
	f.name(selPeer, selPeer)
	f.name(selB, selPeer)
	peerToA := bus.PeerReport{IA: selA, RTT: 8 * time.Millisecond}
	if linked {
		peerToA.IfID = 1
	}
	f.report(selPeer, peerToA, bus.PeerReport{IA: selD, RTT: 30 * time.Millisecond})
	f.report(selB, bus.PeerReport{IA: selA, RTT: 12 * time.Millisecond},
		bus.PeerReport{IA: selD, RTT: 31 * time.Millisecond})
	f.report(selA, bus.PeerReport{IA: selIA, RTT: 18 * time.Millisecond})
	f.report(selD, bus.PeerReport{IA: selIA, RTT: 9 * time.Millisecond})
}

// TestSelectionPromotesThroughChosenPairs checks the candidates outside the
// node's cluster: A beats its price fastest, but the pairs linking the
// cluster to A are Peer's and B's, so D, whose pair the node holds, is the
// one promoted.
func TestSelectionPromotesThroughChosenPairs(t *testing.T) {
	f := newSelFixture(t, selPeer, selB)
	f.candidate(selA, 5*time.Millisecond, 30*time.Millisecond)
	f.candidate(selD, 6*time.Millisecond, 30*time.Millisecond)
	f.clustered(false)
	for range 8 {
		f.pass(t)
	}
	if !slices.Equal(f.established, []addr.IA{selD}) {
		t.Errorf("promoted %v, want D alone", f.established)
	}
}

// TestSelectionSecondRouteThroughChosenPairs checks the redundancy purchase
// outside the node's cluster: A's tier of one route would admit A within
// SecondRouteRatio of its price, but the pairs linking the cluster to A are
// Peer's and B's, so A stays a candidate.
func TestSelectionSecondRouteThroughChosenPairs(t *testing.T) {
	f := newSelFixture(t, selPeer, selB) // at the floor
	f.candidate(selA, 21*time.Millisecond, 20*time.Millisecond, cand(link(selX)))
	f.clustered(false)
	for range promoteWindows(selIA, selA) + 1 {
		f.pass(t)
	}
	if len(f.established) != 0 {
		t.Errorf("promoted %v, want none", f.established)
	}
}

// TestSelectionStrandedTakesAnyReachable checks a stranded tier outside the
// node's cluster: no route reaches A's tier, so A is promoted at once though
// the pairs linking the cluster to A are Peer's and B's, ahead of the faster
// C, whose tier a route reaches.
func TestSelectionStrandedTakesAnyReachable(t *testing.T) {
	f := newSelFixture(t, selPeer, selB) // at the floor
	f.candidate(selC, 3*time.Millisecond, 30*time.Millisecond)
	f.candidate(selA, 22*time.Millisecond, 0)
	f.clustered(false)
	f.pass(t)
	if !slices.Equal(f.established, []addr.IA{selA}) {
		t.Errorf("promoted %v, want the stranded A", f.established)
	}
}

// TestSelectionPublishesItsCluster checks the cluster topic: the node's
// unit while it names a cluster — Peer, B, and the node itself, not A — and
// no member once no other node names it and the node names none.
func TestSelectionPublishesItsCluster(t *testing.T) {
	f := newSelFixture(t, selPeer, selB)
	topic := new(bus.Topic[bus.Cluster])
	f.sel.cfg.Cluster = topic
	f.clustered(false)
	f.pass(t)
	for ia, want := range map[addr.IA]bool{selIA: true, selPeer: true, selB: true, selA: false} {
		if got := topic.Latest().Has(ia); got != want {
			t.Errorf("published %v as a member: %v, want %v", ia, got, want)
		}
	}
	f.name(selPeer, 0)
	f.name(selB, 0)
	f.pass(t)
	if topic.Latest().Has(selIA) {
		t.Error("a node in no cluster published itself a member")
	}
}

// TestSelectionReportsTheClusterAndBounds checks the report: the cluster the
// node named this window, and each peer's bounds beside its round trip, here
// Peer's twenty-one round trips of 10ms.
func TestSelectionReportsTheClusterAndBounds(t *testing.T) {
	f := newSelFixture(t, selPeer, selB)
	f.clustered(false)
	by := instrument{ia: selPeer, ifID: f.ifID(t, selPeer)}
	f.sel.history = map[instrument][]heard{
		by: slices.Repeat([]heard{{at: time.Now().Add(-time.Minute), rtt: 10 * time.Millisecond}}, 20),
	}
	f.sel.last = map[addr.IA]instrument{selPeer: by}
	f.pass(t)
	if f.cluster != selPeer {
		t.Errorf("reported the cluster %v, want %v", f.cluster, selPeer)
	}
	if r, _ := f.reported(selPeer); r.Low != 10*time.Millisecond || r.High != 10*time.Millisecond {
		t.Errorf("reported Peer's bounds %v and %v, want 10ms", r.Low, r.High)
	}
}

// TestSelectionFloorPrefersChosenPairs checks the floor: below it, the
// fastest candidate the clustering allows goes first, D before the faster
// A; with no such candidate reachable, any reachable one.
func TestSelectionFloorPrefersChosenPairs(t *testing.T) {
	f := newSelFixture(t)
	f.candidate(selA, 3*time.Millisecond, 30*time.Millisecond)
	f.candidate(selD, 8*time.Millisecond, 30*time.Millisecond)
	f.clustered(false)
	f.pass(t)
	if !slices.Equal(f.established, []addr.IA{selD}) {
		t.Errorf("below the floor promoted %v, want D", f.established)
	}

	f = newSelFixture(t)
	f.candidate(selA, 3*time.Millisecond, 30*time.Millisecond)
	f.candidate(selD, 0, 0)
	f.clustered(false)
	f.pass(t)
	if !slices.Equal(f.established, []addr.IA{selA}) {
		t.Errorf("below the floor with D unreachable promoted %v, want A", f.established)
	}
}

// TestSelectionRetiresLinksOutsideTheClusters checks a link the clustering
// does not allow: A's helps, its route through Peer slower than its round
// trip, yet it retires once Peer's link to A joins the units, and stands
// while none does.
func TestSelectionRetiresLinksOutsideTheClusters(t *testing.T) {
	for _, linked := range []bool{false, true} {
		f := newSelFixture(t, selPeer, selA, selB) // above the floor of two
		f.carried(selA, 18*time.Millisecond, 10*time.Millisecond, f.via(t, selPeer, 0, selPeer, selA))
		f.clustered(linked)
		for range 2 * DemoteWindows {
			f.pass(t)
		}
		if got := f.state(t, selA) == links.StateRetired; got != linked {
			t.Errorf("with Peer's link to A reported %v: A's link retired %v, want %v", linked, got, linked)
		}
		if f.state(t, selPeer) != links.StateEstablished || f.state(t, selB) != links.StateEstablished {
			t.Errorf("with Peer's link to A reported %v: a link inside the cluster retired", linked)
		}
	}
}

// TestSelectionEvictsOutsideLinksFirst checks the cap: A's link earns its
// place, its route through Peer slower by more than a fifth, but the
// clustering does not allow it, so D, whose pair the node holds, takes its
// slot.
func TestSelectionEvictsOutsideLinksFirst(t *testing.T) {
	f := newSelFixture(t, selPeer, selA, selB)
	f.accept(t, selB) // two dialed up links: the floor holds the useless retirement back
	f.sel.cfg.MaxLinks = 3
	f.carried(selA, 18*time.Millisecond, 30*time.Millisecond, f.via(t, selPeer, 0, selPeer, selA))
	f.candidate(selD, 6*time.Millisecond, 30*time.Millisecond)
	f.clustered(true)
	for range 8 {
		f.pass(t)
	}
	if !slices.Equal(f.established, []addr.IA{selD}) {
		t.Errorf("promoted %v, want D", f.established)
	}
	if f.state(t, selA) != links.StateRetired {
		t.Error("the cap's eviction passed over the link the clustering does not allow")
	}
}

// TestSelectionRetirementWaitsForTheHistory checks that a useless
// retirement waits for the history: A's link, read fast twenty times, slows
// past the route around it. The reading turns at the sixth slow sample, the
// lower bound only once the fast samples fall short of its rank, at the
// eleventh; the link retires on the third window after.
func TestSelectionRetirementWaitsForTheHistory(t *testing.T) {
	f := newSelFixture(t, selPeer, selA, selB) // above the floor of two
	by := instrument{ia: selA, ifID: f.ifID(t, selA)}
	f.sel.history = map[instrument][]heard{
		by: slices.Repeat([]heard{{at: time.Now().Add(-time.Minute), rtt: 10 * time.Millisecond}}, 20),
	}
	f.sel.last = map[addr.IA]instrument{selA: by}
	// A's route through Peer prices it at 14ms with its transit, beside its
	// own round trip of 20ms now, which keeps A in its tier.
	f.carried(selA, 20*time.Millisecond, 4*time.Millisecond, f.via(t, selPeer, 0, selPeer, selA))
	for window := 1; window <= 12; window++ {
		f.pass(t)
		if f.state(t, selA) != links.StateEstablished {
			t.Fatalf("the link retired in window %d, before its history confirmed it useless", window)
		}
		if r, _ := f.reported(selA); r.Retiring != (window >= 11) {
			t.Fatalf("window %d announced A's retirement %v, want from the eleventh", window, r.Retiring)
		}
	}
	f.pass(t)
	if f.state(t, selA) != links.StateRetired {
		t.Fatal("the link stayed once its history confirmed it useless")
	}
}

// TestSelectionConfidentPromotion checks the confirmed case of a beaten
// price: on a long path, a round trip that beats its price by the band's
// cap, though by less than a fifth, promotes once the history bounds it —
// its upper bound gaining on the price's lower bound by the band — and one
// within the band never does.
func TestSelectionConfidentPromotion(t *testing.T) {
	ms := time.Millisecond
	for _, tc := range []struct {
		name     string
		direct   time.Duration
		promotes bool
	}{
		{"past the band", 185 * ms, true},
		{"within the band", 191 * ms, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSelFixture(t, selPeer, selA) // at the floor
			// D's two disjoint routes price it at 200ms.
			f.candidate(selD, tc.direct, 200*ms,
				route(-time.Hour, 0, link(selX), link(selD)),
				measured(route(-time.Hour, 0, link(selE), segment.LinkID{IA: selD, IfID: 2}), 210*ms))
			// Fourteen samples bound a round trip from above: until then the
			// candidate neither counts a window nor is announced.
			for window := 1; window <= 13; window++ {
				f.pass(t)
				if len(f.established) != 0 {
					t.Fatalf("promoted %v in window %d, before the history bounds the round trip", f.established, window)
				}
				if r, _ := f.reported(selD); r.Promoting || f.sel.streak(selD).promote != 0 {
					t.Fatalf("window %d counted or announced D before the history bounds its round trip", window)
				}
			}
			f.pass(t) // announced
			f.pass(t)
			if promoted := len(f.established) == 1 && f.established[0].Equal(selD); promoted != tc.promotes {
				t.Errorf("promoted %v, want the candidate %v", f.established, tc.promotes)
			}
		})
	}
}

// TestSelectionWaitsForReadPrices checks that only read routes price a
// decision: a candidate whose one route its declaration alone prices
// promotes nothing, however far its round trip beats the declaration, and
// promotes once the route is read.
func TestSelectionWaitsForReadPrices(t *testing.T) {
	f := newSelFixture(t, selPeer, selA) // at the floor
	declared := route(-time.Minute, 20*time.Millisecond, link(selX), link(selB))
	f.candidate(selB, 8*time.Millisecond, 0, declared)
	for range 2 * PromoteWindows {
		f.pass(t)
	}
	if len(f.established) != 0 {
		t.Fatalf("promoted %v on a declared price", f.established)
	}
	f.carried(selB, 8*time.Millisecond, 0, measured(declared, 40*time.Millisecond))
	for range PromoteWindows {
		f.pass(t)
	}
	if len(f.established) != 1 || !f.established[0].Equal(selB) {
		t.Fatalf("promoted %v, want the candidate once its route is read", f.established)
	}
}

// TestSelectionRetirementWaits checks the useless retirement's
// coordination: a link whose judgment rests on a link another node
// announced to retire stands while that announcement holds, and retires
// once it is withdrawn.
func TestSelectionRetirementWaits(t *testing.T) {
	f := newSelFixture(t, selPeer, selA, selB) // above the floor of two
	f.carried(selA, 18*time.Millisecond, 8*time.Millisecond, f.via(t, selPeer, 0, selPeer, selA))
	// Peer announces retiring its link to A, which A's route rides.
	f.report(selPeer, bus.PeerReport{IA: selA, RTT: 3 * time.Millisecond, IfID: 1, Retiring: true})
	for range 2 * DemoteWindows {
		f.pass(t)
	}
	if f.state(t, selA) != links.StateEstablished {
		t.Fatal("a link retired resting on another node's announced retirement")
	}
	f.report(selPeer, bus.PeerReport{IA: selA, RTT: 3 * time.Millisecond, IfID: 1})
	f.pass(t)
	if f.state(t, selA) != links.StateRetired {
		t.Fatal("the useless link stood past the announcement's withdrawal")
	}
}

// TestSelectionAcceptedLinkStands checks the useless retirement's owner: a
// link a peer dialed stands through the windows that retire a dialed one
// under the same measurements, for the peer judges it; its verdict staying
// down still retires it, and at the cap the least-harm eviction still takes
// it.
func TestSelectionAcceptedLinkStands(t *testing.T) {
	f := newSelFixture(t, selPeer, selA, selB) // above the floor of two
	f.accept(t, selA)
	f.carried(selA, 18*time.Millisecond, 8*time.Millisecond, f.via(t, selPeer, 0, selPeer, selA))
	for range 2 * DemoteWindows {
		f.pass(t)
	}
	if f.state(t, selA) != links.StateEstablished {
		t.Fatal("a useless link a peer dialed retired at the accepting end")
	}
	f.down[selA] = true
	for range DemoteWindows {
		f.pass(t)
	}
	if f.state(t, selA) != links.StateRetired {
		t.Fatal("an accepted link whose verdict stayed down was not retired")
	}

	// At the cap, B — useless, the least harm, and a peer's dial — is the
	// victim that admits D, as in TestSelectionCapEviction.
	f = capFixture(t)
	f.accept(t, selB)
	f.pass(t)
	f.pass(t)
	if len(f.established) != 1 || !f.established[0].Equal(selD) {
		t.Fatalf("promoted %v, want the displacing candidate", f.established)
	}
	if f.state(t, selB) != links.StateRetired {
		t.Error("the cap's eviction passed over the accepted least-harm link")
	}
}

// TestSelectionOwnFloor checks the useless retirement's floor: it counts the
// up links the node dialed, so a link it accepted never frees it to shed one
// it dialed — a useless dialed link stands, unannounced, while the dialed
// links sit at the floor, and once a third dialed link lifts them above it,
// is announced, then retired a window later.
func TestSelectionOwnFloor(t *testing.T) {
	f := newSelFixture(t, selPeer, selA, selB) // up links above the floor
	f.accept(t, selB)
	f.carried(selA, 18*time.Millisecond, 8*time.Millisecond, f.via(t, selPeer, 0, selPeer, selA))
	for range 2 * DemoteWindows {
		f.pass(t)
	}
	if f.state(t, selA) != links.StateEstablished {
		t.Fatal("a useless dialed link retired with the dialed links at the floor")
	}
	if r, _ := f.reported(selA); r.Retiring {
		t.Fatal("a retirement was announced with the dialed links at the floor")
	}

	if err := f.store.Insert(context.Background(), neighborLink(selC, links.StateEstablished)); err != nil {
		t.Fatal(err)
	}
	f.directory = append(f.directory, entryOf(selC))
	f.samples[selC] = f.priced(selC, 50*time.Millisecond, 60*time.Millisecond)
	f.pass(t)
	if r, _ := f.reported(selA); !r.Retiring || f.state(t, selA) != links.StateEstablished {
		t.Fatalf("above the floor the report of A = %+v, state %v; want announced, not yet retired",
			r, f.state(t, selA))
	}
	f.pass(t)
	if f.state(t, selA) != links.StateRetired {
		t.Error("a useless dialed link stood with the dialed links above the floor")
	}
}

// TestSelectionSecondRouteKept checks the route count's half of the useless
// test: a link bought as its tier's second route never decides useless
// while it is one of the tier's two routes, though its exclusion leaves the
// first route answering at the price — where latency alone would retire it.
func TestSelectionSecondRouteKept(t *testing.T) {
	f := newSelFixture(t, selPeer, selA, selB, selC)
	// A slow tier of B and C, both reached over B's link alone besides C's
	// own: excluding C's link leaves B's route at the price, C's within the
	// ratio of its round trip with its transit charged, and one route.
	f.carried(selB, 50*time.Millisecond, 60*time.Millisecond, f.via(t, selB, 0, selB))
	f.carried(selC, 60*time.Millisecond, 60*time.Millisecond, f.via(t, selB, 0, selB, selC))
	for range 5 {
		f.pass(t)
	}
	if f.state(t, selC) != links.StateEstablished {
		t.Error("the tier's second route retired as useless")
	}
}

// TestSelectionLinkKeptForItsRoutes checks the useless test's members: a
// link stays while its neighbor keeps no route as fast as its round trip,
// transits charged, and while another member's route needs it — though its
// exclusion leaves the tier's price and route count as they were.
func TestSelectionLinkKeptForItsRoutes(t *testing.T) {
	f := newSelFixture(t, selPeer, selA, selB) // above the floor of two
	// B's baseline rides Peer's link at 10ms and prices the tier: 20ms with
	// its transit, slower than B's 10ms round trip.
	f.carried(selB, 10*time.Millisecond, 10*time.Millisecond, f.via(t, selPeer, 0, selPeer, selB))
	// C's cheap route rides A's link and prices C at 22ms; its other route
	// detours through Peer and X at 60ms.
	f.candidate(selC, 19*time.Millisecond, 0,
		measured(route(-time.Minute, 0,
			local(f.ifID(t, selA)), link(selA), link(selC)), 12*time.Millisecond),
		measured(route(-time.Minute, 0,
			local(f.ifID(t, selPeer)), link(selPeer), link(selX), link(selC)), 40*time.Millisecond))

	for range 2 * DemoteWindows {
		f.pass(t)
	}
	if f.state(t, selA) != links.StateEstablished {
		t.Error("a link retired while a member's route needs it")
	}
	if f.state(t, selB) != links.StateEstablished {
		t.Error("a link retired while its neighbor's other route is slower")
	}
}

// TestSelectionRetirementCounts checks that each rule counts its own
// windows: a down window holds the useless count, an up window resets the
// down count alone, an undecided window holds the useless count, and a
// count at DemoteWindows retires a link only in a window decided useless.
func TestSelectionRetirementCounts(t *testing.T) {
	// A down window between useless ones holds the useless count: the link
	// retires on the third useless window, not on the down one. C keeps the
	// dialed up links above the floor through the down window, so the
	// retirement's announcement stands.
	// The first window of each holds one sample of A's link, which confirms
	// nothing.
	f := newSelFixture(t, selPeer, selA, selB, selC)
	f.carried(selA, 18*time.Millisecond, 8*time.Millisecond, f.via(t, selPeer, 0, selPeer, selA))
	f.pass(t)
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

	// Without C, the down window drops the dialed up links to the floor,
	// which withdraws the announcement: announced again on the third
	// useless window, the link retires on the fourth.
	f = newSelFixture(t, selPeer, selA, selB)
	f.carried(selA, 18*time.Millisecond, 8*time.Millisecond, f.via(t, selPeer, 0, selPeer, selA))
	f.pass(t)
	f.pass(t)
	f.pass(t)
	f.down[selA] = true
	f.pass(t)
	if r, _ := f.reported(selA); r.Retiring {
		t.Fatal("the retirement stayed announced at the floor")
	}
	f.down[selA] = false
	f.pass(t)
	if f.state(t, selA) != links.StateEstablished {
		t.Fatal("the link retired in the window its announcement resumed")
	}
	f.pass(t)
	if f.state(t, selA) != links.StateRetired {
		t.Fatal("the fourth useless window did not retire the link")
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
	// third up link lifts the floor in a window A's survivor is ejected, so
	// the freshest survivor left is unknown, which decides nothing; the next
	// window decided useless retires A.
	f = newSelFixture(t, selPeer, selA)
	carrier := f.via(t, selPeer, 0, selPeer, selA)
	around := route(-time.Minute, 0, local(9), link(selX), link(selA))
	f.carried(selA, 18*time.Millisecond, 8*time.Millisecond, carrier, around)
	for range DemoteWindows + 1 {
		f.pass(t)
	}
	if f.state(t, selA) != links.StateEstablished {
		t.Fatal("an up link retired at the floor")
	}
	if err := f.store.Insert(context.Background(),
		neighborLink(selB, links.StateEstablished)); err != nil {
		t.Fatal(err)
	}
	f.directory = append(f.directory, entryOf(selB))
	f.samples[selB] = f.priced(selB, 10*time.Millisecond, 20*time.Millisecond)
	f.carried(selA, 18*time.Millisecond, 0, with(carrier, scion.HealthEjected), around)
	f.pass(t)
	if f.state(t, selA) != links.StateEstablished {
		t.Fatal("a count at the threshold retired the link in an undecided window")
	}
	f.carried(selA, 18*time.Millisecond, 8*time.Millisecond, carrier, around)
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
	// A, B, and C ride Peer's link at 8ms, as fast as their 18ms round
	// trips with the transit charged: every exclusion but Peer's leaves the
	// tier two up links and an answered route at the price.
	for _, ia := range []addr.IA{selA, selB, selC} {
		f.carried(ia, 18*time.Millisecond, 8*time.Millisecond, f.via(t, selPeer, 0, selPeer, ia))
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
	// The first window holds one sample of each link, which confirms
	// nothing.
	for range DemoteWindows {
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
	f.carried(selA, 18*time.Millisecond, 8*time.Millisecond, f.via(t, selPeer, 0, selPeer, selA))
	f.carried(selB, 19*time.Millisecond, 8*time.Millisecond, f.via(t, selPeer, 0, selPeer, selB))
	f.pass(t)
	// D, which no route prices, beats the tier's price, sustained from the
	// second window: the third window evicts at the cap while A's useless
	// count reaches the threshold.
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
	f.carried(selA, 18*time.Millisecond, 8*time.Millisecond, f.via(t, selPeer, 0, selPeer, selA))

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

// capFixture builds the cap's fixture: Peer, A, B, and C at a cap of four in
// one tier, and the candidate D, whose one route through Peer prices it at
// 50ms, its 24ms round trip gaining 26ms. C's baseline rides A's link and
// sets the tier's price at 16ms: excluding A's link raises it to 18ms, a
// harm of 2ms, and C keeps its route through Peer. Excluding B's or C's
// link moves the price by nothing, and B is the slower direct sample. None
// of the three saves any price more than 4ms, transits charged, so each
// would yield its slot to D; without Peer's, A, B, and D keep no route.
func capFixture(t *testing.T) *selFixture {
	t.Helper()
	neighbors := []addr.IA{selPeer, selA, selB, selC}
	f := newSelFixture(t, neighbors...)
	f.sel.cfg.MaxLinks = len(neighbors)
	viaPeer := func(cost time.Duration, ia addr.IA) scion.Candidate {
		return measured(route(-time.Minute, 0, local(f.ifID(t, selPeer)), link(selPeer), link(ia)), cost)
	}
	f.samples[selPeer] = sm(30 * time.Millisecond)
	f.carried(selA, 30*time.Millisecond, 18*time.Millisecond, f.via(t, selPeer, 0, selPeer, selA))
	f.carried(selB, 36*time.Millisecond, 18*time.Millisecond, f.via(t, selPeer, 0, selPeer, selB))
	f.carried(selC, 30*time.Millisecond, 16*time.Millisecond,
		f.via(t, selA, 0, selA, selC), viaPeer(20*time.Millisecond, selC))
	f.candidate(selD, 24*time.Millisecond, 0, viaPeer(40*time.Millisecond, selD))
	return f
}

// TestSelectionCapEviction checks the cap: at it, an admission evicts the
// neighbor qualifying against the candidate whose exclusion moves its tier's
// price least, ties to the slower direct sample; none qualifying means no
// promotion; the bridge, whose exclusion leaves no answered survivor, is
// never evicted and the promotion waits; and a down link whose count
// reached DemoteWindows goes at no harm.
func TestSelectionCapEviction(t *testing.T) {
	f := capFixture(t)
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
	neighbors := []addr.IA{selPeer, selA, selB, selC}
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

// TestSelectionCapWeighsGains checks displacement at the cap by worth: a
// candidate whose gain on its price beats what a link saves by the line to
// buy, on the readings and on the price's lower bound, displaces the link
// though the link would earn its place today, the least harm first, ties to
// the slower direct sample; one whose gain does not, or whose price's lower
// bound does not confirm it, waits.
func TestSelectionCapWeighsGains(t *testing.T) {
	ms := time.Millisecond
	for _, tc := range []struct {
		name string
		// price is what D's route through X prices it at, and low its lower
		// bound, the price itself when zero.
		price, low time.Duration
		displaces  bool
	}{
		{"a gain beating every saving", 30 * ms, 0, true},
		{"a gain short of them", 20 * ms, 0, false},
		{"a gain the history does not confirm", 30 * ms, 20 * ms, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			neighbors := []addr.IA{selPeer, selA, selB, selC}
			f := newSelFixture(t, neighbors...)
			f.sel.cfg.MaxLinks = len(neighbors)
			// Peer, far, sits alone in a tier no route prices. A, B, and C
			// each reach over Peer's link at 20ms, the transit charged: each
			// link saves its own neighbor 12ms, B's 11ms, past promotion's
			// fifth, and moves the tier's price by nothing.
			f.samples[selPeer] = sm(30 * ms)
			f.carried(selA, 8*ms, 10*ms, f.via(t, selPeer, 0, selPeer, selA))
			f.carried(selB, 9*ms, 10*ms, f.via(t, selPeer, 0, selPeer, selB))
			f.carried(selC, 8*ms, 10*ms, f.via(t, selPeer, 0, selPeer, selC))
			// D's 8ms round trip gains 22ms on its 30ms price, or 12ms on
			// 20ms or on a 20ms lower bound: each beats the price.
			viaX := measured(route(-time.Hour, 0, link(selX), link(selD)), tc.price)
			if tc.low > 0 {
				viaX.Low = &tc.low
			}
			f.candidate(selD, 8*ms, 0, viaX)
			f.pass(t) // streak 1
			f.pass(t) // streak 2
			if !tc.displaces {
				if len(f.established) != 0 || !f.sel.coord.promote.Equal(selD) {
					t.Fatalf("promoted %v, announced %v; want the candidate announced and waiting",
						f.established, f.sel.coord.promote)
				}
				return
			}
			if len(f.established) != 1 || !f.established[0].Equal(selD) {
				t.Fatalf("promoted %v, want the candidate", f.established)
			}
			if f.state(t, selB) != links.StateRetired {
				t.Error("the slower of the least-harm links was not displaced")
			}
			for _, ia := range []addr.IA{selPeer, selA, selC} {
				if f.state(t, ia) != links.StateEstablished {
					t.Errorf("displacement retired %s as well", ia)
				}
			}
		})
	}
}

// TestSelectionCapTakesWhatWouldNotEarnItsPlace checks the other way a link
// yields its slot: one that would not earn its place today yields to a
// candidate that earns a link, though it saves near what the candidate
// gains.
func TestSelectionCapTakesWhatWouldNotEarnItsPlace(t *testing.T) {
	ms := time.Millisecond
	neighbors := []addr.IA{selPeer, selA, selB, selC}
	f := newSelFixture(t, neighbors...)
	f.sel.cfg.MaxLinks = len(neighbors)
	// Peer, far, sits alone in a tier no route prices. Over Peer's link, B
	// and C price at 60ms, their 40ms round trips saving them 20ms, and A at
	// 59ms, its 50ms round trip saving it 9ms: short of promotion's fifth,
	// and within the band.
	f.samples[selPeer] = sm(300 * ms)
	f.carried(selA, 50*ms, 49*ms, f.via(t, selPeer, 0, selPeer, selA))
	f.carried(selB, 40*ms, 50*ms, f.via(t, selPeer, 0, selPeer, selB))
	f.carried(selC, 40*ms, 50*ms, f.via(t, selPeer, 0, selPeer, selC))
	// D's 40ms round trip gains 11ms on its 51ms price: not A's 9ms by the
	// line to buy.
	f.candidate(selD, 40*ms, 51*ms)
	f.pass(t) // streak 1
	f.pass(t) // streak 2
	if len(f.established) != 1 || !f.established[0].Equal(selD) {
		t.Fatalf("promoted %v, want the candidate", f.established)
	}
	if f.state(t, selA) != links.StateRetired {
		t.Error("the link that would not earn its place kept it")
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
	// round route through the bridge; R1's one hop over its own link prices
	// R1 whichever regional link an exclusion leaves out. R2's route through
	// R1 stays within the band of its round trip, its transit charged, while
	// R3's one route rides R1's link: R2's is the regional link an eviction
	// may take.
	oneHop := measured(route(0, 0, local(f.ifID(t, r1)), link(r1)), 20*time.Millisecond)
	f.carried(r1, 10*time.Millisecond, 20*time.Millisecond,
		f.via(t, r2, 0, r2, r1), oneHop, f.via(t, z, -time.Minute, z, selX, r1))
	f.carried(r2, 18*time.Millisecond, 11*time.Millisecond,
		f.via(t, r1, 0, r1, r2), f.via(t, z, -time.Minute, z, selX, r2))
	f.carried(z, 100*time.Millisecond, 200*time.Millisecond, f.via(t, z, 0, z))
	f.candidate(r3, 5*time.Millisecond, 20*time.Millisecond, f.via(t, r1, 0, r1, r3))

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
	f.samples[z] = sm(0, f.via(t, z, 0, z))
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
	f.sel.establishFn = func(context.Context, target, string) bool { return false }

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
	f.samples[selB] = sm(0)
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
	if err := f.store.Insert(context.Background(),
		neighborLink(selC, links.StateCandidate)); err != nil {
		t.Fatal(err)
	}
	f.candidate(selD, 8*time.Millisecond, 20*time.Millisecond)

	f.pass(t) // streak 1
	f.pass(t) // streak 2: at the cap, nothing qualifies for eviction
	if len(f.established) != 0 {
		t.Errorf("promoted %v past the candidate holding the cap's last place", f.established)
	}
}

// TestSelectionCapRetryEvictsNothing checks an admission the far end does
// not answer: the displacement frees one slot, the candidate's own entry
// holds it, and the next window's retry evicts nothing more.
func TestSelectionCapRetryEvictsNothing(t *testing.T) {
	f := capFixture(t)
	attempts := 0
	f.sel.establishFn = func(_ context.Context, e target, _ string) bool {
		attempts++
		if !f.hasEntry(t, e.IA) {
			if err := f.store.Insert(context.Background(),
				neighborLink(e.IA, links.StateCandidate)); err != nil {
				t.Error(err)
			}
		}
		return false
	}
	f.pass(t) // streak 1
	f.pass(t) // streak 2: evicts B, and the far end does not answer
	f.pass(t) // the retry
	if attempts != 2 {
		t.Fatalf("establishments tried %d times, want 2", attempts)
	}
	if f.state(t, selB) != links.StateRetired {
		t.Error("the displacement retired no link")
	}
	for _, ia := range []addr.IA{selPeer, selA, selC} {
		if f.state(t, ia) != links.StateEstablished {
			t.Errorf("the retry displaced %s as well", ia)
		}
	}
}

// TestSelectionSweepCandidateWindow checks the candidate sweep: a candidate
// whose confirm never lands retires once the window passes — the sweep
// establishes nothing on its own, the authenticated link request alone does,
// and the chain's existence no longer promotes. The sweep reads the clock,
// so the test runs in a bubble: the window's passage is a fake-time sleep —
// instant, and never a real-time race.
func TestSelectionSweepCandidateWindow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newSelFixture(t)
		f.sel.cfg.Window = 10 * time.Millisecond
		unconfirmed := &links.Link{
			NeighborIA: selPeer,
			Local:      netip.MustParseAddrPort("127.0.0.1:40003"),
			Remote:     netip.MustParseAddrPort("127.0.0.1:40004"),
			State:      links.StateCandidate,
		}
		if err := f.store.Insert(context.Background(), unconfirmed); err != nil {
			t.Fatal(err)
		}

		time.Sleep(20 * time.Millisecond)
		f.pass(t)
		if got := f.state(t, selPeer); got != links.StateRetired {
			t.Errorf("the candidate no confirm landed on is %v, want it retired", got)
		}
	})
}

// TestSelectionNoAction checks the comparator's quiet case: neutral
// evidence — no verdict edges, no streak thresholds met, no cap pressure —
// moves nothing.
func TestSelectionNoAction(t *testing.T) {
	f := newSelFixture(t, selPeer, selA)
	f.samples[selPeer] = f.priced(selPeer, 20*time.Millisecond, 20*time.Millisecond)
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
	if f.writes != 0 {
		t.Errorf("the loop wrote %d times on neutral evidence, want none", f.writes)
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
			l := neighborLink(name, links.StateCandidate)
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

// TestSelectionCancelledPassLandsNothing checks a pass its context ends
// mid-window: a grace echo the end cut short is no silence, so the stale
// candidate keeps its entry, and the window's samples promote and declare
// nothing though the floor stands unmet with a reachable candidate in view.
// The sweep reads the clock, so the test runs in a bubble.
func TestSelectionCancelledPassLandsNothing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newSelFixture(t, selPeer) // below the floor
		f.sel.cfg.Window = 50 * time.Millisecond
		latencies := new(bus.Topic[bus.LinkLatencies])
		f.sel.cfg.Latencies = latencies
		if err := f.store.Insert(context.Background(), &links.Link{
			NeighborIA: selB,
			Local:      netip.MustParseAddrPort("127.0.0.1:40003"),
			Remote:     netip.MustParseAddrPort("127.0.0.1:40004"),
			State:      links.StateCandidate,
		}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(60 * time.Millisecond) // the candidate outlives the window
		f.candidate(selA, 30*time.Millisecond, 10*time.Millisecond)

		// The context ends during the sweep's grace echo, which goes
		// unanswered.
		ctx, cancel := context.WithCancel(context.Background())
		f.sel.aliveFn = func(*links.Link) bool {
			cancel()
			return false
		}
		f.refresh()
		f.sel.pass(ctx)
		if f.state(t, selB) != links.StateCandidate {
			t.Error("the candidate whose grace echo the end cut short retired")
		}
		if len(f.established) != 0 {
			t.Errorf("promoted %v, want nothing", f.established)
		}
		if got := latencies.Latest().Of(f.ifID(t, selPeer)); got != 0 {
			t.Errorf("declared one-way delay = %v, want nothing declared", got)
		}
	})
}

// TestEchoesEndWithTheirContext checks the SCMP echoes' wait: a probe no
// one answers, its context ending once the first request is out, returns
// well inside the run's ProbeWait — the end cuts the wait short, and no next
// run starts. A plain UDP socket stands in for the router the requests leave
// through.
func TestEchoesEndWithTheirContext(t *testing.T) {
	host := netip.MustParseAddr("127.0.0.1")
	router, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(host, 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = router.Close() }()
	conn, err := scion.NewConn(scion.ConnConfig{
		IA:           selIA,
		Bind:         netip.AddrPortFrom(host, 0).String(),
		InternalAddr: router.LocalAddr().String(),
		MACKey:       make([]byte, 16),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	s := &selection{cfg: SelectionConfig{Conn: conn}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	returned := make(chan struct{})
	start := time.Now()
	go func() {
		s.echoes(ctx, &scion.Addr{
			IA:   selPeer,
			Addr: netip.AddrPortFrom(host, 30041),
			IfID: 1,
		})
		close(returned)
	}()
	if _, _, err := router.ReadFromUDP(make([]byte, 2048)); err != nil {
		t.Fatal(err)
	}
	cancel()
	<-returned
	// The run's deadline is set after start: a wait the end does not cut
	// short holds the probe a full ProbeWait.
	if held := time.Since(start); held >= ProbeWait {
		t.Errorf("the echoes returned after %v, want under ProbeWait", held)
	}
}

// interfaceDownAnswer builds the data plane's refusal of a down egress: an
// SCMP External Interface Down quoting the refused packet.
func interfaceDownAnswer(quoted []byte) ([]byte, error) {
	host := addr.HostIP(netip.MustParseAddr("127.0.0.1"))
	scn := &slayers.SCION{
		NextHdr:  slayers.L4SCMP,
		PathType: empty.PathType,
		Path:     &empty.Path{},
		SrcIA:    selIA,
		DstIA:    selIA,
	}
	if err := scn.SetSrcAddr(host); err != nil {
		return nil, err
	}
	if err := scn.SetDstAddr(host); err != nil {
		return nil, err
	}
	scmp := &slayers.SCMP{TypeCode: slayers.CreateSCMPTypeCode(
		slayers.SCMPTypeExternalInterfaceDown, 0)}
	scmp.SetNetworkLayerForChecksum(scn)
	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, scn, scmp, &slayers.SCMPExternalInterfaceDown{IA: selIA, IfID: 1},
		gopacket.Payload(quoted))
	return buffer.Bytes(), err
}

// TestEchoesEndAtTheInterfaceDownSignal checks the refused run: a router
// answering every request with an interface-down signal quoting it — the
// data plane refusing a down egress — ends each run at once, so the probe
// reports no round trip well inside one ProbeWait rather than after
// ProbeRuns of them.
func TestEchoesEndAtTheInterfaceDownSignal(t *testing.T) {
	host := netip.MustParseAddr("127.0.0.1")
	router, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(host, 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = router.Close() }()
	conn, err := scion.NewConn(scion.ConnConfig{
		IA:           selIA,
		Bind:         netip.AddrPortFrom(host, 0).String(),
		InternalAddr: router.LocalAddr().String(),
		MACKey:       make([]byte, 16),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	s := &selection{cfg: SelectionConfig{Conn: conn}}

	refused := make(chan error, 1)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := router.ReadFromUDP(buf)
			if err != nil {
				refused <- nil // the episode closed the router
				return
			}
			answer, err := interfaceDownAnswer(buf[:n])
			if err == nil {
				_, err = router.WriteToUDP(answer, from)
			}
			if err != nil {
				refused <- err
				return
			}
		}
	}()
	start := time.Now()
	rtts := s.echoes(context.Background(), &scion.Addr{
		IA:   selPeer,
		Addr: netip.AddrPortFrom(host, 30041),
		IfID: 1,
	})
	held := time.Since(start)
	_ = router.Close()
	if err := <-refused; err != nil {
		t.Fatal(err)
	}
	if len(rtts) != 0 {
		t.Errorf("the echoes = %v over refused runs, want no round trip", rtts)
	}
	if held >= ProbeWait {
		t.Errorf("the echoes returned after %v, want under one ProbeWait", held)
	}
}

// emptyPathDB is a path database holding no segment; Get is all a probe's
// enumeration reads.
type emptyPathDB struct{ pathdb.DB }

func (emptyPathDB) Get(context.Context, pathdb.Query) ([]*pathdb.Segment, error) {
	return nil, nil
}

// TestProbeSendsNothingOverAnUnusableLink checks a down neighbor's probe:
// the node's conns resolve one-hop writes over the links it can send over,
// so a neighbor whose link the snapshot lacks — its verdict down — fails
// every run's write at once, and the probe sends the router nothing and
// returns no direct sample within one ProbeWait.
func TestProbeSendsNothingOverAnUnusableLink(t *testing.T) {
	host := netip.MustParseAddr("127.0.0.1")
	router, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(host, 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = router.Close() }()
	noLinks := new(bus.Topic[bus.LinkState])
	noLinks.Publish(bus.NewLinkState())
	conn, err := scion.NewConn(scion.ConnConfig{
		IA:           selIA,
		Bind:         netip.AddrPortFrom(host, 0).String(),
		InternalAddr: router.LocalAddr().String(),
		MACKey:       make([]byte, 16),
		Links:        noLinks,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	s := &selection{cfg: SelectionConfig{
		Conn: conn,
		Paths: &scion.PathProvider{
			IA:     selIA,
			DB:     emptyPathDB{},
			Lookup: func(context.Context, addr.IA) []*pathdb.Segment { return nil },
		},
	}}

	start := time.Now()
	_, _, rtts := s.probe(context.Background(),
		target{IA: selPeer, ControlAddr: netip.AddrPortFrom(host, 30042)},
		&links.Link{NeighborIA: selPeer, IfID: 1, State: links.StateEstablished})
	if held := time.Since(start); held >= ProbeWait {
		t.Errorf("the probe returned after %v, want under one ProbeWait", held)
	}
	if len(rtts) != 0 {
		t.Errorf("round trips = %v, want none for the down neighbor", rtts)
	}
	// A request the probe sent is queued at the router by now; the deadline
	// bounds the read when none was.
	if err := router.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if n, _, err := router.ReadFromUDP(make([]byte, 2048)); err == nil {
		t.Errorf("the probe sent %d bytes toward the down neighbor", n)
	}
}

// probeHost is the loopback host the probe's two-node episode binds on, one
// no other test of any package takes: the peer's responder holds the fixed
// endhost port.
var probeHost = netip.MustParseAddr("127.0.0.132")

// TestProbeEchoesTheHostThePeerResolves checks the host a neighbor's echoes
// address: the one the peer's own resolution names, never the directory's
// published host. The peer publishes a host none of its sockets hold — a
// NAT's public side — while its control service answers the drafts'
// resolution with the host it binds and its responder answers the echoes
// there: the direct sample measures, and the window keeps the resolved host
// for the echoes after it.
func TestProbeEchoesTheHostThePeerResolves(t *testing.T) {
	extP, extQ := dataplanetest.FreeUDPAddr(t, probeHost), dataplanetest.FreeUDPAddr(t, probeHost)
	p := dataplanetest.StartNode(t, probeHost, selIA, selPeer, extP, extQ)
	q := dataplanetest.StartNode(t, probeHost, selPeer, selIA, extQ, extP)
	newConn := func(n *dataplanetest.Node, port uint16) *scion.Conn {
		t.Helper()
		conn, err := scion.NewConn(scion.ConnConfig{
			IA:           n.IA,
			Bind:         netip.AddrPortFrom(n.ControlIP, port).String(),
			InternalAddr: n.Internal,
			MACKey:       n.MACKey,
			Links:        n.Links(),
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	}

	// The peer's control service answers the resolution with its own
	// socket's address, the endpoint's answer; its responder answers the
	// echoes on the endhost port beside it.
	endpoint := newConn(q, 0)
	q.MapService(t, addr.SvcCS, endpoint.LocalPort())
	go func() {
		buf := make([]byte, 64)
		for {
			_, from, err := endpoint.ReadFrom(buf)
			if err != nil {
				return
			}
			local, _ := endpoint.SourceAddr()
			resp, err := proto.Marshal(&control_plane.ServiceResolutionResponse{
				Transports: map[string]*control_plane.Transport{
					scionrpc.TransportQUIC: {Address: local.String()},
				},
			})
			if err == nil {
				_, _ = endpoint.WriteTo(resp, from)
			}
		}
	}()
	responder := newConn(q, underlay.EndhostPort)
	go func() {
		for {
			echo, from, err := responder.ReadEchoFrom()
			if err != nil {
				return
			}
			if !echo.Reply {
				_ = responder.WriteEchoReplyTo(from, echo.Identifier, echo.Seq, echo.Payload)
			}
		}
	}()

	s := &selection{cfg: SelectionConfig{
		IA:   selIA,
		Conn: newConn(p, 0),
		Paths: &scion.PathProvider{
			IA:     selIA,
			DB:     emptyPathDB{},
			Lookup: func(context.Context, addr.IA) []*pathdb.Segment { return nil },
		},
	}}
	external := netip.MustParseAddr("192.0.2.1")
	_, by, rtts := s.probe(t.Context(),
		target{IA: selPeer, ControlAddr: netip.AddrPortFrom(external, 30042)},
		&links.Link{NeighborIA: selPeer, IfID: dataplanetest.IfID, State: links.StateEstablished})
	if len(rtts) != ProbeRuns {
		t.Errorf("round trips = %v, want ProbeRuns echoes' to the resolved host", rtts)
	}
	if want := (instrument{ia: selPeer, ifID: dataplanetest.IfID}); by != want {
		t.Errorf("instrument = %+v, want the link's %+v", by, want)
	}
	if got := s.hosts[selPeer]; got != q.ControlIP {
		t.Errorf("the window's host of the peer = %v, want the resolved %v", got, q.ControlIP)
	}
}

// TestSelectionDrawsEveryScope checks the candidates' source: every address
// the entries of every directory name, a peer's addresses gathered across
// the directories by directory ID, the peers ordered by ISD-AS, and an
// entry naming no address naming no target.
func TestSelectionDrawsEveryScope(t *testing.T) {
	topic := new(bus.Topic[bus.Directory])
	at := func(ia addr.IA, rendezvous ...string) bus.DirectoryEntry {
		e := bus.DirectoryEntry{IA: ia}
		for _, r := range rendezvous {
			e.Addresses = append(e.Addresses, bus.Address{RendezvousAddr: netip.MustParseAddrPort(r)})
		}
		return e
	}
	inner, outer := bus.DirectoryID{1}, bus.DirectoryID{2}
	topic.Publish(bus.NewDirectory(nil,
		bus.NewScope(outer, at(selB, "203.0.113.1:30043", "203.0.113.2:30043"), at(selA, "203.0.113.3:30043")),
		bus.NewScope(inner, at(selB, "10.0.0.2:30043"), at(selC))))
	s := &selection{cfg: SelectionConfig{Directory: topic}}
	type got struct {
		IA    addr.IA
		Scope bus.DirectoryID
		Host  string
	}
	var peers []got
	for _, p := range s.peers() {
		for _, t := range p.targets {
			peers = append(peers, got{p.IA, t.Scope, t.RendezvousAddr.String()})
		}
	}
	want := []got{
		{selA, outer, "203.0.113.3:30043"},
		{selB, inner, "10.0.0.2:30043"},
		{selB, outer, "203.0.113.1:30043"},
		{selB, outer, "203.0.113.2:30043"},
	}
	if diff := cmp.Diff(want, peers); diff != "" {
		t.Errorf("the peers' targets (-want +got):\n%s", diff)
	}
}

// TestSelectionChoosesTheAddress checks the address a candidate is measured
// at: its only one unprobed; of those whose report says they answer, the
// one whose binding request answers fastest, the unanswering ones never
// asked; else the first that reports itself unanswered, which the punch
// reaches; else the first.
func TestSelectionChoosesTheAddress(t *testing.T) {
	at := func(rendezvous string, unanswered bool) target {
		return target{IA: selB, Scope: selScope,
			RendezvousAddr: netip.MustParseAddrPort(rendezvous),
			Reach:          bus.Reach{RendezvousUnanswered: unanswered}}
	}
	slow, fast := at("192.0.2.1:30043", false), at("10.0.0.2:30043", false)
	silent, gateway := at("192.0.2.9:30043", false), at("203.0.113.1:30043", true)
	rtts := map[netip.AddrPort]time.Duration{
		slow.RendezvousAddr: 20 * time.Millisecond, fast.RendezvousAddr: 2 * time.Millisecond,
	}
	var asked []netip.AddrPort
	s := &selection{rendezvousFn: func(_ context.Context, socket netip.AddrPort) (time.Duration, error) {
		asked = append(asked, socket)
		if rtt, ok := rtts[socket]; ok {
			return rtt, nil
		}
		return 0, errors.New("no answer")
	}}
	for _, tc := range []struct {
		name    string
		punch   bool
		targets []target
		want    target
		asked   int
	}{
		{"the only address", false, []target{gateway}, gateway, 0},
		{"the fastest answering", false, []target{slow, gateway, fast}, fast, 2},
		{"the punched one when none answers", true, []target{silent, gateway}, gateway, 1},
		{"the first with no punch", false, []target{silent, gateway}, silent, 1},
	} {
		asked = nil
		s.cfg.Punch = nil
		if tc.punch {
			s.cfg.Punch = &stubPuncher{}
		}
		if got := s.choose(t.Context(), peer{IA: selB, targets: tc.targets}); got != tc.want {
			t.Errorf("%s: chose %v, want %v", tc.name, got.RendezvousAddr, tc.want.RendezvousAddr)
		}
		if len(asked) != tc.asked {
			t.Errorf("%s: asked %v, want %d binding requests", tc.name, asked, tc.asked)
		}
	}
}

// TestProbeRendezvousRecordsNothing checks the round trips that ask a
// candidate's rendezvous socket whether it answers: the window's probe
// measures the candidate's direct round trip and the sweep finds it alive,
// each over a binding request, while the candidate's acceptor records
// nothing.
func TestProbeRendezvousRecordsNothing(t *testing.T) {
	f := newRendezvousFixture(t, func(cfg *RendezvousConfig) {
		cfg.IA = selB
	})
	s := &selection{cfg: SelectionConfig{
		ControlHost: netip.MustParseAddr("127.0.0.1"),
		Paths: &scion.PathProvider{
			IA:     selIA,
			DB:     emptyPathDB{},
			Lookup: func(context.Context, addr.IA) []*pathdb.Segment { return nil },
		},
	}}

	_, by, rtts := s.probe(t.Context(), targetOf(selB, f.addr.String()), nil)
	if len(rtts) != ProbeRuns {
		t.Errorf("round trips = %v, want ProbeRuns binding requests' answered", rtts)
	}
	if want := (instrument{ia: selB, at: f.addr}); by != want {
		t.Errorf("instrument = %+v, want the address's %+v", by, want)
	}
	candidate := &links.Link{NeighborIA: selB, Rendezvous: f.addr, State: links.StateCandidate}
	if !s.candidateAlive(t.Context(), candidate) {
		t.Error("the sweep found the answering candidate silent")
	}
	entries, err := f.store.All(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("the candidate's acceptor recorded %v, want nothing", entries)
	}
}

// readingPaths answers every enumeration with its routes.
type readingPaths []scion.Candidate

func (p readingPaths) Enumerate(context.Context, addr.IA) ([]scion.Candidate, error) {
	return slices.Clone(p), nil
}

// TestProbeReadsTheCandidate checks a candidate's window probe: up to
// ProbeRuns binding requests to its address, the first unanswered one ending
// them, and the routes to it each priced by its reading rather than its
// cost.
func TestProbeReadsTheCandidate(t *testing.T) {
	ms := time.Millisecond
	cost, reading := 10*ms, 25*ms
	for _, tc := range []struct {
		name    string
		answers []bool
		want    []time.Duration
		asked   int
	}{
		{"every request answered", []bool{true, true, true}, []time.Duration{ms, 2 * ms, 3 * ms}, 3},
		{"the second unanswered", []bool{true, false, true}, []time.Duration{ms}, 2},
	} {
		asked := 0
		s := &selection{
			cfg: SelectionConfig{Paths: readingPaths{{ID: "route", Cost: &cost, Reading: &reading}}},
			rendezvousFn: func(context.Context, netip.AddrPort) (time.Duration, error) {
				asked++
				if !tc.answers[asked-1] {
					return 0, errors.New("no answer")
				}
				return time.Duration(asked) * ms, nil
			},
		}
		sm, by, rtts := s.probe(t.Context(), targetOf(selB, "192.0.2.1:30043"), nil)
		if !slices.Equal(rtts, tc.want) || asked != tc.asked {
			t.Errorf("%s: round trips = %v over %d requests, want %v over %d", tc.name, rtts, asked,
				tc.want, tc.asked)
		}
		if want := (instrument{ia: selB, at: netip.MustParseAddrPort("192.0.2.1:30043")}); by != want {
			t.Errorf("%s: instrument = %+v, want %+v", tc.name, by, want)
		}
		if len(sm.candidates) != 1 || sm.candidates[0].Cost == nil || *sm.candidates[0].Cost != reading {
			t.Errorf("%s: routes = %+v, want the route priced at its reading %v", tc.name, sm.candidates, reading)
		}
	}
}

// TestSelectionRendezvousGuard checks the rendezvous establishment's guard:
// a reply naming the entry's ISD-AS records the link, and one naming another
// ISD-AS — the answer of a colliding subnet's real peer at the published
// address — is refused.
func TestSelectionRendezvousGuard(t *testing.T) {
	f := newRendezvousFixture(t, func(cfg *RendezvousConfig) {
		cfg.IA = rendezvousIA
	})
	s := &selection{
		cfg: SelectionConfig{
			Store:    memory.New(),
			LinkHost: netip.MustParseAddr("127.0.0.1"),
		},
	}
	// Each entry takes its own local address: the store refuses two live
	// entries on one.
	port := uint16(40000)
	entry := func(t *testing.T, claimed addr.IA) *links.Link {
		t.Helper()
		port++
		l := &links.Link{
			NeighborIA: claimed,
			Local:      netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port),
			State:      links.StateCandidate,
		}
		if err := s.cfg.Store.Insert(context.Background(), l); err != nil {
			t.Fatal(err)
		}
		return l
	}

	// The matching reply records the link's remote side.
	l := entry(t, rendezvousIA)
	e := targetOf(rendezvousIA, f.addr.String())
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

	// A reply naming another ISD-AS is refused: the entry keeps its side.
	l = entry(t, strangerKeyIA)
	e = targetOf(strangerKeyIA, f.addr.String())
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

// linkRequester adapts a function to the establishment's client seam.
type linkRequester func(context.Context, *scion.Addr, *links.Link) (*nodev1.LinkReply, error)

func (f linkRequester) Link(
	ctx context.Context, peer *scion.Addr, l *links.Link,
) (*nodev1.LinkReply, error) {
	return f(ctx, peer, l)
}

// TestEstablishmentSeedsAndConfirms checks the establishment's flip: the
// rendezvous exchange seeds and names — its dial leaving from the entry's
// own link address, the state it leaves the candidate the confirm waits on,
// the acceptor's entry aimed at the observed mapping — and the link request
// over the one-hop path establishes on the reply, the claim rule recording
// the reply's side on the host the request dialed; a reply naming a host
// records it verbatim, and an entry already holding its remote skips the
// exchange.
func TestEstablishmentSeedsAndConfirms(t *testing.T) {
	f := newRendezvousFixture(t, func(cfg *RendezvousConfig) {
		cfg.IA = selB
	})
	store := memory.New()
	claimed := "0.0.0.0:4242"
	var dialed *scion.Addr
	var dialedIfID uint16
	s := &selection{
		streaks: make(map[addr.IA]*peerStreak),
		cfg: SelectionConfig{
			IA:       selIA,
			Store:    store,
			LinkHost: netip.MustParseAddr("127.0.0.1"),
			Link: linkRequester(func(_ context.Context, peer *scion.Addr,
				l *links.Link) (*nodev1.LinkReply, error) {
				dialed = peer
				dialedIfID = l.IfID
				return &nodev1.LinkReply{LocalAddr: claimed, IfId: 9}, nil
			}),
		}}
	published := netip.MustParseAddr("198.51.100.7")
	e := target{IA: selB, Scope: selScope,
		ControlAddr:    netip.AddrPortFrom(published, 30042),
		RendezvousAddr: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), f.addr.Port())}
	if !s.establishLink(context.Background(), e, "the test") {
		t.Fatal("the establishment failed")
	}
	entry, err := store.ByNeighbor(context.Background(), selB)
	if err != nil || entry == nil {
		t.Fatalf("no entry recorded (%v)", err)
	}
	// The confirm's reply establishes, the claim rule recording the claim's
	// port on the published host — the peer's address as the directory
	// spells it.
	if entry.State != links.StateEstablished {
		t.Errorf("entry state = %v, want established", entry.State)
	}
	if want := netip.AddrPortFrom(published, 4242); entry.Remote != want {
		t.Errorf("entry remote = %v, want the published host under the claim's port %v",
			entry.Remote, want)
	}
	if entry.RemoteIfID != 9 {
		t.Errorf("entry remote interface = %d, want the reply's 9", entry.RemoteIfID)
	}
	// The confirm dialed the peer's control service — the receiving AS's
	// own resolution names the endpoint, no host of the peer spelled — over
	// the seeded entry's interface.
	if dialed == nil || dialed.IA != selB || dialed.Service != addr.SvcCS || dialed.Path != nil {
		t.Errorf("the request dialed %+v, want the peer's control service one-hop", dialed)
	}
	if dialedIfID != entry.IfID {
		t.Errorf("the request offered interface %d, want the entry's %d", dialedIfID, entry.IfID)
	}
	// The exchange seeded the far side: the acceptor's entry a candidate
	// aimed at the establishment dial's observation — the entry's own link
	// address, the socket that will serve.
	accepted, err := f.store.ByNeighbor(context.Background(), selIA)
	if err != nil || accepted == nil {
		t.Fatalf("the acceptor recorded no entry (%v)", err)
	}
	if accepted.State != links.StateCandidate {
		t.Errorf("the acceptor's entry is %v, want the candidate the confirm lands on",
			accepted.State)
	}
	if accepted.Remote != entry.Local {
		t.Errorf("the acceptor's entry aims at %v, want the joiner's link address %v",
			accepted.Remote, entry.Local)
	}

	// A reply naming a host records it verbatim, the entry already holding
	// its remote: the exchange is skipped, the confirm re-run alone.
	claimed = "127.0.0.1:4343"
	if !s.establishLink(context.Background(), e, "the test") {
		t.Fatal("the re-establishment failed")
	}
	entry, err = store.ByNeighbor(context.Background(), selB)
	if err != nil || entry == nil {
		t.Fatalf("no entry recorded (%v)", err)
	}
	if want := netip.MustParseAddrPort(claimed); entry.Remote != want {
		t.Errorf("the concrete claim's remote = %v, want it verbatim %v", entry.Remote, want)
	}
	entries, err := f.store.All(context.Background())
	if err != nil || len(entries) != 1 {
		t.Errorf("the acceptor holds %v, want the one seeded entry", entries)
	}
}

// TestSelectionLosesRecordRace checks a promotion that loses the race to
// record its neighbor: another writer records the neighbor between the
// selection's lookup and its insert, the store refuses the second live
// entry, and the promotion proceeds on the recorded one.
func TestSelectionLosesRecordRace(t *testing.T) {
	store := &staleStore{DB: memory.New()}
	s := &selection{cfg: SelectionConfig{
		Store:    store,
		LinkHost: netip.MustParseAddr("127.0.0.1"),
	}}
	recorded := liveLink(selA, 40001)
	recorded.State = links.StateCandidate
	if err := store.Insert(context.Background(), recorded); err != nil {
		t.Fatal(err)
	}
	store.armed.Store(true)
	entry, err := s.ownEntry(context.Background(), targetOf(selA, "127.0.0.1:30043"))
	if err != nil {
		t.Fatal(err)
	}
	if entry.IfID != recorded.IfID {
		t.Errorf("the promotion's entry = %+v, want the recorded one, interface %d",
			entry, recorded.IfID)
	}
	want := []links.State{links.StateCandidate}
	if got := statesOf(t, store.DB, selA); !slices.Equal(got, want) {
		t.Errorf("the neighbor's entries = %v, want the recorded one alone", got)
	}
}

// TestSelectionLosesPortRace checks a promotion that loses the race for
// the port it drew: another writer records an entry on that address
// between the selection's draw and its insert, the store refuses a second
// live entry on it, and the promotion records its own entry on a fresh
// address.
func TestSelectionLosesPortRace(t *testing.T) {
	store := &squattedStore{DB: memory.New()}
	s := &selection{cfg: SelectionConfig{
		Store:    store,
		LinkHost: netip.MustParseAddr("127.0.0.1"),
	}}
	store.armed.Store(true)
	entry, err := s.ownEntry(context.Background(), targetOf(selA, "127.0.0.1:30043"))
	if err != nil {
		t.Fatal(err)
	}
	lostPortRace(t, store, selA, entry.Local)
}

// TestSelectionRejoinTakesRetiredLocal checks the promotion of a neighbor
// whose link the node retired while the neighbor's side stays established:
// the neighbor's acceptor answers the rendezvous claim with that side
// unchanged, its remote the retired entry's local address, so the new entry
// takes that address, the neighbor's latest retired one, not an earlier
// entry's or another neighbor's, and the two sides name each other. Once a
// live entry holds the address, the promotion draws a fresh one.
func TestSelectionRejoinTakesRetiredLocal(t *testing.T) {
	ctx := context.Background()
	peer := newRendezvousFixture(t, func(cfg *RendezvousConfig) {
		cfg.IA = rendezvousIA
	})
	host := netip.MustParseAddr("127.0.0.1")
	retiredSide := netip.AddrPortFrom(host, 40001)
	peerSide := netip.AddrPortFrom(host, 40002)
	if err := peer.store.Insert(ctx, &links.Link{
		NeighborIA: selIA,
		Local:      peerSide,
		Remote:     retiredSide,
		State:      links.StateEstablished,
	}); err != nil {
		t.Fatal(err)
	}
	newSelection := func(t *testing.T) *selection {
		t.Helper()
		s := &selection{cfg: SelectionConfig{
			IA:       selIA,
			Store:    memory.New(),
			LinkHost: host,
		}}
		now := time.Now()
		for _, l := range []*links.Link{
			// An earlier retired link to the neighbor, and a later one to
			// another neighbor: neither is the address the neighbor's side
			// names.
			{NeighborIA: rendezvousIA, Local: netip.AddrPortFrom(host, 40003),
				Remote: peerSide, State: links.StateRetired, Retired: now.Add(-time.Hour)},
			{NeighborIA: selB, Local: netip.AddrPortFrom(host, 40004),
				Remote: netip.AddrPortFrom(host, 40005), State: links.StateRetired,
				Retired: now.Add(time.Minute)},
			{NeighborIA: rendezvousIA, Local: retiredSide, Remote: peerSide,
				State: links.StateRetired, Retired: now},
		} {
			if err := s.cfg.Store.Insert(ctx, l); err != nil {
				t.Fatal(err)
			}
		}
		return s
	}
	e := targetOf(rendezvousIA, peer.addr.String())

	s := newSelection(t)
	entry, err := s.ownEntry(ctx, e)
	if err != nil {
		t.Fatal(err)
	}
	if !s.establishByRendezvous(ctx, e, entry) {
		t.Fatal("the rendezvous establishment failed")
	}
	if entry.Local != retiredSide || entry.Remote != peerSide {
		t.Errorf("the re-joined entry links %v to %v, want %v to %v, the neighbor's side",
			entry.Local, entry.Remote, retiredSide, peerSide)
	}

	s = newSelection(t)
	if err := s.cfg.Store.Insert(ctx, liveLink(selB, retiredSide.Port())); err != nil {
		t.Fatal(err)
	}
	entry, err = s.ownEntry(ctx, e)
	if err != nil {
		t.Fatal(err)
	}
	if entry.Local == retiredSide {
		t.Errorf("the promotion took %v, which a live entry holds", entry.Local)
	}
}
