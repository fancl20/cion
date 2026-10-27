package measured

import (
	"context"
	"errors"
	"maps"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/scionrpc"
	"github.com/fancl20/cion/pkg/libs/underlay"
	"github.com/fancl20/cion/pkg/modules/links"
	"github.com/fancl20/cion/pkg/modules/links/impl/memory"
	"github.com/fancl20/cion/pkg/modules/topology"
	"github.com/fancl20/cion/pkg/modules/topology/impl/providertest"
	nodev1 "github.com/fancl20/cion/proto/node/v1"
	nodev1connect "github.com/fancl20/cion/proto/node/v1/nodev1connect"
)

// zeroconfDraw is a first start's provisional draw: a private-range ISD-AS
// whose ISD the provider completes.
var zeroconfDraw = addr.MustIAFrom(20, 0xfd0000000051)

// TestZeroconfCompletesByEcho checks the measured completion: a first
// start's provisional ISD draw is completed from a bootstrap neighbor's
// rendezvous reply — the AS drawn kept, the ISD the network's — with the
// bootstrap remembered so the seed lands retargeted.
func TestZeroconfCompletesByEcho(t *testing.T) {
	f := newRendezvousFixture(t, func(cfg *RendezvousConfig) {
		cfg.IA = rendezvousIA
	})
	z, err := New(Config{
		Neighbors:   []string{f.addr.String()},
		ControlHost: netip.MustParseAddr("127.0.0.1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	ia, err := z.CompleteIdentity(context.Background(), zeroconfDraw)
	if err != nil {
		t.Fatal(err)
	}
	if ia.ISD() != rendezvousIA.ISD() {
		t.Errorf("completed ISD = %d, want the answering neighbor's %d",
			ia.ISD(), rendezvousIA.ISD())
	}
	if ia.AS() != zeroconfDraw.AS() {
		t.Errorf("completed AS = %x, want the drawn %x", ia.AS(), zeroconfDraw.AS())
	}
	if z.bootstrap == nil || z.bootstrap.target != f.addr {
		t.Error("the bootstrap's reply was not kept for the seed")
	}

	// The seed lands the bootstrap's neighbor retargeted: the reply's
	// addresses carry, the entry a candidate.
	store := memory.New()
	z.Wire(topology.Environment{IA: ia, Store: store})
	if err := z.Seed(context.Background()); err != nil {
		t.Fatal(err)
	}
	entry, err := store.ByNeighbor(context.Background(), rendezvousIA)
	if err != nil || entry == nil {
		t.Fatalf("no seeded entry (%v)", err)
	}
	if entry.State != links.StateCandidate || entry.Remote != z.bootstrap.reply.LinkAddr {
		t.Errorf("seeded entry = %+v, want the retargeted candidate", entry)
	}
}

// TestZeroconfCoreDrawIsFinal checks the founding core's completion: its
// draw is its network's name already, so the identity returns unchanged and
// no dial is made — a dead rendezvous would fail it.
func TestZeroconfCoreDrawIsFinal(t *testing.T) {
	z, err := New(Config{
		Core:      true,
		Neighbors: []string{"127.0.0.1:1"}, // nothing answers there
	})
	if err != nil {
		t.Fatal(err)
	}
	ia, err := z.CompleteIdentity(context.Background(), zeroconfDraw)
	if err != nil {
		t.Fatal(err)
	}
	if ia != zeroconfDraw {
		t.Errorf("the core's completed identity = %v, want the draw %v", ia, zeroconfDraw)
	}
}

// TestZeroconfFirstStartNeedsNeighbor checks the measured provider's half of
// the first-start neighbor requirement: a non-core with no
// --topology.neighbor and an empty store refuses to start, one with
// a neighbor does not.
func TestZeroconfFirstStartNeedsNeighbor(t *testing.T) {
	z, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := z.CompleteIdentity(context.Background(), zeroconfDraw); err == nil {
		t.Error("a non-core's first start without a --topology.neighbor completed")
	}
	z, err = New(Config{Neighbors: []string{"127.0.0.1:1"}})
	if err != nil {
		t.Fatal(err)
	}
	z.Wire(topology.Environment{Store: memory.New()})
	if _, err := z.CompleteIdentity(context.Background(), zeroconfDraw); err == nil {
		t.Error("a first start whose bootstrap neighbor never answered completed")
	}
	// The same empty store seeds cleanly once a neighbor is named and
	// answered — the requirement is the neighbor, not the store.
	f := newRendezvousFixture(t, func(cfg *RendezvousConfig) {
		cfg.IA = rendezvousIA
	})
	z, err = New(Config{Neighbors: []string{f.addr.String()}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := z.CompleteIdentity(context.Background(), zeroconfDraw); err != nil {
		t.Fatal(err)
	}
	z.Wire(topology.Environment{Store: memory.New()})
	if err := z.Seed(context.Background()); err != nil {
		t.Fatalf("seeding with a bootstrap neighbor: %v", err)
	}
}

// TestZeroconfMounts checks the mounts: the measured provider mounts the
// in-band link service on every node and the node directory's service
// beside it on the core, at the patterns the handlers name. The conventional
// rendezvous port is part of what mounts, so each join takes a loopback
// host of this package's own — the shared first host's fixed slot is not
// this suite's to hold.
func TestZeroconfMounts(t *testing.T) {
	joined := func(t *testing.T, host string, core bool) []string {
		t.Helper()
		z, err := New(Config{
			Core:        core,
			ControlHost: netip.MustParseAddr(host),
			NewConn:     func() (*scion.Conn, error) { return nil, nil },
			CoreRoute:   func() *scion.Addr { return nil },
		})
		if err != nil {
			t.Fatal(err)
		}
		z.Wire(topology.Environment{Store: memory.New()})
		// Mounts binds the rendezvous port; releasing it lets a rerun of the
		// test in the same process bind it again.
		t.Cleanup(func() { _ = z.Close() })
		mounts, err := z.Mounts()
		if err != nil {
			t.Fatal(err)
		}
		patterns := make([]string, 0, len(mounts))
		for _, m := range mounts {
			patterns = append(patterns, m.Pattern)
		}
		return patterns
	}
	linkPath := "/" + nodev1connect.LinkServiceName + "/"
	directoryPath := "/" + nodev1connect.DirectoryServiceName + "/"
	// Hosts no integration lab takes: the testnetwork pool starts above
	// 127.0.0.0/24, so the package-parallel run holds no rendezvous collision.
	if got := joined(t, "127.0.0.119", false); len(got) != 1 || got[0] != linkPath {
		t.Errorf("a non-core's mounts = %v, want the link service's alone", got)
	}
	got := joined(t, "127.0.0.120", true)
	if len(got) != 2 || got[0] != linkPath || got[1] != directoryPath {
		t.Errorf("the core's mounts = %v, want the link and directory services'", got)
	}
}

// TestProviderRunReturnsAndCloseReleases checks the provider's loops and
// sockets: a joiner assembled through Mounts on a loopback host no other
// test of the package takes, with NewConn drawing real conns, holds Run
// while its acceptor answers and returns from it once its context is
// canceled, and after Close a read on each drawn conn reports net.ErrClosed
// and the rendezvous port binds again.
func TestProviderRunReturnsAndCloseReleases(t *testing.T) {
	host := netip.MustParseAddr("127.0.0.122")
	var drawn []*scion.Conn
	z, err := New(Config{
		ControlHost: host,
		NewConn: func() (*scion.Conn, error) {
			conn, err := scion.NewConn(scion.ConnConfig{
				IA:           zeroconfDraw,
				Bind:         netip.AddrPortFrom(host, 0).String(),
				InternalAddr: netip.AddrPortFrom(host, 30001).String(),
				MACKey:       make([]byte, 16),
			})
			if err == nil {
				drawn = append(drawn, conn)
			}
			return conn, err
		},
		CoreRoute: func() *scion.Addr { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	z.Wire(topology.Environment{IA: zeroconfDraw, Store: memory.New()})
	if _, err := z.Mounts(); err != nil {
		t.Fatal(err)
	}
	if len(drawn) != 2 {
		t.Fatalf("NewConn drew %d conns, want the directory's and the probe's", len(drawn))
	}

	ctx, cancel := context.WithCancel(context.Background())
	returned := make(chan struct{})
	go func() {
		z.Run(ctx)
		close(returned)
	}()
	if _, _, _, err := RendezvousEcho(context.Background(), underlay.Kernel, netip.AddrPortFrom(host, 0),
		netip.AddrPortFrom(host, RendezvousPort), addr.IA(0),
		netip.AddrPortFrom(host, 4242)); err != nil {
		t.Fatalf("the acceptor did not answer while Run served: %v", err)
	}
	select {
	case <-returned:
		t.Fatal("Run returned before its context ended")
	default:
	}
	cancel()
	var expired <-chan time.Time
	if deadline, ok := t.Deadline(); ok {
		expired = time.After(time.Until(deadline) - 5*time.Second)
	}
	select {
	case <-returned:
	case <-expired:
		t.Fatal("Run kept running after its context ended")
	}

	if err := z.Close(); err != nil {
		t.Fatalf("Close = %v", err)
	}
	for i, conn := range drawn {
		// A past deadline ends a read on a conn Close left open.
		_ = conn.SetReadDeadline(time.Now())
		if _, _, err := conn.ReadFrom(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
			t.Errorf("a read on drawn conn %d = %v, want net.ErrClosed", i, err)
		}
	}
	rebound, err := net.ListenUDP("udp",
		net.UDPAddrFromAddrPort(netip.AddrPortFrom(host, RendezvousPort)))
	if err != nil {
		t.Fatalf("rebinding the rendezvous port: %v", err)
	}
	_ = rebound.Close()
}

// TestContract runs the module's shared contract suite: a founding core
// whose draw is final, seeding an entry per --topology.neighbor, idempotent by
// rendezvous address.
func TestContract(t *testing.T) {
	providertest.Run(t, providertest.Suite{
		New: func(t *testing.T) topology.Provider {
			z, err := New(Config{
				Core:      true,
				Neighbors: []string{"127.0.0.1:1"}, // nothing answers there
			})
			if err != nil {
				t.Fatal(err)
			}
			return z
		},
		Store: memory.New(),
	})
}

// TestPublishedHostFollowsLearning checks the host the node's own entry
// publishes: a non-core's follows the learned external host — a restart
// republishes the persisted one — the wildcard fallback publishing nothing
// until one is learned, and the founding core resolving its own domain
// through its socket source, of the family its control host binds — the
// wildcard's first answer, which names no family to filter by — holding no
// address the resolver did not vouch for.
func TestPublishedHostFollowsLearning(t *testing.T) {
	control := netip.MustParseAddr("10.0.0.7")
	z, err := New(Config{ControlHost: control, StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if got := z.publishedHost(ctx); got != control {
		t.Errorf("unlearned host = %v, want the control host %v", got, control)
	}
	learned := netip.MustParseAddr("203.0.113.7")
	z.learn(learned)
	if got := z.publishedHost(ctx); got != learned {
		t.Errorf("learned host = %v, want %v", got, learned)
	}

	restarted, err := New(Config{ControlHost: control, StateDir: z.cfg.StateDir})
	if err != nil {
		t.Fatal(err)
	}
	if got := restarted.publishedHost(ctx); got != learned {
		t.Errorf("restarted host = %v, want the persisted %v", got, learned)
	}

	// The wildcard fallback publishes nothing until a host is learned: the
	// control host names none, exactly the founder's unresolved name.
	wild, err := New(Config{
		ControlHost: netip.MustParseAddr("0.0.0.0"),
		StateDir:    t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := wild.publishedHost(ctx); got.IsValid() {
		t.Errorf("the unlearned wildcard host = %v, want the zero address", got)
	}
	wild.learn(learned)
	if got := wild.publishedHost(ctx); got != learned {
		t.Errorf("the learned wildcard host = %v, want %v", got, learned)
	}

	// The core's domain resolves through its socket source.
	resolving := func(addrs ...netip.Addr) underlay.Sockets {
		return underlay.Sockets{LookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
			return addrs, nil
		}}
	}
	core, err := New(Config{
		Core:        true,
		Domain:      "core.example.org",
		ControlHost: control,
		StateDir:    t.TempDir(),
		Sockets: resolving(
			netip.MustParseAddr("2001:db8::1"), // the wrong family
			netip.MustParseAddr("192.0.2.20"),
		),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := core.publishedHost(ctx); got != netip.MustParseAddr("192.0.2.20") {
		t.Errorf("the core's host = %v, want its domain's 192.0.2.20", got)
	}

	// A wildcard-bound core publishes the resolver's first answer.
	first := netip.MustParseAddr("2001:db8::2")
	wildCore, err := New(Config{
		Core:        true,
		Domain:      "core.example.org",
		ControlHost: netip.MustParseAddr("0.0.0.0"),
		StateDir:    t.TempDir(),
		Sockets:     resolving(first, netip.MustParseAddr("192.0.2.21")),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := wildCore.publishedHost(ctx); got != first {
		t.Errorf("the wildcard core's host = %v, want the resolver's first answer %v", got, first)
	}

	// A name that has never answered publishes nothing: no address the
	// resolver did not vouch for.
	failing, err := New(Config{
		Core:        true,
		Domain:      "core.example.org",
		ControlHost: control,
		StateDir:    t.TempDir(),
		Sockets: underlay.Sockets{LookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
			return nil, errors.New("no such name")
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := failing.publishedHost(ctx); got.IsValid() {
		t.Errorf("the core's unresolved host = %v, want the zero address", got)
	}
}

// TestStrandedRedial checks the stranded dialer: an unstranded node's dial
// pass skips the retired entries, and a stranded one — the selection loop's
// window found no reachable candidate from the directory — re-dials the
// rendezvous addresses the table already holds, an answered re-dial reviving
// the entry as a candidate with the recorded sides for the sweep to settle
// by the peer's evidence.
func TestStrandedRedial(t *testing.T) {
	f := newRendezvousFixture(t, func(cfg *RendezvousConfig) {
		cfg.IA = rendezvousIA
	})
	z, err := New(Config{ControlHost: netip.MustParseAddr("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	store := memory.New()
	z.Wire(topology.Environment{IA: zeroconfDraw, Store: store})
	retired := &links.Link{
		NeighborIA: rendezvousIA,
		Local:      netip.MustParseAddrPort("127.0.0.1:40001"),
		Remote:     netip.MustParseAddrPort("127.0.0.1:40002"),
		Rendezvous: f.addr,
		State:      links.StateRetired,
	}
	if err := store.Insert(context.Background(), retired); err != nil {
		t.Fatal(err)
	}
	entryOf := func() *links.Link {
		entries, err := store.All(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range entries {
			if l.IfID == retired.IfID {
				return l
			}
		}
		t.Fatal("the retired entry vanished")
		return nil
	}

	// Not stranded: the retired entry keeps its state.
	z.dialJoins(context.Background())
	if entry := entryOf(); entry.State != links.StateRetired {
		t.Fatalf("an unstranded dial pass revived the retired entry to %v", entry.State)
	}

	// Stranded: the re-dial revives it as a candidate, the reply's sides
	// recorded.
	z.stranded.Store(true)
	z.dialJoins(context.Background())
	entry := entryOf()
	if entry.State != links.StateCandidate {
		t.Errorf("the revived entry's state = %v, want a candidate", entry.State)
	}
	if !entry.Remote.IsValid() || entry.RemoteIfID == 0 {
		t.Errorf("the revived entry's remote = %v, interface %d, want the reply's side",
			entry.Remote, entry.RemoteIfID)
	}
}

// strandedDialer returns a stranded provider over a store holding the given
// entries, claiming its own ISD-AS so that no two dialers meet in the
// acceptor's per-ISD-AS rate limit.
func strandedDialer(t *testing.T, ia addr.IA, entries ...*links.Link) (*Provider, *memory.DB) {
	t.Helper()
	z, err := New(Config{ControlHost: netip.MustParseAddr("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	store := memory.New()
	z.Wire(topology.Environment{IA: ia, Store: store})
	for _, l := range entries {
		if err := store.Insert(context.Background(), l); err != nil {
			t.Fatal(err)
		}
	}
	z.stranded.Store(true)
	return z, store
}

// TestStrandedRevivalConfirms checks the revival's confirm: a stranded pass
// returns the entry it revived, and the revived entry's link request
// establishes it on the reply's side, whatever the confirm pass did before.
func TestStrandedRevivalConfirms(t *testing.T) {
	f := newRendezvousFixture(t, func(cfg *RendezvousConfig) {
		cfg.IA = rendezvousIA
	})
	retired := retiredLink(rendezvousIA, f.addr, 40021)
	z, store := strandedDialer(t, zeroconfDraw, retired)
	revived := z.dialJoins(context.Background())
	if len(revived) != 1 || revived[0].IfID != retired.IfID {
		t.Fatalf("the pass revived %v, want the retired entry", revived)
	}
	fake := &fakeLinkServiceClient{reply: &nodev1.LinkReply{LocalAddr: "127.0.0.1:4242", IfId: 9}}
	z.linker = linkClientOf(map[*links.Link]*fakeLinkServiceClient{revived[0]: fake})
	z.confirmRevived(context.Background(), revived[0])
	entry := entryByIfID(t, store, retired.IfID)
	if entry.State != links.StateEstablished || entry.RemoteIfID != 9 ||
		entry.Remote != netip.MustParseAddrPort("127.0.0.1:4242") {
		t.Errorf("the revived entry = %+v, want established on the reply's side", entry)
	}
	if got := fake.requests.Load(); got != 1 {
		t.Errorf("the revival sent %d link requests, want one", got)
	}
}

// liveLink returns an established entry of the neighbor, retargeted
// already so that no dial pass touches it.
func liveLink(ia addr.IA, port uint16) *links.Link {
	return &links.Link{
		NeighborIA: ia,
		Local:      netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port),
		Remote:     netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port+1),
		State:      links.StateEstablished,
	}
}

// retiredLink returns a retired entry of the neighbor recording the
// rendezvous address, its link addresses at the port and the next: a
// revival's dial claims the local one, and the acceptor holds one serving
// entry per remote address.
func retiredLink(ia addr.IA, rendezvous netip.AddrPort, port uint16) *links.Link {
	l := liveLink(ia, port)
	l.Rendezvous = rendezvous
	l.State = links.StateRetired
	return l
}

// statesOf returns the states of the neighbor's entries.
func statesOf(t *testing.T, store *memory.DB, ia addr.IA) []links.State {
	t.Helper()
	entries, err := store.All(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var states []links.State
	for _, l := range entries {
		if l.NeighborIA.Equal(ia) {
			states = append(states, l.State)
		}
	}
	slices.Sort(states)
	return states
}

// TestStrandedRedialRespectsTable checks what a revival reads from the
// table: a retired entry whose neighbor holds a live one stays retired, the
// named live entries at the cap revive nothing, an answer naming a
// neighbor the table holds live revives nothing, and of two retired entries
// of one neighbor only the first revives, the second reading the first's
// revival.
func TestStrandedRedialRespectsTable(t *testing.T) {
	f := newRendezvousFixture(t, func(cfg *RendezvousConfig) {
		cfg.IA = rendezvousIA
	})
	other := addr.MustIAFrom(20, 0xfd0000000061)
	retired := []links.State{links.StateRetired}

	t.Run("a live neighbor", func(t *testing.T) {
		z, store := strandedDialer(t, addr.MustIAFrom(20, 0xfd0000000071),
			retiredLink(rendezvousIA, f.addr, 40001), liveLink(rendezvousIA, 40011))
		z.dialJoins(context.Background())
		want := []links.State{links.StateEstablished, links.StateRetired}
		if got := statesOf(t, store, rendezvousIA); !slices.Equal(got, want) {
			t.Errorf("the neighbor's entries = %v, want %v", got, want)
		}
	})

	t.Run("the cap", func(t *testing.T) {
		entries := []*links.Link{retiredLink(rendezvousIA, f.addr, 40003)}
		for i := range MaxNeighbors {
			entries = append(entries,
				liveLink(addr.MustIAFrom(20, 0xfd0000000080+addr.AS(i)), uint16(40100+2*i)))
		}
		z, store := strandedDialer(t, addr.MustIAFrom(20, 0xfd0000000072), entries...)
		z.dialJoins(context.Background())
		if got := statesOf(t, store, rendezvousIA); !slices.Equal(got, retired) {
			t.Errorf("the retired entry at the cap = %v, want %v", got, retired)
		}
	})

	t.Run("an answer naming a live neighbor", func(t *testing.T) {
		z, store := strandedDialer(t, addr.MustIAFrom(20, 0xfd0000000073),
			retiredLink(other, f.addr, 40005), liveLink(rendezvousIA, 40011))
		z.dialJoins(context.Background())
		if got := statesOf(t, store, other); !slices.Equal(got, retired) {
			t.Errorf("the entry answered by a live neighbor = %v, want %v", got, retired)
		}
		if got := statesOf(t, store, rendezvousIA); len(got) != 1 {
			t.Errorf("the answering neighbor's entries = %v, want its live one alone", got)
		}
	})

	t.Run("two retired entries of one neighbor", func(t *testing.T) {
		z, store := strandedDialer(t, addr.MustIAFrom(20, 0xfd0000000074),
			retiredLink(rendezvousIA, f.addr, 40007), retiredLink(rendezvousIA, f.addr, 40009))
		z.dialJoins(context.Background())
		want := []links.State{links.StateCandidate, links.StateRetired}
		if got := statesOf(t, store, rendezvousIA); !slices.Equal(got, want) {
			t.Errorf("the neighbor's entries = %v, want %v", got, want)
		}
	})
}

// TestStrandedRedialAcceptorMinted checks the revival of an entry the
// acceptor minted: it records no rendezvous address, so the re-dial aims at
// the fixed rendezvous port on its remote host, and the revived entry
// records the socket it dialed, for the revival is this node's dial. The
// acceptor binds that port on a loopback host no other test of the package
// takes.
func TestStrandedRedialAcceptorMinted(t *testing.T) {
	host := netip.MustParseAddr("127.0.0.121")
	newRendezvousFixture(t, func(cfg *RendezvousConfig) {
		cfg.IA = rendezvousIA
		cfg.Bind = netip.AddrPortFrom(host, RendezvousPort).String()
		cfg.LinkHost = host
	})
	minted := &links.Link{
		NeighborIA: rendezvousIA,
		Local:      netip.MustParseAddrPort("127.0.0.1:40001"),
		Remote:     netip.AddrPortFrom(host, 40002),
		State:      links.StateRetired,
	}
	z, store := strandedDialer(t, zeroconfDraw, minted)
	z.dialJoins(context.Background())
	want := []links.State{links.StateCandidate}
	if got := statesOf(t, store, rendezvousIA); !slices.Equal(got, want) {
		t.Errorf("the acceptor-minted entry = %v, want %v", got, want)
	}
	revived, err := store.ByNeighbor(context.Background(), rendezvousIA)
	if err != nil {
		t.Fatal(err)
	}
	if target := netip.AddrPortFrom(host, RendezvousPort); revived == nil || revived.Rendezvous != target {
		t.Errorf("the revived entry = %+v, want it recording the dialed %v", revived, target)
	}
}

// TestJoinDialRetiresRedundantEntry checks a live entry whose rendezvous
// answers for a neighbor the table holds live — a second seed of one node:
// the store refuses to name it after that neighbor, and it retires rather
// than dial on.
func TestJoinDialRetiresRedundantEntry(t *testing.T) {
	f := newRendezvousFixture(t, func(cfg *RendezvousConfig) {
		cfg.IA = rendezvousIA
	})
	z, store := strandedDialer(t, addr.MustIAFrom(20, 0xfd0000000075),
		liveLink(rendezvousIA, 40011), &links.Link{
			Local:      netip.MustParseAddrPort("127.0.0.1:40021"),
			Rendezvous: f.addr,
			State:      links.StateCandidate,
		})
	z.dialJoins(context.Background())
	want := []links.State{links.StateEstablished, links.StateRetired}
	if got := statesOf(t, store, rendezvousIA); !slices.Equal(got, want) {
		t.Errorf("the neighbor's entries = %v, want the live one and the retired seed %v",
			got, want)
	}
}

// TestStrandedRedialFreshAddress checks a revival's local address: a
// retired entry whose address a live entry now holds — a later allocation
// drew the retired entry's port — revives on a fresh address, the one its
// re-dial claims and the acceptor records, while one whose address no live
// entry holds revives on it.
func TestStrandedRedialFreshAddress(t *testing.T) {
	f := newRendezvousFixture(t, func(cfg *RendezvousConfig) {
		cfg.IA = rendezvousIA
	})
	// revive runs a stranded dial pass over the entries and returns the
	// retired entry as the pass left it and the acceptor's entry for the
	// dialer.
	revive := func(t *testing.T, dialer addr.IA, retired *links.Link,
		others ...*links.Link) (*links.Link, *links.Link) {
		t.Helper()
		z, store := strandedDialer(t, dialer, append([]*links.Link{retired}, others...)...)
		z.dialJoins(context.Background())
		entries, err := store.All(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		var revived *links.Link
		for _, l := range entries {
			if l.IfID == retired.IfID {
				revived = l
			}
		}
		if revived == nil {
			t.Fatal("the retired entry vanished")
		}
		accepted, err := f.store.ByNeighbor(context.Background(), dialer)
		if err != nil {
			t.Fatal(err)
		}
		return revived, accepted
	}

	t.Run("held", func(t *testing.T) {
		retired := retiredLink(rendezvousIA, f.addr, 40001)
		holder := liveLink(addr.MustIAFrom(20, 0xfd0000000076), 40031)
		holder.Local = retired.Local
		revived, accepted := revive(t, addr.MustIAFrom(20, 0xfd0000000077), retired, holder)
		if revived.State != links.StateCandidate {
			t.Fatalf("the revived entry's state = %v, want a candidate", revived.State)
		}
		if !revived.Local.IsValid() || revived.Local == retired.Local {
			t.Errorf("the revived entry lies on %v, want a fresh address, not the held %v",
				revived.Local, retired.Local)
		}
		if accepted == nil || accepted.Remote != revived.Local {
			t.Errorf("the acceptor's entry = %+v, want it aimed at the revived %v",
				accepted, revived.Local)
		}
	})

	t.Run("free", func(t *testing.T) {
		retired := retiredLink(rendezvousIA, f.addr, 40003)
		revived, accepted := revive(t, addr.MustIAFrom(20, 0xfd0000000078), retired)
		if revived.State != links.StateCandidate || revived.Local != retired.Local {
			t.Errorf("the revived entry = %v on %v, want a candidate on its own %v",
				revived.State, revived.Local, retired.Local)
		}
		if accepted == nil || accepted.Remote != retired.Local {
			t.Errorf("the acceptor's entry = %+v, want it aimed at %v", accepted, retired.Local)
		}
	})
}

// fakeLinkServiceClient answers every link request with the reply it holds,
// or fails it with err, counting the requests.
type fakeLinkServiceClient struct {
	reply    *nodev1.LinkReply
	err      error
	requests atomic.Int32
}

func (c *fakeLinkServiceClient) Request(
	context.Context, *nodev1.LinkRequest,
) (*nodev1.LinkReply, error) {
	c.requests.Add(1)
	if c.err != nil {
		return nil, c.err
	}
	return c.reply, nil
}

// TestProviderReportsReach checks the published report: the link client
// keeps the latest reply's report of the acceptor's echo — a reply without
// one keeps the last — and the report names the published host translated
// when it is not one of the node's own.
func TestProviderReportsReach(t *testing.T) {
	z := &Provider{}
	peer := &scion.Addr{IA: linkIA, Service: addr.SvcCS}
	const ifID = 3
	fake := &fakeLinkServiceClient{}
	c := &linkClient{
		answered: z.recordAnswer,
		clts: map[string]nodev1connect.LinkServiceClient{
			scionrpc.PeerAuthority(&scion.Addr{IA: peer.IA, Service: peer.Service, IfID: ifID}): fake,
		},
	}
	own := netip.MustParseAddr("127.0.0.1")
	steps := []struct {
		answered *bool
		want     Reach
	}{
		{want: Reach{}},
		{answered: new(false), want: Reach{RendezvousUnanswered: true}},
		{want: Reach{RendezvousUnanswered: true}},
		{answered: new(true), want: Reach{}},
	}
	for i, step := range steps {
		fake.reply = &nodev1.LinkReply{
			LocalAddr: "127.0.0.1:4242", IfId: 7, RendezvousAnswered: step.answered,
		}
		if _, err := c.Link(t.Context(), peer, netip.MustParseAddrPort("127.0.0.1:4243"), ifID); err != nil {
			t.Fatal(err)
		}
		got, err := z.reach(own)
		if err != nil {
			t.Fatal(err)
		}
		if got != step.want {
			t.Errorf("after reply %d: report = %+v, want %+v", i, got, step.want)
		}
	}

	// Documentation space no interface holds stands for a translator's
	// host.
	got, err := z.reach(netip.MustParseAddr("192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	if !got.Translated {
		t.Errorf("the report at a host the node does not hold = %+v, want translated", got)
	}
}

// TestEchoPublishedReportsTheAnswer checks the acceptor's echo: a peer whose
// published rendezvous address answers is answered, one whose address is
// silent is not, and a peer the directory copy lacks is not echoed. No
// answer teaches the node its own external host.
func TestEchoPublishedReportsTheAnswer(t *testing.T) {
	acceptor := newRendezvousFixture(t, nil)
	silent := addr.MustIAFrom(20, 0xfd0000000052)
	z := &Provider{
		cfg: Config{ControlHost: netip.MustParseAddr("127.0.0.1")},
		directory: &NodeDirectory{local: []DirectoryEntry{
			{IA: linkIA, RendezvousAddr: acceptor.addr},
			{IA: silent, RendezvousAddr: netip.MustParseAddrPort("127.0.0.1:1")},
		}},
	}
	cases := []struct {
		name         string
		peer         addr.IA
		answered, ok bool
	}{
		{name: "an answering address", peer: linkIA, answered: true, ok: true},
		{name: "a silent address", peer: silent, ok: true},
		{name: "no entry", peer: linkIA2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			answered, ok := z.echoPublished(t.Context(), tc.peer)
			if answered != tc.answered || ok != tc.ok {
				t.Errorf("echoPublished(%v) = %v, %v, want %v, %v",
					tc.peer, answered, ok, tc.answered, tc.ok)
			}
		})
	}
	if got := z.external.host(); got.IsValid() {
		t.Errorf("the echoes taught the node the external host %v, want none", got)
	}
}

// TestReachUnderTheWildcardBind checks the report under the default bind,
// on the kernel's sockets: a wildcard-bound node publishes nothing until it
// learns a host, then checks the learned host its entry publishes — never
// the wildcard — so the loopback, which the machine holds, reports
// untranslated, and documentation space no interface holds, translated.
func TestReachUnderTheWildcardBind(t *testing.T) {
	z, err := New(Config{ControlHost: netip.MustParseAddr("0.0.0.0")})
	if err != nil {
		t.Fatal(err)
	}
	store := NewDirectoryStore()
	d := NewNodeDirectory(NodeDirectoryConfig{
		IA:    directoryIA,
		Host:  z.publishedHost,
		Reach: z.reach,
		Store: store,
	})
	ctx := context.Background()
	if err := d.publish(ctx); err == nil {
		t.Fatal("the unlearned wildcard published an entry")
	}
	for _, tc := range []struct {
		learned    netip.Addr
		translated bool
	}{
		{learned: netip.MustParseAddr("127.0.0.1")},
		{learned: netip.MustParseAddr("192.0.2.1"), translated: true},
	} {
		z.learn(tc.learned)
		if err := d.publish(ctx); err != nil {
			t.Fatal(err)
		}
		entries := store.List(time.Now())
		if len(entries) != 1 {
			t.Fatalf("entries = %v, want the one", entries)
		}
		want := Reach{Translated: tc.translated}
		if got := entries[0]; got.RendezvousAddr.Addr() != tc.learned || got.Reach != want {
			t.Errorf("learning %v published %v with %+v, want the learned host with %+v",
				tc.learned, got.RendezvousAddr, got.Reach, want)
		}
	}
}

// linkClientOf returns a link client whose request over each entry's own
// interface the entry's fake answers.
func linkClientOf(fakes map[*links.Link]*fakeLinkServiceClient) *linkClient {
	clts := make(map[string]nodev1connect.LinkServiceClient, len(fakes))
	for l, fake := range fakes {
		clts[scionrpc.PeerAuthority(&scion.Addr{
			IA: l.NeighborIA, Service: addr.SvcCS, IfID: l.IfID,
		})] = fake
	}
	return &linkClient{clts: clts}
}

// entryByIfID returns the store's entry on the interface.
func entryByIfID(t *testing.T, store links.DB, ifID uint16) *links.Link {
	t.Helper()
	entries, err := store.All(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range entries {
		if l.IfID == ifID {
			return l
		}
	}
	t.Fatalf("no entry on interface %d", ifID)
	return nil
}

// TestConfirmRecordsTheObservation checks the record a node's own confirm
// lands: the address the entry's link observes the peer at, which a
// translated peer's claim — the socket it bound inside its translator —
// cannot name, and the claim rule's record only while the link observed
// nothing.
func TestConfirmRecordsTheObservation(t *testing.T) {
	claim := netip.MustParseAddrPort("10.0.0.5:31005")
	mapped := netip.MustParseAddrPort("203.0.113.9:26001")
	for _, tc := range []struct {
		name           string
		observed, want netip.AddrPort
	}{
		{name: "an observing link", observed: mapped, want: mapped},
		{name: "a link observing nothing", want: claim},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := memory.New()
			z := &Provider{}
			z.Wire(topology.Environment{
				Store:    store,
				Observed: func(uint16) netip.AddrPort { return tc.observed },
			})
			l := &links.Link{
				NeighborIA: linkIA,
				Local:      netip.MustParseAddrPort("127.0.0.1:40001"),
				Remote:     netip.MustParseAddrPort("203.0.113.9:26000"),
				State:      links.StateEstablished,
			}
			if err := store.Insert(context.Background(), l); err != nil {
				t.Fatal(err)
			}
			z.linker = linkClientOf(map[*links.Link]*fakeLinkServiceClient{
				l: {reply: &nodev1.LinkReply{LocalAddr: claim.String(), IfId: 7}},
			})
			if !z.confirmEntry(context.Background(), l) {
				t.Fatal("the confirm did not land")
			}
			if got := entryByIfID(t, store, l.IfID).Remote; got != tc.want {
				t.Errorf("recorded remote = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestFollowKeepsTheLocatorOnTheFlow checks the follow loop: an established
// entry its link observes elsewhere sends a confirm and records the
// observation the answer leaves; one whose confirm fails sends one per
// FollowRetry; a candidate takes the observation once its BFD session
// answers there, and not before; an entry observed at its locator sends
// nothing.
func TestFollowKeepsTheLocatorOnTheFlow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := memory.New()
		var mtx sync.Mutex
		observed := map[uint16]netip.AddrPort{}
		verdicts := map[uint16]bool{}
		z := &Provider{}
		z.Wire(topology.Environment{
			Store: store,
			Observed: func(ifID uint16) netip.AddrPort {
				mtx.Lock()
				defer mtx.Unlock()
				return observed[ifID]
			},
			Verdicts: func() map[uint16]bool {
				mtx.Lock()
				defer mtx.Unlock()
				return maps.Clone(verdicts)
			},
		})
		entry := func(ia addr.IA, port uint16, state links.State) *links.Link {
			l := &links.Link{
				NeighborIA: ia,
				Local:      netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port),
				Remote:     netip.AddrPortFrom(netip.MustParseAddr("203.0.113.9"), port),
				State:      state,
			}
			if err := store.Insert(context.Background(), l); err != nil {
				t.Fatal(err)
			}
			return l
		}
		moved := entry(linkIA, 40001, links.StateEstablished)
		failing := entry(linkIA2, 40002, links.StateEstablished)
		candidate := entry(addr.MustIAFrom(20, 0xfd0000000034), 40003, links.StateCandidate)
		steady := entry(addr.MustIAFrom(20, 0xfd0000000035), 40004, links.StateEstablished)
		flow := func(port uint16) netip.AddrPort {
			return netip.AddrPortFrom(netip.MustParseAddr("198.51.100.7"), port)
		}
		mtx.Lock()
		observed[moved.IfID] = flow(1)
		observed[failing.IfID] = flow(2)
		observed[candidate.IfID] = flow(3)
		observed[steady.IfID] = steady.Remote
		verdicts[candidate.IfID] = false
		mtx.Unlock()
		fakes := map[*links.Link]*fakeLinkServiceClient{
			moved:   {reply: &nodev1.LinkReply{LocalAddr: "10.0.0.5:31001", IfId: 7}},
			failing: {err: errors.New("no answer")},
			steady:  {reply: &nodev1.LinkReply{LocalAddr: "10.0.0.5:31004", IfId: 8}},
		}
		z.linker = linkClientOf(fakes)

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		go z.runFollow(ctx)
		time.Sleep(3 * FollowInterval)
		synctest.Wait()
		if got := entryByIfID(t, store, moved.IfID).Remote; got != flow(1) {
			t.Errorf("the moved entry's remote = %v, want the observation %v", got, flow(1))
		}
		if n := fakes[moved].requests.Load(); n != 1 {
			t.Errorf("the moved entry sent %d confirms, want 1", n)
		}
		if n := fakes[failing].requests.Load(); n != 1 {
			t.Errorf("the failing entry sent %d confirms within FollowRetry, want 1", n)
		}
		if got := entryByIfID(t, store, candidate.IfID).Remote; got != candidate.Remote {
			t.Errorf("the candidate followed an observation its session never answered: %v", got)
		}
		if n := fakes[steady].requests.Load(); n != 0 {
			t.Errorf("the steady entry sent %d confirms, want none", n)
		}

		// The session answers at the observation, and the candidate takes
		// it; past FollowRetry, the failing entry tries once more.
		mtx.Lock()
		verdicts[candidate.IfID] = true
		mtx.Unlock()
		time.Sleep(FollowRetry)
		synctest.Wait()
		if got := entryByIfID(t, store, candidate.IfID).Remote; got != flow(3) {
			t.Errorf("the candidate's remote = %v, want the answered observation %v", got, flow(3))
		}
		if n := fakes[failing].requests.Load(); n != 2 {
			t.Errorf("the failing entry sent %d confirms past FollowRetry, want 2", n)
		}
		cancel()
	})
}
