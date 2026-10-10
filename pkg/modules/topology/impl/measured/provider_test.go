package measured

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/modules/links"
	"github.com/fancl20/cion/pkg/modules/links/impl/memory"
	"github.com/fancl20/cion/pkg/modules/topology"
	"github.com/fancl20/cion/pkg/modules/topology/impl/providertest"
	"github.com/fancl20/cion/pkg/scion"
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
	z.Wire(topology.Pieces{IA: ia, Store: store})
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
	z.Wire(topology.Pieces{Store: memory.New()})
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
	z.Wire(topology.Pieces{Store: memory.New()})
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
		z.Wire(topology.Pieces{Store: memory.New()})
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
	// Hosts no integration lab takes: the testnetwork slots stop at 0x76,
	// so the package-parallel run holds no rendezvous collision.
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
	z.Wire(topology.Pieces{IA: zeroconfDraw, Store: memory.New()})
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
	if _, _, err := RendezvousEcho(context.Background(), host,
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
// republishes the persisted one — and the founding core resolves its own
// domain, of the family its control host binds, the control host beside it
// as the fallback.
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

	core, err := New(Config{
		Core:        true,
		Domain:      "core.example.org",
		ControlHost: control,
		StateDir:    t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	core.domain.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{
			netip.MustParseAddr("2001:db8::1"), // the wrong family
			netip.MustParseAddr("192.0.2.20"),
		}, nil
	}
	if got := core.publishedHost(ctx); got != netip.MustParseAddr("192.0.2.20") {
		t.Errorf("the core's host = %v, want its domain's 192.0.2.20", got)
	}

	// A name that fails leaves the control host published.
	failing, err := New(Config{
		Core:        true,
		Domain:      "core.example.org",
		ControlHost: control,
		StateDir:    t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	failing.domain.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		return nil, errors.New("no such name")
	}
	if got := failing.publishedHost(ctx); got != control {
		t.Errorf("the core's fallback host = %v, want the control host %v", got, control)
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
	z.Wire(topology.Pieces{IA: zeroconfDraw, Store: store})
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
	z.Wire(topology.Pieces{IA: ia, Store: store})
	for _, l := range entries {
		if err := store.Insert(context.Background(), l); err != nil {
			t.Fatal(err)
		}
	}
	z.stranded.Store(true)
	return z, store
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
// the fixed rendezvous port on its remote host. The acceptor binds that
// port on a loopback host no other test of the package takes.
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
