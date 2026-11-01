package measured

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"maps"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/fancl20/cion/pkg/core/trust/trusttest"

	"github.com/google/go-cmp/cmp"
	"github.com/scionproto/scion/pkg/addr"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/core/trust"
	"github.com/fancl20/cion/pkg/libs/bus"
	"github.com/fancl20/cion/pkg/libs/loops"
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
	z.Wire(topology.Environment{IA: ia, Store: store, Bus: bus.New()})
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
	z.Wire(topology.Environment{Store: memory.New(), Bus: bus.New()})
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
	z.Wire(topology.Environment{Store: memory.New(), Bus: bus.New()})
	if err := z.Seed(context.Background()); err != nil {
		t.Fatalf("seeding with a bootstrap neighbor: %v", err)
	}
}

// TestZeroconfMounts checks the mounts: the measured provider mounts the
// in-band link service and the node directory's service on every node, at
// the patterns the handlers name. The conventional rendezvous port is part
// of what mounts, so each join takes a loopback host of this package's own
// — the shared first host's fixed slot is not this suite's to hold.
func TestZeroconfMounts(t *testing.T) {
	joined := func(t *testing.T, host string, core bool) []string {
		t.Helper()
		z, err := New(Config{
			Core:        core,
			ControlHost: netip.MustParseAddr(host),
			NewConn:     func() (*scion.Conn, error) { return nil, nil },
		})
		if err != nil {
			t.Fatal(err)
		}
		z.Wire(topology.Environment{Store: memory.New(), Bus: bus.New()})
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
	want := []string{linkPath, directoryPath}
	if got := joined(t, "127.0.0.119", false); !slices.Equal(got, want) {
		t.Errorf("a non-core's mounts = %v, want %v", got, want)
	}
	if got := joined(t, "127.0.0.120", true); !slices.Equal(got, want) {
		t.Errorf("the core's mounts = %v, want %v", got, want)
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
	})
	if err != nil {
		t.Fatal(err)
	}
	z.Wire(topology.Environment{IA: zeroconfDraw, Store: memory.New(), Bus: bus.New()})
	if _, err := z.Mounts(); err != nil {
		t.Fatal(err)
	}
	if len(drawn) != 2 {
		t.Fatalf("NewConn drew %d conns, want the punches' and the probe's", len(drawn))
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

// wiredSelf wires the provider to a bus of its own and returns the bus's
// topic of the node's own state.
func wiredSelf(z *Provider) *bus.Topic[bus.SelfState] {
	b := bus.New()
	z.Wire(topology.Environment{Bus: b})
	return b.Self()
}

// TestSelfHost checks the host the node's own state carries: a joiner's
// names none at wiring and follows its directories' views — the host its
// own entry names first in the scope that holds the founder's entry, else
// in the scope of the least ID that holds one, a view naming neither
// keeping it; the founding core's literal domain publishes at wiring, and a
// name publishes the lookup's answer of the family the control host binds —
// the wildcard's first answer, which names no family to filter by — nothing
// before an answer lands, and the last answer held through a failed lookup.
func TestSelfHost(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		control := netip.MustParseAddr("10.0.0.7")
		z, err := New(Config{ControlHost: control})
		if err != nil {
			t.Fatal(err)
		}
		b := bus.New()
		z.Wire(topology.Environment{IA: linkIA, Bus: b})
		if got := b.Self().Latest().Host; got.IsValid() {
			t.Errorf("a joiner's host at wiring = %v, want none", got)
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		go z.runSelfHost(ctx)
		inside, outside := netip.MustParseAddr("10.0.0.7"), netip.MustParseAddr("203.0.113.7")
		own := func(hosts ...string) bus.DirectoryEntry {
			e := bus.DirectoryEntry{IA: linkIA}
			for _, h := range hosts {
				e.Addresses = append(e.Addresses, bus.Address{
					RendezvousAddr: netip.AddrPortFrom(netip.MustParseAddr(h), RendezvousPort),
				})
			}
			return e
		}
		b.Directory().Publish(bus.NewDirectory(nil,
			bus.NewScope(bus.DirectoryID{2}, own(outside.String())),
			bus.NewScope(bus.DirectoryID{1}, own(inside.String()))))
		synctest.Wait()
		if got := b.Self().Latest().Host; got != inside {
			t.Errorf("with no engine to name the founder the host = %v, want the least ID's %v", got, inside)
		}
		b.Directory().Publish(bus.NewDirectory(nil, bus.NewScope(bus.DirectoryID{3})))
		synctest.Wait()
		if got := b.Self().Latest().Host; got != inside {
			t.Errorf("a view naming no host of its own moved the host to %v, want %v kept", got, inside)
		}

		// The founder's scope wins over the least ID.
		v := bus.NewDirectory(nil,
			bus.NewScope(bus.DirectoryID{2}, own(outside.String(), "203.0.113.8"),
				bus.DirectoryEntry{IA: founderIA}),
			bus.NewScope(bus.DirectoryID{1}, own(inside.String())))
		if got, ok := selfHost(v, linkIA, founderIA); !ok || got != outside {
			t.Errorf("selfHost = %v (%t), want the founder's scope's first host %v", got, ok, outside)
		}
		if _, ok := selfHost(bus.NewDirectory(nil, bus.NewScope(bus.DirectoryID{1},
			bus.DirectoryEntry{IA: founderIA})), linkIA, founderIA); ok {
			t.Error("selfHost named a host of a view holding no entry of the node's own")
		}

		// The core's literal domain is its host from the start.
		literal := netip.MustParseAddr("192.0.2.30")
		lit, err := New(Config{Core: true, Domain: literal.String(), ControlHost: control})
		if err != nil {
			t.Fatal(err)
		}
		if got := wiredSelf(lit).Latest().Host; got != literal {
			t.Errorf("the literal core's host = %v, want %v", got, literal)
		}

		// A name's host is the lookup loop's answer, held through a failure.
		lookups := func(failing *atomic.Bool, addrs ...netip.Addr) underlay.Sockets {
			return underlay.Sockets{LookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
				if failing.Load() {
					return nil, errors.New("no such name")
				}
				return addrs, nil
			}}
		}
		lookedUp := func(control netip.Addr, failing *atomic.Bool, addrs ...netip.Addr) *bus.Topic[bus.SelfState] {
			core, err := New(Config{
				Core: true, Domain: "core.example.org", ControlHost: control,
				Sockets: lookups(failing, addrs...),
			})
			if err != nil {
				t.Fatal(err)
			}
			coreSelf := wiredSelf(core)
			if got := coreSelf.Latest().Host; got.IsValid() {
				t.Errorf("the core's host before a lookup = %v, want the zero address", got)
			}
			go core.runDomain(t.Context())
			synctest.Wait()
			return coreSelf
		}
		failing := new(atomic.Bool)
		coreSelf := lookedUp(control, failing,
			netip.MustParseAddr("2001:db8::1"), // the wrong family
			netip.MustParseAddr("192.0.2.20"))
		if got := coreSelf.Latest().Host; got != netip.MustParseAddr("192.0.2.20") {
			t.Errorf("the core's host = %v, want its domain's 192.0.2.20", got)
		}
		failing.Store(true)
		time.Sleep(domainSuccessTTL)
		synctest.Wait()
		if got := coreSelf.Latest().Host; got != netip.MustParseAddr("192.0.2.20") {
			t.Errorf("the core's host after a failed lookup = %v, want the last answer held", got)
		}

		first := netip.MustParseAddr("2001:db8::2")
		wildCore := lookedUp(netip.MustParseAddr("0.0.0.0"), new(atomic.Bool),
			first, netip.MustParseAddr("192.0.2.21"))
		if got := wildCore.Latest().Host; got != first {
			t.Errorf("the wildcard core's host = %v, want the resolver's first answer %v", got, first)
		}

		never := new(atomic.Bool)
		never.Store(true)
		if got := lookedUp(control, never).Latest().Host; got.IsValid() {
			t.Errorf("the core's unanswered host = %v, want the zero address", got)
		}
	})
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
	z.Wire(topology.Environment{IA: zeroconfDraw, Store: store, Bus: bus.New()})
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
	z, store := wiredProvider(t, ia, entries...)
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
	z.confirmLanded(context.Background(), revived[0])
	entry := entryByIfID(t, store, retired.IfID)
	if entry.State != links.StateEstablished || entry.RemoteIfID != 9 ||
		entry.Remote != netip.MustParseAddrPort("127.0.0.1:4242") {
		t.Errorf("the revived entry = %+v, want established on the reply's side", entry)
	}
	if got := fake.requests.Load(); got != 1 {
		t.Errorf("the revival sent %d link requests, want one", got)
	}
}

// TestConfirmPassRetriesSoon checks the confirm pass's first retry: an
// entry whose confirm found no answer is confirmed again confirmPassRetry
// later, well inside a selection window.
func TestConfirmPassRetriesSoon(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		held := liveLink(rendezvousIA, 40041)
		z, _ := wiredProvider(t, zeroconfDraw, held)
		fake := &fakeLinkServiceClient{err: errors.New("the node holds no chain yet")}
		z.linker = linkClientOf(map[*links.Link]*fakeLinkServiceClient{held: fake})
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		go z.runConfirmPass(ctx)
		synctest.Wait()
		first := fake.requests.Load()
		time.Sleep(confirmPassRetry)
		synctest.Wait()
		if got := fake.requests.Load(); got <= first {
			t.Errorf("%d confirms %v after the first %d, want a retry", got-first, confirmPassRetry, first)
		}
	})
}

// TestConfirmPassWaitsForTheChain checks the confirm pass's start: a node
// holding no chain confirms nothing, for no peer's channel admits it, and
// confirms its entries within a poll of its chain's arrival.
func TestConfirmPassWaitsForTheChain(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		founder := newFounded(t)
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		held := liveLink(rendezvousIA, 40051)
		z, _ := wiredProvider(t, directoryIA, held)
		z.env.Engine = trust.NewEngine(directoryIA, key, &trust.NetworkProvider{DB: founder.DB},
			trusttest.Unchecked{})
		fake := &fakeLinkServiceClient{reply: &nodev1.LinkReply{LocalAddr: "127.0.0.1:4242", IfId: 9}}
		z.linker = linkClientOf(map[*links.Link]*fakeLinkServiceClient{held: fake})
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		go z.runConfirmPass(ctx)
		time.Sleep(time.Minute)
		synctest.Wait()
		if got := fake.requests.Load(); got != 0 {
			t.Fatalf("%d confirms without a chain, want none", got)
		}

		csr, err := trust.CreateCSR(directoryIA, key)
		if err != nil {
			t.Fatal(err)
		}
		chain, err := founder.Issuer.IssueChain(csr)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := founder.DB.InsertChain(t.Context(), chain); err != nil {
			t.Fatal(err)
		}
		time.Sleep(confirmPassChainPoll)
		synctest.Wait()
		if got := fake.requests.Load(); got != 1 {
			t.Errorf("%d confirms a poll after the chain, want one", got)
		}
	})
}

// TestJoinDialsConfirmTheLanded checks the join loop's confirms: a landed
// seed's link request is retried on its backoff while the peer refuses it,
// until one answers and establishes the seed, which is then forgotten.
func TestJoinDialsConfirmTheLanded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		seed := liveLink(rendezvousIA, 40031)
		seed.State = links.StateCandidate
		z, store := wiredProvider(t, zeroconfDraw, seed)
		fake := &fakeLinkServiceClient{err: errors.New("the peer holds no chain yet")}
		z.linker = linkClientOf(map[*links.Link]*fakeLinkServiceClient{seed: fake})
		retries := loops.Attempts[uint16]{
			Backoff: loops.Backoff{Base: joinDialInterval, Max: joinDialRetryMax},
		}
		landed := map[uint16]bool{seed.IfID: true}
		z.confirmJoins(t.Context(), landed, &retries)
		refused := fake.requests.Load()
		if !landed[seed.IfID] || refused == 0 {
			t.Fatalf("after %d refused requests the seed is landed %t, want it kept", refused, landed[seed.IfID])
		}
		z.confirmJoins(t.Context(), landed, &retries)
		if got := fake.requests.Load(); got != refused {
			t.Errorf("%d requests inside the backoff, want none", got-refused)
		}

		fake.err = nil
		fake.reply = &nodev1.LinkReply{LocalAddr: "127.0.0.1:4242", IfId: 9}
		time.Sleep(joinDialInterval)
		z.confirmJoins(t.Context(), landed, &retries)
		if entry := entryByIfID(t, store, seed.IfID); entry.State != links.StateEstablished {
			t.Errorf("the answered seed's state = %v, want established", entry.State)
		}
		if landed[seed.IfID] {
			t.Error("the established seed is still landed")
		}
	})
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

// fakeSeen is where the fake link service's acceptor sees its requesters.
const fakeSeen = "203.0.113.200:40000"

// fakeLinkServiceClient answers every link request with the side the reply
// it holds names, seeing the requester at fakeSeen with its echo
// unanswered, or fails it with err, counting the requests and keeping the
// last.
type fakeLinkServiceClient struct {
	reply    *nodev1.LinkReply
	err      error
	requests atomic.Int32
	last     atomic.Pointer[nodev1.LinkRequest]
}

func (c *fakeLinkServiceClient) Request(
	_ context.Context, req *nodev1.LinkRequest,
) (*nodev1.LinkReply, error) {
	c.requests.Add(1)
	c.last.Store(req)
	if c.err != nil {
		return nil, c.err
	}
	return &nodev1.LinkReply{LocalAddr: c.reply.LocalAddr, IfId: c.reply.IfId, Observed: fakeSeen}, nil
}

func (c *fakeLinkServiceClient) Punch(
	context.Context, *nodev1.PunchRequest,
) (*nodev1.PunchReply, error) {
	return nil, errors.New("the fake punches nothing")
}

func (c *fakeLinkServiceClient) PunchProbe(
	context.Context, *nodev1.PunchProbeRequest,
) (nodev1connect.LinkServicePunchProbeClientStream, error) {
	return nodev1connect.LinkServicePunchProbeClientStream{}, errors.New("the fake probes nothing")
}

// TestProviderEchoes checks the provider's echo, a link exchange's check of
// the other end's rendezvous port: an answering address answers and a silent
// one does not, and the answering peer records nothing.
func TestProviderEchoes(t *testing.T) {
	acceptor := newRendezvousFixture(t, nil)
	z := &Provider{cfg: Config{ControlHost: netip.MustParseAddr("127.0.0.1")}}
	if !z.echo(t.Context(), acceptor.addr) {
		t.Error("the answering address did not answer")
	}
	if z.echo(t.Context(), netip.MustParseAddrPort("127.0.0.1:1")) {
		t.Error("the silent address answered")
	}
	if entries, err := acceptor.store.All(t.Context()); err != nil || len(entries) != 0 {
		t.Errorf("the answering peer recorded %v (%v), want nothing", entries, err)
	}
}

// TestProviderAddresses checks the node's addresses as its entries name
// them, under the default bind on the kernel's sockets: the endpoint and
// rendezvous ports on each host; the loopback, which the machine holds,
// behind no NAT, and documentation space no interface holds behind one; and
// each host's latest echo, a host no peer echoed reporting nothing
// unanswered. A peer's report attaches its link at the host it names, and a
// changed answer re-signs the node's entries.
func TestProviderAddresses(t *testing.T) {
	z, err := New(Config{ControlHost: netip.MustParseAddr("0.0.0.0")})
	if err != nil {
		t.Fatal(err)
	}
	z.directory = NewNodeDirectory(NodeDirectoryConfig{IA: directoryIA})
	held, translated := netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("192.0.2.1")
	z.seen(1, netip.AddrPortFrom(translated, 40001), false)
	if got := z.directory.links[1]; got != translated {
		t.Errorf("the reported link joins the attachment at %v, want %v", got, translated)
	}
	addresses, err := z.addresses([]netip.Addr{held, translated})
	if err != nil {
		t.Fatal(err)
	}
	type address struct {
		Control, Rendezvous   string
		BehindNAT, Unanswered bool
	}
	var got []address
	for _, a := range addresses {
		got = append(got, address{a.ControlAddr, a.RendezvousAddr, a.BehindNat, a.RendezvousUnanswered})
	}
	want := []address{
		{Control: "127.0.0.1:30042", Rendezvous: "127.0.0.1:30043"},
		{Control: "192.0.2.1:30042", Rendezvous: "192.0.2.1:30043", BehindNAT: true, Unanswered: true},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("the addresses (-want +got):\n%s", diff)
	}

	// A changed answer wakes the signing, and an unchanged report does not.
	resigned := func() bool {
		select {
		case <-z.directory.signWake:
			return true
		default:
			return false
		}
	}
	resigned()
	z.seen(1, netip.AddrPortFrom(translated, 40001), true)
	if !resigned() {
		t.Error("a changed answer woke no signing")
	}
	z.seen(1, netip.AddrPortFrom(translated, 40001), true)
	if resigned() {
		t.Error("an unchanged report woke the signing")
	}
	if addresses, err := z.addresses([]netip.Addr{translated}); err != nil ||
		addresses[0].RendezvousUnanswered {
		t.Errorf("after an answered echo the address = %v (%v), want it answering", addresses, err)
	}
}

// linkClientOf returns a link client whose request over each entry's own
// interface the entry's fake answers, whose echoes answer, and which
// records nothing of what the replies report.
func linkClientOf(fakes map[*links.Link]*fakeLinkServiceClient) *linkClient {
	clts := make(map[string]nodev1connect.LinkServiceClient, len(fakes))
	for l, fake := range fakes {
		clts[scionrpc.PeerAuthority(&scion.Addr{
			IA: l.NeighborIA, Service: addr.SvcCS, IfID: l.IfID,
		})] = fake
	}
	return &linkClient{
		clts: clts,
		echo: func(context.Context, netip.AddrPort) bool { return true },
		seen: func(uint16, netip.AddrPort, bool) {},
	}
}

// TestLinkClientExchangesWhatEachEndSees checks the exchange's reports from
// the requester's side: the request names how the node sees the peer — the
// link's observation, else the entry's locator — and whether the peer's
// rendezvous port answered there; and the node records what the reply
// reports of it, on the entry's interface.
func TestLinkClientExchangesWhatEachEndSees(t *testing.T) {
	l := liveLink(linkIA, 40091)
	fake := &fakeLinkServiceClient{reply: &nodev1.LinkReply{LocalAddr: "127.0.0.1:4242", IfId: 9}}
	c := linkClientOf(map[*links.Link]*fakeLinkServiceClient{l: fake})
	var echoed []netip.AddrPort
	c.echo = func(_ context.Context, target netip.AddrPort) bool {
		echoed = append(echoed, target)
		return false
	}
	type report struct {
		ifID     uint16
		observed netip.AddrPort
		answered bool
	}
	var reports []report
	c.seen = func(ifID uint16, observed netip.AddrPort, answered bool) {
		reports = append(reports, report{ifID, observed, answered})
	}
	peer := &scion.Addr{IA: linkIA, Service: addr.SvcCS}
	if _, err := c.Link(t.Context(), peer, l); err != nil {
		t.Fatal(err)
	}
	if req := fake.last.Load(); req.Observed != l.Remote.String() || req.RendezvousAnswered {
		t.Errorf("the request reports %q (answered %t), want the locator %v unanswered",
			req.Observed, req.RendezvousAnswered, l.Remote)
	}
	if want := []report{{l.IfID, netip.MustParseAddrPort(fakeSeen), false}}; !slices.Equal(reports, want) {
		t.Errorf("recorded %v, want %v", reports, want)
	}

	observed := netip.MustParseAddrPort("192.0.2.77:31077")
	c.links = new(bus.Topic[bus.LinkState])
	c.links.Publish(bus.NewLinkState(bus.Link{Entry: *l, Observed: observed}))
	if _, err := c.Link(t.Context(), peer, l); err != nil {
		t.Fatal(err)
	}
	if req := fake.last.Load(); req.Observed != observed.String() {
		t.Errorf("the request reports %q, want the link's observation %v", req.Observed, observed)
	}
	want := []netip.AddrPort{
		netip.AddrPortFrom(l.Remote.Addr(), RendezvousPort),
		netip.AddrPortFrom(observed.Addr(), RendezvousPort),
	}
	if !slices.Equal(echoed, want) {
		t.Errorf("echoed %v, want %v", echoed, want)
	}
}

// TestHeldEchoesReuseAnOutcome checks the exchange's memory of echoes: an
// address answers as its latest echo did, echoed only the first time; once
// echoTTL passes it still answers so at once, while a fresh echo behind it
// sets what it answers next.
func TestHeldEchoesReuseAnOutcome(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var echoes atomic.Int32
		h := &heldEchoes{echo: func(context.Context, netip.AddrPort) bool {
			return echoes.Add(1) == 1
		}}
		target := netip.MustParseAddrPort("192.0.2.9:30043")
		first, again := h.at(t.Context(), target), h.at(t.Context(), target)
		if !first || !again || echoes.Load() != 1 {
			t.Errorf("within the hold: %d echoes, want one answered", echoes.Load())
		}
		time.Sleep(echoTTL)
		if !h.at(t.Context(), target) {
			t.Error("past the hold the address no longer answers as its latest echo did")
		}
		synctest.Wait()
		if h.at(t.Context(), target) || echoes.Load() != 2 {
			t.Errorf("after the renewal: %d echoes, want a second, unanswered", echoes.Load())
		}
	})
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
// lands: the address the entry's link observes the peer at, which the
// claim of a peer behind a NAT — the socket it bound inside its NAT —
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
			b := bus.New()
			z := &Provider{}
			z.Wire(topology.Environment{Store: store, Bus: b})
			l := &links.Link{
				NeighborIA: linkIA,
				Local:      netip.MustParseAddrPort("127.0.0.1:40001"),
				Remote:     netip.MustParseAddrPort("203.0.113.9:26000"),
				State:      links.StateEstablished,
			}
			if err := store.Insert(context.Background(), l); err != nil {
				t.Fatal(err)
			}
			b.Links().Publish(bus.NewLinkState(
				bus.Link{Entry: *l, Observed: tc.observed}))
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

// TestFollowKeepsTheLocatorOnTheFlow checks the upkeep's following: an
// established entry its link observes elsewhere sends a confirm once the
// observation held for UpkeepGrace, and records the observation the answer
// leaves; one whose confirm fails retries on the backoff from FollowRetry; a
// candidate takes the observation once its BFD session answers there, and
// not before; an entry observed at its locator sends nothing.
func TestFollowKeepsTheLocatorOnTheFlow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := memory.New()
		b := bus.New()
		z := &Provider{}
		z.Wire(topology.Environment{Store: store, Bus: b})
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
		// publish lands the links' observations, the candidate's verdict as
		// given; the moved entry's link is down, which follows the flow all
		// the same.
		publish := func(candidateUp bool) {
			b.Links().Publish(bus.NewLinkState(
				bus.Link{Entry: *moved, Down: true, Observed: flow(1)},
				bus.Link{Entry: *failing, Observed: flow(2)},
				bus.Link{Entry: *candidate, Down: !candidateUp, Observed: flow(3)},
				bus.Link{Entry: *steady, Observed: steady.Remote},
			))
		}
		publish(false)
		fakes := map[*links.Link]*fakeLinkServiceClient{
			moved:   {reply: &nodev1.LinkReply{LocalAddr: "10.0.0.5:31001", IfId: 7}},
			failing: {err: errors.New("no answer")},
			steady:  {reply: &nodev1.LinkReply{LocalAddr: "10.0.0.5:31004", IfId: 8}},
		}
		z.linker = linkClientOf(fakes)

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		go z.runUpkeep(ctx)
		synctest.Wait()
		if n := fakes[moved].requests.Load() + fakes[failing].requests.Load(); n != 0 {
			t.Errorf("%d confirms within UpkeepGrace, want none", n)
		}
		time.Sleep(UpkeepGrace)
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
		// it at once; past FollowRetry, the failing entry tries once more.
		publish(true)
		synctest.Wait()
		if got := entryByIfID(t, store, candidate.IfID).Remote; got != flow(3) {
			t.Errorf("the candidate's remote = %v, want the answered observation %v", got, flow(3))
		}
		time.Sleep(FollowRetry)
		synctest.Wait()
		if n := fakes[failing].requests.Load(); n != 2 {
			t.Errorf("the failing entry sent %d confirms past FollowRetry, want 2", n)
		}
		cancel()
	})
}

// TestRepunchDue checks which punched links the upkeep punches again, and
// when it wakes for the next: an established link the punched set holds,
// down for UpkeepGrace, again on the backoff from RepunchRetry — each wait
// within its band — RepunchAttempts in all, and only at the end with the
// lower ISD-AS; a link whose verdict comes back is forgotten, its next down
// period counted afresh.
func TestRepunchDue(t *testing.T) {
	punched := liveLink(linkIA, 40041)
	punched.IfID = 4
	entries := []*links.Link{punched}
	down := map[uint16]bool{4: false}
	set := map[uint16]bus.DirectoryID{4: {1}}
	t0 := time.Unix(1000, 0)
	st := newRepunchState()
	// Each retry is taken at its wait's upper bound, the earliest step past
	// the band's lower one.
	first := t0.Add(UpkeepGrace)
	second := first.Add(RepunchRetry)
	third := second.Add(2 * RepunchRetry)
	later := third.Add(time.Hour)
	// next bands the wake a step returns: the zero band, none.
	steps := []struct {
		at       time.Time
		verdicts map[uint16]bool
		want     int
		next     [2]time.Time
	}{
		{t0, down, 0, [2]time.Time{first, first}},
		{first.Add(-time.Second), down, 0, [2]time.Time{first, first}},
		{first, down, 1, [2]time.Time{}},
		{first.Add(RepunchRetry/2 - time.Millisecond), down, 0, [2]time.Time{first.Add(RepunchRetry / 2), second}},
		{second, down, 1, [2]time.Time{}},
		{second.Add(RepunchRetry - time.Millisecond), down, 0, [2]time.Time{second.Add(RepunchRetry), third}},
		{third, down, 1, [2]time.Time{}},
		{later, down, 0, [2]time.Time{}},
		{later.Add(time.Second), map[uint16]bool{4: true}, 0, [2]time.Time{}},
		{later.Add(2 * time.Second), down, 0, [2]time.Time{later.Add(2*time.Second + UpkeepGrace), later.Add(2*time.Second + UpkeepGrace)}},
		{later.Add(2*time.Second + UpkeepGrace), down, 1, [2]time.Time{}},
	}
	for _, step := range steps {
		due, next := st.due(rendezvousIA, entries, verdictState(step.verdicts).Up, set, step.at)
		if len(due) != step.want {
			t.Errorf("at %v: %d links due, want %d", step.at.Sub(t0), len(due), step.want)
		}
		if next.Before(step.next[0]) || next.After(step.next[1]) {
			t.Errorf("at %v: next wake %v, want within [%v, %v]", step.at.Sub(t0), next.Sub(t0),
				step.next[0].Sub(t0), step.next[1].Sub(t0))
		}
		for _, l := range due {
			st.attempts.Tried(l.IfID, step.at)
		}
	}

	never := []struct {
		name     string
		mine     addr.IA
		entry    func() *links.Link
		verdicts map[uint16]bool
		set      map[uint16]bus.DirectoryID
	}{
		{"the end with the higher ISD-AS", linkIA2, func() *links.Link { return punched }, down, set},
		{"a link the set lacks", rendezvousIA, func() *links.Link { return punched }, down, nil},
		{"no verdict", rendezvousIA, func() *links.Link { return punched }, nil, set},
		{"a candidate", rendezvousIA, func() *links.Link {
			l := *punched
			l.State = links.StateCandidate
			return &l
		}, down, set},
		{"an entry naming no locator", rendezvousIA, func() *links.Link {
			l := *punched
			l.Remote = netip.AddrPort{}
			return &l
		}, down, set},
	}
	for _, tt := range never {
		st := newRepunchState()
		for _, after := range []time.Duration{0, UpkeepGrace, UpkeepGrace + RepunchRetry} {
			if due, next := st.due(tt.mine, []*links.Link{tt.entry()}, verdictState(tt.verdicts).Up, tt.set,
				t0.Add(after)); len(due) != 0 || !next.IsZero() {
				t.Errorf("%s: due %d at %v, the next wake at %v", tt.name, len(due), after, next)
			}
		}
	}
}

// TestRepunchMovesTheLink checks a re-punch: it punches in the link's
// directory, the entry keeps its interface ID, moves to a fresh link address
// aimed at the peer's reflexive address, and its link request lands; a
// failed punch leaves the entry as it was.
func TestRepunchMovesTheLink(t *testing.T) {
	standing := liveLink(linkIA, 40051)
	z, store := wiredProvider(t, rendezvousIA, standing)
	theirs := netip.MustParseAddrPort("127.0.0.1:26001")
	fake := &fakeLinkServiceClient{reply: &nodev1.LinkReply{LocalAddr: theirs.String(), IfId: 8}}
	z.linker = linkClientOf(map[*links.Link]*fakeLinkServiceClient{standing: fake})

	id := bus.DirectoryID{5}
	z.repunch(context.Background(), &stubPuncher{}, standing, id)
	if entry := entryByIfID(t, store, standing.IfID); entry.Local != standing.Local ||
		entry.Remote != standing.Remote {
		t.Errorf("a failed re-punch left %+v, want the entry unchanged", entry)
	}

	punch := &stubPuncher{reflexive: theirs, ifID: 8}
	z.repunch(context.Background(), punch, standing, id)
	entry := entryByIfID(t, store, standing.IfID)
	if entry.Local == standing.Local || entry.Remote != theirs || entry.RemoteIfID != 8 ||
		entry.State != links.StateEstablished {
		t.Errorf("the re-punched entry = %+v, want interface %d established on a fresh address "+
			"aimed at %v, interface 8", entry, standing.IfID, theirs)
	}
	if want := []addr.IA{linkIA}; !slices.Equal(punch.established, want) {
		t.Errorf("the re-punch punched %v, want %v", punch.established, want)
	}
	if want := []bus.DirectoryID{id}; !slices.Equal(punch.establishedIn, want) {
		t.Errorf("the re-punch punched in %v, want the link's directory %v", punch.establishedIn, want)
	}
	if got := fake.requests.Load(); got != 1 {
		t.Errorf("the re-punch sent %d link requests, want one", got)
	}
}

// failingPunchPaths counts the routes a punch asks for, answering none.
type failingPunchPaths struct{ calls atomic.Int32 }

func (p *failingPunchPaths) Path(context.Context, addr.IA) (*spath.Decoded, error) {
	p.calls.Add(1)
	return nil, errors.New("no route")
}

// reported returns an entry of the ISD-AS naming one address whose report
// says its rendezvous answers, or not.
func reported(ia addr.IA, rendezvous string, unanswered bool) bus.DirectoryEntry {
	return bus.DirectoryEntry{IA: ia, Addresses: []bus.Address{{
		RendezvousAddr: netip.MustParseAddrPort(rendezvous),
		Reach:          bus.Reach{BehindNAT: unanswered, RendezvousUnanswered: unanswered},
	}}}
}

// linkScoped returns a view of one directory holding the entries, each of
// the interfaces' links joining it.
func linkScoped(id bus.DirectoryID, ifIDs []uint16, entries ...bus.DirectoryEntry) bus.Directory {
	joins := make(map[uint16]bus.DirectoryID, len(ifIDs))
	for _, ifID := range ifIDs {
		joins[ifID] = id
	}
	return bus.NewDirectory(joins, bus.NewScope(id, entries...))
}

// TestUpkeepRepunchesOnTheViews checks the upkeep's wake on the views: a
// punched link that went down while the node's own entry in the link's
// directory reported an answering address is punched again once its entry
// reports none, and one that went down while the peer's entry there
// reported an answering address once the peer's reports none, UpkeepGrace
// later, with no link state event between.
func TestUpkeepRepunchesOnTheViews(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		ownAnswered, peerAnswered bool
	}{
		{name: "the node's own report", ownAnswered: true},
		{name: "the peer's report", peerAnswered: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				standing := liveLink(linkIA, 40071)
				z, _ := wiredProvider(t, rendezvousIA, standing)
				id := bus.DirectoryID{5}
				view := func(ownUnanswered, peerUnanswered bool) bus.Directory {
					return linkScoped(id, []uint16{standing.IfID},
						reported(rendezvousIA, "192.0.2.1:30043", ownUnanswered),
						reported(linkIA, "192.0.2.2:30043", peerUnanswered))
				}
				z.directoryState.Publish(view(!tc.ownAnswered, !tc.peerAnswered))
				paths := &failingPunchPaths{}
				z.puncher = &puncher{paths: paths}
				z.linkState.Publish(bus.NewLinkState(bus.Link{Entry: *standing, Down: true}))
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				go z.runUpkeep(ctx)
				time.Sleep(2 * UpkeepGrace)
				synctest.Wait()
				if n := paths.calls.Load(); n != 0 {
					t.Fatalf("punched %d times while an end's address answered, want none", n)
				}

				z.directoryState.Publish(view(true, true))
				time.Sleep(UpkeepGrace + time.Millisecond)
				synctest.Wait()
				if n := paths.calls.Load(); n != 1 {
					t.Errorf("punched %d times after the report flipped, want 1", n)
				}
			})
		})
	}
}

// TestPunchedLinks checks which links count as punched: those whose
// directory holds the node's own entry and the peer's, neither naming an
// answering address; never one whose own end answers there, whose peer
// answers there, or that joins no directory.
func TestPunchedLinks(t *testing.T) {
	entry := func(ia addr.IA, ifID uint16) *links.Link {
		l := liveLink(ia, 40080+ifID)
		l.IfID = ifID
		return l
	}
	entries := []*links.Link{entry(linkIA, 1), entry(linkIA2, 2), entry(addr.MustIAFrom(20, 0xfd0000000036), 3)}
	id := bus.DirectoryID{5}
	view := bus.NewDirectory(map[uint16]bus.DirectoryID{1: id, 2: id},
		bus.NewScope(id,
			reported(rendezvousIA, "192.0.2.1:30043", true),
			reported(linkIA, "192.0.2.2:30043", true),
			reported(linkIA2, "192.0.2.3:30043", false)))
	if got := punchedLinks(rendezvousIA, entries, view); !maps.Equal(got, map[uint16]bus.DirectoryID{1: id}) {
		t.Errorf("punched = %v, want the link to the unanswered peer alone", got)
	}
	answering := bus.NewDirectory(map[uint16]bus.DirectoryID{1: id},
		bus.NewScope(id,
			reported(rendezvousIA, "192.0.2.1:30043", false),
			reported(linkIA, "192.0.2.2:30043", true)))
	if got := punchedLinks(rendezvousIA, entries, answering); len(got) != 0 {
		t.Errorf("punched where the node's own address answers = %v, want none", got)
	}
}

// TestPickReflector checks the reflector's choice: a neighbor in the named
// directory whose own report there says an address answers and whose
// established link joining the directory is up, never one whose link is
// down, nor a candidate, nor a node that reports itself undialable, nor a
// neighbor whose link joins another directory.
func TestPickReflector(t *testing.T) {
	entry := func(ia addr.IA, ifID uint16, state links.State) *links.Link {
		l := liveLink(ia, 40060+ifID)
		l.IfID, l.State = ifID, state
		return l
	}
	id, other := bus.DirectoryID{5}, bus.DirectoryID{6}
	view := bus.NewDirectory(map[uint16]bus.DirectoryID{1: id, 2: id, 3: id, 4: other},
		bus.NewScope(id,
			reported(linkIA, "192.0.2.1:30043", false),
			reported(linkIA2, "192.0.2.2:30043", false),
			reported(rendezvousIA, "192.0.2.3:30043", true),
			reported(selPeer, "192.0.2.4:30043", false)),
		bus.NewScope(other, reported(selPeer, "198.51.100.4:30043", false)))
	tests := []struct {
		name     string
		entries  []*links.Link
		verdicts map[uint16]bool
		want     string
	}{
		{"the first one up", []*links.Link{entry(linkIA, 1, links.StateEstablished),
			entry(linkIA2, 2, links.StateEstablished)}, nil, "192.0.2.1:30043"},
		{"past a down one", []*links.Link{entry(linkIA, 1, links.StateEstablished),
			entry(linkIA2, 2, links.StateEstablished)}, map[uint16]bool{1: false}, "192.0.2.2:30043"},
		{"past a candidate", []*links.Link{entry(linkIA, 1, links.StateCandidate),
			entry(linkIA2, 2, links.StateEstablished)}, nil, "192.0.2.2:30043"},
		{"none dialable", []*links.Link{entry(rendezvousIA, 3, links.StateEstablished)}, nil, ""},
		{"a link of another directory", []*links.Link{entry(selPeer, 4, links.StateEstablished)}, nil, ""},
		{"none up", []*links.Link{entry(linkIA, 1, links.StateEstablished)},
			map[uint16]bool{1: false}, ""},
	}
	for _, tt := range tests {
		got, ok := pickReflector(tt.entries, verdictState(tt.verdicts).Up, view, id)
		if want := tt.want != ""; ok != want || want && got != netip.MustParseAddrPort(tt.want) {
			t.Errorf("%s: picked %v (%t), want %q", tt.name, got, ok, tt.want)
		}
	}
}

// wiredProvider returns a provider over a store holding the given entries.
func wiredProvider(t *testing.T, ia addr.IA, entries ...*links.Link) (*Provider, *memory.DB) {
	t.Helper()
	z, err := New(Config{ControlHost: netip.MustParseAddr("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	store := memory.New()
	z.Wire(topology.Environment{IA: ia, Store: store, Bus: bus.New()})
	for _, l := range entries {
		if err := store.Insert(context.Background(), l); err != nil {
			t.Fatal(err)
		}
	}
	return z, store
}
