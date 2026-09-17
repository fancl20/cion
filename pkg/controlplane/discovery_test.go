package controlplane

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/dataplane"
	"github.com/fancl20/cion/pkg/links"
	"github.com/fancl20/cion/pkg/links/impl/memory"
)

const (
	ifID         = 1
	discoveryGap = 50 * time.Millisecond
)

// startNode brings up one CION node: data plane with an internal and an
// external link, plus a registered discovery service. The link store seeds
// the established link the data plane carries and discovery validates
// against. The changed hook, when set, is the discovery's arrival signal.
func startNode(
	t *testing.T, ia addr.IA, internal, extLocal, extRemote, control string, changed func(),
) *Discovery {
	t.Helper()
	key := []byte("0123456789abcdef")

	neighbor := addr.MustIAFrom(1, 0xff0000000001)
	if ia == neighbor {
		neighbor = addr.MustIAFrom(1, 0xff0000000002)
	}
	store := memory.New()
	entry := &links.Link{
		NeighborIA: neighbor,
		Local:      netip.MustParseAddrPort(extLocal),
		Remote:     netip.MustParseAddrPort(extRemote),
		State:      links.StateEstablished,
	}
	if err := store.Insert(context.Background(), entry); err != nil {
		t.Fatal(err)
	}

	metrics, err := dataplane.NewMetrics()
	if err != nil {
		t.Fatal(err)
	}
	provider := dataplane.NewUDPProvider(64, 0, 0)
	il, err := provider.NewInternalLink(internal, 64, metrics.NewInterfaceMetrics(0, ia, 0))
	if err != nil {
		t.Fatal(err)
	}
	el, err := provider.NewExternalLink(64, nil, extLocal, extRemote, entry.IfID,
		metrics.NewInterfaceMetrics(entry.IfID, ia, neighbor))
	if err != nil {
		t.Fatal(err)
	}
	local := addr.HostIP(netip.MustParseAddr("127.0.0.1"))
	d, err := dataplane.NewDataPlane(ia, local, key, provider, []dataplane.Link{il, el})
	if err != nil {
		t.Fatal(err)
	}
	d.RunConfig = dataplane.RunConfig{
		NumProcessors:         2,
		NumSlowPathProcessors: 1,
		BatchSize:             64,
	}

	discovery, err := NewDiscovery(DiscoveryConfig{
		IA:           ia,
		ControlAddr:  control,
		MACKey:       key,
		InternalAddr: internal,
		Store:        store,
		Interval:     discoveryGap,
		Changed:      changed,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := discovery.Register(provider); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		provider.Stop()
		_ = discovery.Close()
	})
	go func() { _ = d.Serve(ctx) }()
	go discovery.Run(ctx)
	return discovery
}

// signalArrival returns the discovery change hook that signals one pending
// arrival, dropping the rest — the first greeting tells the waiter all it
// needs, and a dropped signal never blocks the receiver.
func signalArrival(learned chan<- struct{}) func() {
	return func() {
		select {
		case learned <- struct{}{}:
		default:
		}
	}
}

// waitNeighbor blocks until the node records a greeting — the arrival
// channel's signal, delivered after the table learned from it — and returns
// the neighbor it learned. No polling: the event is the readiness.
func waitNeighbor(t *testing.T, learned <-chan struct{}, d *Discovery) Neighbor {
	t.Helper()
	select {
	case <-learned:
	case <-time.After(5 * time.Second):
		t.Fatal("no greeting recorded in time")
		return Neighbor{}
	}
	ns := d.Neighbors()
	if len(ns) != 1 {
		t.Fatalf("neighbors = %v, want the one learned", ns)
	}
	for _, n := range ns {
		return n
	}
	return Neighbor{}
}

// freeUDPAddr returns a loopback UDP address with a port picked by the
// kernel, so that concurrent test runs do not collide on fixed ports.
func freeUDPAddr(t *testing.T) string {
	t.Helper()
	return freeUDPAddrOn(t, netip.MustParseAddr("127.0.0.1"))
}

// freeUDPAddrOn returns an unused port on the given local address; distinct
// loopback addresses let several nodes share one test host even with fixed
// ports.
func freeUDPAddrOn(t *testing.T, ip netip.Addr) string {
	t.Helper()
	c, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	return c.LocalAddr().String()
}

// TestDiscoveryTwoNodes checks that two directly connected nodes learn each
// other's IA, interface ID, and control address via the greeting handshake,
// with all traffic forwarded by the data plane over the direct link.
func TestDiscoveryTwoNodes(t *testing.T) {
	iaA := addr.MustIAFrom(1, 0xff0000000001)
	iaB := addr.MustIAFrom(1, 0xff0000000002)

	intA, intB := freeUDPAddr(t), freeUDPAddr(t)
	extA, extB := freeUDPAddr(t), freeUDPAddr(t)
	ctrlA, ctrlB := freeUDPAddr(t), freeUDPAddr(t)

	learnedA, learnedB := make(chan struct{}, 1), make(chan struct{}, 1)
	a := startNode(t, iaA, intA, extA, extB, ctrlA, signalArrival(learnedA))
	b := startNode(t, iaB, intB, extB, extA, ctrlB, signalArrival(learnedB))

	nb := waitNeighbor(t, learnedA, a)
	if nb.IA != iaB {
		t.Fatalf("learned IA = %v, want %v", nb.IA, iaB)
	}
	if nb.IfID != ifID {
		t.Fatalf("learned ifID = %d, want %d", nb.IfID, ifID)
	}
	want, err := netip.ParseAddrPort(ctrlB)
	if err != nil {
		t.Fatal(err)
	}
	if nb.ControlAddr != want {
		t.Fatalf("learned control address = %v, want %v", nb.ControlAddr, want)
	}

	na := waitNeighbor(t, learnedB, b)
	if na.IA != iaA {
		t.Fatalf("learned IA = %v, want %v", na.IA, iaA)
	}
	if na.IfID != ifID {
		t.Fatalf("learned ifID = %d, want %d", na.IfID, ifID)
	}
}

// TestDiscoveryRejectsMismatchedIA checks the neighbor cross-check of the
// link-table model: a greeting advertising an ISD-AS that does not match the
// entry of the receiving interface is dropped.
func TestDiscoveryRejectsMismatchedIA(t *testing.T) {
	iaA := addr.MustIAFrom(1, 0xff0000000001)
	iaB := addr.MustIAFrom(1, 0xff0000000002)

	store := memory.New()
	entry := &links.Link{
		NeighborIA: iaB,
		Local:      netip.MustParseAddrPort("127.0.0.1:40001"),
		Remote:     netip.MustParseAddrPort("127.0.0.1:40002"),
		State:      links.StateEstablished,
	}
	if err := store.Insert(context.Background(), entry); err != nil {
		t.Fatal(err)
	}
	d, err := NewDiscovery(DiscoveryConfig{
		IA:           iaA,
		ControlAddr:  freeUDPAddr(t),
		MACKey:       []byte("0123456789abcdef"),
		InternalAddr: freeUDPAddr(t),
		Store:        store,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	foreign := addr.MustIAFrom(1, 0xff0000000f0f)
	d.record(entry.IfID, Greeting{
		IA:          foreign,
		IfID:        entry.IfID,
		ControlAddr: netip.MustParseAddrPort("127.0.0.1:30043"),
	})
	if ns := d.Neighbors(); len(ns) != 0 {
		t.Errorf("neighbors after foreign greeting = %v, want none", ns)
	}

	// The legitimate neighbor is accepted on the same interface.
	d.record(entry.IfID, Greeting{
		IA:          iaB,
		IfID:        entry.IfID,
		ControlAddr: netip.MustParseAddrPort("127.0.0.1:30044"),
	})
	if ns := d.Neighbors(); len(ns) != 1 || !ns[entry.IfID].IA.Equal(iaB) {
		t.Errorf("neighbors after legitimate greeting = %v, want %v", ns, iaB)
	}
}

// TestDiscoveryAdoptsNeighbor checks the entry a joiner's rendezvous created
// without a named neighbor: the first greeting's ISD-AS is adopted into it,
// and a later greeting of another ISD-AS is refused.
func TestDiscoveryAdoptsNeighbor(t *testing.T) {
	iaA := addr.MustIAFrom(1, 0xff0000000001)
	iaB := addr.MustIAFrom(1, 0xff0000000002)

	store := memory.New()
	entry := &links.Link{
		Local:  netip.MustParseAddrPort("127.0.0.1:40001"),
		Remote: netip.MustParseAddrPort("127.0.0.1:40002"),
		State:  links.StateCandidate,
	}
	if err := store.Insert(context.Background(), entry); err != nil {
		t.Fatal(err)
	}
	d, err := NewDiscovery(DiscoveryConfig{
		IA:           iaA,
		ControlAddr:  freeUDPAddr(t),
		MACKey:       []byte("0123456789abcdef"),
		InternalAddr: freeUDPAddr(t),
		Store:        store,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	d.record(entry.IfID, Greeting{
		IA:          iaB,
		IfID:        entry.IfID + 1,
		ControlAddr: netip.MustParseAddrPort("127.0.0.1:30044"),
	})
	if ns := d.Neighbors(); len(ns) != 1 || !ns[entry.IfID].IA.Equal(iaB) {
		t.Fatalf("neighbors after the first greeting = %v, want %v", ns, iaB)
	}
	// The adoption and the remote interface ID landed in the entry.
	entries, err := store.All(context.Background())
	if err != nil || len(entries) != 1 {
		t.Fatalf("entries = %v (%v), want the one", entries, err)
	}
	if !entries[0].NeighborIA.Equal(iaB) || entries[0].RemoteIfID != entry.IfID+1 {
		t.Errorf("entry after adoption = %+v, want %s with the remote ID", entries[0], iaB)
	}

	// A greeting of another ISD-AS on the same interface is refused now that
	// the entry names its neighbor.
	foreign := addr.MustIAFrom(1, 0xff0000000f0f)
	d.record(entry.IfID, Greeting{
		IA:          foreign,
		IfID:        entry.IfID,
		ControlAddr: netip.MustParseAddrPort("127.0.0.1:30045"),
	})
	if ns := d.Neighbors(); len(ns) != 1 || !ns[entry.IfID].IA.Equal(iaB) {
		t.Errorf("neighbors after a foreign greeting = %v, want the adopted %v", ns, iaB)
	}
}

// TestParseGreetingRoundTrip checks the greeting wire format.
func TestParseGreetingRoundTrip(t *testing.T) {
	g := Greeting{
		IA:          addr.MustIAFrom(2, 0xff0000000110),
		IfID:        42,
		ControlAddr: netip.MustParseAddrPort("192.0.2.10:30043"),
	}
	got, err := ParseGreeting(g.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if got != g {
		t.Fatalf("round trip = %+v, want %+v", got, g)
	}
}

// TestParseGreetingTruncated checks that malformed greetings are rejected.
func TestParseGreetingTruncated(t *testing.T) {
	g := Greeting{IA: addr.MustIAFrom(1, 1), IfID: 1,
		ControlAddr: netip.MustParseAddrPort("127.0.0.1:1")}
	raw := g.Marshal()
	for _, n := range []int{0, 3, 9, 13} {
		if n >= len(raw) {
			continue
		}
		if _, err := ParseGreeting(raw[:n]); err == nil {
			t.Errorf("ParseGreeting(%d bytes) succeeded, want error", n)
		}
	}
}
