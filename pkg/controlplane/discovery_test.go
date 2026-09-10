package controlplane

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/dataplane"
)

const (
	ifID         = 1
	discoveryGap = 50 * time.Millisecond
)

// startNode brings up one CION node: data plane with an internal and an
// external link, plus a registered discovery service.
func startNode(t *testing.T, ia addr.IA, internal, extLocal, extRemote, control string) *Discovery {
	t.Helper()
	key := []byte("0123456789abcdef")

	metrics, err := dataplane.NewMetrics()
	if err != nil {
		t.Fatal(err)
	}
	provider := dataplane.NewUDPProvider(64, 0, 0)
	il, err := provider.NewInternalLink(internal, 64, metrics.NewInterfaceMetrics(0, ia, 0))
	if err != nil {
		t.Fatal(err)
	}
	neighbor := addr.MustIAFrom(1, 0xff0000000001)
	if ia == neighbor {
		neighbor = addr.MustIAFrom(1, 0xff0000000002)
	}
	el, err := provider.NewExternalLink(64, nil, extLocal, extRemote, ifID,
		metrics.NewInterfaceMetrics(ifID, ia, neighbor))
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
		Links:        map[uint16]addr.IA{ifID: neighbor},
		Interval:     discoveryGap,
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
	})
	go func() { _ = d.Serve(ctx) }()
	go discovery.Run(ctx)
	return discovery
}

// waitNeighbor polls until the neighbor is learned or the timeout expires.
func waitNeighbor(t *testing.T, d *Discovery) Neighbor {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ns := d.Neighbors(); len(ns) == 1 {
			return ns[ifID]
		}
		time.Sleep(2 * discoveryGap)
	}
	t.Fatal("neighbor not discovered in time")
	return Neighbor{}
}

// TestDiscoveryTwoNodes checks that two directly connected nodes learn each
// other's IA, interface ID, and control address via the greeting handshake,
// with all traffic forwarded by the data plane over the direct link.
func TestDiscoveryTwoNodes(t *testing.T) {
	iaA := addr.MustIAFrom(1, 0xff0000000001)
	iaB := addr.MustIAFrom(1, 0xff0000000002)

	a := startNode(t, iaA, "127.0.0.1:31051",
		"127.0.0.1:31151", "127.0.0.1:31152", "127.0.0.1:31061")
	b := startNode(t, iaB, "127.0.0.1:31052",
		"127.0.0.1:31152", "127.0.0.1:31151", "127.0.0.1:31062")

	nb := waitNeighbor(t, a)
	if nb.IA != iaB {
		t.Fatalf("learned IA = %v, want %v", nb.IA, iaB)
	}
	if nb.IfID != ifID {
		t.Fatalf("learned ifID = %d, want %d", nb.IfID, ifID)
	}
	want := netip.MustParseAddrPort("127.0.0.1:31062")
	if nb.ControlAddr != want {
		t.Fatalf("learned control address = %v, want %v", nb.ControlAddr, want)
	}

	na := waitNeighbor(t, b)
	if na.IA != iaA {
		t.Fatalf("learned IA = %v, want %v", na.IA, iaA)
	}
	if na.IfID != ifID {
		t.Fatalf("learned ifID = %d, want %d", na.IfID, ifID)
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
