package wireguard

import (
	"net/netip"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// netipToAddress converts an overlay address for a netstack header — the
// helper the egress machinery carried, kept for the packet builders here.
func netipToAddress(ip netip.Addr) tcpip.Address {
	return tcpip.AddrFromSlice(ip.AsSlice())
}

// ipPacket builds a minimal IPv4 packet between two overlay addresses; proto
// 1 (ICMP) keeps the payload trivial.
func ipPacket(t *testing.T, src, dst netip.Addr, payload []byte) []byte {
	t.Helper()
	pkt := make([]byte, header.IPv4MinimumSize+len(payload))
	ipHdr := header.IPv4(pkt)
	ipHdr.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(pkt)),
		TTL:         64,
		Protocol:    1,
		SrcAddr:     netipToAddress(src),
		DstAddr:     netipToAddress(dst),
	})
	copy(pkt[header.IPv4MinimumSize:], payload)
	return pkt
}

// take reads the next packet a pipe delivered.
func take(t *testing.T, p *pipe) []byte {
	t.Helper()
	select {
	case pkt := <-p.inbound:
		return pkt
	case <-time.After(2 * time.Second):
		t.Fatal("no packet was delivered")
		return nil
	}
}

func assertNothing(t *testing.T, p *pipe) {
	t.Helper()
	select {
	case pkt := <-p.inbound:
		t.Fatalf("packet %x arrived uninvited", pkt)
	case <-time.After(50 * time.Millisecond):
	}
}

// TestRouterRoutesByDestination checks the table's lookups (ADR-0011's
// table): host /32s to the host device, mesh slices longest-prefix first —
// and no default anywhere, a destination no slice claims counting
// unroutable.
func TestRouterRoutesByDestination(t *testing.T) {
	cnt := &counters{}
	r := newRouter(OverlayMTU, cnt)
	hostDev := newPipe("host", OverlayMTU, cnt)
	meshA := newPipe("mesh-a", OverlayMTU, cnt)
	meshB := newPipe("mesh-b", OverlayMTU, cnt)

	host := netip.MustParseAddr("100.64.1.10")
	netA := netip.MustParsePrefix("100.64.1.0/24")
	netWide := netip.MustParsePrefix("100.64.0.0/16")
	r.rebuild(
		[]hostRoute{{addr: host, pipe: hostDev}},
		[]route{{prefix: netWide, dst: meshA}, {prefix: netA, dst: meshB}},
	)

	// A host's /32 goes to the host device — from anywhere.
	fromMesh := func(pkt []byte) { r.route(pkt) }
	fromMesh(ipPacket(t, netip.MustParseAddr("100.64.2.10"), host, nil))
	if pkt := take(t, hostDev); pkt == nil {
		t.Fatal("host /32 did not route")
	}

	// Longest prefix wins: the /24's slice routes to its device over the
	// covering /16.
	r.route(ipPacket(t, host, netip.MustParseAddr("100.64.1.20"), nil))
	if pkt := take(t, meshB); pkt == nil {
		t.Fatal("the longest slice did not route to its device")
	}
	r.route(ipPacket(t, host, netip.MustParseAddr("100.64.9.20"), nil))
	if pkt := take(t, meshA); pkt == nil {
		t.Fatal("the covering slice did not route to its device")
	}

	// No default exists: a destination no slice claims counts unroutable,
	// wherever the packet came from — the internet is a service on the
	// overlay, never a property of the routing.
	before := cnt.unroutablePackets.Load()
	r.route(ipPacket(t, host, netip.MustParseAddr("192.0.2.53"), nil))
	if unroutable := cnt.unroutablePackets.Load(); unroutable != before+1 {
		t.Errorf("unroutable count = %d after an internet-bound packet, want %d",
			unroutable, before)
	}

	// A reply a service produces still routes to its host, never a default.
	r.Route(ipPacket(t, netip.MustParseAddr("192.0.2.53"), host, nil))
	if pkt := take(t, hostDev); pkt == nil {
		t.Fatal("service reply did not route to the host")
	}
}

// TestRouterDeliversServedAddress checks the delivery a resident service
// installs (proposal 0024): with one standing, packets reach it by
// destination exactly — from any arrival — while an address of the node's
// own slice that is neither a host's nor the served one stays unroutable,
// and the undo leaves the address unroutable again, the service's assembly
// the only thing that routes it.
func TestRouterDeliversServedAddress(t *testing.T) {
	cnt := &counters{}
	r := newRouter(OverlayMTU, cnt)
	hostDev := newPipe("host", OverlayMTU, cnt)
	mesh := newPipe("mesh", OverlayMTU, cnt)
	host := netip.MustParseAddr("100.64.1.10")
	own := netip.MustParseAddr("100.64.1.1")
	r.rebuild(
		[]hostRoute{{addr: host, pipe: hostDev}},
		[]route{{prefix: netip.MustParsePrefix("100.64.2.0/24"), dst: mesh}},
	)

	// Without the application the node's own address stays unroutable.
	before := cnt.unroutablePackets.Load()
	r.route(ipPacket(t, host, own, nil))
	if unroutable := cnt.unroutablePackets.Load(); unroutable != before+1 {
		t.Fatalf("the unserved own address counted %d unroutable, want %d",
			unroutable, before+1)
	}

	// delivery is one packet the served address received, by destination
	// and payload — strings for go-cmp's eyes, netip being unexported
	// fields all the way down.
	type delivery struct {
		Dst  string
		Data string
	}
	var got []delivery
	undo := r.Deliver(own, func(pkt []byte) {
		got = append(got, delivery{
			Dst:  addressToNetip(header.IPv4(pkt).DestinationAddress()).String(),
			Data: string(pkt[header.IPv4MinimumSize:]),
		})
	})

	// The host's leg and a far peer's leg alike: delivery is by
	// destination, never by arrival.
	r.route(ipPacket(t, host, own, []byte("near")))
	r.route(ipPacket(t, netip.MustParseAddr("100.64.2.10"), own, []byte("far")))
	want := []delivery{
		{Dst: own.String(), Data: "near"},
		{Dst: own.String(), Data: "far"},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("the served address's deliveries (-want +got):\n%s", diff)
	}

	// An address of the node's own slice that is neither a host's nor the
	// node's own stays unroutable.
	before = cnt.unroutablePackets.Load()
	r.route(ipPacket(t, host, netip.MustParseAddr("100.64.1.99"), nil))
	if unroutable := cnt.unroutablePackets.Load(); unroutable != before+1 {
		t.Errorf("an unallocated address of the own slice routed, want unroutable")
	}

	undo()
	r.route(ipPacket(t, host, own, []byte("gone")))
	if unroutable := cnt.unroutablePackets.Load(); unroutable != before+2 {
		t.Error("the served address routed after the delivery's undo")
	}
}

// TestRouterDropsOversized checks the overlay MTU: an inner packet larger
// than the constant is dropped, never sent.
func TestRouterDropsOversized(t *testing.T) {
	cnt := &counters{}
	r := newRouter(OverlayMTU, cnt)
	dst := newPipe("dst", OverlayMTU, cnt)
	host := netip.MustParseAddr("100.64.1.10")
	r.rebuild([]hostRoute{{addr: host, pipe: dst}}, nil)

	oversized := ipPacket(t, netip.MustParseAddr("100.64.2.1"), host,
		make([]byte, OverlayMTU))
	r.route(oversized)
	if dropped := cnt.droppedPackets.Load(); dropped == 0 {
		t.Error("an oversized inner packet was not dropped")
	}
	assertNothing(t, dst)

	// A non-IPv4 packet drops as well.
	r.route([]byte{0x60, 0, 0, 0, 0, 0, 0, 0})
	if dropped := cnt.droppedPackets.Load(); dropped < 2 {
		t.Error("a non-IPv4 packet was not dropped")
	}
	assertNothing(t, dst)
}
