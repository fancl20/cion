package wireguard

import (
	"net/netip"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// netipToAddress converts an overlay address for a netstack header.
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

// landed names the pipe the router's last delivery went to — the router
// delivers before it returns — and "" when none of the pipes holds one.
func landed(pipes ...*pipe) string {
	for _, p := range pipes {
		select {
		case <-p.inbound:
			return p.name
		default:
		}
	}
	return ""
}

// TestRouterRoutesByDestination checks the table's lookups: owned host /32s
// to the host device, mesh slices longest-prefix first — and no default for
// a mesh device's packets, a destination no slice claims counting
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
	r.rebuild(hostDev,
		[]hostRoute{{addr: host, owned: true}},
		[]route{{prefix: netWide, dst: meshA}, {prefix: netA, dst: meshB}},
	)

	// An owned host's /32 goes to the host device — from anywhere.
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

	// A mesh device's packet takes no default: a destination no slice
	// claims counts unroutable.
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
// installs: with one standing, packets reach it by destination exactly — from
// any arrival — while an address of the node's own slice that is neither a
// host's nor the served one stays unroutable, and the undo leaves the address
// unroutable again, the service's assembly the only thing that routes it.
func TestRouterDeliversServedAddress(t *testing.T) {
	cnt := &counters{}
	r := newRouter(OverlayMTU, cnt)
	hostDev := newPipe("host", OverlayMTU, cnt)
	mesh := newPipe("mesh", OverlayMTU, cnt)
	host := netip.MustParseAddr("100.64.1.10")
	own := netip.MustParseAddr("100.64.1.1")
	r.rebuild(hostDev,
		[]hostRoute{{addr: host, owned: true}},
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
	r.routeFromHost(ipPacket(t, host, own, []byte("near")))
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

// TestRouterDeliversTheDefault checks the default delivery: a destination
// outside the tailnet that the host device decrypted reaches it while it
// stands and counts unroutable before and after; the same destination from
// a mesh device, or from the node's own services, counts unroutable even
// while it stands; and a tailnet destination from the host device routes as
// it always has.
func TestRouterDeliversTheDefault(t *testing.T) {
	cnt := &counters{}
	r := newRouter(OverlayMTU, cnt)
	hostDev := newPipe("host", OverlayMTU, cnt)
	mesh := newPipe("mesh", OverlayMTU, cnt)
	host := netip.MustParseAddr("100.64.1.10")
	far := netip.MustParseAddr("100.64.2.10")
	internet := netip.MustParseAddr("192.0.2.53")
	r.rebuild(hostDev,
		[]hostRoute{{addr: host, owned: true}},
		[]route{{prefix: netip.MustParsePrefix("100.64.2.0/24"), dst: mesh}},
	)
	unroutable := func() int64 { return cnt.unroutablePackets.Load() }

	r.routeFromHost(ipPacket(t, host, internet, []byte("before")))
	if got := unroutable(); got != 1 {
		t.Fatalf("with no default the host's internet-bound packet counted %d unroutable, want 1", got)
	}

	var got []string
	undo := r.DeliverDefault(func(pkt []byte) {
		got = append(got, string(pkt[header.IPv4MinimumSize:]))
	})
	r.routeFromHost(ipPacket(t, host, internet, []byte("from the host")))
	r.route(ipPacket(t, far, internet, []byte("from the mesh")))
	r.Route(ipPacket(t, netip.MustParseAddr("100.64.1.1"), internet, []byte("from the node")))
	r.routeFromHost(ipPacket(t, host, far, []byte("to the tailnet")))
	if diff := cmp.Diff([]string{"from the host"}, got); diff != "" {
		t.Errorf("the default's deliveries (-want +got):\n%s", diff)
	}
	if got := unroutable(); got != 3 {
		t.Errorf("unroutable = %d, want 3: the mesh's and the node's internet-bound packets", got)
	}
	if pkt := take(t, mesh); string(pkt[header.IPv4MinimumSize:]) != "to the tailnet" {
		t.Errorf("the host's tailnet packet reached the mesh as %q", pkt[header.IPv4MinimumSize:])
	}

	undo()
	r.routeFromHost(ipPacket(t, host, internet, []byte("after")))
	if len(got) != 1 {
		t.Errorf("the default delivered %q after its undo", got[1:])
	}
	if got := unroutable(); got != 4 {
		t.Errorf("unroutable = %d after the undo, want 4", got)
	}
}

// TestRouterRoutesOwnPacketsToEveryHost checks the rule for the packets the
// node's own services produce: any directory host's address enters the host
// device, whoever owns the host, and a tailnet destination no host holds
// routes by slice; a packet forwarded from a device reaches the owned hosts
// alone, a foreign host's going to the slice that holds it. The rule follows
// the directory: a host the rebuild drops routes by slice again.
func TestRouterRoutesOwnPacketsToEveryHost(t *testing.T) {
	cnt := &counters{}
	r := newRouter(OverlayMTU, cnt)
	hostDev := newPipe("host", OverlayMTU, cnt)
	mesh := newPipe("mesh", OverlayMTU, cnt)
	own := netip.MustParseAddr("100.64.1.1")
	owned := netip.MustParseAddr("100.64.1.10")
	foreign := netip.MustParseAddr("100.64.2.10")
	farNode := netip.MustParseAddr("100.64.2.1")
	nets := []route{{prefix: netip.MustParsePrefix("100.64.2.0/24"), dst: mesh}}
	r.rebuild(hostDev, []hostRoute{{addr: owned, owned: true}, {addr: foreign}}, nets)

	var trace []string
	for _, send := range []func(){
		func() { r.Route(ipPacket(t, own, owned, nil)) },
		func() { r.Route(ipPacket(t, own, foreign, nil)) },
		func() { r.Route(ipPacket(t, own, farNode, nil)) },
		func() { r.route(ipPacket(t, netip.MustParseAddr("100.64.3.10"), foreign, nil)) },
		func() { r.routeFromHost(ipPacket(t, owned, foreign, nil)) },
		func() { r.route(ipPacket(t, foreign, owned, nil)) },
		func() {
			r.rebuild(hostDev, []hostRoute{{addr: owned, owned: true}}, nets)
			r.Route(ipPacket(t, own, foreign, nil))
		},
	} {
		send()
		trace = append(trace, landed(hostDev, mesh))
	}
	want := []string{
		"host", // the node's own packet for the owned host
		"host", // the node's own packet for the foreign host
		"mesh", // the node's own packet for a far node's address
		"mesh", // a forwarded packet for the foreign host
		"mesh", // the owned host's packet for the foreign host
		"host", // a forwarded packet for the owned host
		"mesh", // the node's own packet for the foreign host, dropped
	}
	if diff := cmp.Diff(want, trace); diff != "" {
		t.Errorf("where the packets landed (-want +got):\n%s", diff)
	}
}

// TestRouterDropsOversized checks the overlay MTU: an inner packet larger
// than the constant is dropped, never sent.
func TestRouterDropsOversized(t *testing.T) {
	cnt := &counters{}
	r := newRouter(OverlayMTU, cnt)
	dst := newPipe("dst", OverlayMTU, cnt)
	host := netip.MustParseAddr("100.64.1.10")
	r.rebuild(dst, []hostRoute{{addr: host, owned: true}}, nil)

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
