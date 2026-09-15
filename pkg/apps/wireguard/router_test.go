package wireguard

import (
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/header"
)

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

// TestRouterRoutesByDestination checks the table's lookups: host /32s to
// their devices, mesh subnets longest-prefix first, and the per-decryption
// default to the exit whose device decrypted the packet.
func TestRouterRoutesByDestination(t *testing.T) {
	cnt := &counters{}
	r := newRouter(OverlayMTU, cnt)
	hostA := newPipe("host-a", OverlayMTU, cnt) // the host device of exit X
	meshX := newPipe("mesh-x", OverlayMTU, cnt) // exit X's mesh device
	meshB := newPipe("mesh-b", OverlayMTU, cnt) // a remote subnet's device

	host := netip.MustParseAddr("10.64.1.10")
	remoteNet := netip.MustParsePrefix("10.64.2.0/24")
	xSubnet := netip.MustParsePrefix("10.64.3.0/24")
	r.rebuild(
		[]hostRoute{{addr: host, pipe: hostA}},
		[]route{{prefix: remoteNet, dst: meshB}, {prefix: xSubnet, dst: meshX}},
		map[*pipe]*pipe{hostA: meshX},
	)

	// A host peer's /32 goes to its host device — from anywhere.
	fromMesh := func(pkt []byte) { r.route(pkt, meshB) }
	fromMesh(ipPacket(t, netip.MustParseAddr("10.64.2.10"), host, nil))
	if pkt := take(t, hostA); pkt == nil {
		t.Fatal("host /32 did not route")
	}

	// A remote overlay subnet wins over the default, longest prefix first.
	r.route(ipPacket(t, host, netip.MustParseAddr("10.64.2.20"), nil), hostA)
	if pkt := take(t, meshB); pkt == nil {
		t.Fatal("remote subnet did not route")
	}

	// Everything else goes to the exit whose device decrypted the packet:
	// traffic from exit X's host device defaults to X's mesh device.
	internet := netip.MustParseAddr("192.0.2.53")
	r.route(ipPacket(t, host, internet, nil), hostA)
	if pkt := take(t, meshX); pkt == nil {
		t.Fatal("exit default did not route to the exit's mesh device")
	}

	// Traffic decrypted by a mesh device for no overlay destination has
	// reached the exit this node offers and enters the egress.
	var egressed []byte
	done := make(chan struct{})
	r.setEgress(func(pkt []byte) {
		egressed = pkt
		close(done)
	})
	r.route(ipPacket(t, netip.MustParseAddr("203.0.113.9"), internet, nil), meshB)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("default-routed mesh traffic did not enter the egress")
	}
	if len(egressed) == 0 {
		t.Fatal("egress received no packet")
	}

	// A reply the egress produced routes to its host, never a default.
	r.routeFromEgress(ipPacket(t, internet, host, nil))
	if pkt := take(t, hostA); pkt == nil {
		t.Fatal("egress reply did not route to the host")
	}
}

// TestRouterLocalExitDefault checks the local exit: the host device whose
// exit is this node itself enters the egress directly.
func TestRouterLocalExitDefault(t *testing.T) {
	cnt := &counters{}
	r := newRouter(OverlayMTU, cnt)
	local := newPipe("host-local", OverlayMTU, cnt)
	r.rebuild(nil, nil, map[*pipe]*pipe{local: nil})
	egress := make(chan []byte, 1)
	r.setEgress(func(pkt []byte) { egress <- pkt })

	host := netip.MustParseAddr("10.64.1.10")
	r.route(ipPacket(t, host, netip.MustParseAddr("192.0.2.1"), nil), local)
	select {
	case <-egress:
	case <-time.After(2 * time.Second):
		t.Fatal("local-exit default traffic did not enter the egress")
	}
}

// TestRouterDropsOversized checks the overlay MTU: an inner packet larger
// than the constant is dropped, never sent.
func TestRouterDropsOversized(t *testing.T) {
	cnt := &counters{}
	r := newRouter(OverlayMTU, cnt)
	dst := newPipe("dst", OverlayMTU, cnt)
	host := netip.MustParseAddr("10.64.1.10")
	r.rebuild([]hostRoute{{addr: host, pipe: dst}}, nil, nil)

	oversized := ipPacket(t, netip.MustParseAddr("10.64.2.1"), host,
		make([]byte, OverlayMTU))
	r.route(oversized, nil)
	if dropped := cnt.droppedPackets.Load(); dropped == 0 {
		t.Error("an oversized inner packet was not dropped")
	}
	assertNothing(t, dst)

	// A non-IPv4 packet drops as well.
	r.route([]byte{0x60, 0, 0, 0, 0, 0, 0, 0}, nil)
	if dropped := cnt.droppedPackets.Load(); dropped < 2 {
		t.Error("a non-IPv4 packet was not dropped")
	}
	assertNothing(t, dst)
}
