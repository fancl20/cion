package fabric

import (
	"net"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/fancl20/cion/pkg/modules/topology/impl/measured"
)

// gatewayAddr is the NAT's own host, the address its inside nodes'
// crossings are named for.
var gatewayAddr = netip.MustParseAddr("127.0.1.13")

// TestNATTranslatesBothDirections checks the NAT's
// legs: an inside socket's dial to the gateway's rendezvous port reaches
// the upstream from a mapping port the NAT drew, never the socket's
// own; the upstream's reply to the drawn port returns to the inside socket
// with its own source untouched; a packet to a drawn port no mapping spells
// is dropped, the silence a real NAT gives; and a forced rebind
// changes the mapping.
func TestNATTranslatesBothDirections(t *testing.T) {
	f := New(t)
	inside := f.Node(insideAddr)
	upstream := f.Node(upstreamAddr)
	b := f.ForwardingNAT(gatewayAddr, upstreamAddr, measured.RendezvousPort, insideAddr)
	ci, ii := listen(t, inside)
	gatewayRendezvous := netip.AddrPortFrom(gatewayAddr, measured.RendezvousPort)

	// The dial crosses: the upstream answers on its rendezvous socket.
	upstreamAccept, err := upstream.Sockets().NewUDP(&net.UDPAddr{
		IP: upstreamAddr.AsSlice(), Port: measured.RendezvousPort,
	}, netip.AddrPort{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = upstreamAccept.Close() }()

	send(t, ci, gatewayRendezvous, "the first contact")
	got, from := recv(t, upstreamAccept, testWait)
	if got != "the first contact" {
		t.Fatalf("the upstream's rendezvous socket received %q, want the dial", got)
	}
	if from.Addr() != gatewayAddr || !mappingPort(from.Port()) {
		t.Fatalf("the dial arrived from %v, want the gateway under a drawn port", from)
	}
	if socks := b.Mappings(); len(socks) != 1 || socks[0] != ii {
		t.Fatalf("the NAT's mappings = %v, want the dialing socket %v alone", socks, ii)
	}

	// The reply returns to the inside socket, its source untouched — the
	// upstream's rendezvous socket the dial reached.
	send(t, upstreamAccept, from, "the reply")
	want := netip.AddrPortFrom(upstreamAddr, measured.RendezvousPort)
	if got, src := recv(t, ci, testWait); got != "the reply" || src != want {
		t.Fatalf("the inside socket received %q from %v, want the reply from %v",
			got, src, want)
	}

	// A packet to a band port no mapping spells is dropped, the silence a
	// real NAT gives — an outside socket cannot guess its way in.
	stranger, err := upstream.Sockets().NewUDP(&net.UDPAddr{
		IP: upstreamAddr.AsSlice(), Port: 0,
	}, netip.AddrPort{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stranger.Close() }()
	undrawn := netip.AddrPortFrom(gatewayAddr, mappingPortBase+mappingPortSpan-1)
	send(t, stranger, undrawn, "the guess")
	if got, _ := recv(t, ci, 5*testWait); got != "" {
		t.Fatalf("an unmatched inbound datagram reached the inside socket as %q", got)
	}

	// A forced rebind changes the mapping: the next crossing leaves from a
	// different drawn port.
	first := from
	b.Rebind()
	send(t, ci, gatewayRendezvous, "the redial")
	got, from = recv(t, upstreamAccept, testWait)
	if got != "the redial" {
		t.Fatalf("the upstream's rendezvous socket received %q, want the redial", got)
	}
	if !mappingPort(from.Port()) || from == first {
		t.Fatalf("the redial arrived from %v, want a fresh drawn port after %v", from, first)
	}
}

// TestRewriteRenewsChecksums checks the checksum renewal directly: the
// rewritten datagram carries a valid IP checksum and a valid UDP checksum
// over its new addresses and ports — the receiver's acceptance of a
// translated datagram depends on nothing less.
func TestRewriteRenewsChecksums(t *testing.T) {
	src := netip.MustParseAddr("192.0.2.1")
	dst := netip.MustParseAddr("192.0.2.2")
	newSrc := netip.MustParseAddr("198.51.100.1")
	newDst := netip.MustParseAddr("198.51.100.2")
	payload := []byte("the translated payload")
	pkt := udpPacket(src, 1111, dst, 2222, payload)

	out := rewriteDatagram(pkt, newSrc, 3333, newDst, 4444)
	ip := header.IPv4(out)
	udp := header.UDP(out[ip.HeaderLength():])
	if !ip.IsChecksumValid() {
		t.Error("the rewritten datagram's IP checksum is invalid")
	}
	if got := ip.SourceAddress(); got != tcpipAddr(newSrc) {
		t.Errorf("the rewritten source = %v, want %v", got, newSrc)
	}
	if got := ip.DestinationAddress(); got != tcpipAddr(newDst) {
		t.Errorf("the rewritten destination = %v, want %v", got, newDst)
	}
	if udp.SourcePort() != 3333 || udp.DestinationPort() != 4444 {
		t.Errorf("the rewritten ports = %d→%d, want 3333→4444",
			udp.SourcePort(), udp.DestinationPort())
	}
	if !udp.IsChecksumValid(ip.SourceAddress(), ip.DestinationAddress(),
		checksum.Checksum(payload, 0)) {
		t.Error("the rewritten datagram's UDP checksum is invalid")
	}
}

// mappingPort reports whether a port lies in the NAT's drawn band.
func mappingPort(port uint16) bool {
	return port >= mappingPortBase && port < mappingPortBase+mappingPortSpan
}

// udpPacket builds one UDP datagram the proofs rewrite; the checksums are
// computed the way the stack computes them.
func udpPacket(src netip.Addr, srcPort uint16, dst netip.Addr, dstPort uint16, payload []byte) []byte {
	pkt := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize+len(payload))
	ip := header.IPv4(pkt)
	ip.Encode(&header.IPv4Fields{
		TOS:         0,
		TotalLength: uint16(len(pkt)),
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     tcpipAddr(src),
		DstAddr:     tcpipAddr(dst),
	})
	udp := header.UDP(pkt[header.IPv4MinimumSize:])
	udp.Encode(&header.UDPFields{
		SrcPort: srcPort,
		DstPort: dstPort,
		Length:  uint16(header.UDPMinimumSize + len(payload)),
	})
	copy(pkt[header.IPv4MinimumSize+header.UDPMinimumSize:], payload)
	xsum := udp.CalculateChecksum(checksum.Checksum(payload,
		header.PseudoHeaderChecksum(header.UDPProtocolNumber,
			ip.SourceAddress(), ip.DestinationAddress(), udp.Length())))
	if xsum != 0xffff {
		xsum = ^xsum
	}
	udp.SetChecksum(xsum)
	return pkt
}

// tcpipAddr reads a plain address as a header address.
func tcpipAddr(ip netip.Addr) tcpip.Address {
	return tcpip.AddrFrom4(ip.As4())
}

// TestMappingExpiresAndRedraws checks the mapping's life on the fabric's
// clock: past the idle window the mapping retires, a reply to it falls, and
// the socket's next crossing draws a fresh one, never the same port twice.
func TestMappingExpiresAndRedraws(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := New(t, UDPOnly())
		inside, upstream := f.Node(insideAddr), f.Node(upstreamAddr)
		b := f.NAT(FullCone, gatewayAddr, insideAddr)
		ci, _ := listen(t, inside)
		cu, ua := listen(t, upstream)

		send(t, ci, ua, "the first crossing")
		_, first := recv(t, cu, testWait)
		time.Sleep(MappingTimeout)
		if socks := b.Mappings(); len(socks) != 0 {
			t.Fatalf("the mappings %v outlived the idle window", socks)
		}
		send(t, cu, first, "the late reply")
		if got, _ := recv(t, ci, dropWait); got != "" {
			t.Fatalf("a reply to a retired mapping reached the inside socket as %q", got)
		}
		send(t, ci, ua, "the next crossing")
		if _, next := recv(t, cu, testWait); next == first || !mappingPort(next.Port()) {
			t.Errorf("the next crossing left from %v, want a fresh drawn port after %v", next, first)
		}
	})
}

// dropWait is how long the proofs on virtual time read for a datagram that
// should fall: well inside the mapping's idle window, so the read itself
// retires nothing.
const dropWait = MappingTimeout / 4

// The second host behind a NAT the chained proofs draw, and its gateway.
var (
	peerAddr    = netip.MustParseAddr("127.0.1.15")
	peerGateway = netip.MustParseAddr("127.0.1.16")
)

// TestNATBehaviors checks the NATs' behaviors: an inside socket
// leaves through one gateway port for every destination under
// endpoint-independent mapping and through a port per destination under
// endpoint-dependent mapping; a reply from a destination the socket sent to
// returns under every behavior; an outside socket it never sent to gets in
// only under endpoint-independent filtering.
func TestNATBehaviors(t *testing.T) {
	for _, tc := range []struct {
		name     string
		behavior Behavior
		onePort  bool
		open     bool
	}{
		{"full cone", FullCone, true, true},
		{"port-restricted", PortRestricted, true, false},
		{"symmetric", Symmetric, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := New(t, UDPOnly())
				inside, upstream, stranger := f.Node(insideAddr), f.Node(upstreamAddr), f.Node(strangerAddr)
				f.NAT(tc.behavior, gatewayAddr, insideAddr)
				ci, _ := listen(t, inside)
				cu, ua := listen(t, upstream)
				cs, sa := listen(t, stranger)
				unsolicited, _ := listen(t, stranger)

				send(t, ci, ua, "to the upstream")
				_, viaUpstream := recv(t, cu, testWait)
				send(t, ci, sa, "to the stranger")
				_, viaStranger := recv(t, cs, testWait)
				if viaUpstream.Addr() != gatewayAddr || viaStranger.Addr() != gatewayAddr {
					t.Fatalf("the crossings left from %v and %v, want the gateway %v",
						viaUpstream, viaStranger, gatewayAddr)
				}
				if onePort := viaUpstream == viaStranger; onePort != tc.onePort {
					t.Errorf("the socket left through %v and %v: one port %v, want %v",
						viaUpstream, viaStranger, onePort, tc.onePort)
				}
				send(t, cu, viaUpstream, "the reply")
				if got, from := recv(t, ci, testWait); got != "the reply" || from != ua {
					t.Errorf("the inside socket received %q from %v, want the reply from %v", got, from, ua)
				}
				send(t, unsolicited, viaUpstream, "the unsolicited datagram")
				if got, _ := recv(t, ci, dropWait); (got != "") != tc.open {
					t.Errorf("an unsolicited datagram got in: %v, want %v", got != "", tc.open)
				}
			})
		})
	}
}

// TestNATsChain checks a crossing between two hosts behind NATs: the
// datagram leaves through its source's gateway and enters through its
// destination's, as through two NATs — the exchange hole punching
// rides. Behind port-restricted NATs, a side's first datagram toward
// the other's mapping falls until the other has sent toward its own, and
// then both directions pass.
func TestNATsChain(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := New(t, UDPOnly())
		a, b, server := f.Node(insideAddr), f.Node(peerAddr), f.Node(upstreamAddr)
		f.NAT(PortRestricted, gatewayAddr, insideAddr)
		f.NAT(PortRestricted, peerGateway, peerAddr)
		ca, _ := listen(t, a)
		cb, _ := listen(t, b)
		cs, sa := listen(t, server)

		// Each side's mapping, as the third party observes it.
		send(t, ca, sa, "from a")
		_, mapA := recv(t, cs, testWait)
		send(t, cb, sa, "from b")
		_, mapB := recv(t, cs, testWait)

		send(t, ca, mapB, "a's first")
		if got, _ := recv(t, cb, dropWait); got != "" {
			t.Fatalf("a's first datagram passed b's NAT as %q before b sent toward a", got)
		}
		send(t, cb, mapA, "b's")
		if got, from := recv(t, ca, testWait); got != "b's" || from != mapB {
			t.Fatalf("a received %q from %v, want b's datagram from b's mapping %v", got, from, mapB)
		}
		send(t, ca, mapB, "a's second")
		if got, from := recv(t, cb, testWait); got != "a's second" || from != mapA {
			t.Fatalf("b received %q from %v, want a's datagram from a's mapping %v", got, from, mapA)
		}
	})
}

// routerInside is the router's inside host the router proofs draw.
var routerInside = netip.MustParseAddr("127.0.1.17")

// TestRouterSendsFromEachSide checks the stack on a NAT's router: its
// ephemeral ports lie above the mapping band, and its routes answer its
// inside host toward the NAT's inside hosts and the gateway toward every
// other host; a wildcard-bound socket on it, spelled 0.0.0.0, reaches an
// inside host from the inside host, crossing nothing, and an outside host
// from the gateway under its own port, untranslated; the outside host's
// reply to the gateway and the inside host's datagram to either of the
// router's hosts reach it, as a gateway-bound socket's datagram reaches the
// inside host. The NAT keeps the gateway's mapping band: an outside
// datagram to an undrawn port of it falls, and an inside host's crossing
// still leaves translated. A second draw of the gateway names the router's
// stack.
func TestRouterSendsFromEachSide(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := New(t, UDPOnly())
		inside, outside := f.Node(insideAddr), f.Node(upstreamAddr)
		b := f.NAT(PortRestricted, gatewayAddr, insideAddr, routerInside)
		router := b.Router(routerInside)
		if again := f.Node(gatewayAddr); again != router {
			t.Fatal("a second draw of the gateway named another stack than the router's")
		}
		if first, _ := router.stack.PortRange(); first < mappingPortBase+mappingPortSpan {
			t.Errorf("the router's ephemeral ports start at %d, inside or below the mapping band", first)
		}
		for dst, want := range map[netip.Addr]netip.Addr{
			insideAddr: routerInside, routerInside: routerInside,
			upstreamAddr: gatewayAddr, gatewayAddr: gatewayAddr,
		} {
			if got, err := router.Sockets().Source(dst); err != nil || got != want {
				t.Errorf("the router's route toward %v sends from %v, %v; want %v", dst, got, err, want)
			}
		}

		cr, err := router.Sockets().NewUDP(&net.UDPAddr{IP: net.IPv4zero}, netip.AddrPort{})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = cr.Close() }()
		bound := cr.LocalAddr().AddrPort()
		if bound.Addr() != netip.IPv4Unspecified() {
			t.Fatalf("the router's wildcard socket is bound at %v, want 0.0.0.0", bound)
		}
		ci, ia := listen(t, inside)
		co, oa := listen(t, outside)

		send(t, cr, ia, "to the inside")
		if got, from := recv(t, ci, testWait); got != "to the inside" ||
			from != netip.AddrPortFrom(routerInside, bound.Port()) {
			t.Errorf("the inside host received %q from %v, want the datagram from the router's inside host",
				got, from)
		}
		send(t, cr, oa, "to the outside")
		atGateway := netip.AddrPortFrom(gatewayAddr, bound.Port())
		if got, from := recv(t, co, testWait); got != "to the outside" || from != atGateway {
			t.Errorf("the outside host received %q from %v, want the datagram from %v", got, from, atGateway)
		}
		send(t, co, atGateway, "the outside reply")
		if got, from := recv(t, cr, testWait); got != "the outside reply" || from != oa {
			t.Errorf("the router received %q from %v, want the outside reply from %v", got, from, oa)
		}
		for _, to := range []netip.AddrPort{atGateway, netip.AddrPortFrom(routerInside, bound.Port())} {
			send(t, ci, to, "the inside datagram")
			if got, from := recv(t, cr, testWait); got != "the inside datagram" || from != ia {
				t.Errorf("the router received %q from %v at %v, want the inside datagram from %v",
					got, from, to, ia)
			}
		}
		cg, err := router.Sockets().NewUDP(&net.UDPAddr{IP: gatewayAddr.AsSlice()}, netip.AddrPort{})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = cg.Close() }()
		send(t, cg, ia, "from the gateway")
		if got, from := recv(t, ci, testWait); got != "from the gateway" || from != cg.LocalAddr().AddrPort() {
			t.Errorf("the inside host received %q from %v, want the datagram from the router's gateway socket",
				got, from)
		}

		undrawn := netip.AddrPortFrom(gatewayAddr, mappingPortBase+mappingPortSpan-1)
		send(t, co, undrawn, "the guess")
		if got, _ := recv(t, cr, dropWait); got != "" {
			t.Errorf("a datagram to the mapping band reached the router as %q", got)
		}
		send(t, ci, oa, "the crossing")
		if _, from := recv(t, co, testWait); from.Addr() != gatewayAddr || !mappingPort(from.Port()) {
			t.Errorf("the inside host's crossing arrived from %v, want the gateway under a drawn port", from)
		}
	})
}
