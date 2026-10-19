package fabric

import (
	"net"
	"net/netip"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/fancl20/cion/pkg/modules/topology/impl/measured"
)

// gatewayAddr is the boundary's own host, the address the translated nodes'
// crossings are named for.
var gatewayAddr = netip.MustParseAddr("127.0.1.13")

// TestBoundaryTranslatesBothDirections checks the translation boundary's
// legs: an inside socket's dial to the gateway's rendezvous port reaches
// the upstream from a mapping port the boundary drew, never the socket's
// own; the upstream's reply to the drawn port returns to the inside socket
// with its own source untouched; a packet to a drawn port no mapping spells
// is dropped, the silence a real translation gives; and a forced rebind
// changes the mapping.
func TestBoundaryTranslatesBothDirections(t *testing.T) {
	f := New(t)
	inside := f.Node(insideAddr)
	upstream := f.Node(upstreamAddr)
	b := f.Translate(gatewayAddr, upstreamAddr, measured.RendezvousPort, insideAddr)
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
		t.Fatalf("the boundary's mappings = %v, want the dialing socket %v alone", socks, ii)
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
	// real translation gives — an outside socket cannot guess its way in.
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

// mappingPort reports whether a port lies in the boundary's drawn band.
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
// clock: past the idle window the mapping retires, and the socket's next
// crossing draws a fresh one, never the same port twice.
