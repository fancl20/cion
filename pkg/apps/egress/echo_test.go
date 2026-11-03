package egress

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// relayed is an echo request as the relay sent it: its destination and the
// message's fields.
type relayed struct {
	Dst     netip.Addr
	Type    header.ICMPv4Type
	Seq     uint16
	Payload string
}

func decodeRelayed(d icmpDatagram) relayed {
	msg := header.ICMPv4(d.data)
	return relayed{Dst: d.addr, Type: msg.Type(), Seq: msg.Sequence(), Payload: string(msg.Payload())}
}

// echoReply builds the reply the internet returns on the relay's socket:
// the system rewrote the identifier to the socket's own, and the sequence is
// the relay's.
func echoReply(seq uint16, payload string) []byte {
	msg := header.ICMPv4(make([]byte, header.ICMPv4MinimumSize+len(payload)))
	msg.SetType(header.ICMPv4EchoReply)
	msg.SetIdent(0x9999)
	msg.SetSequence(seq)
	copy(msg.Payload(), payload)
	return msg
}

// TestRelaysEcho checks the echo relay: each host's request leaves the
// node's socket under the next relay sequence, never entering the netstack,
// and the reply its sequence names returns to its host from the destination
// it pinged, under the host's own identifier and sequence with fresh
// checksums. A reply from another source than the request's destination is
// dropped, and an answered mapping leaves the table. The echo timeout is an
// hour away, so the mappings wait however slowly the test runs.
func TestRelaysEcho(t *testing.T) {
	l := newLab(t, func(cfg *Config) { cfg.EchoTimeout = time.Hour })
	hostA, hostB := labHost, netip.MustParseAddr("100.64.2.20")
	dst := netip.MustParseAddr("192.0.2.53")

	before := received(l.app)
	l.router.send(echoRequest(hostA, dst, 0x4242, 7, "from a"))
	l.router.send(echoRequest(hostB, dst, 0x4343, 8, "from b"))
	want := []relayed{
		{Dst: dst, Type: header.ICMPv4Echo, Seq: 0, Payload: "from a"},
		{Dst: dst, Type: header.ICMPv4Echo, Seq: 1, Payload: "from b"},
	}
	got := []relayed{decodeRelayed(l.echo.awaitSent(t)), decodeRelayed(l.echo.awaitSent(t))}
	if diff := cmp.Diff(want, got, cmpopts.EquateComparable(netip.Addr{})); diff != "" {
		t.Errorf("the relayed requests (-want +got):\n%s", diff)
	}
	if got := received(l.app); got != before {
		t.Errorf("the netstack took in %d packets, want none", got-before)
	}
	if got := echoCount(l.app); got != 2 {
		t.Errorf("echo mappings held = %d, want the two requests'", got)
	}
	if got := l.app.flowCount(); got != 0 {
		t.Errorf("flows held = %d, want none: echo mappings count apart", got)
	}

	// The second request's reply first, then the first's from a stranger
	// and from its destination: the stranger's routes nothing ahead of it.
	l.echo.replies <- icmpDatagram{data: echoReply(1, "from b"), addr: dst}
	l.echo.replies <- icmpDatagram{data: echoReply(0, "from a"), addr: netip.MustParseAddr("192.0.2.66")}
	l.echo.replies <- icmpDatagram{data: echoReply(0, "from a"), addr: dst}
	wantReplies := []icmpPacket{
		{Src: dst, Dst: hostB, Type: header.ICMPv4EchoReply, Ident: 0x4343, Seq: 8,
			Payload: "from b", Summed: true},
		{Src: dst, Dst: hostA, Type: header.ICMPv4EchoReply, Ident: 0x4242, Seq: 7,
			Payload: "from a", Summed: true},
	}
	gotReplies := []icmpPacket{
		decodeICMP(t, l.router.awaitRouted(t)),
		decodeICMP(t, l.router.awaitRouted(t)),
	}
	if diff := cmp.Diff(wantReplies, gotReplies, cmpopts.EquateComparable(netip.Addr{})); diff != "" {
		t.Errorf("the replies routed to the hosts (-want +got):\n%s", diff)
	}
	if got := echoCount(l.app); got != 0 {
		t.Errorf("echo mappings held after the replies = %d, want none", got)
	}
}

// TestEchoBoundRefuses checks the echo relay's own bound: with the echo
// table full, a further echo request drops and counts, leaving the socket
// unsent, while a TCP flow and a UDP flow still pass, the full echo table
// holding no place under the flow bound.
func TestEchoBoundRefuses(t *testing.T) {
	l := newHostLab(t, func(cfg *Config) {
		cfg.Echoes = 2
		cfg.Flows = 2
		cfg.EchoTimeout = time.Hour
	})
	dst := netip.MustParseAddr("192.0.2.53")

	for seq := range uint16(2) {
		l.router.send(echoRequest(labHost, dst, 1, seq, "held"))
		l.echo.awaitSent(t)
	}
	l.router.send(echoRequest(labHost, dst, 1, 2, "past the bound"))
	if got := l.app.cnt.droppedPackets.Load(); got != 1 {
		t.Errorf("dropped = %d after the echo request past the bound, want 1", got)
	}
	if got := len(l.echo.sent); got != 0 {
		t.Errorf("the echo relay sent %d requests past the bound, want none", got)
	}
	if got := echoCount(l.app); got != 2 {
		t.Errorf("echo mappings held = %d, want the bound's 2", got)
	}

	conn, err := dialHost(t, l.host, tcpEcho(t))
	if err != nil {
		t.Fatalf("a TCP flow at the echo bound: %v", err)
	}
	if got := roundTrip(t, conn, "tcp"); got != "tcp" {
		t.Errorf("echo = %q, want %q", got, "tcp")
	}
	if got := roundTrip(t, hostUDP(t, l.host, udpEcho(t)), "udp"); got != "udp" {
		t.Errorf("echo = %q, want %q", got, "udp")
	}
	if got := l.app.flowCount(); got != 2 {
		t.Errorf("flows held = %d, want the TCP and the UDP flow", got)
	}
	if got := l.app.cnt.droppedPackets.Load(); got != 1 {
		t.Errorf("dropped = %d after the flows, want the echo request alone", got)
	}
}

// TestEchoTimeoutExpiresMappings checks the echo timeout: an expiry before
// the timeout keeps a mapping, one past it forgets the mapping, and the
// reply arriving afterward routes nothing, while a later request's reply
// still returns. The expiry runs at synthetic times, the timeout an hour
// away, so no real elapsed time decides it.
func TestEchoTimeoutExpiresMappings(t *testing.T) {
	l := newLab(t, func(cfg *Config) { cfg.EchoTimeout = time.Hour })
	dst := netip.MustParseAddr("192.0.2.53")

	l.router.send(echoRequest(labHost, dst, 0x4242, 7, "expired"))
	l.echo.awaitSent(t)
	l.app.expireEchoes(time.Now().Add(10 * time.Minute))
	if got := echoCount(l.app); got != 1 {
		t.Fatalf("echo mappings held before the timeout = %d, want 1", got)
	}
	l.app.expireEchoes(time.Now().Add(2 * time.Hour))
	if got := echoCount(l.app); got != 0 {
		t.Errorf("echo mappings held past the timeout = %d, want none", got)
	}

	// The relay reads the replies in order, so the later request's reply
	// arriving first shows the expired one routed nothing.
	l.echo.replies <- icmpDatagram{data: echoReply(0, "expired"), addr: dst}
	l.router.send(echoRequest(labHost, dst, 0x4343, 8, "later"))
	l.echo.awaitSent(t)
	l.echo.replies <- icmpDatagram{data: echoReply(1, "later"), addr: dst}
	want := icmpPacket{
		Src: dst, Dst: labHost, Type: header.ICMPv4EchoReply, Ident: 0x4343, Seq: 8,
		Payload: "later", Summed: true,
	}
	if diff := cmp.Diff(want, decodeICMP(t, l.router.awaitRouted(t)),
		cmpopts.EquateComparable(netip.Addr{})); diff != "" {
		t.Errorf("the first reply routed (-want +got):\n%s", diff)
	}
}

// TestEchoWithoutPingSocketDrops checks the relay's degradation: where the
// system offers no ping socket, every echo request drops and counts.
func TestEchoWithoutPingSocketDrops(t *testing.T) {
	l := newLab(t, func(cfg *Config) {
		cfg.EchoSocket = func() (icmpSocket, error) { return nil, errors.New("no ping socket") }
	})

	l.router.send(echoRequest(labHost, netip.MustParseAddr("192.0.2.53"), 1, 1, "ping"))
	if got := l.app.cnt.droppedPackets.Load(); got != 1 {
		t.Errorf("dropped = %d, want the echo request", got)
	}
	if got := echoCount(l.app); got != 0 {
		t.Errorf("echo mappings held = %d, want none", got)
	}
}

// TestDropsOtherProtocols checks the egress's protocol scope: a protocol
// it carries none of drops and counts on either delivery, and so does ICMP
// toward the internet other than an echo request; none of them enters the
// netstack or leaves the relay's socket.
func TestDropsOtherProtocols(t *testing.T) {
	l := newLab(t, nil)
	l.claim(t)
	internet := netip.MustParseAddr("192.0.2.53")
	unreachable := header.ICMPv4(make([]byte, header.ICMPv4MinimumSize))
	unreachable.SetType(header.ICMPv4DstUnreachable)
	unreachable.SetChecksum(internetChecksum(unreachable))

	before := received(l.app)
	for _, pkt := range [][]byte{
		ipPacket(labHost, internet, 47, make([]byte, 8)), // GRE
		ipPacket(labHost, labOwn, 47, make([]byte, 8)),
		ipPacket(labHost, internet, header.ICMPv4ProtocolNumber, unreachable),
	} {
		if !l.router.send(pkt) {
			t.Fatalf("no delivery took %x", pkt)
		}
	}
	if got := l.app.cnt.droppedPackets.Load(); got != 3 {
		t.Errorf("dropped = %d, want 3", got)
	}
	if got := received(l.app); got != before {
		t.Errorf("the netstack took in %d packets, want none", got-before)
	}
	if got := len(l.echo.sent); got != 0 {
		t.Errorf("the echo relay sent %d requests, want none", got)
	}
}

// TestDropsLoopbackDestinations checks the egress keeps the node's loopback
// from the hosts: a TCP handshake, a UDP datagram, and an echo request
// toward a loopback address drop and count, entering neither the netstack
// nor the relay's socket.
func TestDropsLoopbackDestinations(t *testing.T) {
	l := newLab(t, nil)
	loopback := netip.MustParseAddr("127.0.0.1")
	syn := header.TCP(make([]byte, header.TCPMinimumSize))
	syn.Encode(&header.TCPFields{
		SrcPort:    4000,
		DstPort:    22,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn,
		WindowSize: 65535,
	})

	before := received(l.app)
	for _, pkt := range [][]byte{
		ipPacket(labHost, loopback, header.TCPProtocolNumber, syn),
		udpPacket(netip.AddrPortFrom(labHost, 4000), netip.AddrPortFrom(loopback, 53), "query"),
		echoRequest(labHost, loopback, 1, 1, "ping"),
	} {
		if !l.router.send(pkt) {
			t.Fatalf("no delivery took %x", pkt)
		}
	}
	if got := l.app.cnt.droppedPackets.Load(); got != 3 {
		t.Errorf("dropped = %d, want all three", got)
	}
	if got := received(l.app); got != before {
		t.Errorf("the netstack took in %d packets, want none", got-before)
	}
	if got := len(l.echo.sent); got != 0 {
		t.Errorf("the echo relay sent %d requests, want none", got)
	}
	if got := l.app.flowCount(); got != 0 {
		t.Errorf("flows held = %d, want none", got)
	}
}

// TestIPv6NeverEnters checks the egress serves IPv4 alone: an IPv6 packet
// on either delivery drops and counts, never entering the netstack.
func TestIPv6NeverEnters(t *testing.T) {
	l := newLab(t, nil)
	l.claim(t)
	ipv6 := make([]byte, header.IPv6MinimumSize+8)
	header.IPv6(ipv6).Encode(&header.IPv6Fields{
		PayloadLength:     8,
		TransportProtocol: header.UDPProtocolNumber,
		HopLimit:          64,
	})

	before := received(l.app)
	l.app.deliverDefault(ipv6)
	l.app.deliverOwn(ipv6)
	if got := l.app.cnt.droppedPackets.Load(); got != 2 {
		t.Errorf("dropped = %d, want both IPv6 packets", got)
	}
	if got := received(l.app); got != before {
		t.Errorf("the netstack took in %d packets, want none", got-before)
	}
}
