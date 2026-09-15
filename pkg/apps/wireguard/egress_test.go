package wireguard

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	netipv4 "gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// newHostStack builds the test's host side: a netstack whose outbound
// packets the test feeds to the egress under test and whose inbound the
// egress's replies feed back — a host's whole overlay leg without the
// tunnels.
func newHostStack(t *testing.T, hostAddr netip.Addr, e *egress) *stack.Stack {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			// The "internet" the tests serve rides the loopback range; the
			// host side accepts its replies the way the egress side does.
			netipv4.NewProtocolWithOptions(netipv4.Options{
				AllowExternalLoopbackTraffic: true,
			}),
		},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	link := channel.New(512, OverlayMTU, "")
	if err := s.CreateNIC(1, link); err != nil {
		t.Fatal(err)
	}
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol: netipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   netipToAddress(hostAddr),
			PrefixLen: 24,
		},
	}, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	defaultSubnet, err := tcpip.NewSubnet(
		netipToAddress(netip.MustParseAddr("0.0.0.0")),
		tcpip.MaskFromBytes([]byte{0, 0, 0, 0}))
	if err != nil {
		t.Fatal(err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: defaultSubnet, NIC: 1}})
	// Host → egress: every packet the host stack writes enters the exit.
	go func() {
		for {
			pkt := link.ReadContext(context.Background())
			if pkt == nil {
				return
			}
			data := stack.BufferSince(pkt.LinkHeader())
			e.Inbound(bytes.Clone(data.Flatten()))
			pkt.DecRef()
		}
	}()
	// Egress → host: every reply routes back into the host stack.
	e.setRouter(func(pkt []byte) {
		link.InjectInbound(netipv4.ProtocolNumber,
			stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(pkt),
			}))
	})
	return s
}

// newTestEgress builds an exit with a fake echo socket and the given idle
// bound, serving it.
func newTestEgress(t *testing.T, idle time.Duration) (*egress, *fakeICMP) {
	t.Helper()
	socket := &fakeICMP{sent: make(chan fakeICMPSend, 16)}
	e, err := newEgress(egressConfig{
		OverlayAddr:   netip.MustParseAddr("10.64.1.1"),
		OverlayPrefix: netip.MustParsePrefix("10.64.1.0/24"),
		MTU:           OverlayMTU,
		Cnt:           &counters{},
		EchoSocket:    socket,
		Idle:          idle,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		e.link.Close()
		socket.Close() //nolint:errcheck
	})
	go e.run(ctx)
	return e, socket
}

// TestEgressSplicesTCP checks the TCP leg end to end: a host's flow — whose
// handshake completes at the exit, not the destination — splices to one
// outbound connection, and bytes flow both legs.
func TestEgressSplicesTCP(t *testing.T) {
	e, _ := newTestEgress(t, 0)

	// The "internet": a loopback echo service.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn) //nolint:errcheck
			}()
		}
	}()
	internet := listener.Addr().(*net.TCPAddr).AddrPort()

	host := newHostStack(t, netip.MustParseAddr("10.64.1.10"), e)
	conn, err := gonet.DialTCP(host, tcpip.FullAddress{
		NIC:  1,
		Addr: netipToAddress(internet.Addr()),
		Port: internet.Port(),
	}, netipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("the host's handshake did not complete at the exit: %v", err)
	}
	defer conn.Close()

	msg := []byte("through the exit")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("the echoed reply did not return through the exit: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Errorf("echo = %q, want %q", got, msg)
	}
	if got := e.flowCount(); got != 1 {
		t.Errorf("flows held = %d, want 1", got)
	}
}

// TestEgressMapsUDP checks the UDP leg: a flow maps to one outbound socket
// with the addresses rewritten, and the reply returns to the host.
func TestEgressMapsUDP(t *testing.T) {
	e, _ := newTestEgress(t, 0)

	// The "internet": a loopback UDP echo service.
	osConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer osConn.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := osConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			osConn.WriteToUDP(buf[:n], from) //nolint:errcheck
		}
	}()
	internet := osConn.LocalAddr().(*net.UDPAddr).AddrPort()

	host := newHostStack(t, netip.MustParseAddr("10.64.1.10"), e)
	udpConn, err := gonet.DialUDP(host,
		&tcpip.FullAddress{NIC: 1, Addr: netipToAddress(netip.MustParseAddr("10.64.1.10"))},
		&tcpip.FullAddress{NIC: 1, Addr: netipToAddress(internet.Addr()), Port: internet.Port()},
		netipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()

	msg := []byte("udp through the exit")
	if _, err := udpConn.Write(msg); err != nil {
		t.Fatal(err)
	}
	if err := udpConn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(udpConn, got); err != nil {
		t.Fatalf("the UDP reply did not return through the exit: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Errorf("echo = %q, want %q", got, msg)
	}
}

// fakeICMP captures the echo relay's sends.
type fakeICMP struct {
	sent chan fakeICMPSend
}

type fakeICMPSend struct {
	data []byte
	dst  netip.Addr
}

func (f *fakeICMP) WriteTo(b []byte, dst netip.Addr) error {
	out := make([]byte, len(b))
	copy(out, b)
	select {
	case f.sent <- fakeICMPSend{data: out, dst: dst}:
	default:
	}
	return nil
}

func (f *fakeICMP) ReadFrom([]byte) (int, netip.Addr, error) {
	// The tests drive replies through echoReplyPacket directly; the read
	// loop idles until closed.
	select {}
}

func (f *fakeICMP) Close() error { return nil }

// TestEgressRelaysEcho checks the echo relay: a request is re-sent with a
// relay sequence number, and the reply is rewritten to the host's own
// identifier and address with a fresh checksum.
func TestEgressRelaysEcho(t *testing.T) {
	e, socket := newTestEgress(t, 0)

	host := netip.MustParseAddr("10.64.1.10")
	dst := netip.MustParseAddr("192.0.2.53")

	// A host's echo request: identifier 0x4242, sequence 7, payload "ping".
	payload := []byte("ping")
	pkt := make([]byte, header.IPv4MinimumSize+header.ICMPv4MinimumSize+len(payload))
	ipHdr := header.IPv4(pkt)
	ipHdr.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(pkt)),
		TTL:         64,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     netipToAddress(host),
		DstAddr:     netipToAddress(dst),
	})
	icmpHdr := header.ICMPv4(ipHdr.Payload())
	icmpHdr.SetType(header.ICMPv4Echo)
	icmpHdr.SetIdent(0x4242)
	icmpHdr.SetSequence(7)
	copy(icmpHdr.Payload(), payload)

	e.echo.request(pkt, nil)

	var relaySend fakeICMPSend
	select {
	case relaySend = <-socket.sent:
	case <-time.After(2 * time.Second):
		t.Fatal("the echo relay never sent the request")
	}
	if relaySend.dst != dst {
		t.Errorf("relay sent to %s, want %s", relaySend.dst, dst)
	}
	relay := header.ICMPv4(relaySend.data)
	if relay.Type() != header.ICMPv4Echo {
		t.Errorf("relay type = %d, want echo request", relay.Type())
	}
	if relay.Sequence() != 0 {
		t.Errorf("first relay sequence = %d, want 0", relay.Sequence())
	}
	if !bytes.Equal(relay.Payload(), payload) {
		t.Errorf("relay payload = %q, want %q", relay.Payload(), payload)
	}

	// The rewritten reply the internet's answer becomes: from the
	// destination the host named, to the host, identifier and sequence
	// restored.
	got := echoReplyPacket(dst, echoFlow{host: host, id: 0x4242, seq: 7},
		relay.Payload())
	gotIP := header.IPv4(got)
	if addressToNetip(gotIP.SourceAddress()) != dst {
		t.Errorf("reply source = %s, want %s",
			addressToNetip(gotIP.SourceAddress()), dst)
	}
	if addressToNetip(gotIP.DestinationAddress()) != host {
		t.Errorf("reply destination = %s, want %s",
			addressToNetip(gotIP.DestinationAddress()), host)
	}
	if addressToNetip(gotIP.SourceAddress()) != dst || gotIP.TransportProtocol() != header.ICMPv4ProtocolNumber {
		t.Fatalf("reply header = %v", gotIP)
	}
	gotICMP := header.ICMPv4(gotIP.Payload())
	if gotICMP.Type() != header.ICMPv4EchoReply {
		t.Errorf("reply type = %d, want echo reply", gotICMP.Type())
	}
	if gotICMP.Ident() != 0x4242 || gotICMP.Sequence() != 7 {
		t.Errorf("reply id/seq = %d/%d, want 0x4242/7",
			gotICMP.Ident(), gotICMP.Sequence())
	}
	if !bytes.Equal(gotICMP.Payload(), payload) {
		t.Errorf("reply payload = %q, want %q", gotICMP.Payload(), payload)
	}
	// A correct ones-complement checksum sums to zero over the header it
	// protects.
	if csum := internetChecksum(gotIP.Payload()); csum != 0 {
		t.Errorf("reply ICMP checksum = %#x, want 0", csum)
	}
	if csum := internetChecksum(got[:header.IPv4MinimumSize]); csum != 0 {
		t.Errorf("reply IP checksum = %#x, want 0", csum)
	}
}

// TestEgressDropsOtherProtocols checks the exit's protocol scope: a
// non-TCP/UDP/echo-ICMP packet entering an exit is dropped.
func TestEgressDropsOtherProtocols(t *testing.T) {
	e, _ := newTestEgress(t, 0)
	var routed int
	e.setRouter(func([]byte) { routed++ })

	host := netip.MustParseAddr("10.64.1.10")
	dst := netip.MustParseAddr("192.0.2.53")
	pkt := make([]byte, header.IPv4MinimumSize+8)
	ipHdr := header.IPv4(pkt)
	ipHdr.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(pkt)),
		TTL:         64,
		Protocol:    47, // GRE
		SrcAddr:     netipToAddress(host),
		DstAddr:     netipToAddress(dst),
	})
	before := e.cnt.egressDroppedPackets.Load()
	e.Inbound(pkt)
	if dropped := e.cnt.egressDroppedPackets.Load(); dropped != before+1 {
		t.Errorf("dropped counter went %d → %d, want one more drop", before, dropped)
	}
	if routed != 0 {
		t.Error("a dropped protocol's packet was routed")
	}
}

// TestEgressExpiresIdleFlows checks the idle bound: silent flows close and
// leave the table.
func TestEgressExpiresIdleFlows(t *testing.T) {
	e, _ := newTestEgress(t, 100*time.Millisecond)

	osConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer osConn.Close()
	internet := osConn.LocalAddr().(*net.UDPAddr).AddrPort()

	host := newHostStack(t, netip.MustParseAddr("10.64.1.10"), e)
	udpConn, err := gonet.DialUDP(host,
		&tcpip.FullAddress{NIC: 1, Addr: netipToAddress(netip.MustParseAddr("10.64.1.10"))},
		&tcpip.FullAddress{NIC: 1, Addr: netipToAddress(internet.Addr()), Port: internet.Port()},
		netipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()
	if _, err := udpConn.Write([]byte("kick")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for e.flowCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := e.flowCount(); got != 1 {
		t.Fatalf("flows held = %d, want 1", got)
	}
	e.expireIdle(time.Now().Add(time.Second))
	if got := e.flowCount(); got != 0 {
		t.Errorf("flows held after the idle bound = %d, want 0", got)
	}
}
