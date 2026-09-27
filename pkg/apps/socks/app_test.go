package socks

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/fancl20/cion/internal/socksclient"
	"github.com/fancl20/cion/pkg/apps/wireguard"
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

// The lab's addresses: the service's own slice, its first address the
// service answers on, and the client the slice's second address holds.
var (
	labSubnet = netip.MustParsePrefix("100.64.1.0/24")
	labOwn    = netip.MustParseAddr("100.64.1.1")
	labClient = netip.MustParseAddr("100.64.1.10")
)

// labRouter is the borrowed router's in-process stand-in: Route feeds the
// service's replies into the client stack, and Deliver records the inbound
// path the service installs.
type labRouter struct {
	inject func(pkt []byte)

	mtx     sync.RWMutex
	deliver func(pkt []byte)
}

func (r *labRouter) Route(pkt []byte) { r.inject(pkt) }

func (r *labRouter) Deliver(addr netip.Addr, deliver func(pkt []byte)) func() {
	r.mtx.Lock()
	defer r.mtx.Unlock()
	r.deliver = deliver
	return func() {
		r.mtx.Lock()
		defer r.mtx.Unlock()
		r.deliver = nil
	}
}

func (r *labRouter) deliverNow(pkt []byte) {
	r.mtx.RLock()
	defer r.mtx.RUnlock()
	if r.deliver != nil {
		r.deliver(pkt)
	}
}

// newLab assembles the service beside its client double — the egress
// suite's in-process lab: a client netstack whose outbound packets the lab
// feeds to the service's inbound path and whose inbound the service's
// replies feed back, the whole tailnet leg without the tunnels.
func newLab(t *testing.T, mutate func(*Config)) (*App, *stack.Stack) {
	t.Helper()
	client := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			netipv4.NewProtocolWithOptions(netipv4.Options{}),
		},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	link := channel.New(512, uint32(wireguard.OverlayMTU), "")
	if err := client.CreateNIC(1, link); err != nil {
		t.Fatal(err)
	}
	if err := client.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol: netipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   netipToAddress(labClient),
			PrefixLen: 24,
		},
	}, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	defaultSubnet, err := tcpip.NewSubnet(
		tcpip.AddrFrom4([4]byte{}), tcpip.MaskFromBytes([]byte{0, 0, 0, 0}))
	if err != nil {
		t.Fatal(err)
	}
	client.SetRouteTable([]tcpip.Route{{Destination: defaultSubnet, NIC: 1}})
	router := &labRouter{inject: func(pkt []byte) {
		link.InjectInbound(netipv4.ProtocolNumber,
			stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(pkt),
			}))
	}}
	cfg := Config{Subnet: labSubnet, Router: router}
	if mutate != nil {
		mutate(&cfg)
	}
	app, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Client → service: every packet the client stack writes enters the
	// service's inbound path.
	go func() {
		for {
			pkt := link.ReadContext(context.Background())
			if pkt == nil {
				return
			}
			data := stack.BufferSince(pkt.LinkHeader())
			router.deliverNow(bytes.Clone(data.Flatten()))
			pkt.DecRef()
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = app.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		app.Close()
	})
	return app, client
}

// dialClient dials the service's listener from the client stack.
func dialClient(t *testing.T, client *stack.Stack) net.Conn {
	t.Helper()
	conn, err := gonet.DialTCP(client, tcpip.FullAddress{
		NIC:  1,
		Addr: netipToAddress(labOwn),
		Port: Port,
	}, netipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("the client's dial of the service: %v", err)
	}
	return conn
}

// tcpEcho stands a loopback echo service for the internet.
func tcpEcho(t *testing.T) netip.AddrPort {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return listener.Addr().(*net.TCPAddr).AddrPort()
}

// udpEcho stands a loopback UDP echo service for the internet.
func udpEcho(t *testing.T) netip.AddrPort {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(buf[:n], from)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

// refusedTCPAddr reserves and releases a TCP port, so connecting to it
// refuses.
func refusedTCPAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()
	return addr
}

// clientUDP binds the client's UDP leg on the client stack.
func clientUDP(t *testing.T, client *stack.Stack) net.PacketConn {
	t.Helper()
	conn, err := gonet.DialUDP(client, &tcpip.FullAddress{
		NIC: 1, Addr: netipToAddress(labClient), Port: 0,
	}, nil, netipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// TestConnectSplices checks the CONNECT leg end to end: the client's
// connection to the service splices to one outbound connection of the
// node's own, and bytes flow both directions.
func TestConnectSplices(t *testing.T) {
	app, client := newLab(t, nil)
	internet := tcpEcho(t)

	conn, err := socksclient.Connect(dialClient(t, client), internet.String())
	if err != nil {
		t.Fatalf("CONNECT: %v", err)
	}
	defer func() { _ = conn.Close() }()

	msg := []byte("through the exit")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("the echoed reply did not return through the service: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Errorf("echo = %q, want %q", got, msg)
	}
	if got := app.flowCount(); got != 1 {
		t.Errorf("flows held = %d, want 1", got)
	}
}

// TestConnectRefusedIsTold checks a destination's refusal is answered as a
// SOCKS error on the client's own leg — told, not implied.
func TestConnectRefusedIsTold(t *testing.T) {
	_, client := newLab(t, nil)

	_, err := socksclient.Connect(dialClient(t, client), refusedTCPAddr(t))
	var refused *socksclient.Refused
	if !errors.As(err, &refused) {
		t.Fatalf("CONNECT to a refusing destination = %v, want the told refusal", err)
	}
	if refused.Rep != repConnectionRefused {
		t.Errorf("the reply = %#x, want connection refused %#x",
			refused.Rep, repConnectionRefused)
	}
}

// TestMethodNegotiationRefused checks the dialect's admission: method none
// is the one offer, and a client offering anything but none is refused.
func TestMethodNegotiationRefused(t *testing.T) {
	_, client := newLab(t, nil)

	conn := dialClient(t, client)
	defer func() { _ = conn.Close() }()
	// Username/password alone, no method none among the offers.
	if _, err := conn.Write([]byte{version, 1, 0x02}); err != nil {
		t.Fatal(err)
	}
	var reply [2]byte
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		t.Fatalf("reading the method reply: %v", err)
	}
	if reply[0] != version || reply[1] != methodNoAcceptable {
		t.Errorf("the method reply = %x, want no acceptable method", reply)
	}
}

// TestBindRefused checks the one command the dialect refuses by name: BIND
// is told unsupported on its own leg.
func TestBindRefused(t *testing.T) {
	_, client := newLab(t, nil)

	conn := dialClient(t, client)
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte{version, 1, methodNone}); err != nil {
		t.Fatal(err)
	}
	var method [2]byte
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(conn, method[:]); err != nil {
		t.Fatalf("reading the method reply: %v", err)
	}
	// BIND for the loopback echo, whatever its address: the command itself
	// is the refusal.
	if _, err := conn.Write([]byte{
		version, cmdBind, 0, atypIPv4, 127, 0, 0, 1, 0, 80,
	}); err != nil {
		t.Fatal(err)
	}
	var reply [10]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		t.Fatalf("reading the BIND reply: %v", err)
	}
	if reply[1] != repCommandNotSupported {
		t.Errorf("the BIND reply = %#x, want command not supported %#x",
			reply[1], repCommandNotSupported)
	}
}

// TestAssociateRelaysUDP checks the UDP leg: the reply carries the exit's
// true tailnet address and the relay's port, a datagram relays to its
// destination, and the reply returns with the header rewritten to name its
// source.
func TestAssociateRelaysUDP(t *testing.T) {
	app, client := newLab(t, nil)
	internet := udpEcho(t)

	conn := dialClient(t, client)
	defer func() { _ = conn.Close() }()
	pc := clientUDP(t, client)
	relay, err := socksclient.Associate(conn, pc)
	if err != nil {
		t.Fatalf("UDP ASSOCIATE: %v", err)
	}
	if relay.Addr.Addr() != labOwn {
		t.Errorf("the reply's address = %s, want the exit's own %s",
			relay.Addr.Addr(), labOwn)
	}
	if relay.Addr.Port() == 0 || relay.Addr.Port() == Port {
		t.Errorf("the reply's relay port = %d, want an allocated one", relay.Addr.Port())
	}

	msg := []byte("udp through the exit")
	if err := relay.WriteTo(msg, internet); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	_ = pc.(*gonet.UDPConn).SetReadDeadline(time.Now().Add(10 * time.Second))
	n, from, err := relay.ReadFrom(got)
	if err != nil {
		t.Fatalf("the UDP reply did not return through the service: %v", err)
	}
	if !bytes.Equal(got[:n], msg) {
		t.Errorf("echo = %q, want %q", got[:n], msg)
	}
	if from != internet {
		t.Errorf("the reply's header named %s, want the destination %s",
			from, internet)
	}
	// The association and its one outbound socket: two flows.
	if got := app.flowCount(); got != 2 {
		t.Errorf("flows held = %d, want 2", got)
	}
}

// TestFragmentedDatagramRefused checks the datagram dialect: a datagram
// with FRAG set is refused — dropped, the UDP leg having no error channel —
// and never reaches its destination.
func TestFragmentedDatagramRefused(t *testing.T) {
	app, client := newLab(t, nil)
	internet := udpEcho(t)

	conn := dialClient(t, client)
	defer func() { _ = conn.Close() }()
	pc := clientUDP(t, client)
	relay, err := socksclient.Associate(conn, pc)
	if err != nil {
		t.Fatalf("UDP ASSOCIATE: %v", err)
	}

	// The fragmented datagram, hand-framed: RSV FRAG(1) ATYP DST PORT.
	frag := []byte{0, 0, 1, atypIPv4}
	ip := internet.Addr().As4()
	frag = append(frag, ip[0], ip[1], ip[2], ip[3])
	frag = binary.BigEndian.AppendUint16(frag, internet.Port())
	frag = append(frag, "fragmented"...)
	if _, err := pc.WriteTo(frag, net.UDPAddrFromAddrPort(relay.Addr)); err != nil {
		t.Fatal(err)
	}

	// The refusal is a drop: nothing relays, the counter tells it, and no
	// outbound socket appears.
	time.Sleep(100 * time.Millisecond)
	if dropped := app.cnt.droppedPackets.Load(); dropped != 1 {
		t.Errorf("dropped = %d after the fragmented datagram, want 1", dropped)
	}
	if got := app.flowCount(); got != 1 {
		t.Errorf("flows held = %d, want the association alone", got)
	}
}

// TestRelayAnswersArrival checks the reply path's address: a datagram
// returns to the source the client's datagrams arrived from, not the
// address its TCP request named — a second source sending receives the
// reply there.
func TestRelayAnswersArrival(t *testing.T) {
	_, client := newLab(t, nil)
	internet := udpEcho(t)

	conn := dialClient(t, client)
	defer func() { _ = conn.Close() }()
	first := clientUDP(t, client)
	relay, err := socksclient.Associate(conn, first)
	if err != nil {
		t.Fatalf("UDP ASSOCIATE: %v", err)
	}

	// A second source on the client stack sends the datagram; the reply
	// answers it, not the association's first source.
	second := clientUDP(t, client)
	if _, err := second.WriteTo(
		socksclient.EncodeDatagram([]byte("from the second source"), internet),
		net.UDPAddrFromAddrPort(relay.Addr)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 64)
	_ = second.(*gonet.UDPConn).SetReadDeadline(time.Now().Add(10 * time.Second))
	n, _, err := second.ReadFrom(got)
	if err != nil {
		t.Fatalf("the reply never reached the second source: %v", err)
	}
	payload, from, err := socksclient.DecodeDatagram(got[:n])
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "from the second source" {
		t.Errorf("echo = %q, want the second source's", payload)
	}
	if from != internet {
		t.Errorf("the reply's header named %s, want the destination %s", from, internet)
	}
	_ = first.(*gonet.UDPConn).SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if n, _, err := first.ReadFrom(got); err == nil {
		t.Fatalf("the first source received %x, want the reply at the arrival address", got[:n])
	}
}

// TestDropsICMP checks the echo relay's retirement: an ICMP packet
// addressed to the node's own address is dropped and counted, never
// relayed.
func TestDropsICMP(t *testing.T) {
	app, _ := newLab(t, nil)

	// A well-formed echo request: identifier, sequence, and a checksum that
	// sums to zero over the header it protects.
	pkt := make([]byte, header.IPv4MinimumSize+header.ICMPv4MinimumSize+len("ping"))
	ipHdr := header.IPv4(pkt)
	ipHdr.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(pkt)),
		TTL:         64,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     netipToAddress(labClient),
		DstAddr:     netipToAddress(labOwn),
	})
	icmpHdr := header.ICMPv4(ipHdr.Payload())
	icmpHdr.SetType(header.ICMPv4Echo)
	icmpHdr.SetIdent(0x4242)
	icmpHdr.SetSequence(7)
	copy(icmpHdr.Payload(), "ping")
	icmpHdr.SetChecksum(internetChecksum(ipHdr.Payload()))

	before := app.cnt.droppedPackets.Load()
	app.Inbound(pkt)
	if dropped := app.cnt.droppedPackets.Load(); dropped != before+1 {
		t.Errorf("dropped = %d after the ICMP packet, want one more", dropped)
	}
	if got := app.flowCount(); got != 0 {
		t.Errorf("flows held = %d, want none", got)
	}
}

// internetChecksum is the ones-complement checksum IPv4 and ICMP carry —
// the helper the echo machinery carried, kept for the packet builders
// here.
func internetChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// TestFlowBoundRefuses checks the accounting at the bound, TCP and UDP
// counted together: with the bound held by one flow, a CONNECT and an
// association are both refused on their own legs.
func TestFlowBoundRefuses(t *testing.T) {
	app, client := newLab(t, func(cfg *Config) { cfg.Flows = 1 })
	internet := tcpEcho(t)

	// The one flow the bound holds: a CONNECT spliced to the echo.
	held, err := socksclient.Connect(dialClient(t, client), internet.String())
	if err != nil {
		t.Fatalf("the held CONNECT: %v", err)
	}
	defer func() { _ = held.Close() }()
	if _, err := held.Write([]byte("held")); err != nil {
		t.Fatal(err)
	}
	if got := app.flowCount(); got != 1 {
		t.Fatalf("flows held = %d, want 1", got)
	}

	if _, err := socksclient.Connect(dialClient(t, client), internet.String()); err == nil {
		t.Error("a CONNECT at the bound succeeded, want the told refusal")
	} else {
		var refused *socksclient.Refused
		if !errors.As(err, &refused) {
			t.Errorf("the CONNECT at the bound = %v, want the told refusal", err)
		}
	}

	conn := dialClient(t, client)
	defer func() { _ = conn.Close() }()
	if _, err := socksclient.Associate(conn, clientUDP(t, client)); err == nil {
		t.Error("an association at the bound succeeded, want the told refusal")
	} else {
		var refused *socksclient.Refused
		if !errors.As(err, &refused) {
			t.Errorf("the association at the bound = %v, want the told refusal", err)
		}
	}
}

// TestIdleSweepExpiresSilentFlows checks the idle bound: flows with traffic
// survive the sweep at their touch, and silent ones — a CONNECT leg, an
// association, and its outbound sockets — close and leave the tables.
func TestIdleSweepExpiresSilentFlows(t *testing.T) {
	app, client := newLab(t, func(cfg *Config) { cfg.Idle = 100 * time.Millisecond })
	tcpNet := tcpEcho(t)
	udpNet := udpEcho(t)

	conn, err := socksclient.Connect(dialClient(t, client), tcpNet.String())
	if err != nil {
		t.Fatalf("CONNECT: %v", err)
	}
	if _, err := conn.Write([]byte("touch")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 5)
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("the TCP touch never returned: %v", err)
	}

	assocConn := dialClient(t, client)
	pc := clientUDP(t, client)
	relay, err := socksclient.Associate(assocConn, pc)
	if err != nil {
		t.Fatalf("UDP ASSOCIATE: %v", err)
	}
	if err := relay.WriteTo([]byte("touch"), udpNet); err != nil {
		t.Fatal(err)
	}
	_ = pc.(*gonet.UDPConn).SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, _, err := relay.ReadFrom(got); err != nil {
		t.Fatalf("the UDP touch never returned: %v", err)
	}

	// Three flows — the CONNECT leg, the association, its outbound socket —
	// all touched, all surviving a sweep at now.
	if want := 3; app.flowCount() != want {
		t.Fatalf("flows held = %d, want %d", app.flowCount(), want)
	}
	app.expireIdle(time.Now())
	if got := app.flowCount(); got != 3 {
		t.Fatalf("flows with traffic swept: %d remain, want 3", got)
	}

	// Silent past the bound, the same sweep closes them all.
	app.expireIdle(time.Now().Add(time.Second))
	if got := app.flowCount(); got != 0 {
		t.Errorf("flows held after the idle bound = %d, want 0", got)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Read(got); err == nil {
		t.Error("the swept CONNECT leg still answers")
	}
	_ = assocConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := assocConn.Read(got); err == nil {
		t.Error("the swept association's leg still answers")
	}
}

// TestAssociationClosesWithLeg checks the association's lifetime: its TCP
// leg's close sweeps the outbound sockets and releases the relay port at
// once, no idle bound waited — the idle bound here is an hour, so the
// teardown alone can be what closed the flows. (The suite runs on real time
// for this: the leg's pump blocks on a real socket, and a synctest bubble
// never waits a real socket out.)
func TestAssociationClosesWithLeg(t *testing.T) {
	internet := udpEcho(t)
	app, client := newLab(t, func(cfg *Config) { cfg.Idle = time.Hour })

	conn := dialClient(t, client)
	pc := clientUDP(t, client)
	relay, err := socksclient.Associate(conn, pc)
	if err != nil {
		t.Fatalf("UDP ASSOCIATE: %v", err)
	}
	if err := relay.WriteTo([]byte("one leg"), internet); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the association and its leg", func() bool {
		return app.flowCount() == 2
	})

	// The leg's end sweeps the association whole.
	_ = conn.Close()
	waitFor(t, "the association swept", func() bool {
		return app.flowCount() == 0
	})
}

// waitFor sleeps until cond holds, failing the test when it never does.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !cond() {
		t.Fatalf("%s never came", what)
	}
}
