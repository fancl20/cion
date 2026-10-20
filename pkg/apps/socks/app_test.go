package socks

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
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

	"github.com/fancl20/cion/internal/socksclient"
	"github.com/fancl20/cion/pkg/apps/wireguard"
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
// replies feed back, the whole tailnet leg without the tunnels. The
// service runs until the test's cleanup stops it.
func newLab(t *testing.T, mutate func(*Config)) (*App, *stack.Stack) {
	t.Helper()
	app, client, _ := runLab(t, mutate)
	return app, client
}

// runLab is newLab handing the test the service's stop: stop cancels Run's
// context and returns what Run returned, or an error once ten seconds pass
// without its return. The cleanup stops the service too, then closes it.
func runLab(t *testing.T, mutate func(*Config)) (*App, *stack.Stack, func() error) {
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
	// service's inbound path. The pump closes with the lab — its context
	// cancels at cleanup, or it would outlive every episode a silent tenant.
	pumpCtx, stopPump := context.WithCancel(context.Background())
	go func() {
		for {
			pkt := link.ReadContext(pumpCtx)
			if pkt == nil {
				return
			}
			data := stack.BufferSince(pkt.LinkHeader())
			router.deliverNow(bytes.Clone(data.Flatten()))
			pkt.DecRef()
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	returned := make(chan error, 1)
	go func() { returned <- app.Run(ctx) }()
	stop := sync.OnceValue(func() error {
		cancel()
		select {
		case err := <-returned:
			return err
		case <-time.After(10 * time.Second):
			return errors.New("Run did not return once its context was canceled")
		}
	})
	t.Cleanup(func() {
		if err := stop(); err != nil {
			t.Error(err)
		}
		app.Close()
		stopPump()
	})
	return app, client, stop
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
// refuses. The host is the package's own loopback address, where only a
// wildcard bind can take the released port.
func refusedTCPAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.130:0")
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

	// The refusal is a drop: nothing relays, the counter tells it — read to
	// the drop, not to an instant — and no outbound socket appears.
	waitFor(t, "the fragmented datagram's drop", func() bool {
		return app.cnt.droppedPackets.Load() >= 1
	})
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

// internetChecksum is the ones-complement checksum IPv4 and ICMP carry.
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
		if _, ok := errors.AsType[*socksclient.Refused](err); !ok {
			t.Errorf("the CONNECT at the bound = %v, want the told refusal", err)
		}
	}

	conn := dialClient(t, client)
	defer func() { _ = conn.Close() }()
	if _, err := socksclient.Associate(conn, clientUDP(t, client)); err == nil {
		t.Error("an association at the bound succeeded, want the told refusal")
	} else {
		if _, ok := errors.AsType[*socksclient.Refused](err); !ok {
			t.Errorf("the association at the bound = %v, want the told refusal", err)
		}
	}
}

// TestIdleSweepExpiresSilentFlows checks the idle bound: flows with traffic
// survive the sweep at their touch, and silent ones — a CONNECT leg, an
// association, and its outbound sockets — close and leave the tables.
func TestIdleSweepExpiresSilentFlows(t *testing.T) {
	app, client := newLab(t, func(cfg *Config) { cfg.Idle = time.Hour })
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
	// all touched, all surviving the sweep a synthetic ten minutes on: the
	// bound an hour away, no real-elapsed race decides it.
	if want := 3; app.flowCount() != want {
		t.Fatalf("flows held = %d, want %d", app.flowCount(), want)
	}
	app.expireIdle(time.Now().Add(10 * time.Minute))
	if got := app.flowCount(); got != 3 {
		t.Fatalf("flows with traffic swept: %d remain, want 3", got)
	}

	// Silent past the bound — a synthetic two hours — the same sweep closes
	// them all.
	app.expireIdle(time.Now().Add(2 * time.Hour))
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

// TestRunStopsItsFlows checks the stop: once its context is canceled, Run
// returns with a client held mid-handshake, a CONNECT whose dial blocks
// until its context ends, and a spliced flow, whose internet leg sees its
// connection close. A CONNECT whose dial returns only after the stop closes
// both its legs at once and enters no table.
func TestRunStopsItsFlows(t *testing.T) {
	internet := newHoldingListener(t)
	const blocked, late = "192.0.2.1:9", "192.0.2.2:9"
	dialing := make(chan struct{}, 2)
	release := make(chan struct{})
	app, client, stop := runLab(t, func(cfg *Config) {
		cfg.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			var d net.Dialer
			switch address {
			case blocked:
				dialing <- struct{}{}
				<-ctx.Done()
				return nil, ctx.Err()
			case late:
				dialing <- struct{}{}
				<-release
				return d.Dial(network, internet.addr.String())
			}
			return d.DialContext(ctx, network, address)
		}
	})
	releaseLate := sync.OnceFunc(func() { close(release) })
	t.Cleanup(releaseLate)

	// A client held mid-handshake: its method agreed, its request unsent.
	held := dialClient(t, client)
	t.Cleanup(func() { _ = held.Close() })
	if _, err := held.Write([]byte{version, 1, methodNone}); err != nil {
		t.Fatal(err)
	}
	var method [2]byte
	_ = held.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(held, method[:]); err != nil {
		t.Fatalf("reading the method reply: %v", err)
	}

	// A spliced flow, its internet leg held by the test.
	spliced, err := socksclient.Connect(dialClient(t, client), internet.addr.String())
	if err != nil {
		t.Fatalf("CONNECT: %v", err)
	}
	t.Cleanup(func() { _ = spliced.Close() })
	splicedLeg := internet.next(t)

	// The two CONNECTs whose dials block. The client side never hears the
	// stop — the service's drain ends with it — so the cleanup closes them.
	for _, dst := range []string{blocked, late} {
		conn := dialClient(t, client)
		t.Cleanup(func() { _ = conn.Close() })
		go func() { _, _ = socksclient.Connect(conn, dst) }()
	}
	for range 2 {
		select {
		case <-dialing:
		case <-time.After(10 * time.Second):
			t.Fatal("a CONNECT's dial never started")
		}
	}

	stopped := make(chan error, 1)
	go func() { stopped <- stop() }()
	assertClosed(t, "the spliced flow's internet leg", splicedLeg)
	select {
	case err := <-stopped:
		t.Fatalf("Run returned while a dial was in flight: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	// The late dial returns only now, once the stop has closed the flows.
	releaseLate()
	assertClosed(t, "the late CONNECT's internet leg", internet.next(t))
	if err := <-stopped; err != nil {
		t.Fatal(err)
	}
	if got := app.flowCount(); got != 0 {
		t.Errorf("flows held after the stop = %d, want none", got)
	}
}

// TestStoppedRefusesLateFlows checks the stop's mark alone, the netstack
// still open: a CONNECT or an ASSOCIATE completing once the application
// has stopped closes its legs, tells the client nothing, and enters no
// table.
func TestStoppedRefusesLateFlows(t *testing.T) {
	internet := newHoldingListener(t)
	app, _ := newLab(t, nil)
	app.mtx.Lock()
	app.stopped = true
	app.mtx.Unlock()

	in, client := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	dst := destination{ip: internet.addr.Addr(), port: internet.addr.Port()}
	go app.connect(t.Context(), in, dst)
	assertClosed(t, "the late CONNECT's internet leg", internet.next(t))
	assertClosed(t, "the late CONNECT's client leg", client)

	in, client = net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	go app.associate(t.Context(), in, destination{})
	assertClosed(t, "the late ASSOCIATE's client leg", client)

	if got := app.flowCount(); got != 0 {
		t.Errorf("flows held = %d, want none", got)
	}
}

// TestHandshakeBound checks the handshake's bound: a client that connects
// and sends nothing sees its connection close once the bound has passed.
func TestHandshakeBound(t *testing.T) {
	const bound = 200 * time.Millisecond
	_, client := newLab(t, func(cfg *Config) { cfg.Handshake = bound })

	start := time.Now()
	conn := dialClient(t, client)
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("a silent client's read = %v, want the service's close", err)
	}
	if elapsed := time.Since(start); elapsed < bound {
		t.Errorf("the service closed a silent client after %v, inside the bound %v",
			elapsed, bound)
	}
}

// holdingListener is an internet service that accepts each connection and
// hands it to the test, reading and closing nothing itself: a peer that
// never ends a flow.
type holdingListener struct {
	addr  netip.AddrPort
	conns chan net.Conn
}

func newHoldingListener(t *testing.T) *holdingListener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	h := &holdingListener{
		addr:  listener.Addr().(*net.TCPAddr).AddrPort(),
		conns: make(chan net.Conn, 4),
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			h.conns <- conn
		}
	}()
	return h
}

// next returns the next connection the service accepted.
func (h *holdingListener) next(t *testing.T) net.Conn {
	t.Helper()
	select {
	case conn := <-h.conns:
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	case <-time.After(10 * time.Second):
		t.Fatal("the internet leg never arrived")
		return nil
	}
}

// assertClosed checks that the connection's peer has closed it: a read
// ends in an error other than its deadline's.
func assertClosed(t *testing.T, what string, conn net.Conn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("a read on %s = %v, want the connection closed", what, err)
	}
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
