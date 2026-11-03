package egress

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"github.com/fancl20/cion/pkg/apps/wireguard"
	"github.com/fancl20/cion/pkg/libs/bus"
)

// The lab's addresses: the node's slice, its first address the node's own,
// and the host the slice's tenth address holds.
var (
	labSlice = netip.MustParsePrefix("100.64.1.0/24")
	labOwn   = netip.MustParseAddr("100.64.1.1")
	labHost  = netip.MustParseAddr("100.64.1.10")
)

// labInternet is the documentation range the lab's hosts address the
// internet at. The egress drops loopback destinations, so each loopback
// service of the lab stands at the address of the range whose last octet
// is its own.
var labInternet = netip.MustParsePrefix("198.51.100.0/24")

// internetOf returns the documentation address a host reaches the loopback
// service at addr by.
func internetOf(addr netip.AddrPort) netip.AddrPort {
	octets := addr.Addr().As4()
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, 100, octets[3]}), addr.Port())
}

// reachLab is the lab's internet as the egress's outbound legs reach it: a
// documentation address leaves for the loopback service it stands for, and
// every other destination as addressed.
func reachLab(dst netip.AddrPort) netip.AddrPort {
	if !labInternet.Contains(dst.Addr()) {
		return dst
	}
	octets := dst.Addr().As4()
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, octets[3]}), dst.Port())
}

// wait bounds every wait for an event the lab expects.
const wait = 10 * time.Second

// labRouter is the borrowed router's stand-in. It records the deliveries
// the egress installs, announcing each on installs, and hands a host's
// packet to the one its destination names under its read lock, the way the
// router does; the egress's packets reach routed, or the host stack the lab
// wired in.
type labRouter struct {
	routed   chan []byte
	installs chan string
	// inject carries the egress's packets into the lab's host stack; nil
	// where the lab wired none.
	inject func(pkt []byte)

	mtx      sync.RWMutex
	local    map[netip.Addr]func(pkt []byte)
	fallback func(pkt []byte)
}

func newLabRouter() *labRouter {
	return &labRouter{
		routed:   make(chan []byte, 64),
		installs: make(chan string, 8),
		local:    make(map[netip.Addr]func(pkt []byte)),
	}
}

func (r *labRouter) Route(pkt []byte) {
	if r.inject != nil {
		r.inject(pkt)
		return
	}
	r.routed <- pkt
}

func (r *labRouter) Deliver(addr netip.Addr, deliver func(pkt []byte)) func() {
	r.mtx.Lock()
	defer r.mtx.Unlock()
	r.local[addr] = deliver
	r.installs <- addr.String()
	return func() {
		r.mtx.Lock()
		defer r.mtx.Unlock()
		delete(r.local, addr)
	}
}

func (r *labRouter) DeliverDefault(deliver func(pkt []byte)) func() {
	r.mtx.Lock()
	defer r.mtx.Unlock()
	r.fallback = deliver
	r.installs <- "default"
	return func() {
		r.mtx.Lock()
		defer r.mtx.Unlock()
		r.fallback = nil
	}
}

// send hands a host's IPv4 packet to the delivery its destination names —
// the address's own, else the default for a destination outside the
// tailnet — and reports whether one took it.
func (r *labRouter) send(pkt []byte) bool {
	dst := addressToNetip(header.IPv4(pkt).DestinationAddress())
	r.mtx.RLock()
	defer r.mtx.RUnlock()
	deliver, ok := r.local[dst]
	if !ok && !wireguard.Tailnet.Contains(dst) && r.fallback != nil {
		deliver, ok = r.fallback, true
	}
	if ok {
		deliver(pkt)
	}
	return ok
}

// installed lists the deliveries standing: each address delivered, and
// "default" while the default stands.
func (r *labRouter) installed() []string {
	r.mtx.RLock()
	defer r.mtx.RUnlock()
	got := []string{}
	for addr := range r.local {
		got = append(got, addr.String())
	}
	if r.fallback != nil {
		got = append(got, "default")
	}
	return got
}

// awaitInstall waits for the next delivery the egress installs and returns
// its name: the address, or "default".
func (r *labRouter) awaitInstall(t *testing.T) string {
	t.Helper()
	select {
	case name := <-r.installs:
		return name
	case <-time.After(wait):
		t.Fatal("the egress installed no delivery")
		return ""
	}
}

// awaitRouted waits for the next packet the egress routed.
func (r *labRouter) awaitRouted(t *testing.T) []byte {
	t.Helper()
	select {
	case pkt := <-r.routed:
		return pkt
	case <-time.After(wait):
		t.Fatal("the egress routed no packet")
		return nil
	}
}

// fakeICMP is the echo relay's socket double: it hands each request the
// relay sends to the test, and reads the replies the test injects until
// closed.
type fakeICMP struct {
	sent    chan icmpDatagram
	replies chan icmpDatagram
	closed  chan struct{}
	once    sync.Once
}

// icmpDatagram is one ICMP message on the fake socket and the address it
// went to or came from.
type icmpDatagram struct {
	data []byte
	addr netip.Addr
}

func newFakeICMP() *fakeICMP {
	return &fakeICMP{
		sent:    make(chan icmpDatagram, 16),
		replies: make(chan icmpDatagram, 16),
		closed:  make(chan struct{}),
	}
}

func (f *fakeICMP) WriteTo(b []byte, dst netip.Addr) error {
	f.sent <- icmpDatagram{data: bytes.Clone(b), addr: dst}
	return nil
}

func (f *fakeICMP) ReadFrom(b []byte) (int, netip.Addr, error) {
	select {
	case r := <-f.replies:
		return copy(b, r.data), r.addr, nil
	case <-f.closed:
		return 0, netip.Addr{}, net.ErrClosed
	}
}

func (f *fakeICMP) Close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}

// awaitSent waits for the next request the relay sent.
func (f *fakeICMP) awaitSent(t *testing.T) icmpDatagram {
	t.Helper()
	select {
	case d := <-f.sent:
		return d
	case <-time.After(wait):
		t.Fatal("the echo relay sent no request")
		return icmpDatagram{}
	}
}

// lab is one running egress beside its router double, the tailnet topic it
// reads, and its echo socket double.
type lab struct {
	app    *App
	router *labRouter
	topic  *bus.Topic[bus.TailnetState]
	echo   *fakeICMP
	// host is the host stack riding the router double; nil where the lab
	// wired none.
	host *stack.Stack
	// stop cancels Run's context and returns what Run returned, or an
	// error once the wait passes without its return.
	stop func() error
}

// newLab runs the egress over a router double and a fake echo socket until
// the test's cleanup stops and closes it, the default delivery installed
// when it returns. The egress's packets reach the router double's routed.
func newLab(t *testing.T, mutate func(*Config)) *lab {
	t.Helper()
	return runLab(t, newLabRouter(), nil, mutate)
}

// newHostLab is newLab with a host stack at the lab's host address riding
// the router double: the host's packets reach the deliveries by
// destination, and the egress's packets reach the host.
func newHostLab(t *testing.T, mutate func(*Config)) *lab {
	t.Helper()
	router := newLabRouter()
	return runLab(t, router, newHostStack(t, router), mutate)
}

func runLab(t *testing.T, router *labRouter, host *stack.Stack, mutate func(*Config)) *lab {
	t.Helper()
	l := &lab{
		router: router,
		topic:  &bus.Topic[bus.TailnetState]{},
		echo:   newFakeICMP(),
		host:   host,
	}
	cfg := Config{
		Router:     router,
		Tailnet:    l.topic,
		Internet:   reachLab,
		EchoSocket: func() (icmpSocket, error) { return l.echo, nil },
	}
	if mutate != nil {
		mutate(&cfg)
	}
	app, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	l.app = app
	ctx, cancel := context.WithCancel(context.Background())
	returned := make(chan error, 1)
	go func() { returned <- app.Run(ctx) }()
	l.stop = sync.OnceValue(func() error {
		cancel()
		select {
		case err := <-returned:
			return err
		case <-time.After(wait):
			return errors.New("Run did not return once its context was canceled")
		}
	})
	t.Cleanup(func() {
		if err := l.stop(); err != nil {
			t.Error(err)
		}
		app.Close()
	})
	if got := router.awaitInstall(t); got != "default" {
		t.Fatalf("the egress's first delivery = %s, want the default", got)
	}
	return l
}

// claim publishes the lab's slice and waits for the egress to claim the
// own address.
func (l *lab) claim(t *testing.T) {
	t.Helper()
	l.topic.Publish(bus.TailnetState{Slice: labSlice})
	select {
	case <-l.app.claimed:
	case <-time.After(wait):
		t.Fatal("the egress never claimed the own address")
	}
}

// newHostStack builds the lab's host: a netstack at the host address whose
// packets the router double delivers by destination and into which the
// egress's packets route. It stops with the test.
func newHostStack(t *testing.T, router *labRouter) *stack.Stack {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	t.Cleanup(s.Destroy)
	link := channel.New(512, uint32(wireguard.OverlayMTU), "")
	if err := s.CreateNIC(1, link); err != nil {
		t.Fatal(err)
	}
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4(labHost.As4()),
			PrefixLen: labSlice.Bits(),
		},
	}, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	anywhere := tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4([4]byte{})}
	s.SetRouteTable([]tcpip.Route{{Destination: anywhere.Subnet(), NIC: 1}})
	router.inject = func(pkt []byte) {
		link.InjectInbound(ipv4.ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(pkt),
		}))
	}
	ctx, cancel := context.WithCancel(context.Background())
	pumped := make(chan struct{})
	go func() {
		defer close(pumped)
		for {
			pkt := link.ReadContext(ctx)
			if pkt == nil {
				return
			}
			wire := stack.BufferSince(pkt.LinkHeader())
			raw := bytes.Clone(wire.Flatten())
			wire.Release()
			pkt.DecRef()
			router.send(raw)
		}
	}()
	t.Cleanup(func() {
		cancel()
		<-pumped
	})
	return s
}

// fullAddress converts an address of the lab for the host stack's NIC.
func fullAddress(addr netip.AddrPort) tcpip.FullAddress {
	return tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(addr.Addr().As4()), Port: addr.Port()}
}

// dialHost dials dst from the host stack, a reset ending the dial at once
// and silence at the wait.
func dialHost(t *testing.T, host *stack.Stack, dst netip.AddrPort) (*gonet.TCPConn, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	conn, err := gonet.DialContextTCP(ctx, host, fullAddress(dst), ipv4.ProtocolNumber)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn, nil
}

// hostUDP binds a UDP socket on the host stack connected to dst.
func hostUDP(t *testing.T, host *stack.Stack, dst netip.AddrPort) *gonet.UDPConn {
	t.Helper()
	local := fullAddress(netip.AddrPortFrom(labHost, 0))
	remote := fullAddress(dst)
	conn, err := gonet.DialUDP(host, &local, &remote, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// roundTrip writes msg on conn and returns as many bytes read back.
func roundTrip(t *testing.T, conn net.Conn, msg string) string {
	t.Helper()
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("writing %q: %v", msg, err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(wait))
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("reading the answer to %q: %v", msg, err)
	}
	return string(got)
}

// assertRefused checks a host's dial ended in a reset: refused at once,
// never waiting out the dial.
func assertRefused(t *testing.T, what string, conn net.Conn, err error) {
	t.Helper()
	if err == nil {
		_ = conn.Close()
		t.Errorf("%s connected, want a reset", what)
		return
	}
	if !strings.Contains(err.Error(), (&tcpip.ErrConnectionRefused{}).String()) {
		t.Errorf("%s = %v, want a reset", what, err)
	}
}

// assertClosed checks that the connection's peer has closed it: a read ends
// in an error other than its deadline's.
func assertClosed(t *testing.T, what string, conn net.Conn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(wait))
	if _, err := conn.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("a read on %s = %v, want the connection closed", what, err)
	}
}

// tcpEcho stands a loopback TCP echo service for the internet, returning
// the documentation address hosts reach it at.
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
	return internetOf(listener.Addr().(*net.TCPAddr).AddrPort())
}

// udpEchoAt stands a loopback UDP echo service for the internet at addr,
// returning its socket.
func udpEchoAt(t *testing.T, addr netip.AddrPort) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(addr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDPAddrPort(buf[:n], from)
		}
	}()
	return conn
}

// udpEcho stands a loopback UDP echo service for the internet, returning
// the documentation address hosts reach it at.
func udpEcho(t *testing.T) netip.AddrPort {
	t.Helper()
	conn := udpEchoAt(t, netip.MustParseAddrPort("127.0.0.1:0"))
	return internetOf(conn.LocalAddr().(*net.UDPAddr).AddrPort())
}

// refusedTCPAddr reserves and releases a TCP port, so connecting to it
// refuses, returning the documentation address hosts reach it at. The host
// is a loopback address of the package's own, where only a wildcard bind
// can take the released port.
func refusedTCPAddr(t *testing.T) netip.AddrPort {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.130:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().(*net.TCPAddr).AddrPort()
	_ = listener.Close()
	return internetOf(addr)
}

// holdingListener is an internet service that accepts each connection and
// hands it to the test, reading and closing nothing itself: a peer that
// never ends a flow. Its addr is the service's own loopback address.
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
	case <-time.After(wait):
		t.Fatal("the outbound leg never arrived")
		return nil
	}
}

// ipPacket builds an IPv4 packet carrying the protocol's payload, its
// header checksum set.
func ipPacket(src, dst netip.Addr, proto tcpip.TransportProtocolNumber, payload []byte) []byte {
	pkt := make([]byte, header.IPv4MinimumSize+len(payload))
	ip := header.IPv4(pkt)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(pkt)),
		TTL:         64,
		Protocol:    uint8(proto),
		SrcAddr:     tcpip.AddrFrom4(src.As4()),
		DstAddr:     tcpip.AddrFrom4(dst.As4()),
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	copy(pkt[header.IPv4MinimumSize:], payload)
	return pkt
}

// echoRequest builds a host's echo request, its checksums set.
func echoRequest(src, dst netip.Addr, ident, seq uint16, payload string) []byte {
	msg := header.ICMPv4(make([]byte, header.ICMPv4MinimumSize+len(payload)))
	msg.SetType(header.ICMPv4Echo)
	msg.SetIdent(ident)
	msg.SetSequence(seq)
	copy(msg.Payload(), payload)
	msg.SetChecksum(internetChecksum(msg))
	return ipPacket(src, dst, header.ICMPv4ProtocolNumber, msg)
}

// udpPacket builds a UDP datagram carrying no checksum, as IPv4 allows.
func udpPacket(src, dst netip.AddrPort, payload string) []byte {
	dgram := header.UDP(make([]byte, header.UDPMinimumSize+len(payload)))
	dgram.Encode(&header.UDPFields{
		SrcPort: src.Port(),
		DstPort: dst.Port(),
		Length:  uint16(len(dgram)),
	})
	copy(dgram.Payload(), payload)
	return ipPacket(src.Addr(), dst.Addr(), header.UDPProtocolNumber, dgram)
}

// icmpPacket is an IPv4 ICMP packet as the tests compare it.
type icmpPacket struct {
	Src, Dst netip.Addr
	Type     header.ICMPv4Type
	Code     header.ICMPv4Code
	Ident    uint16
	Seq      uint16
	Payload  string
	// Summed reports whether both checksums sum to zero over what they
	// protect.
	Summed bool
}

// decodeICMP reads an IPv4 ICMP packet the egress routed.
func decodeICMP(t *testing.T, pkt []byte) icmpPacket {
	t.Helper()
	ip := header.IPv4(pkt)
	if !ip.IsValid(len(pkt)) || ip.TransportProtocol() != header.ICMPv4ProtocolNumber {
		t.Fatalf("the routed packet %x is no IPv4 ICMP", pkt)
	}
	msg := header.ICMPv4(ip.Payload())
	return icmpPacket{
		Src:     addressToNetip(ip.SourceAddress()),
		Dst:     addressToNetip(ip.DestinationAddress()),
		Type:    msg.Type(),
		Code:    msg.Code(),
		Ident:   msg.Ident(),
		Seq:     msg.Sequence(),
		Payload: string(msg.Payload()),
		Summed: internetChecksum(pkt[:ip.HeaderLength()]) == 0 &&
			internetChecksum(msg) == 0,
	}
}

// received counts the packets the egress's netstack took in.
func received(a *App) uint64 {
	return a.stack.Stats().IP.PacketsReceived.Value()
}

// echoCount returns the echo mappings the egress holds.
func echoCount(a *App) int {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	return len(a.echoes)
}
