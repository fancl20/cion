// Package fabric is the integration labs' userspace network: one gVisor
// netstack per node — the egress application's own recipe — connected by a
// forwarder the harness owns, so a lab's nodes hold no kernel port at all
// and the network's behaviors are taps the lab draws: delay, loss,
// blackhole, cut, and the NAT, on whose router a node may run. The hosts
// the labs draw from the loopback pool become plain names, each stack
// routing its own, so two fabrics may draw the same host and two labs may
// overlap freely; the host names a lab draws resolve through every node's
// socket source, and no lookup reaches the system resolver. Every stack and
// every tap's scheduler read one clock, the seam a deterministic network
// later builds on.
package fabric

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	netipv4 "gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/fancl20/cion/pkg/libs/underlay"
)

// queueDepth is the depth of every channel endpoint's packet queue, the
// egress application's own choice for the same pump.
const queueDepth = 512

// drawnPortBase is the first port DrawPort draws. The band from it up to
// the stack's ephemeral range holds no port a bind of port zero lands on
// and no fixed port the node binds.
const drawnPortBase = 10000

// Fabric is the userspace network a lab draws: the stacks it booted, the
// taps it drew between them, the NATs it placed, the host names it
// drew, and the one clock they all read. It stops with the test.
type Fabric struct {
	t      *testing.T
	clock  tcpip.Clock
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// mtx guards the drawn network: the stacks by host, the taps, the
	// NATs, the names, and the watches. A packet's walk from one stack to
	// another reads it twice — once for the taps, once for the destination
	// — so no tap draw or node boot waits on a packet in flight.
	mtx     sync.Mutex
	hosts   map[netip.Addr]*Node
	taps    []*tap
	nats    []*NAT
	names   map[string]netip.Addr
	watches []*watch
	closed  bool

	// udpOnly boots every stack with the UDP transport alone.
	udpOnly bool
}

// Option shapes the fabric New boots.
type Option func(*Fabric)

// UDPOnly boots every stack with the UDP transport alone, the fabric a
// synctest bubble runs: gVisor's TCP transport parks its dispatchers where
// the bubble cannot see them durably blocked, so a stack carrying it stops
// the bubble's clock at its first idle moment. A UDP-only stack binds no
// TCP listener.
func UDPOnly() Option {
	return func(f *Fabric) { f.udpOnly = true }
}

// New boots the fabric on the test's lifetime: the forwarders drain until
// the test's context ends, then the stacks close with it. The fabric reads
// its clock from the moment New runs, so a bubble's fabric is booted inside
// the bubble.
func New(t *testing.T, opts ...Option) *Fabric {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	f := &Fabric{
		t:      t,
		clock:  tcpip.NewStdClock(),
		ctx:    ctx,
		cancel: cancel,
		hosts:  make(map[netip.Addr]*Node),
		names:  make(map[string]netip.Addr),
	}
	for _, opt := range opts {
		opt(f)
	}
	t.Cleanup(f.stop)
	return f
}

// Name draws a host name on the fabric: every node's socket source resolves
// it to the host. A name names one host for the fabric's life.
func (f *Fabric) Name(name string, host netip.Addr) {
	f.t.Helper()
	f.mtx.Lock()
	defer f.mtx.Unlock()
	if drawn, ok := f.names[name]; ok && drawn != host {
		f.t.Fatalf("the fabric's name %q names %v, not %v", name, drawn, host)
	}
	f.names[name] = host
}

// lookup resolves a name the lab drew to its host, and refuses any other as
// the system resolver refuses a name no server holds. The fabric's hosts are
// IPv4 alone, so an IPv6 resolution answers nothing.
func (f *Fabric) lookup(_ context.Context, network, name string) ([]netip.Addr, error) {
	f.mtx.Lock()
	host, ok := f.names[name]
	f.mtx.Unlock()
	if !ok || network == "ip6" {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	return []netip.Addr{host}, nil
}

// stop ends the fabric: the forwarders return, and every stack closes and
// releases with them.
func (f *Fabric) stop() {
	f.cancel()
	f.wg.Wait()
	f.mtx.Lock()
	defer f.mtx.Unlock()
	if f.closed {
		return
	}
	f.closed = true
	for _, n := range f.hosts {
		n.stack.Close()
		n.stack.Wait()
		n.stack.Destroy()
	}
}

// Node boots the host's stack on the fabric: one netstack — IPv4 with UDP
// and, unless the fabric is UDP-only, TCP transports — on a channel
// endpoint the forwarder drains, holding
// the host the lab drew from the loopback pool as a plain name. No kernel
// interface carries the host; each stack routes its own; the host's stack
// stands for the fabric's life, so a node's restart rebinds on it — the
// stack's immediate release making the ports free again. A second draw of
// one host names the one stack that holds it. A NAT's gateway is its
// router's alone.
func (f *Fabric) Node(host netip.Addr) *Node {
	f.t.Helper()
	if host.IsUnspecified() || !host.Is4() {
		f.t.Fatalf("the fabric boots a node on a concrete IPv4 host, not %v", host)
	}
	f.mtx.Lock()
	defer f.mtx.Unlock()
	if n, ok := f.hosts[host]; ok {
		return n
	}
	for _, b := range f.nats {
		if b.gateway == host {
			f.t.Fatalf("the host %v is a NAT's gateway, which its router alone holds", host)
		}
	}
	// Everything the node sends leaves through the one NIC: the fabric's
	// hosts are one hop apart by construction.
	return f.bootLocked([]netip.Addr{host}, []tcpip.Route{{Destination: anyHost(), NIC: 1}})
}

// bootLocked boots a stack holding the hosts, the first its own, every one
// on its one NIC, sending by the routes given; the caller holds the
// fabric's lock and has checked no stack holds the hosts.
func (f *Fabric) bootLocked(hosts []netip.Addr, routes []tcpip.Route) *Node {
	f.t.Helper()
	transports := []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol}
	if f.udpOnly {
		transports = []stack.TransportProtocolFactory{udp.NewProtocol}
	}
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			// The fabric's hosts are the labs' loopback pool's, carried on a
			// NIC that is no kernel loopback: the stack admits them inbound.
			netipv4.NewProtocolWithOptions(netipv4.Options{
				AllowExternalLoopbackTraffic: true,
			}),
		},
		TransportProtocols: transports,
		Clock:              f.clock,
	})
	n := &Node{
		f:     f,
		host:  hosts[0],
		stack: s,
		link:  channel.New(queueDepth, underlay.BufferSize, ""),
	}
	if err := s.CreateNIC(1, n.link); err != nil {
		f.t.Fatalf("creating %v's NIC: %v", hosts[0], err)
	}
	for _, host := range hosts {
		if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
			Protocol: header.IPv4ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   tcpip.AddrFrom4(host.As4()),
				PrefixLen: 32,
			},
		}, stack.AddressProperties{}); err != nil {
			f.t.Fatalf("adding %v's address: %v", host, err)
		}
		f.hosts[host] = n
	}
	// A socket bound to a host sends from it; one bound to the wildcard
	// sends from the host its route toward the destination hints, the
	// stack's own where the route hints none.
	s.SetRouteTable(routes)
	f.wg.Add(1)
	go f.forward(n)
	return n
}

// anyHost is the default route's destination: every IPv4 host.
func anyHost() tcpip.Subnet {
	return tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4([4]byte{})}.Subnet()
}

// oneHost is a route's destination of the host alone.
func oneHost(host netip.Addr) tcpip.Subnet {
	return tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4(host.As4()), PrefixLen: 32}.Subnet()
}

// Node is one host's stack on the fabric — or a router's, holding the
// NAT's gateway beside an inside host.
type Node struct {
	f *Fabric
	// host is the stack's own host: the one it was booted for, a router's
	// gateway.
	host  netip.Addr
	stack *stack.Stack
	link  *channel.Endpoint
	// drawn counts the ports DrawPort drew.
	drawn atomic.Uint32
}

// DrawPort draws a port of the node's stack for an address the node binds
// by number — its control or internal address: the band's next port below
// the stack's ephemeral range. Only the node binds on its stack, and
// nothing it binds lands in the band unless drawn there, so the draw needs
// no probe.
func (n *Node) DrawPort() uint16 {
	n.f.t.Helper()
	first, _ := n.stack.PortRange()
	port := drawnPortBase + n.drawn.Add(1) - 1
	if port >= uint32(first) {
		n.f.t.Fatalf("the drawn port band on %v is drawn dry", n.host)
	}
	return uint16(port)
}

// Sockets is the socket source that binds on the node's stack: the seam the
// node's sites construct through, its ports the stack's alone and their
// release immediate, its routes the stack's, its names the ones the lab
// drew on the fabric.
func (n *Node) Sockets() underlay.Sockets {
	return underlay.Sockets{
		ListenUDP:   n.listenUDP,
		ListenTCP:   n.listenTCP,
		LookupNetIP: n.f.lookup,
		RouteSource: n.routeSource,
	}
}

// routeSource returns the host the stack's routes send from toward dst — a
// router's inside host toward the NAT's inside hosts, the stack's own host
// otherwise — as the kernel's routing table answers it.
func (n *Node) routeSource(dst netip.Addr) (netip.Addr, error) {
	if !dst.Unmap().Is4() {
		return netip.Addr{}, fmt.Errorf("the fabric routes IPv4 alone, not %v", dst)
	}
	r, err := n.stack.FindRoute(0, tcpip.Address{}, tcpip.AddrFrom4(dst.Unmap().As4()),
		header.IPv4ProtocolNumber, false)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("routing toward %v: %v", dst, err)
	}
	defer r.Release()
	return toNetip(r.LocalAddress()), nil
}

// listenUDP binds an unconnected UDP socket on the node's stack at the
// address given — per-family ports and immediate release are the stack's
// own facts, so the remote hint names nothing to select. The stack draws
// the port where the address names none. A host's bind names no NIC, so
// the stack checks the host against the ones its NIC holds: an IPv4 bind
// naming the NIC skips that check, and would bind a host the node lacks.
// The wildcard's bind receives at every host the stack holds.
func (n *Node) listenUDP(
	listen *net.UDPAddr, _ netip.AddrPort,
) (underlay.UDPConn, error) {

	ap, err := listenAddr(listen)
	if err != nil {
		return nil, err
	}
	wq := waiter.Queue{}
	ep, tcpErr := n.stack.NewEndpoint(udp.ProtocolNumber, header.IPv4ProtocolNumber, &wq)
	if tcpErr != nil {
		return nil, fmt.Errorf("creating the UDP endpoint: %v", tcpErr)
	}
	bind := tcpip.FullAddress{Port: ap.Port()}
	if !ap.Addr().IsUnspecified() {
		bind.Addr = tcpip.AddrFrom4(ap.Addr().As4())
	}
	if tcpErr := ep.Bind(bind); tcpErr != nil {
		ep.Close()
		return nil, bindError(tcpErr)
	}
	return &fabricConn{conn: gonet.NewUDPConn(&wq, ep)}, nil
}

// listenTCP binds a TCP listener on the node's stack at the concrete
// address given.
func (n *Node) listenTCP(addr string) (net.Listener, error) {
	if n.f.udpOnly {
		return nil, fmt.Errorf("the fabric's stacks carry UDP alone; no TCP listener binds %s", addr)
	}
	ap, err := underlay.ResolveAddrPort(addr)
	if err != nil {
		return nil, err
	}
	if ap.Addr().IsUnspecified() || !ap.Addr().Is4() {
		return nil, fmt.Errorf("the fabric binds a TCP listener on a concrete IPv4 host, not %v", ap)
	}
	ln, err := gonet.ListenTCP(n.stack, tcpip.FullAddress{
		NIC: 1, Addr: tcpip.AddrFrom4(ap.Addr().As4()), Port: ap.Port(),
	}, header.IPv4ProtocolNumber)
	if err != nil {
		return nil, fmt.Errorf("binding on the stack: %w", err)
	}
	return ln, nil
}

// listenAddr resolves the address a UDP bind names: a host, or the IPv4
// wildcard. A v4-mapped form names the plain address beneath it.
func listenAddr(listen *net.UDPAddr) (netip.AddrPort, error) {
	if listen == nil || listen.IP == nil {
		return netip.AddrPort{}, fmt.Errorf("the fabric binds an address, not %v", listen)
	}
	ip, ok := netip.AddrFromSlice(listen.IP)
	if !ok || !ip.Unmap().Is4() {
		return netip.AddrPort{}, fmt.Errorf("the fabric binds an IPv4 address, not %v", listen.IP)
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(listen.Port)), nil
}

// bindError carries a bind refusal in the errno shape the kernel gives: a
// held port as EADDRINUSE, which the band allocation's probe reads, and a
// host the stack does not hold as EADDRNOTAVAIL, which the published host's
// check reads.
func bindError(err tcpip.Error) error {
	switch err.(type) {
	case *tcpip.ErrPortInUse:
		return os.NewSyscallError("bind", syscall.EADDRINUSE)
	case *tcpip.ErrBadLocalAddress:
		return os.NewSyscallError("bind", syscall.EADDRNOTAVAIL)
	}
	return fmt.Errorf("binding on the stack: %v", err)
}

// forward drains the node's channel and carries every packet by its
// destination, until the fabric stops.
func (f *Fabric) forward(n *Node) {
	defer f.wg.Done()
	for {
		pkt := n.link.ReadContext(f.ctx)
		if pkt == nil {
			return
		}
		// Outbound packets carry their headers in the header views, so the
		// wire packet is everything from the (empty) link header on; the
		// copy outlives the packet buffer the taps may hold it past.
		wire := stack.BufferSince(pkt.LinkHeader())
		raw := slices.Clone(wire.Flatten())
		pkt.DecRef()
		f.carry(raw)
	}
}

// carry moves one wire packet the forwarder drained: the taps shape its
// pair, the NATs translate it, and the destination's stack receives
// it. A packet held by a delay tap re-enters here on the fabric's clock.
func (f *Fabric) carry(pkt []byte) {
	if len(pkt) < header.IPv4MinimumSize || pkt[0]>>4 != 4 {
		return
	}
	src := header.IPv4(pkt).SourceAddress()
	dst := header.IPv4(pkt).DestinationAddress()
	drop, delay := f.shape(toNetip(src), toNetip(dst))
	if drop {
		return
	}
	if delay > 0 {
		held := pkt
		f.clock.AfterFunc(delay, func() { f.crossNATs(held) })
		return
	}
	f.crossNATs(pkt)
}

// crossNATs passes the packet out of the NAT holding its source, then
// into the NAT owning its destination — a packet between two
// hosts behind NATs crosses both, as it would two NATs — and a
// NAT drops what it holds no admitted mapping for. It then delivers
// the packet to the destination its address finally names.
func (f *Fabric) crossNATs(pkt []byte) {
	f.mtx.Lock()
	nats := slices.Clone(f.nats)
	f.mtx.Unlock()
	for _, leg := range []func(*NAT, []byte) ([]byte, bool){
		(*NAT).egress, (*NAT).ingress,
	} {
		for _, b := range nats {
			rewritten, ok := leg(b, pkt)
			if !ok {
				continue
			}
			if rewritten == nil {
				return
			}
			pkt = rewritten
			break
		}
	}
	f.deliver(toNetip(header.IPv4(pkt).DestinationAddress()), pkt)
}

// deliver injects the packet into the stack that holds the destination
// host, dropping it where none does, and notes it in the watches on its
// destination address.
func (f *Fabric) deliver(dst netip.Addr, pkt []byte) {
	f.mtx.Lock()
	n := f.hosts[dst]
	if n != nil {
		f.recordLocked(dst, pkt)
	}
	f.mtx.Unlock()
	if n == nil {
		return
	}
	n.link.InjectInbound(header.IPv4ProtocolNumber, stack.NewPacketBuffer(
		stack.PacketBufferOptions{Payload: buffer.MakeWithData(pkt)}))
}

// toNetip reads a header address as the plain IPv4 address the taps and the
// NATs key by.
func toNetip(addr tcpip.Address) netip.Addr {
	ip, _ := netip.AddrFromSlice(addr.AsSlice())
	return ip.Unmap()
}

// fabricConn is a UDP socket bound on a node's stack.
type fabricConn struct {
	conn *gonet.UDPConn
}

var _ underlay.UDPConn = (*fabricConn)(nil)

func (c *fabricConn) ReadFromUDP(b []byte) (int, *net.UDPAddr, error) {
	n, addr, err := c.conn.ReadFrom(b)
	if err != nil {
		return 0, nil, err
	}
	return n, addr.(*net.UDPAddr), nil
}

func (c *fabricConn) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	return c.conn.WriteTo(b, addr)
}

// ReadBatch returns the first datagram then whatever is immediately ready —
// the shape MSG_WAITFORONE gives — for batching remains a fast path the
// kernel owns. Only the data plane's receive loop reads batches, and it
// sets no deadline, so the probe's momentary deadline clears to none.
func (c *fabricConn) ReadBatch(msgs []ipv4.Message) (int, error) {
	n, addr, err := c.ReadFromUDP(msgs[0].Buffers[0])
	if err != nil {
		return 0, err
	}
	msgs[0].N = n
	msgs[0].Addr = addr
	read := 1
	_ = c.conn.SetReadDeadline(time.Now())
	for _, m := range msgs[1:] {
		n, addr, err := c.ReadFromUDP(m.Buffers[0])
		if err != nil {
			break
		}
		m.N = n
		m.Addr = addr
		read++
	}
	_ = c.conn.SetReadDeadline(time.Time{})
	return read, nil
}

// WriteBatch writes each message through.
func (c *fabricConn) WriteBatch(msgs []ipv4.Message) (int, error) {
	written := 0
	for _, m := range msgs {
		if _, err := c.WriteToUDP(m.Buffers[0], m.Addr.(*net.UDPAddr)); err != nil {
			return written, err
		}
		written++
	}
	return written, nil
}

func (c *fabricConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *fabricConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *fabricConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// LocalAddr returns the bound address, the wildcard's spelled as the
// kernel spells it: 0.0.0.0 beside the port.
func (c *fabricConn) LocalAddr() *net.UDPAddr {
	a := c.conn.LocalAddr().(*net.UDPAddr)
	if len(a.IP) == 0 {
		a.IP = net.IPv4zero.To4()
	}
	return a
}

// SetReadBuffer and SetWriteBuffer size nothing: the stack's buffers are
// the channel's queue, sized at the fabric's boot.
func (c *fabricConn) SetReadBuffer(int) error  { return nil }
func (c *fabricConn) SetWriteBuffer(int) error { return nil }

func (c *fabricConn) Close() error {
	return c.conn.Close()
}
