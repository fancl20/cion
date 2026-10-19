// Package fabric is the integration labs' userspace network: one gVisor
// netstack per node — the SOCKS application's own recipe — connected by a
// forwarder the harness owns, so a lab's nodes hold no kernel port at all
// and the network's behaviors are taps the lab draws: delay, loss,
// blackhole, cut, and the translation boundary. The hosts the labs draw
// from the loopback pool become plain names, each stack routing its own, so
// two fabrics may draw the same host and two labs may overlap freely. Every
// stack and every tap's scheduler read one clock, the seam a deterministic
// network later builds on.
package fabric

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
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
// SOCKS application's own choice for the same pump.
const queueDepth = 512

// Fabric is the userspace network a lab draws: the stacks it booted, the
// taps it drew between them, the boundaries it placed, and the one clock
// they all read. It stops with the test.
type Fabric struct {
	t      *testing.T
	clock  tcpip.Clock
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// mtx guards the drawn network: the stacks by host, the taps, and the
	// boundaries. A packet's walk from one stack to another reads it twice
	// — once for the taps, once for the destination — so no tap draw or
	// node boot waits on a packet in flight.
	mtx    sync.Mutex
	hosts  map[netip.Addr]*Node
	taps   []*tap
	bounds []*Boundary
	closed bool
}

// New boots the fabric on the test's lifetime: the forwarders drain until
// the test's context ends, then the stacks close with it.
func New(t *testing.T) *Fabric {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	f := &Fabric{
		t:      t,
		clock:  tcpip.NewStdClock(),
		ctx:    ctx,
		cancel: cancel,
		hosts:  make(map[netip.Addr]*Node),
	}
	t.Cleanup(f.stop)
	return f
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
// and TCP transports — on a channel endpoint the forwarder drains, holding
// the host the lab drew from the loopback pool as a plain name. No kernel
// interface carries the host; each stack routes its own; the host's stack
// stands for the fabric's life, so a node's restart rebinds on it — the
// stack's immediate release making the ports free again. A second draw of
// one host names the one stack that holds it.
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
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			// The fabric's hosts are the labs' loopback pool's, carried on a
			// NIC that is no kernel loopback: the stack admits them inbound.
			netipv4.NewProtocolWithOptions(netipv4.Options{
				AllowExternalLoopbackTraffic: true,
			}),
		},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
		Clock:              f.clock,
	})
	n := &Node{
		f:     f,
		host:  host,
		stack: s,
		link:  channel.New(queueDepth, underlay.BufferSize, ""),
	}
	if err := s.CreateNIC(1, n.link); err != nil {
		f.t.Fatalf("creating %v's NIC: %v", host, err)
	}
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol: header.IPv4ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4(host.As4()),
			PrefixLen: 32,
		},
	}, stack.AddressProperties{}); err != nil {
		f.t.Fatalf("adding %v's address: %v", host, err)
	}
	// Everything the node sends leaves through the one NIC: the fabric's
	// hosts are one hop apart by construction. The loopback pool's hosts
	// need no route at all — the stack carries loopback destinations out
	// its interfaces by itself — and the table's default covers whatever
	// else a lab names.
	subnet, err := tcpip.NewSubnet(
		tcpip.AddrFrom4([4]byte{}), tcpip.MaskFromBytes([]byte{0, 0, 0, 0}))
	if err != nil {
		f.t.Fatalf("building the default route: %v", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: subnet, NIC: 1}})
	f.hosts[host] = n
	f.wg.Add(1)
	go f.forward(n)
	return n
}

// Node is one host's stack on the fabric.
type Node struct {
	f     *Fabric
	host  netip.Addr
	stack *stack.Stack
	link  *channel.Endpoint
}

// Sockets is the socket source that binds on the node's stack: the seam the
// node's sites construct through, its ports the stack's alone and their
// release immediate.
func (n *Node) Sockets() underlay.Sockets {
	return underlay.Sockets{
		ListenUDP: n.listenUDP,
		ListenTCP: n.listenTCP,
	}
}

// listenUDP binds an unconnected UDP socket on the node's stack at the
// concrete address given — per-family ports and immediate release are the
// stack's own facts, so the remote hint names nothing to select. The stack
// draws the port where the address names none.
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
	if tcpErr := ep.Bind(tcpip.FullAddress{
		NIC: 1, Addr: tcpip.AddrFrom4(ap.Addr().As4()), Port: ap.Port(),
	}); tcpErr != nil {
		ep.Close()
		return nil, bindError(tcpErr)
	}
	return &fabricConn{conn: gonet.NewUDPConn(&wq, ep)}, nil
}

// listenTCP binds a TCP listener on the node's stack at the concrete
// address given.
func (n *Node) listenTCP(addr string) (net.Listener, error) {
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

// listenAddr resolves the address a UDP bind names, refusing the wildcard:
// the fabric binds the concrete address it is given. A v4-mapped form names
// the plain address beneath it.
func listenAddr(listen *net.UDPAddr) (netip.AddrPort, error) {
	if listen == nil || listen.IP == nil || listen.IP.IsUnspecified() {
		return netip.AddrPort{}, fmt.Errorf("the fabric binds a concrete address, not %v", listen)
	}
	ip, ok := netip.AddrFromSlice(listen.IP)
	if !ok || !ip.Unmap().Is4() {
		return netip.AddrPort{}, fmt.Errorf("the fabric binds an IPv4 address, not %v", listen.IP)
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(listen.Port)), nil
}

// bindError carries a bind refusal in the errno shape the band allocation's
// probe reads, the held port its own.
func bindError(err tcpip.Error) error {
	if _, ok := err.(*tcpip.ErrPortInUse); ok {
		return os.NewSyscallError("bind", syscall.EADDRINUSE)
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
// pair, the boundaries translate it, and the destination's stack receives
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
		f.clock.AfterFunc(delay, func() { f.translate(held) })
		return
	}
	f.translate(pkt)
}

// translate passes the packet through the drawn boundaries — the first that
// claims it rewrites it, and a boundary drops what it holds no mapping for
// — then delivers it to the destination its address finally names.
func (f *Fabric) translate(pkt []byte) {
	f.mtx.Lock()
	bounds := slices.Clone(f.bounds)
	f.mtx.Unlock()
	for _, b := range bounds {
		rewritten, ok := b.rewrite(pkt)
		if !ok {
			continue
		}
		if rewritten == nil {
			return
		}
		pkt = rewritten
		break
	}
	f.deliver(toNetip(header.IPv4(pkt).DestinationAddress()), pkt)
}

// deliver injects the packet into the stack that holds the destination
// host, dropping it where none does.
func (f *Fabric) deliver(dst netip.Addr, pkt []byte) {
	f.mtx.Lock()
	n := f.hosts[dst]
	f.mtx.Unlock()
	if n == nil {
		return
	}
	n.link.InjectInbound(header.IPv4ProtocolNumber, stack.NewPacketBuffer(
		stack.PacketBufferOptions{Payload: buffer.MakeWithData(pkt)}))
}

// toNetip reads a header address as the plain IPv4 address the taps and the
// boundaries key by.
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

func (c *fabricConn) LocalAddr() *net.UDPAddr {
	return c.conn.LocalAddr().(*net.UDPAddr)
}

// SetReadBuffer and SetWriteBuffer size nothing: the stack's buffers are
// the channel's queue, sized at the fabric's boot.
func (c *fabricConn) SetReadBuffer(int) error  { return nil }
func (c *fabricConn) SetWriteBuffer(int) error { return nil }

func (c *fabricConn) Close() error {
	return c.conn.Close()
}
