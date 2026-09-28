// Package socks is the SOCKS application: internet egress as a service the
// node's own tailnet address names. RFC 1928 CONNECT and UDP ASSOCIATE are
// served on a gVisor netstack the node runs in-process — the machinery the
// egress already was, its forwarders left behind with the default they served
// — with the listener as the serving surface and the flow bounds, idle sweep,
// and dial timeout unchanged. The application assembles beside the WireGuard
// application and borrows its router the way the coordination application
// borrows its store: the node's own address — the slice's first, which the
// coordination allocator never issues — stands delivered to the application's
// inbound path exactly while the application runs, and the packets the
// netstack produces route back to whatever device the destination claims. It
// carries no selection semantics of its own: it assembles whenever the
// WireGuard application does, every node offering by default, a unit the
// applications architecture record to come can select.
package socks

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
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

	"github.com/fancl20/cion/pkg/apps/wireguard"
)

// Egress flow policy, carried whole by the service: flow state is bounded by a
// code constant and expired by idleness, and the outbound legs are the node's
// own sockets.
const (
	// maxEgressFlows bounds the concurrent flows — CONNECT legs, the
	// associations' outbound sockets, and the associations themselves
	// counted together — one node holds.
	maxEgressFlows = 4096
	// egressIdle is how long a flow stays silent before the service drops
	// it.
	egressIdle = 5 * time.Minute
	// egressDialTimeout bounds an outbound leg's establishment.
	egressDialTimeout = 15 * time.Second
)

// PayloadBudget is the payload an application should assume one UDP
// datagram through the service carries: the tunnel's inner MTU less the
// IPv4 and UDP headers and the ten-byte SOCKS UDP header. It is advisory on
// the inbound wire, where the router's MTU enforcement already bounds the
// reply.
const PayloadBudget = wireguard.OverlayMTU - 20 - 8 - 10

// counters are the service's own accounting: the operating system's tooling
// cannot see in-process relaying, so the application counts. Every counter
// is a monotonic total since start.
type counters struct {
	// droppedPackets counts packets and datagrams the service dropped:
	// protocols it carries none of — internet ICMP, retired with the echo
	// relay — fragmented or malformed datagrams, and bound refusals.
	droppedPackets atomic.Int64
}

// Config configures the application.
type Config struct {
	// Subnet is the node's slice of the tailnet range: the slice's first
	// address — the one the coordination allocator never issues — is the
	// node's own, the address the service claims and answers on.
	Subnet netip.Prefix
	// Router is the overlay routing the application borrows from the
	// WireGuard application: packets the service produces — replies and
	// relays — route to their overlay destinations, and the node's own
	// address stands delivered to the application's inbound path exactly
	// while the application runs. Without the WireGuard application there
	// is nothing to borrow, and this application does not assemble.
	Router wireguard.Router

	// Idle overrides the flow idle bound, for tests; zero means the
	// constant.
	Idle time.Duration
	// Flows overrides the flow bound, for tests; zero means the constant.
	Flows int
}

// App is the SOCKS application: a netstack claiming the node's own address,
// the SOCKS listener bound on it, and the flow machinery — CONNECT legs
// spliced to the node's own sockets and UDP associations relayed through
// them — under the bound, the idle sweep, and the dial timeout the egress
// always ran.
type App struct {
	stack *stack.Stack
	link  *channel.Endpoint
	nicID tcpip.NICID
	// own is the node's own overlay address, the service's serving address.
	own    netip.Addr
	cnt    *counters
	dialer *net.Dialer
	ln     *gonet.TCPListener
	idle   time.Duration
	bound  int

	// route carries the packets netstack produces to the borrowed router.
	route func(pkt []byte)
	// undo uninstalls the own address's delivery.
	undo func()

	mtx sync.Mutex
	// tcpFlows holds the CONNECT legs, udpLegs the associations' outbound
	// sockets, and assocs the associations — TCP and UDP counted together
	// against the bound. The mutex guards the tables and, through them,
	// each association's peer and outbound map.
	tcpFlows map[*tcpFlow]struct{}
	udpLegs  map[*udpLeg]struct{}
	assocs   map[*association]struct{}

	closeOnce sync.Once
}

// New assembles the application: the netstack claims the node's own address
// on a link endpoint the borrowed router feeds, the SOCKS listener binds the
// registered port on that address alone, and the flow tables stand empty.
// The delivery installs here and uninstalls at Close: the address is routed
// exactly while the application exists.
func New(cfg Config) (*App, error) {
	if cfg.Router == nil {
		return nil, fmt.Errorf("no overlay router configured to borrow")
	}
	own := firstAddr(cfg.Subnet)
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			netipv4.NewProtocolWithOptions(netipv4.Options{}),
		},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	link := channel.New(512, uint32(wireguard.OverlayMTU), "")
	a := &App{
		stack:    s,
		link:     link,
		nicID:    1,
		own:      own,
		cnt:      &counters{},
		dialer:   &net.Dialer{Timeout: egressDialTimeout},
		idle:     cfg.Idle,
		bound:    cfg.Flows,
		tcpFlows: make(map[*tcpFlow]struct{}),
		udpLegs:  make(map[*udpLeg]struct{}),
		assocs:   make(map[*association]struct{}),
	}
	if a.idle == 0 {
		a.idle = egressIdle
	}
	if a.bound == 0 {
		a.bound = maxEgressFlows
	}
	if err := s.CreateNIC(a.nicID, link); err != nil {
		return nil, fmt.Errorf("creating the service NIC: %v", err)
	}
	if err := s.AddProtocolAddress(a.nicID, tcpip.ProtocolAddress{
		Protocol: netipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   netipToAddress(own),
			PrefixLen: cfg.Subnet.Bits(),
		},
	}, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("adding the own address: %v", err)
	}
	// The stack's own route covers the tailnet and nothing else: every
	// packet netstack writes — a reply or a relay — names an overlay
	// destination, and the borrowed router carries it from the link, where
	// the real table decides.
	tailnet := wireguard.Tailnet
	subnet, err := tcpip.NewSubnet(
		tcpip.AddrFrom4(tailnet.Masked().Addr().As4()),
		tcpip.MaskFromBytes(prefixMask(tailnet.Bits())))
	if err != nil {
		return nil, fmt.Errorf("building the tailnet route: %w", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: subnet, NIC: a.nicID}})
	ln, err := gonet.ListenTCP(s, tcpip.FullAddress{
		NIC:  a.nicID,
		Addr: netipToAddress(own),
		Port: Port,
	}, netipv4.ProtocolNumber)
	if err != nil {
		return nil, fmt.Errorf("binding the SOCKS listener: %v", err)
	}
	a.ln = ln
	a.route = cfg.Router.Route
	a.undo = cfg.Router.Deliver(own, a.Inbound)
	return a, nil
}

// Inbound takes a plaintext packet the borrowed router delivered to the node's
// own address: TCP and UDP — the listener's legs and the associations' relays
// — enter the netstack, and everything else is dropped and counted, internet
// ICMP included. The echo relay that served it retired with the default it
// served, and no protocol exists to inherit it.
func (a *App) Inbound(pkt []byte) {
	if len(pkt) < header.IPv4MinimumSize || pkt[0]>>4 != 4 {
		a.cnt.droppedPackets.Add(1)
		return
	}
	switch header.IPv4(pkt).TransportProtocol() {
	case tcp.ProtocolNumber, udp.ProtocolNumber:
		a.link.InjectInbound(netipv4.ProtocolNumber,
			stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(pkt),
			}))
	default:
		a.cnt.droppedPackets.Add(1)
	}
}

// Run serves the application until the context is canceled: the listener
// accepts, netstack's own packets route toward their overlay destinations
// through the borrowed router, and idle flows expire.
func (a *App) Run(ctx context.Context) error {
	defer a.Close()
	go a.accept()
	go a.drain(ctx)
	sweep := time.NewTicker(a.idle / 2)
	defer sweep.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-sweep.C:
			a.expireIdle(time.Now())
		}
	}
}

// Close retires the application: the served address's delivery uninstalls —
// the address counting unroutable again — the listener and the link close,
// and every flow and association tears down. No operating-system
// provisioning exists to undo.
func (a *App) Close() {
	a.closeOnce.Do(func() {
		if a.undo != nil {
			a.undo()
		}
		_ = a.ln.Close()
		a.link.Close()
		a.mtx.Lock()
		defer a.mtx.Unlock()
		for f := range a.tcpFlows {
			delete(a.tcpFlows, f)
			f.close()
		}
		for asc := range a.assocs {
			a.teardownLocked(asc)
		}
	})
}

// accept serves the listener until it closes: one conversation per
// connection.
func (a *App) accept() {
	for {
		conn, err := a.ln.Accept()
		if err != nil {
			return
		}
		go a.serve(conn)
	}
}

// drain moves packets netstack wrote — replies and relays — into the
// borrowed router.
func (a *App) drain(ctx context.Context) {
	for {
		pkt := a.link.ReadContext(ctx)
		if pkt == nil {
			return
		}
		// Outbound packets carry their headers in the header views, so the
		// wire packet is everything from the (empty) link header on.
		data := stack.BufferSince(pkt.LinkHeader())
		a.route(slices.Clone(data.Flatten()))
		pkt.DecRef()
	}
}

// expireIdle closes flows silent past the idle bound: CONNECT legs, the
// associations' outbound sockets, and whole associations alike.
func (a *App) expireIdle(now time.Time) {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	for f := range a.tcpFlows {
		if now.Sub(time.Unix(0, f.last.Load())) > a.idle {
			delete(a.tcpFlows, f)
			f.close()
		}
	}
	for l := range a.udpLegs {
		if now.Sub(time.Unix(0, l.last.Load())) > a.idle {
			a.removeLegLocked(l)
		}
	}
	for asc := range a.assocs {
		if now.Sub(time.Unix(0, asc.last.Load())) > a.idle {
			a.teardownLocked(asc)
		}
	}
}

// flowCount returns the flows the service currently holds.
func (a *App) flowCount() int {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	return a.flowCountLocked()
}

func (a *App) flowCountLocked() int {
	return len(a.tcpFlows) + len(a.udpLegs) + len(a.assocs)
}

// atCapacityLocked reports whether the service holds its bound of flows.
func (a *App) atCapacityLocked() bool {
	return a.flowCountLocked() >= a.bound
}

// removeTCPFlow retires one CONNECT leg from the table and closes it.
func (a *App) removeTCPFlow(f *tcpFlow) {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	delete(a.tcpFlows, f)
	f.close()
}

// removeLeg retires one outbound socket from the tables and closes it.
func (a *App) removeLeg(l *udpLeg) {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	a.removeLegLocked(l)
}

func (a *App) removeLegLocked(l *udpLeg) {
	if _, ok := a.udpLegs[l]; !ok {
		return
	}
	delete(a.udpLegs, l)
	delete(l.assoc.out, l.dst)
	_ = l.conn.Close()
}

// teardown sweeps one association on its TCP leg's end, and teardownLocked
// is its held-lock form.
func (a *App) teardown(asc *association) {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	a.teardownLocked(asc)
}

// teardownLocked closes one association whole — the TCP leg whose lifetime
// it is, the relay endpoint, and every outbound socket — releasing the
// tables' flows at once.
func (a *App) teardownLocked(asc *association) {
	if _, ok := a.assocs[asc]; !ok {
		return
	}
	delete(a.assocs, asc)
	_ = asc.tcp.Close()
	_ = asc.relay.Close()
	for _, l := range asc.out {
		a.removeLegLocked(l)
	}
}

// tcpFlow is one spliced CONNECT leg: the service's accepted connection and
// the outbound internet leg.
type tcpFlow struct {
	in, out net.Conn
	last    atomic.Int64
}

func (f *tcpFlow) close() {
	_ = f.in.Close()
	_ = f.out.Close()
}

// association is one UDP ASSOCIATE: the TCP connection its lifetime is, the
// relay endpoint bound on the netstack at the node's own address, and one
// outbound socket per destination the client names. The peer and the
// outbound map are guarded by the App's mutex.
type association struct {
	tcp   net.Conn
	relay *gonet.UDPConn
	// peer is the arrival address the client's datagrams came from — where
	// the replies answer, never the address the TCP request named.
	peer netip.AddrPort
	// out maps each named destination to its outbound socket.
	out  map[netip.AddrPort]*udpLeg
	last atomic.Int64
}

// udpLeg is one destination's outbound socket within an association: the
// socket itself the reply mapping, the shape the egress's UDP mapping
// already was.
type udpLeg struct {
	assoc *association
	dst   netip.AddrPort
	conn  *net.UDPConn
	last  atomic.Int64
}

// spliceConns copies both directions between the legs, propagating
// half-closes, and touches last on every byte moved.
func spliceConns(a, b net.Conn, last *atomic.Int64) {
	var wg sync.WaitGroup
	copyOne := func(dst, src net.Conn) {
		defer wg.Done()
		buf := make([]byte, 32<<10)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				last.Store(time.Now().UnixNano())
				if _, werr := dst.Write(buf[:n]); werr != nil {
					_ = dst.Close()
					_ = src.Close()
					return
				}
			}
			if err != nil {
				// A finished direction half-closes the leg so the peer
				// sees the end of stream instead of a hang.
				if hc, ok := dst.(interface{ CloseWrite() error }); ok {
					_ = hc.CloseWrite()
				} else {
					_ = dst.Close()
				}
				return
			}
		}
	}
	wg.Add(2)
	go copyOne(a, b)
	go copyOne(b, a)
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
}

// firstAddr returns the slice's first address — the node's own, which the
// coordination allocator never issues and the service answers on.
func firstAddr(prefix netip.Prefix) netip.Addr {
	return prefix.Masked().Addr().Next()
}

// netipToAddress converts an overlay address for a netstack header.
func netipToAddress(ip netip.Addr) tcpip.Address {
	return tcpip.AddrFromSlice(ip.AsSlice())
}

// prefixMask renders an IPv4 prefix length as the mask bytes a netstack
// route takes.
func prefixMask(bits int) []byte {
	mask := make([]byte, 4)
	for i := range mask {
		switch {
		case bits >= 8:
			mask[i] = 0xff
		case bits > 0:
			mask[i] = byte(0xff) << (8 - bits)
		}
		bits -= 8
	}
	return mask
}
