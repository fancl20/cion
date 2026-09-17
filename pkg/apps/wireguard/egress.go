package wireguard

import (
	"context"
	"fmt"
	"log/slog"
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
	"gvisor.dev/gvisor/pkg/waiter"
)

// Egress flow policy (ADR-0005): flow state is bounded by a code constant
// and expired by idleness, and a flow lives and dies on one exit.
const (
	// maxEgressFlows bounds the concurrent internet flows — TCP, UDP, and
	// echo mappings counted together — one exit holds.
	maxEgressFlows = 4096
	// egressIdle is how long a flow stays silent before the exit drops it.
	egressIdle = 5 * time.Minute
	// egressDialTimeout bounds an outbound leg's establishment.
	egressDialTimeout = 15 * time.Second
)

// egress is the node's internet exit: an embedded gVisor netstack
// terminating default-routed overlay flows — the host completes its TCP
// handshake with the exit, not the destination — spliced to traffic from the
// node's own sockets. TCP flows splice to one outbound connection, UDP flows
// map to one rewritten socket, and echo ICMP is relayed per identifier;
// other IP protocols are dropped.
type egress struct {
	stack  *stack.Stack
	link   *channel.Endpoint
	nicID  tcpip.NICID
	cnt    *counters
	echo   *echoRelay
	dialer *net.Dialer
	// routeOut hands packets netstack produced — replies and relays — to
	// the router; the mutex guards its late installation.
	routeOut func(pkt []byte)
	// idle is the flow idle bound.
	idle time.Duration

	mtx      sync.Mutex
	tcpFlows map[*tcpFlow]struct{}
	udpFlows map[*udpFlow]struct{}
}

// egressConfig configures the netstack egress.
type egressConfig struct {
	// OverlayAddr is the exit node's own overlay address.
	OverlayAddr netip.Addr
	// OverlayPrefix is the node's overlay subnet.
	OverlayPrefix netip.Prefix
	// MTU is the overlay MTU the link endpoint reports.
	MTU int
	// Cnt receives the egress counters.
	Cnt *counters
	// EchoSocket carries the echo relay's datagrams; nil uses the
	// unprivileged ICMP socket, and the relay degrades to dropping when the
	// operating system offers none.
	EchoSocket icmpSocket
	// Idle overrides the flow idle bound, for tests; zero means the
	// constant.
	Idle time.Duration
}

// newEgress builds the exit's netstack: an IPv4 NIC on a link endpoint the
// router feeds, promiscuous and spoofing so flows to any internet
// destination terminate on the overlay addresses, and TCP and UDP forwarders
// catching every flow.
func newEgress(cfg egressConfig) (*egress, error) {
	s := stack.New(stack.Options{
		// An exit terminates whatever destination a host addressed, the
		// loopback range included; netstack would otherwise drop those as
		// martian packets.
		NetworkProtocols: []stack.NetworkProtocolFactory{
			netipv4.NewProtocolWithOptions(netipv4.Options{
				AllowExternalLoopbackTraffic: true,
			}),
		},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	link := channel.New(512, uint32(cfg.MTU), "")
	e := &egress{
		stack:    s,
		link:     link,
		nicID:    1,
		cnt:      cfg.Cnt,
		dialer:   &net.Dialer{Timeout: egressDialTimeout},
		idle:     cfg.Idle,
		tcpFlows: make(map[*tcpFlow]struct{}),
		udpFlows: make(map[*udpFlow]struct{}),
	}
	if e.idle == 0 {
		e.idle = egressIdle
	}
	if err := s.CreateNIC(e.nicID, link); err != nil {
		return nil, fmt.Errorf("creating the egress NIC: %v", err)
	}
	// Promiscuous accepts every destination address; spoofing makes the
	// stack treat each as its own — an internet destination terminates here.
	s.SetPromiscuousMode(e.nicID, true)
	s.SetSpoofing(e.nicID, true)
	addr := tcpip.AddressWithPrefix{
		Address:   tcpip.AddrFromSlice(cfg.OverlayAddr.AsSlice()),
		PrefixLen: cfg.OverlayPrefix.Bits(),
	}
	if err := s.AddProtocolAddress(e.nicID, tcpip.ProtocolAddress{
		Protocol:          netipv4.ProtocolNumber,
		AddressWithPrefix: addr,
	}, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("adding the overlay address: %v", err)
	}
	// Every flow terminates on this NIC, whatever its destination address;
	// the forwarders' endpoints bind against the default route.
	defaultSubnet, err := tcpip.NewSubnet(
		tcpip.AddrFrom4([4]byte{}), tcpip.MaskFromBytes([]byte{0, 0, 0, 0}))
	if err != nil {
		return nil, fmt.Errorf("building the default route: %w", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: defaultSubnet, NIC: e.nicID}})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcp.NewForwarder(s, 0, maxEgressFlows, e.handleTCP).HandlePacket)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udp.NewForwarder(s, e.handleUDP).HandlePacket)
	e.echo = newEchoRelay(cfg.Cnt, cfg.EchoSocket, cfg.Idle)
	return e, nil
}

// setRouter installs the sink netstack's own packets route through.
func (e *egress) setRouter(routeOut func(pkt []byte)) {
	e.mtx.Lock()
	defer e.mtx.Unlock()
	e.routeOut = routeOut
}

// sink routes a packet netstack produced, when a sink is installed.
func (e *egress) sink(pkt []byte) {
	e.mtx.Lock()
	routeOut := e.routeOut
	e.mtx.Unlock()
	if routeOut != nil {
		routeOut(pkt)
	}
}

// Inbound takes a default-routed plaintext packet from the router: TCP and
// UDP flows enter the netstack, echo ICMP enters the relay, and the rest are
// dropped.
func (e *egress) Inbound(pkt []byte) {
	if len(pkt) < header.IPv4MinimumSize || pkt[0]>>4 != 4 {
		e.cnt.egressDroppedPackets.Add(1)
		return
	}
	switch header.IPv4(pkt).TransportProtocol() {
	case tcp.ProtocolNumber, udp.ProtocolNumber:
		e.link.InjectInbound(netipv4.ProtocolNumber,
			stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(pkt),
			}))
	case header.ICMPv4ProtocolNumber:
		e.echo.request(pkt, e.sink)
	default:
		e.cnt.egressDroppedPackets.Add(1)
	}
}

// run serves the egress until the context ends: netstack's own packets
// route toward their overlay destinations, the echo relay listens, and idle
// flows expire.
func (e *egress) run(ctx context.Context) {
	defer e.echo.close()
	go e.echo.readLoop(e.sink)
	go e.drain(ctx)
	sweep := time.NewTicker(e.idle / 2)
	defer sweep.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-sweep.C:
			e.expireIdle(time.Now())
		}
	}
}

// drain moves packets netstack wrote — replies toward their overlay
// destinations — into the router.
func (e *egress) drain(ctx context.Context) {
	for {
		pkt := e.link.ReadContext(ctx)
		if pkt == nil {
			return
		}
		// Outbound packets carry their headers in the header views, so the
		// wire packet is everything from the (empty) link header on.
		data := stack.BufferSince(pkt.LinkHeader())
		e.sink(slices.Clone(data.Flatten()))
		pkt.DecRef()
	}
}

// expireIdle closes flows silent past the idle bound and drops stale echo
// mappings.
func (e *egress) expireIdle(now time.Time) {
	e.mtx.Lock()
	defer e.mtx.Unlock()
	for f := range e.tcpFlows {
		if now.Sub(time.Unix(0, f.last.Load())) > e.idle {
			f.close()
			delete(e.tcpFlows, f)
		}
	}
	for f := range e.udpFlows {
		if now.Sub(time.Unix(0, f.last.Load())) > e.idle {
			f.close()
			delete(e.udpFlows, f)
		}
	}
	e.echo.expire(now)
}

// flowCount returns the flows the exit currently holds.
func (e *egress) flowCount() int {
	e.mtx.Lock()
	defer e.mtx.Unlock()
	return len(e.tcpFlows) + len(e.udpFlows) + e.echo.len()
}

// atCapacity reports whether the exit holds its bound of flows.
func (e *egress) atCapacity() bool {
	e.mtx.Lock()
	defer e.mtx.Unlock()
	return len(e.tcpFlows)+len(e.udpFlows)+e.echo.len() >= maxEgressFlows
}

// handleTCP splices one terminated TCP flow — the host completed its
// handshake with the exit — to one outbound connection dialed from the
// node's own address, each direction a copy between the legs.
func (e *egress) handleTCP(req *tcp.ForwarderRequest) {
	if e.atCapacity() {
		e.cnt.egressDroppedPackets.Add(1)
		req.Complete(true) // refuse with a reset
		return
	}
	var wq waiter.Queue
	// The request's identity must be read before Complete retires it.
	id := req.ID()
	ep, err := req.CreateEndpoint(&wq)
	req.Complete(false)
	if err != nil {
		e.cnt.egressDroppedPackets.Add(1)
		slog.Warn("Egress TCP flow did not establish", "err", err)
		return
	}
	dst := netip.AddrPortFrom(addressToNetip(id.LocalAddress), id.LocalPort)
	out, dialErr := e.dialer.DialContext(context.Background(), "tcp", dst.String())
	if dialErr != nil {
		e.cnt.egressDroppedPackets.Add(1)
		slog.Warn("Egress dialing the internet leg", "dst", dst, "err", dialErr)
		return
	}
	flow := &tcpFlow{in: gonet.NewTCPConn(&wq, ep), out: out}
	e.mtx.Lock()
	e.tcpFlows[flow] = struct{}{}
	e.mtx.Unlock()
	go func() {
		defer func() {
			flow.close()
			e.mtx.Lock()
			delete(e.tcpFlows, flow)
			e.mtx.Unlock()
		}()
		spliceConns(flow.in, flow.out, &flow.last)
	}()
}

// handleUDP maps one UDP flow to a single outbound socket with the
// addresses rewritten; the socket itself is the reply mapping.
func (e *egress) handleUDP(req *udp.ForwarderRequest) {
	if e.atCapacity() {
		e.cnt.egressDroppedPackets.Add(1)
		return
	}
	var wq waiter.Queue
	ep, err := req.CreateEndpoint(&wq)
	if err != nil {
		e.cnt.egressDroppedPackets.Add(1)
		return
	}
	out, listenErr := net.ListenUDP("udp", nil)
	if listenErr != nil {
		e.cnt.egressDroppedPackets.Add(1)
		slog.Warn("Egress binding the UDP leg", "err", listenErr)
		return
	}
	id := req.ID()
	dst := netip.AddrPortFrom(addressToNetip(id.LocalAddress), id.LocalPort)
	flow := &udpFlow{in: gonet.NewUDPConn(&wq, ep), out: out, dst: dst}
	e.mtx.Lock()
	e.udpFlows[flow] = struct{}{}
	e.mtx.Unlock()
	go flow.pump(e)
}

// tcpFlow is one spliced TCP flow: the terminated overlay leg and the
// outbound internet leg.
type tcpFlow struct {
	in, out net.Conn
	last    atomic.Int64
}

// udpFlow is one mapped UDP flow.
type udpFlow struct {
	in   *gonet.UDPConn
	out  *net.UDPConn
	dst  netip.AddrPort
	last atomic.Int64
}

func (f *tcpFlow) close() {
	_ = f.in.Close()
	_ = f.out.Close()
}

func (f *udpFlow) close() {
	_ = f.in.Close()
	_ = f.out.Close()
}

// pump relays both directions of a UDP flow until a leg fails.
func (f *udpFlow) pump(e *egress) {
	defer func() {
		f.close()
		e.mtx.Lock()
		delete(e.udpFlows, f)
		e.mtx.Unlock()
	}()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 64<<10)
		for {
			n, err := f.in.Read(buf)
			if err != nil {
				return
			}
			f.last.Store(time.Now().UnixNano())
			if _, err := f.out.WriteToUDPAddrPort(buf[:n], f.dst); err != nil {
				return
			}
		}
	}()
	buf := make([]byte, 64<<10)
	for {
		n, _, err := f.out.ReadFromUDPAddrPort(buf)
		if err != nil {
			break
		}
		f.last.Store(time.Now().UnixNano())
		if _, err := f.in.Write(buf[:n]); err != nil {
			break
		}
	}
	<-done
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

// addressToNetip converts a netstack address.
func addressToNetip(a tcpip.Address) netip.Addr {
	ip, ok := netip.AddrFromSlice(a.AsSlice())
	if !ok {
		return netip.Addr{}
	}
	return ip.Unmap()
}
