// Package egress is the egress application: the node's netstack, which ends
// the TCP and UDP flows the hosts send to the internet and opens them again
// from the node's own sockets, relays their echo requests on the node's own
// ICMP socket, and serves the node's own address — the first of its slice —
// to the applications that borrow a listener on it. It borrows the WireGuard
// application's router: the hosts' internet-bound packets arrive through the
// default delivery, the own address's through an address delivery, and every
// packet the netstack and the relay produce leaves through Route toward the
// host it answers.
package egress

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
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"github.com/fancl20/cion/pkg/apps/wireguard"
	"github.com/fancl20/cion/pkg/libs/bus"
	"github.com/fancl20/cion/pkg/libs/loops"
)

// Egress flow policy: flow state is bounded by a code constant and expired
// by idleness, echo mappings are bounded and expired apart from the flows,
// and the outbound legs are the node's own sockets.
const (
	// maxEgressFlows bounds the concurrent flows — TCP flows and UDP flows
	// counted together — one node holds.
	maxEgressFlows = 4096
	// egressIdle is how long a flow stays silent before the egress drops it.
	egressIdle = 5 * time.Minute
	// egressDialTimeout bounds a TCP flow's outbound dial.
	egressDialTimeout = 15 * time.Second
	// maxEchoes bounds the echo mappings — the echo requests awaiting their
	// replies — one node holds. Tailscale's userspace exit allows 20 pings
	// at once, each a ping subprocess; a mapping here is a table entry.
	maxEchoes = 64
	// echoTimeout is how long an echo mapping waits for its reply after its
	// request left.
	echoTimeout = 5 * time.Second
)

// The netstack's TCP buffer caps: the receive window and the send buffer
// grow to these, room for the bandwidth-delay product of a long composed
// path.
const (
	maxTCPReceiveBuffer = 8 << 20
	maxTCPSendBuffer    = 6 << 20
)

// nicID is the netstack's one NIC, on the link the borrowed router feeds.
const nicID tcpip.NICID = 1

// counters are the egress's own accounting: the operating system's tooling
// cannot see in-process relaying, so the application counts. Every counter
// is a monotonic total since start.
type counters struct {
	// droppedPackets counts the packets the egress dropped and the flows it
	// refused: a packet that is no IPv4, a loopback destination, a protocol
	// it carries none of, an echo request the relay cannot carry or past the
	// echo bound, a flow toward the tailnet or past the flow bound, and a
	// flow whose outbound leg failed.
	droppedPackets atomic.Int64
}

// Config configures the application.
type Config struct {
	// Router is the overlay routing the application borrows from the
	// WireGuard application.
	Router wireguard.Router
	// Tailnet is the WireGuard application's tailnet topic; its first event
	// carrying the node's slice names the node's own address.
	Tailnet *bus.Topic[bus.TailnetState]
	// Internet is the integration harness's stand-in for the internet: the
	// address a flow's outbound leg — the TCP dial, the UDP socket's peer —
	// reaches for each destination a host addresses, while the netstack
	// still answers the host from the destination it addressed. Nil
	// reaches each destination itself.
	Internet func(netip.AddrPort) netip.AddrPort

	// Idle overrides the flow idle bound, for tests; zero means the
	// constant.
	Idle time.Duration
	// Flows overrides the flow bound, for tests; zero means the constant.
	Flows int
	// Echoes overrides the echo mapping bound, for tests; zero means the
	// constant.
	Echoes int
	// EchoTimeout overrides the echo timeout, for tests; zero means the
	// constant.
	EchoTimeout time.Duration
	// Dial overrides how a TCP flow dials its outbound leg, for tests; nil
	// means the node's own sockets under the dial timeout.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
	// EchoSocket overrides how Run opens the echo relay's socket, for
	// tests; nil opens the unprivileged ICMP socket.
	EchoSocket func() (icmpSocket, error)
}

// App is the egress application: a netstack whose NIC ends every flow the
// hosts send it, the forwarders that splice and map those flows onto the
// node's own sockets under the flow bound, the idle sweep, and the dial
// timeout, and the echo relay under the echo bound and the echo timeout.
type App struct {
	router      wireguard.Router
	tailnet     *bus.Topic[bus.TailnetState]
	stack       *stack.Stack
	link        *channel.Endpoint
	cnt         *counters
	internet    func(netip.AddrPort) netip.AddrPort
	dial        func(ctx context.Context, network, address string) (net.Conn, error)
	openEcho    func() (icmpSocket, error)
	idle        time.Duration
	bound       int
	echoBound   int
	echoTimeout time.Duration

	// own is the node's own address, set once before claimed closes.
	own netip.Addr
	// claimed closes once the own address stands on the NIC with its
	// delivery installed, waking the listeners waiting for it.
	claimed chan struct{}

	// wg joins Run's loops, the forwarders' goroutines, and the flows'.
	wg sync.WaitGroup

	// mtx guards the fields below. The router runs the deliveries under its
	// own lock, and they take mtx, so no router method runs while mtx is
	// held.
	mtx sync.Mutex
	// ctx is Run's context, which the TCP flows dial under.
	ctx context.Context
	// echoSocket is the socket the echo relay rides; nil where the system
	// offers none.
	echoSocket icmpSocket
	// dialing counts the TCP flows whose outbound leg is dialing, tcpFlows
	// holds the spliced ones, and udpFlows the UDP flows — counted together
	// against the flow bound; echoes holds the echo mappings by relay
	// sequence, counted against the echo bound alone.
	dialing  int
	tcpFlows map[*tcpFlow]struct{}
	udpFlows map[*udpFlow]struct{}
	echoes   map[uint16]echoFlow
	// echoSeq hands out the relay sequences.
	echoSeq uint16
	// stopped marks Run's stop: a flow completing afterward closes its legs
	// instead of entering the tables, and a forwarder's goroutine no longer
	// joins the wait group.
	stopped bool
	// undoDefault and undoOwn uninstall the deliveries Run installed; nil
	// until it installs them.
	undoDefault, undoOwn func()

	closeOnce sync.Once
}

// New assembles the application: the netstack's IPv4 NIC on a link the
// borrowed router feeds, promiscuous and spoofing so a flow to any
// destination ends on it, its TCP tuned for long lossy paths, the tailnet its
// one route — every packet the netstack writes answers a host — and the
// forwarders taking each TCP and UDP flow no endpoint of its own holds. The
// deliveries wait for Run. A failed assembly destroys the netstack it
// created.
func New(cfg Config) (*App, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	a := &App{
		router:      cfg.Router,
		tailnet:     cfg.Tailnet,
		stack:       s,
		link:        channel.New(512, uint32(wireguard.OverlayMTU), ""),
		cnt:         &counters{},
		internet:    cfg.Internet,
		dial:        cfg.Dial,
		openEcho:    cfg.EchoSocket,
		idle:        cfg.Idle,
		bound:       cfg.Flows,
		echoBound:   cfg.Echoes,
		echoTimeout: cfg.EchoTimeout,
		claimed:     make(chan struct{}),
		tcpFlows:    make(map[*tcpFlow]struct{}),
		udpFlows:    make(map[*udpFlow]struct{}),
		echoes:      make(map[uint16]echoFlow),
	}
	if a.internet == nil {
		a.internet = func(dst netip.AddrPort) netip.AddrPort { return dst }
	}
	if a.dial == nil {
		a.dial = (&net.Dialer{Timeout: egressDialTimeout}).DialContext
	}
	if a.openEcho == nil {
		a.openEcho = openICMPSocket
	}
	if a.idle == 0 {
		a.idle = egressIdle
	}
	if a.bound == 0 {
		a.bound = maxEgressFlows
	}
	if a.echoBound == 0 {
		a.echoBound = maxEchoes
	}
	if a.echoTimeout == 0 {
		a.echoTimeout = echoTimeout
	}
	if err := a.assemble(); err != nil {
		s.Destroy()
		return nil, err
	}
	return a, nil
}

// assemble raises the netstack's NIC, its route, and its forwarders.
func (a *App) assemble() error {
	if err := tuneTCP(a.stack); err != nil {
		return err
	}
	if err := a.stack.CreateNIC(nicID, a.link); err != nil {
		return fmt.Errorf("creating the egress NIC: %v", err)
	}
	// Promiscuous, the NIC accepts every destination address; spoofing, the
	// netstack answers from each: a flow to any destination ends here.
	if err := a.stack.SetPromiscuousMode(nicID, true); err != nil {
		return fmt.Errorf("setting the egress NIC promiscuous: %v", err)
	}
	if err := a.stack.SetSpoofing(nicID, true); err != nil {
		return fmt.Errorf("setting the egress NIC spoofing: %v", err)
	}
	tailnet := tcpip.AddressWithPrefix{
		Address:   tcpip.AddrFrom4(wireguard.Tailnet.Masked().Addr().As4()),
		PrefixLen: wireguard.Tailnet.Bits(),
	}
	a.stack.SetRouteTable([]tcpip.Route{{Destination: tailnet.Subnet(), NIC: nicID}})
	a.stack.SetTransportProtocolHandler(tcp.ProtocolNumber,
		tcp.NewForwarder(a.stack, 0, a.bound, a.forwardTCP).HandlePacket)
	a.stack.SetTransportProtocolHandler(udp.ProtocolNumber,
		udp.NewForwarder(a.stack, a.forwardUDP).HandlePacket)
	return nil
}

// Run serves the egress until the context is canceled. The default delivery
// installs as Run starts, for the forwarders dial under Run's context and
// join its wait group, and the own address's at the claim the tailnet
// topic's views make; both stand until Close, the stopped egress dropping
// what they deliver. The netstack's packets route toward their hosts, the
// echo relay reads its replies, idle flows expire, and a sweep every echo
// timeout expires the echo mappings past it. Run returns once every
// goroutine it started has returned, the forwarders' and the netstack's own
// with them.
func (a *App) Run(ctx context.Context) error {
	socket, err := a.openEcho()
	if err != nil {
		socket = nil
		slog.Warn("No unprivileged ICMP socket; the egress drops echo requests", "err", err)
	}
	a.mtx.Lock()
	a.ctx = ctx
	a.echoSocket = socket
	a.mtx.Unlock()
	loops.Go(ctx, &a.wg, "egress drain", a.drain)
	if socket != nil {
		loops.Go(ctx, &a.wg, "egress echo replies", func(context.Context) {
			a.relayEchoReplies(socket)
		})
	}
	undo := a.router.DeliverDefault(a.deliverDefault)
	a.mtx.Lock()
	a.undoDefault = undo
	a.mtx.Unlock()
	tailnet := a.tailnet.Subscribe(ctx)
	sweep := time.NewTicker(a.idle / 2)
	defer sweep.Stop()
	echoes := time.NewTicker(a.echoTimeout)
	defer echoes.Stop()
	for {
		select {
		case <-ctx.Done():
			a.stop()
			return nil
		case view, ok := <-tailnet:
			if !ok {
				tailnet = nil
				continue
			}
			claimed, err := a.follow(view)
			if err != nil {
				a.stop()
				return err
			}
			if claimed {
				tailnet = nil
			}
		case <-sweep.C:
			a.expireIdle(time.Now())
		case <-echoes.C:
			a.expireEchoes(time.Now())
		}
	}
}

// follow claims the own address at the first view carrying the node's
// slice, and reports whether the address stands claimed. The WireGuard
// application never moves an assigned slice, so a later view changes
// nothing.
func (a *App) follow(view bus.TailnetState) (bool, error) {
	select {
	case <-a.claimed:
		return true, nil
	default:
	}
	if !view.Slice.IsValid() {
		return false, nil
	}
	if err := a.claim(view.Slice); err != nil {
		return false, err
	}
	return true, nil
}

// claim makes the slice's first address the node's own: the address joins
// the NIC, its delivery installs, and the listeners waiting for it wake.
func (a *App) claim(slice netip.Prefix) error {
	own := slice.Masked().Addr().Next()
	if err := a.stack.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4(own.As4()),
			PrefixLen: slice.Bits(),
		},
	}, stack.AddressProperties{}); err != nil {
		return fmt.Errorf("adding the own address %s: %v", own, err)
	}
	undo := a.router.Deliver(own, a.deliverOwn)
	a.mtx.Lock()
	a.undoOwn = undo
	a.mtx.Unlock()
	a.own = own
	close(a.claimed)
	slog.Info("Egress serving the node's own address", "addr", own)
	return nil
}

// Listen binds a TCP listener at the node's own address and the port alone,
// for an application that borrows the egress, once the address is claimed:
// it waits for the claim until ctx ends. A flow toward another destination
// at the port still reaches the forwarder.
func (a *App) Listen(ctx context.Context, port uint16) (net.Listener, error) {
	select {
	case <-a.claimed:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	ln, err := gonet.ListenTCP(a.stack, tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFrom4(a.own.As4()),
		Port: port,
	}, ipv4.ProtocolNumber)
	if err != nil {
		return nil, fmt.Errorf("listening at %s: %w", netip.AddrPortFrom(a.own, port), err)
	}
	return ln, nil
}

// stop ends what Run started, its context ended — the dials in flight, which
// take it, end with it. The egress stops taking flows and closes the ones it
// holds, so a flow that completes afterward closes its legs instead of
// entering the tables; the echo socket's close ends the relay's reader, and
// the netstack's close aborts every endpoint left, a borrower's listener
// among them. It returns once the goroutines Run started, the forwarders',
// and the netstack's own have returned.
func (a *App) stop() {
	a.mtx.Lock()
	a.stopped = true
	for f := range a.tcpFlows {
		delete(a.tcpFlows, f)
		f.close()
	}
	for f := range a.udpFlows {
		delete(a.udpFlows, f)
		f.close()
	}
	clear(a.echoes)
	socket := a.echoSocket
	a.mtx.Unlock()
	if socket != nil {
		_ = socket.Close()
	}
	a.stack.Close()
	a.wg.Wait()
	a.stack.Wait()
}

// Close retires the application: the deliveries Run installed uninstall —
// the router counting the hosts' internet-bound packets and the own address
// unroutable again — and, when Run never ran, the netstack closes with the
// link beneath it; Run's stop closed it otherwise. No operating-system
// provisioning exists to undo, and a second call releases nothing.
func (a *App) Close() {
	a.closeOnce.Do(func() {
		a.mtx.Lock()
		ran, undoDefault, undoOwn := a.stopped, a.undoDefault, a.undoOwn
		a.mtx.Unlock()
		for _, undo := range []func(){undoOwn, undoDefault} {
			if undo != nil {
				undo()
			}
		}
		if !ran {
			a.stack.Destroy()
		}
	})
}

// deliverDefault takes a packet the host device decrypted for a destination
// outside the tailnet: a loopback destination drops and counts, TCP and UDP
// enter the netstack's forwarders, ICMP the echo relay, and every other
// protocol drops and counts. The node's loopback serves no host: no client
// takes an answer from a loopback source, so a flow there would reach the
// node's local services one way alone. ICMP never enters the netstack from
// here: promiscuous, it would answer a ping as the internet destination.
func (a *App) deliverDefault(pkt []byte) {
	if !isIPv4(pkt) {
		a.cnt.droppedPackets.Add(1)
		return
	}
	ip := header.IPv4(pkt)
	if addressToNetip(ip.DestinationAddress()).IsLoopback() {
		a.cnt.droppedPackets.Add(1)
		return
	}
	switch ip.TransportProtocol() {
	case tcp.ProtocolNumber, udp.ProtocolNumber:
		a.inject(pkt)
	case header.ICMPv4ProtocolNumber:
		a.relayEcho(pkt)
	default:
		a.cnt.droppedPackets.Add(1)
	}
}

// deliverOwn takes a packet addressed to the node's own address: TCP, UDP,
// and ICMP enter the netstack, which answers a ping to the address and hands
// a connection to the listener a borrower holds at its port, and every other
// protocol drops and counts.
func (a *App) deliverOwn(pkt []byte) {
	if !isIPv4(pkt) {
		a.cnt.droppedPackets.Add(1)
		return
	}
	switch header.IPv4(pkt).TransportProtocol() {
	case tcp.ProtocolNumber, udp.ProtocolNumber, header.ICMPv4ProtocolNumber:
		a.inject(pkt)
	default:
		a.cnt.droppedPackets.Add(1)
	}
}

// isIPv4 reports whether the packet carries an IPv4 header: the egress
// serves IPv4 alone.
func isIPv4(pkt []byte) bool {
	return len(pkt) >= header.IPv4MinimumSize && header.IPVersion(pkt) == header.IPv4Version
}

// inject hands one packet to the netstack.
func (a *App) inject(pkt []byte) {
	a.link.InjectInbound(ipv4.ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(pkt),
	}))
}

// drain moves the packets the netstack wrote — each answering a host — into
// the borrowed router until the context ends.
func (a *App) drain(ctx context.Context) {
	for {
		pkt := a.link.ReadContext(ctx)
		if pkt == nil {
			return
		}
		// Outbound packets carry their headers in the header views, so the
		// wire packet is everything from the (empty) link header on.
		wire := stack.BufferSince(pkt.LinkHeader())
		raw := slices.Clone(wire.Flatten())
		wire.Release()
		pkt.DecRef()
		a.router.Route(raw)
	}
}

// expireIdle closes the flows silent past the idle bound — TCP flows and UDP
// flows alike.
func (a *App) expireIdle(now time.Time) {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	for f := range a.tcpFlows {
		if now.Sub(time.Unix(0, f.last.Load())) > a.idle {
			delete(a.tcpFlows, f)
			f.close()
		}
	}
	for f := range a.udpFlows {
		if now.Sub(time.Unix(0, f.last.Load())) > a.idle {
			delete(a.udpFlows, f)
			f.close()
		}
	}
}

// expireEchoes forgets the echo mappings whose requests left the echo
// timeout or longer before now, so a reply arriving afterward routes
// nothing.
func (a *App) expireEchoes(now time.Time) {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	for seq, e := range a.echoes {
		if now.Sub(e.sent) >= a.echoTimeout {
			delete(a.echoes, seq)
		}
	}
}

// flowCount returns the TCP and UDP flows the egress holds.
func (a *App) flowCount() int {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	return a.flowCountLocked()
}

// flowCountLocked counts the flows against the flow bound: the TCP flows
// dialing and spliced, and the UDP flows. The echo mappings count against
// the echo bound alone.
func (a *App) flowCountLocked() int {
	return a.dialing + len(a.tcpFlows) + len(a.udpFlows)
}

// atCapacityLocked reports whether the egress holds its bound of flows.
func (a *App) atCapacityLocked() bool {
	return a.flowCountLocked() >= a.bound
}

// tuneTCP sets the netstack's TCP for long lossy paths: SACK on, which gVisor
// ships off; RACK loss detection off, for gVisor's RACK handles ACKs late
// enough to retransmit spuriously and shrink the congestion window; reno
// pinned, for gVisor's cubic window arithmetic can overflow; and buffers
// growing to maxTCPReceiveBuffer and maxTCPSendBuffer.
func tuneTCP(s *stack.Stack) error {
	sack := tcpip.TCPSACKEnabled(true)
	recovery := tcpip.TCPRecovery(0)
	reno := tcpip.CongestionControlOption("reno")
	receive := tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     tcp.MinBufferSize,
		Default: tcp.DefaultReceiveBufferSize,
		Max:     maxTCPReceiveBuffer,
	}
	send := tcpip.TCPSendBufferSizeRangeOption{
		Min:     tcp.MinBufferSize,
		Default: tcp.DefaultSendBufferSize,
		Max:     maxTCPSendBuffer,
	}
	for _, opt := range []tcpip.SettableTransportProtocolOption{
		&sack, &recovery, &reno, &receive, &send,
	} {
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, opt); err != nil {
			return fmt.Errorf("setting the netstack's TCP option %T: %v", opt, err)
		}
	}
	return nil
}

// addressToNetip converts a netstack address.
func addressToNetip(a tcpip.Address) netip.Addr {
	ip, ok := netip.AddrFromSlice(a.AsSlice())
	if !ok {
		panic("netstack address is no IP address")
	}
	return ip.Unmap()
}
