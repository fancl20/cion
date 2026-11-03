package egress

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"

	"github.com/fancl20/cion/pkg/libs/bus"
)

// TestNetstackTCPTuning checks the netstack's TCP runs tuned for long lossy
// paths: SACK on, RACK off, reno pinned, and the buffer caps.
func TestNetstackTCPTuning(t *testing.T) {
	app, err := New(Config{Router: newLabRouter(), Tailnet: &bus.Topic[bus.TailnetState]{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Close)
	type tuning struct {
		SACK       tcpip.TCPSACKEnabled
		Recovery   tcpip.TCPRecovery
		Congestion tcpip.CongestionControlOption
		Receive    tcpip.TCPReceiveBufferSizeRangeOption
		Send       tcpip.TCPSendBufferSizeRangeOption
	}
	var got tuning
	for _, opt := range []tcpip.GettableTransportProtocolOption{
		&got.SACK, &got.Recovery, &got.Congestion, &got.Receive, &got.Send,
	} {
		if err := app.stack.TransportProtocolOption(tcp.ProtocolNumber, opt); err != nil {
			t.Fatalf("reading the netstack's TCP option %T: %v", opt, err)
		}
	}
	want := tuning{
		SACK:       true,
		Recovery:   0,
		Congestion: "reno",
		Receive: tcpip.TCPReceiveBufferSizeRangeOption{
			Min:     tcp.MinBufferSize,
			Default: tcp.DefaultReceiveBufferSize,
			Max:     maxTCPReceiveBuffer,
		},
		Send: tcpip.TCPSendBufferSizeRangeOption{
			Min:     tcp.MinBufferSize,
			Default: tcp.DefaultSendBufferSize,
			Max:     maxTCPSendBuffer,
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("the netstack's TCP tuning (-want +got):\n%s", diff)
	}
}

// TestSplicesTCP checks the TCP leg end to end: a host's flow to the
// internet completes its handshake at the egress once the outbound leg is
// dialed, and bytes flow both ways through the splice.
func TestSplicesTCP(t *testing.T) {
	l := newHostLab(t, nil)

	conn, err := dialHost(t, l.host, tcpEcho(t))
	if err != nil {
		t.Fatalf("the host's handshake did not complete at the egress: %v", err)
	}
	if got := roundTrip(t, conn, "through the exit"); got != "through the exit" {
		t.Errorf("echo = %q, want %q", got, "through the exit")
	}
	if got := l.app.flowCount(); got != 1 {
		t.Errorf("flows held = %d, want 1", got)
	}
}

// TestRefusalIsReset checks a destination's refusal reaches the host as a
// reset of its own handshake: the egress dials first, and the dial's
// failure refuses the flow, holding nothing.
func TestRefusalIsReset(t *testing.T) {
	l := newHostLab(t, nil)

	conn, err := dialHost(t, l.host, refusedTCPAddr(t))
	assertRefused(t, "the dial of a refusing destination", conn, err)
	if got := l.app.flowCount(); got != 0 {
		t.Errorf("flows held = %d, want none", got)
	}
	if got := l.app.cnt.droppedPackets.Load(); got != 1 {
		t.Errorf("dropped = %d, want the refused flow", got)
	}
}

// TestMapsUDP checks the UDP leg: a host's flow maps to one socket of the
// node's own, connected to the destination, and the reply returns.
func TestMapsUDP(t *testing.T) {
	l := newHostLab(t, nil)
	internet := udpEcho(t)

	conn := hostUDP(t, l.host, internet)
	if got := roundTrip(t, conn, "udp through the exit"); got != "udp through the exit" {
		t.Errorf("echo = %q, want %q", got, "udp through the exit")
	}
	l.app.mtx.Lock()
	var peers []netip.AddrPort
	for f := range l.app.udpFlows {
		peers = append(peers, f.out.RemoteAddr().(*net.UDPAddr).AddrPort())
	}
	l.app.mtx.Unlock()
	if diff := cmp.Diff([]netip.AddrPort{reachLab(internet)}, peers,
		cmpopts.EquateComparable(netip.AddrPort{})); diff != "" {
		t.Errorf("the UDP flows' sockets' peers (-want +got):\n%s", diff)
	}
}

// TestInternetMapsTheOutboundLegs checks the harness's internet: a host's TCP
// flow and UDP flow toward documentation destinations leave for the loopback
// services the mapping names — the TCP leg's dial and the UDP socket's peer
// — and the echoes return, the netstack answering each from the destination
// the host addressed.
func TestInternetMapsTheOutboundLegs(t *testing.T) {
	tcpDst := netip.MustParseAddrPort("198.51.100.7:7")
	udpDst := netip.MustParseAddrPort("198.51.100.9:9")
	internet := map[netip.AddrPort]netip.AddrPort{
		tcpDst: reachLab(tcpEcho(t)),
		udpDst: reachLab(udpEcho(t)),
	}
	l := newHostLab(t, func(cfg *Config) {
		cfg.Internet = func(dst netip.AddrPort) netip.AddrPort { return internet[dst] }
	})

	conn, err := dialHost(t, l.host, tcpDst)
	if err != nil {
		t.Fatalf("the host's handshake toward %s: %v", tcpDst, err)
	}
	if got := roundTrip(t, conn, "tcp through the exit"); got != "tcp through the exit" {
		t.Errorf("echo = %q, want %q", got, "tcp through the exit")
	}
	// The host's socket is connected to the documentation destination, so
	// only an answer from that address reaches it.
	udp := hostUDP(t, l.host, udpDst)
	if got := roundTrip(t, udp, "udp through the exit"); got != "udp through the exit" {
		t.Errorf("echo = %q, want %q", got, "udp through the exit")
	}

	l.app.mtx.Lock()
	var legs []netip.AddrPort
	for f := range l.app.tcpFlows {
		legs = append(legs, f.out.RemoteAddr().(*net.TCPAddr).AddrPort())
	}
	for f := range l.app.udpFlows {
		legs = append(legs, f.out.RemoteAddr().(*net.UDPAddr).AddrPort())
	}
	l.app.mtx.Unlock()
	if diff := cmp.Diff([]netip.AddrPort{internet[tcpDst], internet[udpDst]}, legs,
		cmpopts.EquateComparable(netip.AddrPort{})); diff != "" {
		t.Errorf("the outbound legs' peers (-want +got):\n%s", diff)
	}
}

// TestUDPMappingOutlivesRefusal checks the connected socket's refusal: once
// the destination answers a datagram with an unreachable port, the flow
// keeps its mapping, and the destination's later replies return through
// the same socket.
func TestUDPMappingOutlivesRefusal(t *testing.T) {
	l := newHostLab(t, nil)
	service := udpEchoAt(t, netip.MustParseAddrPort("127.0.0.1:0"))
	internet := service.LocalAddr().(*net.UDPAddr).AddrPort()
	conn := hostUDP(t, l.host, internetOf(internet))
	roundTrip(t, conn, "before")
	l.app.mtx.Lock()
	var mapped *udpFlow
	for f := range l.app.udpFlows {
		mapped = f
	}
	l.app.mtx.Unlock()

	// The destination's port closes, and a datagram the flow's socket sends
	// there is refused, the refusal waiting on the socket the pump reads.
	_ = service.Close()
	if _, err := mapped.out.Write([]byte("refused")); err != nil {
		t.Fatal(err)
	}
	// The port answers again. The refusal may swallow a datagram the
	// socket sends, so the host sends again until one returns.
	udpEchoAt(t, internet)
	answered := false
	for range 10 {
		if _, err := conn.Write([]byte("after")); err != nil {
			t.Fatal(err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		got := make([]byte, len("after"))
		if n, err := conn.Read(got); err == nil && string(got[:n]) == "after" {
			answered = true
			break
		}
	}
	if !answered {
		t.Fatal("the reopened port's reply never returned")
	}
	l.app.mtx.Lock()
	_, kept := l.app.udpFlows[mapped]
	held := len(l.app.udpFlows)
	l.app.mtx.Unlock()
	if !kept || held != 1 {
		t.Errorf("after the refusal the egress holds %d UDP flows, the first kept %v; "+
			"want the first alone", held, kept)
	}
}

// TestFlowBoundRefuses checks the accounting at the flow bound, TCP flows
// and UDP flows counted together: with the bound held by one TCP flow, a
// second TCP flow is reset and a UDP flow refused, both counted, while an
// echo request, counted against the echo bound alone, still relays.
func TestFlowBoundRefuses(t *testing.T) {
	l := newHostLab(t, func(cfg *Config) {
		cfg.Flows = 1
		cfg.EchoTimeout = time.Hour
	})
	internet := tcpEcho(t)

	held, err := dialHost(t, l.host, internet)
	if err != nil {
		t.Fatalf("the held flow: %v", err)
	}
	roundTrip(t, held, "held")
	if got := l.app.flowCount(); got != 1 {
		t.Fatalf("flows held = %d, want 1", got)
	}

	conn, err := dialHost(t, l.host, internet)
	assertRefused(t, "a TCP flow at the bound", conn, err)
	if got := l.app.cnt.droppedPackets.Load(); got != 1 {
		t.Errorf("dropped = %d after the TCP flow at the bound, want 1", got)
	}
	l.router.send(udpPacket(netip.AddrPortFrom(labHost, 4000), udpEcho(t), "at the bound"))
	if got := l.app.cnt.droppedPackets.Load(); got != 2 {
		t.Errorf("dropped = %d after the UDP flow at the bound, want 2", got)
	}
	dst := netip.MustParseAddr("192.0.2.53")
	l.router.send(echoRequest(labHost, dst, 1, 1, "at the bound"))
	want := relayed{Dst: dst, Type: header.ICMPv4Echo, Seq: 0, Payload: "at the bound"}
	if diff := cmp.Diff(want, decodeRelayed(l.echo.awaitSent(t)),
		cmpopts.EquateComparable(netip.Addr{})); diff != "" {
		t.Errorf("the echo request relayed at the flow bound (-want +got):\n%s", diff)
	}
	if got := l.app.cnt.droppedPackets.Load(); got != 2 {
		t.Errorf("dropped = %d after the echo request, want the two flows alone", got)
	}
	if got := echoCount(l.app); got != 1 {
		t.Errorf("echo mappings held = %d, want the request's", got)
	}
	if got := l.app.flowCount(); got != 1 {
		t.Errorf("flows held = %d, want the first alone", got)
	}
}

// TestIdleSweepExpiresSilentFlows checks the idle bound: flows with traffic
// survive the sweep at their touch, and silent ones — a TCP flow and a UDP
// flow — close and leave the tables, while an echo mapping, which expires
// by the echo timeout alone, stays. The sweep runs at synthetic times, the
// idle bound and the echo timeout an hour away, so no real elapsed time
// decides it.
func TestIdleSweepExpiresSilentFlows(t *testing.T) {
	l := newHostLab(t, func(cfg *Config) {
		cfg.Idle = time.Hour
		cfg.EchoTimeout = time.Hour
	})

	tcpConn, err := dialHost(t, l.host, tcpEcho(t))
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, tcpConn, "touch")
	roundTrip(t, hostUDP(t, l.host, udpEcho(t)), "touch")
	l.router.send(echoRequest(labHost, netip.MustParseAddr("192.0.2.53"), 1, 1, "touch"))
	l.echo.awaitSent(t)
	if got := l.app.flowCount(); got != 2 {
		t.Fatalf("flows held = %d, want 2", got)
	}

	l.app.expireIdle(time.Now().Add(10 * time.Minute))
	if got := l.app.flowCount(); got != 2 {
		t.Fatalf("flows with traffic swept: %d remain, want 2", got)
	}
	l.app.expireIdle(time.Now().Add(2 * time.Hour))
	if got := l.app.flowCount(); got != 0 {
		t.Errorf("flows held after the idle bound = %d, want 0", got)
	}
	if got := echoCount(l.app); got != 1 {
		t.Errorf("echo mappings held after the idle sweep = %d, want 1", got)
	}
	assertClosed(t, "the swept TCP flow", tcpConn)
}

// TestRunJoinsItsFlows checks the stop: once its context is canceled, Run
// closes a spliced flow, whose outbound leg sees its connection close, ends
// a dial blocked until its context ends, and returns only once a dial that
// outlives the stop has returned, closing that flow's outbound leg at once
// and taking it into no table.
func TestRunJoinsItsFlows(t *testing.T) {
	internet := newHoldingListener(t)
	blocked := netip.MustParseAddrPort("192.0.2.1:9")
	late := netip.MustParseAddrPort("192.0.2.2:9")
	dialing := make(chan struct{}, 2)
	release := make(chan struct{})
	releaseLate := sync.OnceFunc(func() { close(release) })
	t.Cleanup(releaseLate)
	l := newHostLab(t, func(cfg *Config) {
		cfg.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			var d net.Dialer
			switch address {
			case blocked.String():
				dialing <- struct{}{}
				<-ctx.Done()
				return nil, ctx.Err()
			case late.String():
				dialing <- struct{}{}
				<-release
				return d.Dial(network, internet.addr.String())
			}
			return d.DialContext(ctx, network, address)
		}
	})

	if _, err := dialHost(t, l.host, internetOf(internet.addr)); err != nil {
		t.Fatalf("the spliced flow: %v", err)
	}
	splicedLeg := internet.next(t)
	// The host's dials of the two blocked destinations wait on handshakes
	// the stop never completes; they end with the test.
	dials, cancelDials := context.WithCancel(context.Background())
	t.Cleanup(cancelDials)
	for _, dst := range []netip.AddrPort{blocked, late} {
		go func() {
			conn, err := gonet.DialContextTCP(dials, l.host, fullAddress(dst), ipv4.ProtocolNumber)
			if err == nil {
				_ = conn.Close()
			}
		}()
	}
	for range 2 {
		select {
		case <-dialing:
		case <-time.After(wait):
			t.Fatal("a flow's dial never started")
		}
	}

	stopped := make(chan error, 1)
	go func() { stopped <- l.stop() }()
	assertClosed(t, "the spliced flow's outbound leg", splicedLeg)
	select {
	case err := <-stopped:
		t.Fatalf("Run returned while a dial was in flight: %v", err)
	default:
	}
	releaseLate()
	assertClosed(t, "the late flow's outbound leg", internet.next(t))
	if err := <-stopped; err != nil {
		t.Fatal(err)
	}
	if got := l.app.flowCount(); got != 0 {
		t.Errorf("flows held after the stop = %d, want none", got)
	}
}
