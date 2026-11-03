package egress

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/fancl20/cion/pkg/libs/bus"
)

// TestClaimsTheOwnAddressOnTheSlice checks the claim end to end: before the
// tailnet topic carries the node's slice the own address is unclaimed — no
// delivery for it, a listener still waiting — and once it does, the
// address's delivery installs and the waiting listener binds; the stop and
// the close leave no delivery standing.
func TestClaimsTheOwnAddressOnTheSlice(t *testing.T) {
	l := newLab(t, nil)
	type listened struct {
		ln  net.Listener
		err error
	}
	listening := make(chan listened, 1)
	go func() {
		ln, err := l.app.Listen(t.Context(), 80)
		listening <- listened{ln, err}
	}()

	if diff := cmp.Diff([]string{"default"}, l.router.installed()); diff != "" {
		t.Errorf("the deliveries before the slice (-want +got):\n%s", diff)
	}
	select {
	case got := <-listening:
		t.Fatalf("Listen returned before the slice: %v", got.err)
	default:
	}

	l.topic.Publish(bus.TailnetState{Slice: labSlice})
	if got := l.router.awaitInstall(t); got != labOwn.String() {
		t.Errorf("the delivery the slice installed = %s, want the own address %s", got, labOwn)
	}
	select {
	case got := <-listening:
		if got.err != nil {
			t.Fatalf("Listen once the slice arrived: %v", got.err)
		}
		_ = got.ln.Close()
	case <-time.After(wait):
		t.Fatal("Listen never woke once the slice arrived")
	}

	if err := l.stop(); err != nil {
		t.Fatal(err)
	}
	l.app.Close()
	if diff := cmp.Diff([]string{}, l.router.installed()); diff != "" {
		t.Errorf("the deliveries after the close (-want +got):\n%s", diff)
	}
}

// TestClaimFollowsTheFirstSlice checks the claim's rule: a view without the
// node's slice claims nothing, the first view carrying it claims its first
// address, and a later view — a slice the WireGuard application never moves
// to — changes nothing. A close without Run uninstalls the address's
// delivery, and a second close releases nothing.
func TestClaimFollowsTheFirstSlice(t *testing.T) {
	router := newLabRouter()
	app, err := New(Config{Router: router, Tailnet: &bus.Topic[bus.TailnetState]{}})
	if err != nil {
		t.Fatal(err)
	}
	var trace []bool
	for _, view := range []bus.TailnetState{
		{Nodes: []bus.TailnetNode{{Slice: netip.MustParsePrefix("100.64.2.0/24")}}},
		{Slice: labSlice},
		{Slice: netip.MustParsePrefix("100.64.9.0/24")},
	} {
		claimed, err := app.follow(view)
		if err != nil {
			t.Fatalf("following %+v: %v", view, err)
		}
		trace = append(trace, claimed)
	}
	if diff := cmp.Diff([]bool{false, true, true}, trace); diff != "" {
		t.Errorf("the claim after each view (-want +got):\n%s", diff)
	}
	if app.own != labOwn {
		t.Errorf("the own address = %s, want %s", app.own, labOwn)
	}
	if diff := cmp.Diff([]string{labOwn.String()}, router.installed()); diff != "" {
		t.Errorf("the deliveries (-want +got):\n%s", diff)
	}
	app.Close()
	if diff := cmp.Diff([]string{}, router.installed()); diff != "" {
		t.Errorf("the deliveries after the close (-want +got):\n%s", diff)
	}
	app.Close()
}

// TestPingsTheOwnAddress checks the own address's echo: a host's ping to it
// enters the netstack, which answers from the address, while the echo relay
// sends nothing.
func TestPingsTheOwnAddress(t *testing.T) {
	l := newLab(t, nil)
	l.claim(t)

	if !l.router.send(echoRequest(labHost, labOwn, 0x4242, 7, "ping")) {
		t.Fatal("no delivery took the ping to the own address")
	}
	want := icmpPacket{
		Src: labOwn, Dst: labHost,
		Type: header.ICMPv4EchoReply, Ident: 0x4242, Seq: 7, Payload: "ping",
		Summed: true,
	}
	if diff := cmp.Diff(want, decodeICMP(t, l.router.awaitRouted(t)),
		cmpopts.EquateComparable(netip.Addr{})); diff != "" {
		t.Errorf("the own address's echo reply (-want +got):\n%s", diff)
	}
	if got := len(l.echo.sent); got != 0 {
		t.Errorf("the echo relay sent %d requests, want none", got)
	}
}

// TestListenerAnswersOnTheOwnAddressAlone checks a borrower's listener: a
// host's connection to the own address at its port reaches it, one to an
// internet destination at the same port reaches the forwarder and its
// outbound leg, and one to the own address at a port no listener holds is
// refused with a reset.
func TestListenerAnswersOnTheOwnAddressAlone(t *testing.T) {
	internet := reachLab(tcpEcho(t))
	dialed := make(chan string, 1)
	l := newHostLab(t, func(cfg *Config) {
		cfg.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			dialed <- address
			var d net.Dialer
			return d.DialContext(ctx, network, internet.String())
		}
	})
	l.claim(t)
	ln, err := l.app.Listen(t.Context(), 80)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	accepted := make(chan net.Conn, 2)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- conn
		}
	}()

	conn, err := dialHost(t, l.host, netip.AddrPortFrom(labOwn, 80))
	if err != nil {
		t.Fatalf("the host's dial of the own address: %v", err)
	}
	var served net.Conn
	select {
	case served = <-accepted:
		t.Cleanup(func() { _ = served.Close() })
	case <-time.After(wait):
		t.Fatal("the listener accepted nothing")
	}
	if _, err := served.Write([]byte("from the listener")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("from the listener"))
	_ = conn.SetReadDeadline(time.Now().Add(wait))
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != "from the listener" {
		t.Errorf("the host read %q, %v from the listener's connection", got, err)
	}

	elsewhere := netip.MustParseAddrPort("192.0.2.80:80")
	forwarded, err := dialHost(t, l.host, elsewhere)
	if err != nil {
		t.Fatalf("the host's dial of %s at the listener's port: %v", elsewhere, err)
	}
	if got := roundTrip(t, forwarded, "forwarded"); got != "forwarded" {
		t.Errorf("echo = %q, want %q", got, "forwarded")
	}
	if got := <-dialed; got != elsewhere.String() {
		t.Errorf("the forwarder dialed %s, want %s", got, elsewhere)
	}
	select {
	case conn := <-accepted:
		_ = conn.Close()
		t.Error("the listener accepted the flow to another destination")
	default:
	}

	unheld, err := dialHost(t, l.host, netip.AddrPortFrom(labOwn, 81))
	assertRefused(t, "the dial of the own address at a port no listener holds", unheld, err)
}

// TestRefusesUDPToTheOwnAddress checks a UDP flow to the own address at a
// port nothing holds: the forwarder declines it, counted, and the netstack
// answers the host with an unreachable port.
func TestRefusesUDPToTheOwnAddress(t *testing.T) {
	l := newLab(t, nil)
	l.claim(t)

	l.router.send(udpPacket(netip.AddrPortFrom(labHost, 4000), netip.AddrPortFrom(labOwn, 5353), "own"))
	if got := l.app.cnt.droppedPackets.Load(); got != 1 {
		t.Errorf("dropped = %d, want the refused flow", got)
	}
	want := icmpPacket{
		Src: labOwn, Dst: labHost,
		Type: header.ICMPv4DstUnreachable, Code: header.ICMPv4PortUnreachable,
	}
	if diff := cmp.Diff(want, decodeICMP(t, l.router.awaitRouted(t)),
		cmpopts.EquateComparable(netip.Addr{}),
		cmpopts.IgnoreFields(icmpPacket{}, "Ident", "Seq", "Payload", "Summed")); diff != "" {
		t.Errorf("the netstack's answer (-want +got):\n%s", diff)
	}
	if got := l.app.flowCount(); got != 0 {
		t.Errorf("flows held = %d, want none", got)
	}
}
