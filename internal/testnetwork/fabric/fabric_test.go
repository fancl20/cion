package fabric

import (
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/fancl20/cion/pkg/libs/underlay"
)

// testWait is the proofs' read wait, loose for a loaded runner.
const testWait = 2 * time.Second

// The proofs' hosts, plain names on the fabric.
var (
	insideAddr   = netip.MustParseAddr("127.0.1.11")
	upstreamAddr = netip.MustParseAddr("127.0.1.12")
	strangerAddr = netip.MustParseAddr("127.0.1.14")
)

// listen binds a UDP socket on the node's stack at an ephemeral port of the
// host it holds, closed with the test.
func listen(t *testing.T, n *Node) (underlay.UDPConn, netip.AddrPort) {
	t.Helper()
	c, err := n.Sockets().NewUDP(&net.UDPAddr{IP: n.host.AsSlice()}, netip.AddrPort{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, c.LocalAddr().AddrPort()
}

// send writes one datagram from the socket to the address.
func send(t *testing.T, c underlay.UDPConn, to netip.AddrPort, payload string) {
	t.Helper()
	if _, err := c.WriteToUDP([]byte(payload), net.UDPAddrFromAddrPort(to)); err != nil {
		t.Fatal(err)
	}
}

// recv reads the next datagram within the wait, reporting its payload and
// source; the empty payload and address report silence.
func recv(t *testing.T, c underlay.UDPConn, wait time.Duration) (string, netip.AddrPort) {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(wait)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, underlay.BufferSize)
	n, from, err := c.ReadFromUDP(buf)
	if err != nil {
		return "", netip.AddrPort{}
	}
	return string(buf[:n]), from.AddrPort()
}

// TestRoutingDeliversByDestination is the fabric's own first proof: a
// datagram one stack writes reaches the stack its destination names, the
// source the receiver reads the sender's bound address; a destination no
// stack holds is silence.
func TestRoutingDeliversByDestination(t *testing.T) {
	f := New(t)
	a, b := f.Node(insideAddr), f.Node(upstreamAddr)
	ca, aa := listen(t, a)
	cb, ab := listen(t, b)

	send(t, ca, ab, "to the other stack")
	if got, from := recv(t, cb, testWait); got != "to the other stack" || from != aa {
		t.Fatalf("the other stack received %q from %v, want the datagram from %v", got, from, aa)
	}
	send(t, cb, aa, "and back")
	if got, from := recv(t, ca, testWait); got != "and back" || from != ab {
		t.Fatalf("the first stack received %q from %v, want the datagram from %v", got, from, ab)
	}
	// A destination no stack holds: the silence of an unroutable address.
	send(t, ca, netip.AddrPortFrom(strangerAddr, ab.Port()), "into nothing")
	if got, _ := recv(t, cb, 3*testWait); got != "" {
		t.Fatalf("an unroutable datagram reached the other stack as %q", got)
	}
}

// TestDelayTapHoldsEachPacket checks the delay tap on the fabric's clock:
// a packet of the drawn pair arrives no sooner than the drawn one-way time
// after its send.
func TestDelayTapHoldsEachPacket(t *testing.T) {
	f := New(t)
	a, b := f.Node(insideAddr), f.Node(upstreamAddr)
	ca, _ := listen(t, a)
	cb, ab := listen(t, b)
	const oneWay = 80 * time.Millisecond
	f.Delay(insideAddr, upstreamAddr, oneWay)

	sent := time.Now()
	send(t, ca, ab, "held")
	got, _ := recv(t, cb, 10*oneWay)
	if got != "held" {
		t.Fatalf("the held datagram did not arrive: %q", got)
	}
	if held := time.Since(sent); held < oneWay {
		t.Errorf("the datagram arrived after %v, want no sooner than %v", held, oneWay)
	}
}

// TestDropTapsDropAndLiftRestores checks the dropping taps: the blackhole
// and the cut drop both directions of their pair while they stand, total
// loss beside them, and each lift restores the pair.
func TestDropTapsDropAndLiftRestores(t *testing.T) {
	f := New(t)
	a, b := f.Node(insideAddr), f.Node(upstreamAddr)
	ca, aa := listen(t, a)
	cb, ab := listen(t, b)
	exchange := func() bool {
		send(t, ca, ab, "over the pair")
		got, from := recv(t, cb, testWait)
		return got == "over the pair" && from == aa
	}
	if !exchange() {
		t.Fatal("the pair did not carry before any tap stood")
	}

	for _, tap := range []struct {
		name string
		draw func(netip.Addr, netip.Addr) func()
	}{
		{"the blackhole", f.Blackhole},
		{"the cut", f.Cut},
		{"total loss", func(a, b netip.Addr) func() { return f.Loss(a, b, 1) }},
	} {
		lift := tap.draw(insideAddr, upstreamAddr)
		send(t, ca, ab, "into the drop")
		if got, _ := recv(t, cb, testWait); got != "" {
			t.Fatalf("%s let a datagram through as %q", tap.name, got)
		}
		send(t, cb, aa, "into the drop the other way")
		if got, _ := recv(t, ca, testWait); got != "" {
			t.Fatalf("%s let a reverse datagram through as %q", tap.name, got)
		}
		lift()
		if !exchange() {
			t.Fatalf("the pair did not carry after %s lifted", tap.name)
		}
	}
}

// TestNamesResolveOnEveryStack checks the fabric's names: a name the lab
// drew resolves to its host through every node's socket source, an IPv6
// resolution of it answers nothing, and a name the lab never drew is refused
// as no server holds it.
func TestNamesResolveOnEveryStack(t *testing.T) {
	f := New(t)
	a, b := f.Node(insideAddr), f.Node(upstreamAddr)
	f.Name("core.fabric.test", upstreamAddr)
	for _, n := range []*Node{a, b} {
		got, err := n.Sockets().Lookup(t.Context(), "ip", "core.fabric.test")
		if err != nil || len(got) != 1 || got[0] != upstreamAddr {
			t.Errorf("%v resolved the drawn name to %v, %v; want [%v]", n.host, got, err, upstreamAddr)
		}
	}
	if got, err := a.Sockets().Lookup(t.Context(), "ip6", "core.fabric.test"); err == nil {
		t.Errorf("an IPv6 resolution answered %v, want none on an IPv4 fabric", got)
	}
	var dnsErr *net.DNSError
	if got, err := a.Sockets().Lookup(t.Context(), "ip", "stranger.fabric.test"); !errors.As(err, &dnsErr) ||
		!dnsErr.IsNotFound {
		t.Errorf("an undrawn name resolved to %v, %v; want a not-found refusal", got, err)
	}
}

// TestTapsOnVirtualTime checks the fabric inside a synctest bubble, on
// UDP-only stacks: a delay tap's round trip takes exactly twice its one-way
// time on the bubble's clock, a cut drops both directions — the read's
// deadline expiring at exactly its virtual wait — and the cut's lift
// restores the pair.
func TestTapsOnVirtualTime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := New(t, UDPOnly())
		a, b := f.Node(insideAddr), f.Node(upstreamAddr)
		ca, aa := listen(t, a)
		cb, ab := listen(t, b)
		const oneWay = 30 * time.Second
		f.Delay(insideAddr, upstreamAddr, oneWay)

		sent := time.Now()
		send(t, ca, ab, "there")
		if got, _ := recv(t, cb, 2*oneWay); got != "there" {
			t.Fatalf("the held datagram did not arrive: %q", got)
		}
		send(t, cb, aa, "and back")
		if got, _ := recv(t, ca, 2*oneWay); got != "and back" {
			t.Fatalf("the held reply did not arrive: %q", got)
		}
		if rtt := time.Since(sent); rtt != 2*oneWay {
			t.Errorf("the round trip took %v of virtual time, want exactly %v", rtt, 2*oneWay)
		}

		lift := f.Cut(insideAddr, upstreamAddr)
		for _, dir := range []struct {
			from, to underlay.UDPConn
			at       netip.AddrPort
		}{{ca, cb, ab}, {cb, ca, aa}} {
			waited := time.Now()
			send(t, dir.from, dir.at, "into the cut")
			if got, _ := recv(t, dir.to, testWait); got != "" {
				t.Fatalf("the cut let a datagram through as %q", got)
			}
			if spent := time.Since(waited); spent != testWait {
				t.Errorf("the read under the cut gave up after %v, want exactly %v", spent, testWait)
			}
		}
		lift()
		send(t, ca, ab, "after the lift")
		if got, _ := recv(t, cb, 2*oneWay); got != "after the lift" {
			t.Fatalf("the pair did not carry after the cut lifted: %q", got)
		}
	})
}

// TestUDPOnlyRefusesTCP checks the UDP-only stack's one refusal: it binds no
// TCP listener, and says why.
func TestUDPOnlyRefusesTCP(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := New(t, UDPOnly()).Node(insideAddr)
		if ln, err := n.Sockets().NewTCP(netip.AddrPortFrom(insideAddr, 8443).String()); err == nil {
			_ = ln.Close()
			t.Fatal("a UDP-only stack bound a TCP listener")
		}
	})
}

// TestDrawPortStaysBelowTheEphemeralRange checks the port draws: each draw
// is a fresh port below the stack's ephemeral range, and the drawn port
// binds.
func TestDrawPortStaysBelowTheEphemeralRange(t *testing.T) {
	n := New(t).Node(insideAddr)
	first, _ := n.stack.PortRange()
	seen := map[uint16]bool{}
	for range 3 {
		port := n.DrawPort()
		if port >= first || seen[port] {
			t.Fatalf("drew port %d after %v, want a fresh one below %d", port, seen, first)
		}
		seen[port] = true
		c, err := n.Sockets().NewUDP(net.UDPAddrFromAddrPort(netip.AddrPortFrom(insideAddr, port)),
			netip.AddrPort{})
		if err != nil {
			t.Fatalf("binding drawn port %d: %v", port, err)
		}
		_ = c.Close()
	}
}

// TestBindRefusesAHostTheStackLacks checks a bind's refusals carry the
// kernel's errnos: a host the stack does not hold — a translator's gateway
// among them — refuses with EADDRNOTAVAIL, and a held port with EADDRINUSE.
func TestBindRefusesAHostTheStackLacks(t *testing.T) {
	n := New(t).Node(insideAddr)
	_, err := n.Sockets().NewUDP(&net.UDPAddr{IP: upstreamAddr.AsSlice()}, netip.AddrPort{})
	if !errors.Is(err, syscall.EADDRNOTAVAIL) {
		t.Errorf("a bind on a host the stack lacks = %v, want EADDRNOTAVAIL", err)
	}
	_, held := listen(t, n)
	if _, err := n.Sockets().NewUDP(net.UDPAddrFromAddrPort(held), netip.AddrPort{}); !errors.Is(err, syscall.EADDRINUSE) {
		t.Errorf("a bind on a held port = %v, want EADDRINUSE", err)
	}
}
