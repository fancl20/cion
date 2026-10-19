package fabric

import (
	"net"
	"net/netip"
	"testing"
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
