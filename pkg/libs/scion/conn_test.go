package scion

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/core/dataplane/dataplanetest"
)

const (
	testIfID   = 1
	testMACKey = "0123456789abcdef"
)

var testMACKeyBytes = []byte(testMACKey)

// testNode is one node of the smallest topology that carries SCION packets:
// a data plane with an internal and an external link.
type testNode struct {
	*dataplanetest.Node
}

// startTestNode brings up the node on testHost; extRemote must be the
// neighbor node's extLocal.
func startTestNode(t *testing.T, ia, neighbor addr.IA, extLocal, extRemote string) *testNode {
	t.Helper()
	return &testNode{dataplanetest.StartNode(t, testHost, ia, neighbor, extLocal, extRemote)}
}

// newConn returns a connection of the node, bound to the control address's
// host with the given port.
func (n *testNode) newConn(t *testing.T, port uint16) *Conn {
	t.Helper()
	conn, err := NewConn(ConnConfig{
		IA:           n.IA,
		Bind:         netip.AddrPortFrom(n.ControlIP, port).String(),
		InternalAddr: n.Internal,
		MACKey:       n.MACKey,
		Links:        n.Links,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// testHost is a loopback host no other package's tests bind, for the
// package's fixed-port binds and the ports freeUDPAddr reserves: go test
// runs the packages in parallel, and on a shared host the endhost port
// would collide across packages and a released reservation could be taken
// before its rebind.
var testHost = netip.MustParseAddr("127.0.0.127")

// TestConnAdvertisedAddr checks the address the conn's service-resolution
// replies name: a concrete bind names itself whatever the advertise
// resolver answers, and the wildcard bind names the advertised host at its
// port — nothing while the resolver has learned none, for the bound
// wildcard names no host a peer could dial.
func TestConnAdvertisedAddr(t *testing.T) {
	var host netip.Addr
	advertise := func(context.Context) netip.Addr { return host }
	conn, err := NewConn(ConnConfig{
		IA:           addr.MustIAFrom(20, 0xff0000000001),
		Bind:         netip.AddrPortFrom(testHost, 0).String(),
		InternalAddr: netip.AddrPortFrom(testHost, 30001).String(),
		MACKey:       testMACKeyBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	conn.advertise = advertise
	if advertised, ok := conn.AdvertisedAddr(); !ok || advertised != conn.local {
		t.Errorf("a concrete bind's AdvertisedAddr() = %v, %v, want the bound %v",
			advertised, ok, conn.local)
	}

	wild, err := NewConn(ConnConfig{
		IA:           addr.MustIAFrom(20, 0xff0000000001),
		Bind:         netip.AddrPortFrom(netip.MustParseAddr("0.0.0.0"), 0).String(),
		InternalAddr: netip.AddrPortFrom(testHost, 30001).String(),
		MACKey:       testMACKeyBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = wild.Close() }()
	wild.advertise = advertise
	if _, ok := wild.AdvertisedAddr(); ok {
		t.Error("an unresolved advertise resolver named an address")
	}
	host = netip.MustParseAddr("203.0.113.7")
	advertised, ok := wild.AdvertisedAddr()
	if !ok || advertised != netip.AddrPortFrom(host, wild.local.Port()) {
		t.Errorf("the wildcard's AdvertisedAddr() = %v, %v, want %v at the bound port %v",
			advertised, ok, host, wild.local.Port())
	}
}

// freeUDPAddr returns a UDP address on testHost with a port picked by the
// kernel and released for the caller's bind.
func freeUDPAddr(t *testing.T) string {
	t.Helper()
	return dataplanetest.FreeUDPAddr(t, testHost)
}

// TestConnDatagrams checks that the socket delivers datagrams over one-hop
// paths in both directions, with replies reversing the path.
func TestConnDatagrams(t *testing.T) {
	iaA := addr.MustIAFrom(20, 0xff0000000001)
	iaB := addr.MustIAFrom(20, 0xff0000000002)
	extA, extB := freeUDPAddr(t), freeUDPAddr(t)
	a := startTestNode(t, iaA, iaB, extA, extB)
	b := startTestNode(t, iaB, iaA, extB, extA)

	// Both nodes run on one host, so each binds its own ephemeral port; a
	// deployed server binds the fixed endpoint port instead.
	connA := a.newConn(t, 0)
	connB := b.newConn(t, 0)

	// A dials B by address; the egress interface is resolved from the link
	// table.
	peerB := &Addr{IA: iaB, Addr: connB.LocalAddr().(*Addr).Addr}
	if _, err := connA.WriteTo([]byte("hello"), peerB); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 128)
	if err := connB.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, from, err := connB.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hello" {
		t.Fatalf("datagram = %q, want %q", buf[:n], "hello")
	}
	fromB, ok := from.(*Addr)
	if !ok {
		t.Fatalf("peer address type %T", from)
	}
	if !fromB.IA.Equal(iaA) {
		t.Errorf("peer IA = %v, want %v", fromB.IA, iaA)
	}
	if fromB.Addr.Addr() != a.ControlIP {
		t.Errorf("peer address = %v, want host %v", fromB.Addr, a.ControlIP)
	}
	if fromB.IfID != testIfID {
		t.Errorf("peer ingress interface = %d, want %d", fromB.IfID, testIfID)
	}

	// B replies to the address it read, reversing the path.
	if _, err := connB.WriteTo([]byte("welcome"), from); err != nil {
		t.Fatal(err)
	}
	if err := connA.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, from, err = connA.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "welcome" {
		t.Fatalf("reply = %q, want %q", buf[:n], "welcome")
	}
	if !from.(*Addr).IA.Equal(iaB) {
		t.Errorf("reply IA = %v, want %v", from.(*Addr).IA, iaB)
	}
}

// TestConnWildcardAdvertisedSource checks the source host a wildcard-bound
// conn's packets carry: none until one is learned — the write fails rather
// than naming an address no reply could deliver to — and the advertised one
// after, which the peer reads as the reply route and the wildcard's own
// delivery receives.
func TestConnWildcardAdvertisedSource(t *testing.T) {
	iaA := addr.MustIAFrom(20, 0xff0000000041)
	iaB := addr.MustIAFrom(20, 0xff0000000042)
	extA, extB := freeUDPAddr(t), freeUDPAddr(t)
	a := startTestNode(t, iaA, iaB, extA, extB)
	b := startTestNode(t, iaB, iaA, extB, extA)

	newWildConn := func(n *testNode, host func() netip.Addr) *Conn {
		conn, err := NewConn(ConnConfig{
			IA:           n.IA,
			Bind:         netip.AddrPortFrom(netip.MustParseAddr("0.0.0.0"), 0).String(),
			InternalAddr: n.Internal,
			MACKey:       n.MACKey,
			Links:        n.Links,
			Advertise: func(context.Context) netip.Addr {
				return host()
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	}
	learned := netip.Addr{}
	connA := newWildConn(a, func() netip.Addr { return learned })
	connB := newWildConn(b, func() netip.Addr { return b.ControlIP })

	// The dial names the peer by its advertised host, as a deployment does.
	peerB := &Addr{IA: iaB, Addr: netip.AddrPortFrom(b.ControlIP, connB.LocalPort())}
	if _, err := connA.WriteTo([]byte("hello"), peerB); err == nil {
		t.Error("a wildcard conn without a learned host sent a packet")
	}
	learned = a.ControlIP
	if _, err := connA.WriteTo([]byte("hello"), peerB); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	if err := connB.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, from, err := connB.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hello" {
		t.Fatalf("datagram = %q, want %q", buf[:n], "hello")
	}
	fromA, ok := from.(*Addr)
	if !ok {
		t.Fatalf("peer address type %T", from)
	}
	if fromA.Addr.Addr() != a.ControlIP {
		t.Errorf("the arrival's source host = %v, want the advertised %v",
			fromA.Addr.Addr(), a.ControlIP)
	}

	// The reply rides the advertised source back through the wildcard's own
	// delivery.
	if _, err := connB.WriteTo([]byte("welcome"), from); err != nil {
		t.Fatal(err)
	}
	if err := connA.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, _, err = connA.ReadFrom(buf); err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "welcome" {
		t.Fatalf("reply = %q, want %q", buf[:n], "welcome")
	}
}

// TestConnWriteWithoutLink checks that writing to a neighbor without a
// configured link fails instead of sending a bogus path.
func TestConnWriteWithoutLink(t *testing.T) {
	iaA := addr.MustIAFrom(20, 0xff0000000001)
	iaB := addr.MustIAFrom(20, 0xff0000000002)
	extA, extB := freeUDPAddr(t), freeUDPAddr(t)
	a := startTestNode(t, iaA, iaB, extA, extB)

	connA := a.newConn(t, 0)
	stranger := &Addr{
		IA:   addr.MustIAFrom(20, 0xff0000000009),
		Addr: netip.MustParseAddrPort("127.0.0.1:1234"),
	}
	if _, err := connA.WriteTo([]byte("hello"), stranger); err == nil {
		t.Error("writing to neighbor without link succeeded, want error")
	}
}

// TestConnServiceDestination checks a service destination end to end: the
// sender names the peer by ISD-AS and service value — no port — and the
// receiving AS's internal link delivers to the registered backend's port,
// with the reply riding the ordinary source address back.
func TestConnServiceDestination(t *testing.T) {
	iaA := addr.MustIAFrom(20, 0xff0000000011)
	iaB := addr.MustIAFrom(20, 0xff0000000012)
	extA, extB := freeUDPAddr(t), freeUDPAddr(t)
	a := startTestNode(t, iaA, iaB, extA, extB)
	b := startTestNode(t, iaB, iaA, extB, extA)

	connA := a.newConn(t, 0)
	connB := b.newConn(t, 0)
	svc := addr.SVC(0x7ff1)
	if err := b.Provider.AddSvc(svc, addr.HostIP(b.ControlIP), connB.LocalPort()); err != nil {
		t.Fatal(err)
	}

	if _, err := connA.WriteTo([]byte("hello"), &Addr{IA: iaB, Service: svc}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	if err := connB.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, from, err := connB.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hello" {
		t.Fatalf("datagram = %q, want %q", buf[:n], "hello")
	}
	// The service destination says nothing of the sender: the reply rides
	// the source the packet carried, an ordinary underlay address.
	fromB, ok := from.(*Addr)
	if !ok {
		t.Fatalf("peer address type %T", from)
	}
	if !fromB.IA.Equal(iaA) || fromB.Service != 0 {
		t.Errorf("peer address = %v, want the underlay source in %s", fromB, iaA)
	}

	if _, err := connB.WriteTo([]byte("welcome"), from); err != nil {
		t.Fatal(err)
	}
	if err := connA.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, _, err = connA.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "welcome" {
		t.Fatalf("reply = %q, want %q", buf[:n], "welcome")
	}
}

// TestConnServiceWithoutBackend checks the unanswered send: a service with
// no registered backend fails the receiving router's resolution — the SCMP
// answer is not a send error, and nothing arrives anywhere.
func TestConnServiceWithoutBackend(t *testing.T) {
	iaA := addr.MustIAFrom(20, 0xff0000000021)
	iaB := addr.MustIAFrom(20, 0xff0000000022)
	extA, extB := freeUDPAddr(t), freeUDPAddr(t)
	a := startTestNode(t, iaA, iaB, extA, extB)
	b := startTestNode(t, iaB, iaA, extB, extA)

	// B registers a backend for one service; the sender addresses another.
	connB := b.newConn(t, 0)
	if err := b.Provider.AddSvc(addr.SVC(0x7ff1), addr.HostIP(b.ControlIP), connB.LocalPort()); err != nil {
		t.Fatal(err)
	}
	connA := a.newConn(t, 0)
	unregistered := &Addr{IA: iaB, Service: addr.SVC(0x7ff2)}
	if _, err := connA.WriteTo([]byte("into the void"), unregistered); err != nil {
		t.Fatalf("the unanswered send reported an error: %v", err)
	}
	if err := connB.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	if _, _, err := connB.ReadFrom(buf); err == nil {
		t.Error("a datagram addressed to a service with no backend was delivered")
	}
}

// TestAddrString checks the address's string form: an underlay destination
// as ISD-AS and address, a service destination as ISD-AS and service value.
func TestAddrString(t *testing.T) {
	ia := addr.MustIAFrom(20, 0xff0000000031)
	underlay := &Addr{IA: ia, Addr: netip.MustParseAddrPort("192.0.2.7:40001")}
	if want := ia.String() + ",192.0.2.7:40001"; underlay.String() != want {
		t.Errorf("underlay string = %q, want %q", underlay.String(), want)
	}
	service := &Addr{IA: ia, Service: addr.SVC(0x7ff1)}
	if want := ia.String() + ",svc:7ff1"; service.String() != want {
		t.Errorf("service string = %q, want %q", service.String(), want)
	}
}
