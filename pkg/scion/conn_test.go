package scion

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/dataplane"
)

const (
	testIfID   = 1
	testMACKey = "0123456789abcdef"
)

var testMACKeyBytes = []byte(testMACKey)

// testNode is one node of the smallest topology that carries SCION packets:
// a data plane with an internal and an external link.
type testNode struct {
	ia        addr.IA
	neighbor  addr.IA
	internal  string
	controlIP netip.Addr
	provider  *dataplane.UDPProvider
	cancel    context.CancelFunc
}

// startTestNode brings up the node; extRemote must be the neighbor node's
// extLocal, so that traffic crosses the data plane over the direct link
// exactly as between two deployed nodes.
func startTestNode(t *testing.T, ia, neighbor addr.IA, extLocal, extRemote string) *testNode {
	t.Helper()

	internal, control := freeUDPAddr(t), freeUDPAddr(t)
	controlAddr, err := netip.ParseAddrPort(control)
	if err != nil {
		t.Fatal(err)
	}

	metrics, err := dataplane.NewMetrics()
	if err != nil {
		t.Fatal(err)
	}
	provider := dataplane.NewUDPProvider(64, 0, 0)
	il, err := provider.NewInternalLink(internal, 64,
		metrics.NewInterfaceMetrics(0, ia, 0))
	if err != nil {
		t.Fatal(err)
	}
	el, err := provider.NewExternalLink(64, nil, extLocal, extRemote, testIfID,
		metrics.NewInterfaceMetrics(testIfID, ia, 0))
	if err != nil {
		t.Fatal(err)
	}
	local := addr.HostIP(controlAddr.Addr())
	d, err := dataplane.NewDataPlane(ia, local, testMACKeyBytes, provider,
		[]dataplane.Link{il, el})
	if err != nil {
		t.Fatal(err)
	}
	d.RunConfig = dataplane.RunConfig{
		NumProcessors:         2,
		NumSlowPathProcessors: 1,
		BatchSize:             64,
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		provider.Stop()
	})
	go func() { _ = d.Serve(ctx) }()

	return &testNode{
		ia:        ia,
		neighbor:  neighbor,
		internal:  internal,
		controlIP: controlAddr.Addr(),
		provider:  provider,
		cancel:    cancel,
	}
}

// newConn returns a connection of the node, bound to the control address's
// host with the given port.
func (n *testNode) newConn(t *testing.T, port uint16) *Conn {
	t.Helper()
	conn, err := NewConn(ConnConfig{
		IA:           n.ia,
		Bind:         netip.AddrPortFrom(n.controlIP, port).String(),
		InternalAddr: n.internal,
		MACKey:       testMACKeyBytes,
		Links:        func() map[uint16]addr.IA { return map[uint16]addr.IA{testIfID: n.neighbor} },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// freeUDPAddr returns a loopback UDP address with a port picked by the
// kernel.
func freeUDPAddr(t *testing.T) string {
	t.Helper()
	c, err := net.ListenUDP("udp4",
		net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	return c.LocalAddr().String()
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
	if fromB.Addr.Addr() != a.controlIP {
		t.Errorf("peer address = %v, want host %v", fromB.Addr, a.controlIP)
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

// TestConnWriteWithoutLink checks that writing to a neighbor without a
// configured link fails instead of sending a bogus path.
func TestConnWriteWithoutLink(t *testing.T) {
	iaA := addr.MustIAFrom(20, 0xff0000000001)
	iaB := addr.MustIAFrom(20, 0xff0000000002)
	extA, extB := freeUDPAddr(t), freeUDPAddr(t)
	a := startTestNode(t, iaA, iaB, extA, extB)

	connA := a.newConn(t, 30044)
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
	if err := b.provider.AddSvc(svc, addr.HostIP(b.controlIP), connB.LocalPort()); err != nil {
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
	if err := b.provider.AddSvc(addr.SVC(0x7ff1), addr.HostIP(b.controlIP), connB.LocalPort()); err != nil {
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
	underlay := &Addr{IA: ia, Addr: netip.MustParseAddrPort("192.0.2.7:30045")}
	if want := ia.String() + ",192.0.2.7:30045"; underlay.String() != want {
		t.Errorf("underlay string = %q, want %q", underlay.String(), want)
	}
	service := &Addr{IA: ia, Service: addr.SVC(0x7ff1)}
	if want := ia.String() + ",svc:7ff1"; service.String() != want {
		t.Errorf("service string = %q, want %q", service.String(), want)
	}
}
