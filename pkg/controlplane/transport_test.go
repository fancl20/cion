package controlplane

import (
	"context"
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

// testNode is one CION node: data plane with an internal and an external
// link, plus a registered discovery service.
type testNode struct {
	ia        addr.IA
	neighbor  addr.IA
	internal  string
	controlIP netip.Addr
	provider  *dataplane.UDPProvider
	discovery *Discovery
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
	discovery, err := NewDiscovery(DiscoveryConfig{
		IA:           ia,
		ControlAddr:  control,
		MACKey:       testMACKeyBytes,
		InternalAddr: internal,
		Links:        map[uint16]addr.IA{testIfID: neighbor},
		Interval:     discoveryGap,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := discovery.Register(provider); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		provider.Stop()
		discovery.Close() //nolint:errcheck
	})
	go func() { _ = d.Serve(ctx) }()
	go discovery.Run(ctx)

	return &testNode{
		ia:        ia,
		neighbor:  neighbor,
		internal:  internal,
		controlIP: controlAddr.Addr(),
		provider:  provider,
		discovery: discovery,
	}
}

// newConn returns a SCION connection of the node, bound to the control
// address's host with the given port.
func (n *testNode) newConn(t *testing.T, port uint16) *SCIONConn {
	t.Helper()
	conn, err := NewSCIONConn(SCIONConnConfig{
		IA:           n.ia,
		Bind:         netip.AddrPortFrom(n.controlIP, port).String(),
		InternalAddr: n.internal,
		MACKey:       testMACKeyBytes,
		Links:        map[uint16]addr.IA{testIfID: n.neighbor},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() }) //nolint:errcheck
	return conn
}

// TestSCIONConnDatagrams checks that the QUIC-over-SCION transport delivers
// datagrams over one-hop paths in both directions, with replies reversing
// the path.
func TestSCIONConnDatagrams(t *testing.T) {
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

// TestSCIONConnWriteWithoutLink checks that writing to a neighbor without a
// configured link fails instead of sending a bogus path.
func TestSCIONConnWriteWithoutLink(t *testing.T) {
	iaA := addr.MustIAFrom(20, 0xff0000000001)
	iaB := addr.MustIAFrom(20, 0xff0000000002)
	extA, extB := freeUDPAddr(t), freeUDPAddr(t)
	a := startTestNode(t, iaA, iaB, extA, extB)

	connA := a.newConn(t, EndpointPort)
	stranger := &Addr{
		IA:   addr.MustIAFrom(20, 0xff0000000009),
		Addr: netip.MustParseAddrPort("127.0.0.1:1234"),
	}
	if _, err := connA.WriteTo([]byte("hello"), stranger); err == nil {
		t.Error("writing to neighbor without link succeeded, want error")
	}
}
