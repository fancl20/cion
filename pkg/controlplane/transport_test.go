package controlplane

import (
	"context"
	"net/netip"
	"testing"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/dataplane"
	"github.com/fancl20/cion/pkg/scion"
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
		cancel:    cancel,
	}
}

// newConn returns a SCION connection of the node, bound to the control
// address's host with the given port.
func (n *testNode) newConn(t *testing.T, port uint16) *scion.Conn {
	t.Helper()
	conn, err := scion.NewConn(scion.ConnConfig{
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
