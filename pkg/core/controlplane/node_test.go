package controlplane

import (
	"net/netip"
	"testing"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/core/dataplane/dataplanetest"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/scionrpc"
)

const testMACKey = "0123456789abcdef"

// testHost is a loopback host no other package's tests bind, for the
// package's fixed-port binds and the ports freeUDPAddr reserves: go test
// runs the packages in parallel, and on a shared host the endpoint port
// would collide across packages and a released reservation could be taken
// before its rebind.
var testHost = netip.MustParseAddr("127.0.0.125")

// freeUDPAddr returns a UDP address on testHost with a port picked by the
// kernel and released for the caller's bind.
func freeUDPAddr(t *testing.T) string {
	t.Helper()
	return dataplanetest.FreeUDPAddr(t, testHost)
}

// testNode is one CION node: a data plane with an internal and an external
// link, plus the CS service registered on the control endpoint's socket —
// the drafts' service routing the endpoint's own traffic rides.
type testNode struct {
	*dataplanetest.Node
}

// startTestNode brings up the node on testHost; extRemote must be the
// neighbor node's extLocal.
func startTestNode(t *testing.T, ia, neighbor addr.IA, extLocal, extRemote string) *testNode {
	t.Helper()
	n := dataplanetest.StartNode(t, testHost, ia, neighbor, extLocal, extRemote)
	// The control service maps to the endpoint's socket, the address a
	// served endpoint (serveCore) binds.
	n.MapService(t, addr.SvcCS, scionrpc.EndpointPort)
	return &testNode{n}
}

// newConn returns a SCION connection of the node, bound to the control
// address's host with the given port.
func (n *testNode) newConn(t *testing.T, port uint16) *scion.Conn {
	t.Helper()
	conn, err := scion.NewConn(scion.ConnConfig{
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
