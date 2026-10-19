// Package dataplanetest runs a data plane for the tests of what rides it: a
// node of the smallest topology that carries SCION packets, one internal
// and one external link, on loopback sockets of the caller's host. Two
// nodes started with each other's external addresses share a direct link,
// so traffic crosses the data plane exactly as between two deployed nodes.
package dataplanetest

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/core/dataplane"
	"github.com/fancl20/cion/pkg/libs/underlay"
)

// IfID is the interface ID of every node's external link.
const IfID = 1

// macKey is the forwarding key every node shares, as if the control plane
// had distributed it already.
const macKey = "0123456789abcdef"

// FreeUDPAddr returns a UDP address on host with a port picked by the kernel
// and released for the caller's bind. Each package's tests reserve on a
// loopback host of their own: go test runs the packages in parallel, and on
// a shared host a released reservation could be taken before its rebind.
func FreeUDPAddr(t testing.TB, host netip.Addr) string {
	t.Helper()
	c, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(host, 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	return c.LocalAddr().String()
}

// Node is one running node and the facts a SCION socket of it needs.
type Node struct {
	// IA is the node's ISD-AS, and Neighbor the ISD-AS across its link.
	IA, Neighbor addr.IA
	// ControlIP is the host the node's sockets bind, and Internal the
	// internal link's address they send through.
	ControlIP netip.Addr
	Internal  string
	// MACKey is the node's forwarding key, which the sockets' one-hop
	// paths are authenticated with.
	MACKey []byte
	// Provider is the node's underlay, which holds its service table.
	Provider *dataplane.UDPProvider
}

// StartNode starts a node on host; extRemote must be the neighbor node's
// extLocal. The node serves until the test ends.
func StartNode(t *testing.T, host netip.Addr, ia, neighbor addr.IA, extLocal, extRemote string) *Node {
	t.Helper()

	internal, control := FreeUDPAddr(t, host), FreeUDPAddr(t, host)
	controlAddr, err := netip.ParseAddrPort(control)
	if err != nil {
		t.Fatal(err)
	}
	key := []byte(macKey)

	metrics, err := dataplane.NewMetrics()
	if err != nil {
		t.Fatal(err)
	}
	provider := dataplane.NewUDPProvider(64, 0, 0, underlay.Kernel)
	il, err := provider.NewInternalLink(internal, 64,
		metrics.NewInterfaceMetrics(0, ia, 0))
	if err != nil {
		t.Fatal(err)
	}
	el, err := provider.NewExternalLink(64, nil, extLocal, extRemote, IfID,
		metrics.NewInterfaceMetrics(IfID, ia, 0))
	if err != nil {
		t.Fatal(err)
	}
	local := addr.HostIP(controlAddr.Addr())
	d, err := dataplane.NewDataPlane(ia, local, key, provider, []dataplane.Link{il, el})
	if err != nil {
		t.Fatal(err)
	}
	d.RunConfig = dataplane.RunConfig{
		NumProcessors:         2,
		NumSlowPathProcessors: 1,
		BatchSize:             64,
	}

	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-serveDone:
			if err != nil {
				t.Errorf("Serve returned %v, want nil", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Serve did not return after cancellation")
		}
		provider.Stop()
	})
	go func() { serveDone <- d.Serve(ctx) }()

	return &Node{
		IA:        ia,
		Neighbor:  neighbor,
		ControlIP: controlAddr.Addr(),
		Internal:  internal,
		MACKey:    key,
		Provider:  provider,
	}
}

// Links returns the node's link table, its one external link, for its
// sockets.
func (n *Node) Links() map[uint16]addr.IA {
	return map[uint16]addr.IA{IfID: n.Neighbor}
}

// MapService registers svc at port on the node's host, where the data
// plane's service routing delivers what is addressed to the service.
func (n *Node) MapService(t testing.TB, svc addr.SVC, port uint16) {
	t.Helper()
	if err := n.Provider.AddSvc(svc, addr.HostIP(n.ControlIP), port); err != nil {
		t.Fatal(err)
	}
}
