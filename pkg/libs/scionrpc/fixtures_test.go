package scionrpc

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/core/dataplane"
	"github.com/fancl20/cion/pkg/core/trust/trusttest"
	"github.com/fancl20/cion/pkg/core/webpki"
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/modules/links"
	"github.com/fancl20/cion/pkg/modules/links/impl/memory"
	"github.com/fancl20/cion/pkg/modules/trustdb"
	"github.com/fancl20/cion/pkg/modules/trustdb/impl/bbolt"
)

const testMACKey = "0123456789abcdef"

var testMACKeyBytes = []byte(testMACKey)

var (
	coreIATest = addr.MustIAFrom(20, 0xff0000000001)
	nodeIATest = addr.MustIAFrom(20, 0xff0000000002)
	// iaLineC is the peer the TLS episodes enroll beside the local node.
	iaLineC = addr.MustIAFrom(20, 0xff0000000003)
)

// newFounder returns the founder of coreIATest's ISD.
func newFounder(t *testing.T) *trusttest.Founder {
	t.Helper()
	return newFounderOf(t, coreIATest)
}

// newFounderOf returns the founder ia over a fresh trust database.
func newFounderOf(t *testing.T, ia addr.IA) *trusttest.Founder {
	t.Helper()
	return trusttest.NewFounder(t, openTrustDB(t, t.TempDir()), ia)
}

// openTrustDB opens the trust database in dir, closed when the test ends.
func openTrustDB(t *testing.T, dir string) trustdb.DB {
	t.Helper()
	db, err := bbolt.New(filepath.Join(dir, "trust.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// testHost is a loopback host no other package's tests bind, for the
// package's fixed-port binds and the ports freeUDPAddr reserves: go test
// runs the packages in parallel, and on a shared host the endpoint port
// would collide across packages and a released reservation could be taken
// before its rebind.
var testHost = netip.MustParseAddr("127.0.0.131")

// freeUDPAddr returns a UDP address on testHost with a port picked by the
// kernel and released for the caller's bind.
func freeUDPAddr(t *testing.T) string {
	t.Helper()
	c, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(testHost, 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	return c.LocalAddr().String()
}

// testNode is one CION node: data plane with an internal and an external
// link, plus the CS service registered on the control endpoint's socket —
// the drafts' service routing the endpoint's own traffic rides.
type testNode struct {
	ia        addr.IA
	neighbor  addr.IA
	ifID      uint16
	internal  string
	controlIP netip.Addr
	provider  *dataplane.UDPProvider
	store     *memory.DB
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

	store := memory.New()
	entry := &links.Link{
		NeighborIA: neighbor,
		Local:      netip.MustParseAddrPort(extLocal),
		Remote:     netip.MustParseAddrPort(extRemote),
		State:      links.StateEstablished,
	}
	if err := store.Insert(context.Background(), entry); err != nil {
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
	el, err := provider.NewExternalLink(64, nil, extLocal, extRemote, entry.IfID,
		metrics.NewInterfaceMetrics(entry.IfID, ia, 0))
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
	// The control service maps to the endpoint's socket, the address a
	// served endpoint (serveEndpoint) binds.
	if err := provider.AddSvc(addr.SvcCS, addr.HostIP(controlAddr.Addr()), EndpointPort); err != nil {
		t.Fatal(err)
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

	return &testNode{
		ia:        ia,
		neighbor:  neighbor,
		ifID:      entry.IfID,
		internal:  internal,
		controlIP: controlAddr.Addr(),
		provider:  provider,
		store:     store,
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
		Links:        n.linkTable,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// linkTable snapshots the node's link table for its connections.
func (n *testNode) linkTable() map[uint16]addr.IA {
	entries, err := n.store.All(context.Background())
	if err != nil {
		return nil
	}
	return links.Links(entries)
}

// TestPeerAuthorityRoundTrip checks the authority encoding both destination

// serveEndpoint serves the node's endpoint socket until the test's context
// ends: the channel alone, with a handler that serves nothing and the test
// CA's certificate for the core's domain.
func serveEndpoint(t *testing.T, n *testNode, wpki *webpkitest.CA) {
	t.Helper()
	certMgr, err := webpki.PrepareTLSCert(webpki.TLSCertConfig{
		Domain:   webpkitest.Domain,
		CertFile: wpki.CertFile,
		KeyFile:  wpki.KeyFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The endpoint outlives the test's own thread — it serves until the
	// test's context ends, just before cleanup — so it reports through the
	// package logger and its cleanup waits for the exit.
	done := make(chan error, 1)
	t.Cleanup(func() {
		select {
		case err := <-done:
			if err != nil {
				slog.Debug("endpoint exited", "err", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("the endpoint did not stop with the test's context")
		}
	})
	endpoint := n.newConn(t, EndpointPort)
	go func() {
		done <- ServeHTTP3(t.Context(), endpoint, http.NotFoundHandler(), certMgr.TLSConfig())
	}()
}
