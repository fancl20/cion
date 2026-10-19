package scionrpc

import (
	"context"
	"log/slog"
	"net/http"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/core/dataplane/dataplanetest"
	"github.com/fancl20/cion/pkg/core/trust/trusttest"
	"github.com/fancl20/cion/pkg/core/webpki"
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/modules/trustdb"
	"github.com/fancl20/cion/pkg/modules/trustdb/impl/bbolt"
)

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
	// served endpoint (serveEndpoint) binds.
	n.MapService(t, addr.SvcCS, EndpointPort)
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

// newWildcardConn returns a SCION connection of the node bound to the
// wildcard with an ephemeral port, naming itself by the given host — the
// learned external host's stand-in, the deployment shape the default control
// address spells.
func (n *testNode) newWildcardConn(t *testing.T, host netip.Addr) *scion.Conn {
	t.Helper()
	conn, err := scion.NewConn(scion.ConnConfig{
		IA:           n.IA,
		Bind:         netip.AddrPortFrom(netip.MustParseAddr("0.0.0.0"), 0).String(),
		InternalAddr: n.Internal,
		MACKey:       n.MACKey,
		Links:        n.Links,
		Advertise: func(context.Context) netip.Addr {
			return host
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

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
