package controlplane

import (
	"context"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/core/dataplane/dataplanetest"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/scionrpc"
	"github.com/fancl20/cion/pkg/libs/segment"
	"github.com/fancl20/cion/pkg/modules/trustdb"
)

// pathOver returns the path from end to origin over their link: the
// two-AS segment origin originated, reversed, each hop MACed with the
// forwarding key the test nodes share.
func pathOver(t *testing.T, origin, end addr.IA) *spath.Decoded {
	t.Helper()
	pcb, err := segment.PCBWithID(time.Now(), 0x555)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pcb.AppendRouteHop(origin,
		segment.EntryOptions{EgressIfID: dataplanetest.IfID}, macFactory()); err != nil {
		t.Fatal(err)
	}
	if _, err := pcb.AppendRouteHop(end,
		segment.EntryOptions{IngressIfID: dataplanetest.IfID}, macFactory()); err != nil {
		t.Fatal(err)
	}
	path, err := pcb.ReversePathTo(0)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

// TestPeerFetcherRidesTheServersPath checks the fetch a registration's
// verification makes: a server whose address carries a path — the
// registrant's control service — is asked over that path, which the
// registrant sees its request arrive over, and its chain returns; a server
// without one is asked over the link, as a beacon's sender is.
func TestPeerFetcherRidesTheServersPath(t *testing.T) {
	f := newFounder(t)
	extA, extB := freeUDPAddr(t), freeUDPAddr(t)
	core := startTestNode(t, coreIATest, nodeIATest, extA, extB)
	registrant := startTestNode(t, nodeIATest, coreIATest, extB, extA)
	coreEngine, registrantEngine := f.Engine(t, coreIATest), f.Engine(t, nodeIATest)

	// The registrant's endpoint serves the chains its database holds and
	// records where each request arrived from.
	arrivals := make(chan *scion.Addr, 4)
	handler := NewServer(&TrustService{DB: f.DB}).Handler
	recording := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrivals <- scionrpc.RemoteAddr(r.Context())
		handler.ServeHTTP(w, r)
	})
	done := make(chan error, 1)
	t.Cleanup(func() {
		select {
		case err := <-done:
			if err != nil {
				slog.Debug("registrant endpoint exited", "err", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("the registrant's endpoint did not stop with the test's context")
		}
	})
	endpoint := registrant.newConn(t, scionrpc.EndpointPort)
	go func() {
		done <- scionrpc.ServeHTTP3(t.Context(), endpoint, recording,
			scionrpc.EndpointTLS(scionrpc.EndpointTLSConfig{
				Credentials: registrantEngine, Key: registrantEngine.Key,
			}))
	}()

	peerClt := NewPeerClient(scionrpc.PeerClientConfig{
		Credentials: coreEngine,
		Key:         coreEngine.Key,
		Conn:        core.newConn(t, 0),
	})
	t.Cleanup(func() { _ = peerClt.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	query := trustdb.ChainQuery{IA: nodeIATest}

	routed := &scion.Addr{IA: nodeIATest, Service: addr.SvcCS,
		Path: pathOver(t, nodeIATest, coreIATest)}
	chains, err := peerClt.Fetcher(routed).Chains(ctx, query)
	if err != nil || len(chains) == 0 {
		t.Fatalf("chains fetched over the server's path = %d (%v), want the registrant's",
			len(chains), err)
	}
	if got := <-arrivals; got == nil || got.Path == nil {
		t.Errorf("the registrant saw the fetch arrive from %v, want over the path", got)
	}

	linked := &scion.Addr{IA: nodeIATest, Service: addr.SvcCS}
	if chains, err := peerClt.Fetcher(linked).Chains(ctx, query); err != nil || len(chains) == 0 {
		t.Fatalf("chains fetched over the link = %d (%v), want the registrant's", len(chains), err)
	}
	if got := <-arrivals; got == nil || got.Path != nil || got.IfID == 0 {
		t.Errorf("the registrant saw the fetch arrive from %v, want one hop", got)
	}
}
