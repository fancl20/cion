package wireguard

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/scionrpc"
	wireguardv1connect "github.com/fancl20/cion/proto/wireguard/v1/wireguardv1connect"
)

// idleTransport serves every request through the handler, recording the
// authority each names, and counts the idle-connection closes asked of it.
type idleTransport struct {
	handler http.Handler
	hosts   []string
	closes  int
}

func (tr *idleTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	tr.hosts = append(tr.hosts, r.URL.Host)
	w := httptest.NewRecorder()
	tr.handler.ServeHTTP(w, r)
	return w.Result(), nil
}

func (tr *idleTransport) CloseIdleConnections() { tr.closes++ }

// TestDirectoryClientReleasesTheReplacedEndpoint checks the client's moved
// route: one HTTP client carries every endpoint the core's route names, an
// unmoved route keeps its endpoint, and a moved one closes the connections
// no request rides — the replaced endpoint's — the request naming the new
// endpoint.
func TestDirectoryClientReleasesTheReplacedEndpoint(t *testing.T) {
	server := connect.NewServer()
	wireguardv1connect.RegisterDirectoryServiceHandler(server,
		&DirectoryService{Store: &fakeStore{}, Cnt: &counters{}})
	mux := http.NewServeMux()
	connecthttp.Mount(mux, server)
	transport := &idleTransport{handler: mux}
	first := &scion.Addr{IA: addr.MustIAFrom(20, 0xff0000000001), Service: SvcDirectory}
	moved := &scion.Addr{IA: addr.MustIAFrom(20, 0xff0000000002), Service: SvcDirectory}
	route := first
	rpc := &rpcDirectoryClient{
		coreRoute: func() *scion.Addr { return route },
		hclt:      &http.Client{Transport: transport},
	}

	ctx := t.Context()
	for range 2 {
		if _, err := rpc.List(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if transport.closes != 0 {
		t.Errorf("idle closes while the route stood = %d, want 0", transport.closes)
	}
	route = moved
	if _, err := rpc.List(ctx); err != nil {
		t.Fatal(err)
	}
	if transport.closes != 1 {
		t.Errorf("idle closes once the route moved = %d, want 1", transport.closes)
	}
	want := []string{
		scionrpc.PeerAuthority(first), scionrpc.PeerAuthority(first),
		scionrpc.PeerAuthority(moved),
	}
	if !slices.Equal(transport.hosts, want) {
		t.Errorf("request authorities = %q, want %q", transport.hosts, want)
	}
}
