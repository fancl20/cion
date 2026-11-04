package scionrpc

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/core/trust"
	"github.com/fancl20/cion/pkg/libs/scion"
)

// TestRouteAuthorityRoundTrip checks the route authority's encoding: an
// address carrying a path decodes back to the same peer and the same path,
// whatever separators the path's bytes hold, and an address without one
// encodes as its peer authority.
func TestRouteAuthorityRoundTrip(t *testing.T) {
	path, err := pathToCore([]byte("0123456789abcdef"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	want := make([]byte, path.Len())
	if err := path.SerializeTo(want); err != nil {
		t.Fatal(err)
	}
	ia := addr.MustIAFrom(20, 0xff0000000021)
	for _, peer := range []*scion.Addr{
		{IA: ia, Service: addr.SvcCS, Path: path},
		{IA: ia, Addr: netip.MustParseAddrPort("[2001:db8::7]:30042"), Path: path},
		{IA: ia, Service: addr.SvcCS, IfID: 7, Path: path},
	} {
		authority, err := RouteAuthority(peer)
		if err != nil {
			t.Fatalf("encoding the route of %s: %v", peer, err)
		}
		got, err := peerFromAuthority(authority)
		if err != nil {
			t.Fatalf("decoding the route of %s: %v", peer, err)
		}
		if !got.IA.Equal(peer.IA) || got.Addr != peer.Addr ||
			got.Service != peer.Service || got.IfID != peer.IfID || got.Path == nil {

			t.Fatalf("route round trip = %v (path %v), want %v", got, got.Path, peer)
		}
		raw := make([]byte, got.Path.Len())
		if err := got.Path.SerializeTo(raw); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(raw, want) {
			t.Errorf("the decoded path of %s differs from the encoded one", peer)
		}
	}
	bare := &scion.Addr{IA: ia, Service: addr.SvcCS, IfID: 7}
	if authority, err := RouteAuthority(bare); err != nil || authority != PeerAuthority(bare) {
		t.Errorf("RouteAuthority(%s) = %q, %v; want the peer authority %q",
			bare, authority, err, PeerAuthority(bare))
	}
}

// recordingEndpoint serves the node's socket with a handler that answers
// "ok" and sends each request's remote address, until the test ends.
func recordingEndpoint(t *testing.T, conn *scion.Conn, creds *trust.Engine) <-chan *scion.Addr {
	t.Helper()
	remotes := make(chan *scion.Addr, 8)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remotes <- RemoteAddr(r.Context())
		_, _ = w.Write([]byte("ok"))
	})
	served := make(chan error, 1)
	t.Cleanup(func() {
		select {
		case err := <-served:
			if !errors.Is(err, net.ErrClosed) {
				t.Errorf("ServeHTTP3 returned (%v), want the closed socket's error", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("the endpoint did not stop with the test's context")
		}
	})
	go func() {
		served <- ServeHTTP3(t.Context(), conn, handler,
			EndpointTLS(EndpointTLSConfig{Credentials: creds, Key: creds.Key}))
	}()
	return remotes
}

// get requests the authority's root and fails the test unless it answers.
func get(ctx context.Context, t *testing.T, hclt *http.Client, authority string) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+authority+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := hclt.Do(req)
	if err != nil {
		t.Fatalf("requesting %s: %v", authority, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if body, err := io.ReadAll(resp.Body); err != nil || string(body) != "ok" {
		t.Fatalf("the response = %q (%v), want %q", body, err, "ok")
	}
}

// TestSCIONClientDialsTheNamedPath checks a registrant's reach back: a
// request the peer sends the core over a SCION path carries, at the core,
// the reverse of that path, and a core's client that leases no path of its
// own reaches the peer's control service over that reverse — the peer seeing
// the request arrive over a SCION path — while the same address without the
// path takes one hop.
func TestSCIONClientDialsTheNamedPath(t *testing.T) {
	f := newMTLSFixture(t)
	extA, extB := freeUDPAddr(t), freeUDPAddr(t)
	core := startTestNode(t, nodeIATest, iaLineC, extA, extB)
	peer := startTestNode(t, iaLineC, nodeIATest, extB, extA)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	coreEndpoint := core.newConn(t, 0)
	atCore := recordingEndpoint(t, coreEndpoint, f.engine)
	atPeer := recordingEndpoint(t, peer.newConn(t, EndpointPort), f.peer)

	// The peer reaches the core over the SCION path its lease holds.
	peerConn := peer.newConn(t, 0)
	peerQUIC := &quic.Transport{Conn: peerConn}
	t.Cleanup(func() { _ = peerQUIC.Close() })
	provider, _ := providerToCore(t, peer.MACKey)
	peerClient := NewSCIONClient(PeerClientConfig{
		Credentials: f.peer,
		Key:         f.peer.Key,
		Conn:        peerConn,
		Lease:       provider.Lease,
	}, peerQUIC, true)
	get(ctx, t, peerClient, PeerAuthority(&scion.Addr{
		IA: nodeIATest, Addr: netip.AddrPortFrom(core.ControlIP, coreEndpoint.LocalPort()),
	}))
	arrived := <-atCore
	if arrived == nil || arrived.Path == nil {
		t.Fatalf("the core saw the request arrive from %v, want over a SCION path", arrived)
	}

	// The core's client leases no path of its own, so it rides the path an
	// authority names, and one hop otherwise.
	coreConn := core.newConn(t, 0)
	coreQUIC := &quic.Transport{Conn: coreConn}
	t.Cleanup(func() { _ = coreQUIC.Close() })
	coreClient := NewSCIONClient(PeerClientConfig{
		Credentials: f.engine,
		Key:         f.engine.Key,
		Conn:        coreConn,
	}, coreQUIC, true)
	back, err := RouteAuthority(&scion.Addr{IA: iaLineC, Service: addr.SvcCS, Path: arrived.Path})
	if err != nil {
		t.Fatal(err)
	}
	get(ctx, t, coreClient, back)
	if got := <-atPeer; got == nil || got.Path == nil {
		t.Errorf("the peer saw the core's request arrive from %v, want over the reversed path", got)
	}
	get(ctx, t, coreClient, PeerAuthority(&scion.Addr{IA: iaLineC, Service: addr.SvcCS}))
	if got := <-atPeer; got == nil || got.Path != nil || got.IfID == 0 {
		t.Errorf("the peer saw the bare address's request arrive from %v, want one hop", got)
	}
}
