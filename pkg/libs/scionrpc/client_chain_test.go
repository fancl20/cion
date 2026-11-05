package scionrpc

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/core/trust/trusttest"
	"github.com/fancl20/cion/pkg/libs/peeria"
	"github.com/fancl20/cion/pkg/libs/scion"
)

// switchedCredentials withholds the chain its credentials hold until it is
// switched on: a node before and after its enrollment.
type switchedCredentials struct {
	Credentials
	enrolled atomic.Bool
}

func (c *switchedCredentials) Chain(ctx context.Context) ([]*x509.Certificate, error) {
	if !c.enrolled.Load() {
		return nil, nil
	}
	return c.Credentials.Chain(ctx)
}

// unpinnedCredentials withholds the TRC its credentials pinned until it is
// switched on: a node inside the bootstrap window, which accepts any
// client certificate unverified.
type unpinnedCredentials struct {
	Credentials
	pinned atomic.Bool
}

func (c *unpinnedCredentials) AnchorPool() ([]*cppki.TRC, error) {
	if !c.pinned.Load() {
		return nil, nil
	}
	return c.Credentials.AnchorPool()
}

// TestSCIONClientRedialsOnceChained checks a client dialed before its node
// held a chain, its peer inside the bootstrap window: the peer authenticates
// nothing over the connection dialed then, and once the node holds a chain
// and the peer a TRC, the next request dials anew and the peer
// authenticates the node.
func TestSCIONClientRedialsOnceChained(t *testing.T) {
	f := newMTLSFixture(t)
	extA, extB := freeUDPAddr(t), freeUDPAddr(t)
	core := startTestNode(t, nodeIATest, iaLineC, extA, extB)
	peer := startTestNode(t, iaLineC, nodeIATest, extB, extA)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	// The endpoint answers each request with the ISD-AS it authenticated,
	// counting the client's dials.
	serverCreds := &unpinnedCredentials{Credentials: f.engine}
	var dials atomic.Int32
	endpoint := core.newConn(t, 0)
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
		served <- ServeHTTP3(t.Context(), endpoint,
			peeria.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(peeria.AuthenticatedIA(r.Context()).String()))
			})),
			countingTLS(EndpointTLS(EndpointTLSConfig{Credentials: serverCreds, Key: f.engine.Key}), &dials))
	}()

	creds := &switchedCredentials{Credentials: f.peer}
	conn := peer.newConn(t, 0)
	qclt := &quic.Transport{Conn: conn}
	t.Cleanup(func() { _ = qclt.Close() })
	provider, _ := providerToCore(t, peer.MACKey)
	hclt := NewSCIONClient(PeerClientConfig{
		Credentials: creds,
		Key:         f.peer.Key,
		Conn:        conn,
		Lease:       provider.Lease,
	}, qclt, true)
	server := &scion.Addr{IA: nodeIATest, Addr: netip.AddrPortFrom(core.ControlIP, endpoint.LocalPort())}
	identity := func() string {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+PeerAuthority(server), nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := hclt.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}

	if got := identity(); got != addr.IA(0).String() {
		t.Fatalf("the peer authenticated %s before the node held a chain, want none", got)
	}
	creds.enrolled.Store(true)
	serverCreds.pinned.Store(true)
	if got := identity(); got != iaLineC.String() {
		t.Errorf("the peer authenticated %s once the node held a chain, want %s", got, iaLineC)
	}
	if got := dials.Load(); got != 2 {
		t.Errorf("dials = %d, want 2: the chained request dialed anew", got)
	}
}

// TestSCIONChannelRecordsThePresentedChains checks the recording over a real
// handshake: after one request on the SCION-native channel, the endpoint
// has recorded the chain the client presented, and the client the
// endpoint's.
func TestSCIONChannelRecordsThePresentedChains(t *testing.T) {
	f := newMTLSFixture(t)
	extA, extB := freeUDPAddr(t), freeUDPAddr(t)
	core := startTestNode(t, nodeIATest, iaLineC, extA, extB)
	peer := startTestNode(t, iaLineC, nodeIATest, extB, extA)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	serverCreds := &recordingCredentials{Credentials: f.engine}
	endpoint := core.newConn(t, 0)
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
		served <- ServeHTTP3(t.Context(), endpoint,
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}),
			EndpointTLS(EndpointTLSConfig{Credentials: serverCreds, Key: f.engine.Key}))
	}()

	clientCreds := &recordingCredentials{Credentials: f.peer}
	conn := peer.newConn(t, 0)
	qclt := &quic.Transport{Conn: conn}
	t.Cleanup(func() { _ = qclt.Close() })
	provider, _ := providerToCore(t, peer.MACKey)
	hclt := NewSCIONClient(PeerClientConfig{
		Credentials: clientCreds,
		Key:         f.peer.Key,
		Conn:        conn,
		Lease:       provider.Lease,
	}, qclt, true)
	server := &scion.Addr{IA: nodeIATest, Addr: netip.AddrPortFrom(core.ControlIP, endpoint.LocalPort())}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+PeerAuthority(server), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := hclt.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	if got := serverCreds.recordedIAs(t); !slices.Equal(got, []addr.IA{iaLineC}) {
		t.Errorf("the endpoint recorded chains of %v, want the client's", got)
	}
	if got := clientCreds.recordedIAs(t); !slices.Equal(got, []addr.IA{nodeIATest}) {
		t.Errorf("the client recorded chains of %v, want the endpoint's", got)
	}
}

// serveNative serves the handler on an ephemeral endpoint socket of the node
// over the SCION-native channel under creds until the test's context ends,
// and returns the endpoint's address.
func serveNative(t *testing.T, n *testNode, handler http.Handler, creds Credentials, key crypto.Signer) *scion.Addr {
	t.Helper()
	endpoint := n.newConn(t, 0)
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
		served <- ServeHTTP3(t.Context(), endpoint, handler,
			EndpointTLS(EndpointTLSConfig{Credentials: creds, Key: key}))
	}()
	return &scion.Addr{IA: n.IA, Addr: netip.AddrPortFrom(n.ControlIP, endpoint.LocalPort())}
}

// forgedCredentials present a chain another root issued in the name of the
// credentials' own ISD-AS: an impostor, whose chain no TRC the network pins
// anchors.
type forgedCredentials struct {
	Credentials
	chain []*x509.Certificate
}

func (c forgedCredentials) Chain(context.Context) ([]*x509.Certificate, error) {
	return c.chain, nil
}

func (forgedCredentials) Beside(context.Context, []*x509.Certificate) ([]*x509.Certificate, error) {
	return nil, nil
}

// TestEndpointServesNoIdentityItDidNotVerify checks the endpoint's side of
// the bootstrap window: a connection it accepted before it pinned a TRC
// carries a client chain it never verified — here an impostor's in the
// peer's name — and serves no identity, before the pin and after it. The
// impostor's next handshake fails, and an enrolled client's serves its
// identity.
func TestEndpointServesNoIdentityItDidNotVerify(t *testing.T) {
	f := newMTLSFixture(t)
	extA, extB := freeUDPAddr(t), freeUDPAddr(t)
	core := startTestNode(t, nodeIATest, iaLineC, extA, extB)
	peer := startTestNode(t, iaLineC, nodeIATest, extB, extA)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	// The endpoint answers each request with the ISD-AS it authenticated.
	serverCreds := &unpinnedCredentials{Credentials: f.engine}
	server := serveNative(t, core,
		peeria.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(peeria.AuthenticatedIA(r.Context()).String()))
		})), serverCreds, f.engine.Key)

	conn := peer.newConn(t, 0)
	qclt := &quic.Transport{Conn: conn}
	t.Cleanup(func() { _ = qclt.Close() })
	provider, _ := providerToCore(t, peer.MACKey)
	client := func(creds Credentials, key crypto.Signer) *http.Client {
		return NewSCIONClient(PeerClientConfig{
			Credentials: creds,
			Key:         key,
			Conn:        conn,
			Lease:       provider.Lease,
		}, qclt, true)
	}
	identity := func(hclt *http.Client) (string, error) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+PeerAuthority(server), nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := hclt.Do(req)
		if err != nil {
			return "", err
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		return string(body), err
	}

	csr, key := trusttest.NewCSR(t, iaLineC)
	forged, err := newFounderOf(t, addr.MustIAFrom(iaLineC.ISD(), 0xff00000000aa)).Issuer.IssueChain(csr)
	if err != nil {
		t.Fatal(err)
	}
	impostor := client(forgedCredentials{Credentials: f.peer, chain: forged}, key)
	none := addr.IA(0).String()
	if got, err := identity(impostor); err != nil || got != none {
		t.Fatalf("the unpinned endpoint served (%s, %v) to the impostor, want no identity", got, err)
	}
	serverCreds.pinned.Store(true)
	if got, err := identity(impostor); err != nil || got != none {
		t.Errorf("the pinned endpoint served (%s, %v) over the connection it accepted unpinned, "+
			"want no identity", got, err)
	}
	impostor.CloseIdleConnections()
	if got, err := identity(impostor); err == nil {
		t.Errorf("the pinned endpoint took the impostor's chain, serving %s", got)
	}
	if got, err := identity(client(f.peer, f.peer.Key)); err != nil || got != iaLineC.String() {
		t.Errorf("the pinned endpoint served (%s, %v) to the enrolled peer, want %s", got, err, iaLineC)
	}
}

// TestEndpointResumesNoSession checks the SCION-native channel resumes no
// session: a resumption would carry over the client certificates of the
// handshake it resumes unverified, so each connection handshakes in full, a
// client that caches sessions included.
func TestEndpointResumesNoSession(t *testing.T) {
	f := newMTLSFixture(t)
	extA, extB := freeUDPAddr(t), freeUDPAddr(t)
	core := startTestNode(t, nodeIATest, iaLineC, extA, extB)
	peer := startTestNode(t, iaLineC, nodeIATest, extB, extA)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	server := serveNative(t, core, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), f.engine, f.engine.Key)

	conn := peer.newConn(t, 0)
	qclt := &quic.Transport{Conn: conn}
	t.Cleanup(func() { _ = qclt.Close() })
	provider, _ := providerToCore(t, peer.MACKey)
	leased, err := provider.Lease(nodeIATest).Path()
	if err != nil {
		t.Fatal(err)
	}
	route := &scion.Addr{IA: server.IA, Addr: server.Addr, Path: leased.Path}
	tlsConf := nativeClientTLS(nodeIATest, f.peer, f.peer.Key, true)
	tlsConf.ClientSessionCache = tls.NewLRUClientSessionCache(1)
	// resumed sends one request over a fresh connection and reports whether
	// its handshake resumed a session; the response follows the handshake's
	// session ticket, if the endpoint sends one.
	resumed := func() bool {
		t.Helper()
		qconn, err := qclt.Dial(ctx, route, tlsConf, &quic.Config{InitialPacketSize: 1200})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = qconn.CloseWithError(0, "") }()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+PeerAuthority(server), nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := (&http3.Transport{}).NewClientConn(qconn).RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.TLS.DidResume
	}
	if resumed() {
		t.Fatal("the first handshake resumed a session")
	}
	if resumed() {
		t.Error("the second handshake resumed the first's session")
	}
}
