package scionrpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"net"
	"net/netip"
	"testing"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/core/trust"
	"github.com/fancl20/cion/pkg/core/trust/trusttest"
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
	"github.com/fancl20/cion/pkg/modules/trustdb"
)

// mtlsFixture is a core with a TRC and two enrolled nodes: the local node
// whose engine serves the endpoint, and a peer.
type mtlsFixture struct {
	db     trustdb.DB
	engine *trust.Engine
	peer   *trust.Engine
}

func newMTLSFixture(t *testing.T) *mtlsFixture {
	t.Helper()
	f := newFounder(t)
	return &mtlsFixture{
		db:     f.DB,
		engine: f.Engine(t, nodeIATest),
		peer:   f.Engine(t, iaLineC),
	}
}

// peerChains returns the peer's current chain in TLS raw form.
func peerChains(f *mtlsFixture) [][]byte {
	chain, err := f.peer.Chain(context.Background())
	if err != nil || len(chain) == 0 {
		return nil
	}
	return [][]byte{chain[0].Raw, chain[1].Raw}
}

// TestNativeTLSVerifiesAgainstTRC checks the SCION-native channel's peer
// verification: a TRC-anchored chain is accepted, a foreign one rejected.
func TestNativeTLSVerifiesAgainstTRC(t *testing.T) {
	f := newMTLSFixture(t)

	verify := verifyChainAgainstTRC(f.engine, &iaLineC)
	if err := verify(peerChains(f), nil); err != nil {
		t.Fatalf("TRC-anchored chain rejected: %v", err)
	}

	// A chain anchored in another ISD's TRC.
	foreignIA := addr.MustIAFrom(21, 0xff0000000001)
	csr, _ := trusttest.NewCSR(t, foreignIA)
	foreignChain, err := newFounderOf(t, foreignIA).Issuer.IssueChain(csr)
	if err != nil {
		t.Fatal(err)
	}
	raw := [][]byte{foreignChain[0].Raw, foreignChain[1].Raw}
	if err := verify(raw, nil); err == nil {
		t.Error("foreign chain accepted against the pinned TRC")
	}
}

// TestNativeTLSWrongPeerIA checks that a chain for another IA fails the
// expected-IA binding.
func TestNativeTLSWrongPeerIA(t *testing.T) {
	f := newMTLSFixture(t)

	expected := coreIATest
	verify := verifyChainAgainstTRC(f.engine, &expected)
	if err := verify(peerChains(f), nil); err == nil {
		t.Error("chain for another ISD-AS accepted")
	}
}

// TestNativeTLSWithoutTRC checks the bootstrap window: without a pinned TRC
// every chain is accepted, so a fresh node can still receive beacons.
func TestNativeTLSWithoutTRC(t *testing.T) {
	db := openTrustDB(t, t.TempDir())
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fresh := trust.NewEngine(nodeIATest, key, &trust.NetworkProvider{DB: db})
	verify := verifyChainAgainstTRC(fresh, &iaLineC)

	// An entirely unanchored self-signed certificate passes the window.
	self, err := ephemeralCert()
	if err != nil {
		t.Fatal(err)
	}
	if err := verify([][]byte{self.Certificate[0]}, nil); err != nil {
		t.Errorf("certificate rejected during the bootstrap window: %v", err)
	}
}

// TestEndpointTLSDispatch checks that the endpoint dispatches by TLS server
// name: the core's domain is served the WebPKI channel, everything else the
// SCION-native channel.
func TestEndpointTLSDispatch(t *testing.T) {
	f := newMTLSFixture(t)

	webPKI := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}}
	conf := EndpointTLS(EndpointTLSConfig{
		Domain:      webpkitest.Domain,
		WebPKI:      webPKI,
		Credentials: f.engine,
		Key:         f.engine.Key,
	})

	native, err := conf.GetConfigForClient(&tls.ClientHelloInfo{ServerName: webpkitest.Domain})
	if err != nil {
		t.Fatal(err)
	}
	if native != webPKI {
		t.Error("client offering the core's domain did not get the WebPKI channel")
	}
	other, err := conf.GetConfigForClient(&tls.ClientHelloInfo{ServerName: "other.test"})
	if err != nil {
		t.Fatal(err)
	}
	if other == webPKI || other.ClientAuth != tls.RequireAnyClientCert {
		t.Error("client offering another server name did not get the SCION-native channel")
	}

	// A non-core node has no WebPKI channel: every name is native.
	coreless := EndpointTLS(EndpointTLSConfig{Credentials: f.engine, Key: f.engine.Key})
	got, err := coreless.GetConfigForClient(&tls.ClientHelloInfo{ServerName: webpkitest.Domain})
	if err != nil {
		t.Fatal(err)
	}
	if got.ClientAuth != tls.RequireAnyClientCert {
		t.Error("non-core endpoint did not serve the SCION-native channel")
	}
}

// TestEndpointTLSDispatchAddressIdentity checks the dispatch's address arm:
// against an address identity a nameless ClientHello — the bootstrap
// client's shape, Go's client omitting the SNI extension for an
// address-shaped ServerName — takes the WebPKI channel and completes its
// handshake, the certificate's IP addresses answering the bare literal the
// client names, while a hello naming anything takes the native channel, and
// a nameless hello against a domain identity keeps the native channel's
// rule.
func TestEndpointTLSDispatchAddressIdentity(t *testing.T) {
	f := newMTLSFixture(t)

	ca := webpkitest.New(t)
	pair, err := tls.LoadX509KeyPair(ca.AddrCertFile, ca.AddrKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	webPKI := &tls.Config{
		Certificates: []tls.Certificate{pair},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h3"},
	}
	conf := EndpointTLS(EndpointTLSConfig{
		Domain:      webpkitest.Address,
		WebPKI:      webPKI,
		Credentials: f.engine,
		Key:         f.engine.Key,
	})

	nameless, err := conf.GetConfigForClient(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if nameless != webPKI {
		t.Error("a nameless ClientHello did not get the WebPKI channel")
	}
	named, err := conf.GetConfigForClient(&tls.ClientHelloInfo{ServerName: webpkitest.Address})
	if err != nil {
		t.Fatal(err)
	}
	if named == webPKI || named.ClientAuth != tls.RequireAnyClientCert {
		t.Error("a ClientHello naming an address did not get the SCION-native channel")
	}

	// The nameless handshake completes, both families: the endpoint serves
	// the WebPKI certificate, and the client verifies the bare literal
	// against its IP addresses.
	for _, identity := range []struct {
		literal string
		ca      *webpkitest.CA
	}{
		{webpkitest.Address, ca},
		{"::1", webpkitest.NewFor(t, netip.MustParseAddr("::1"))},
	} {
		pair, err := tls.LoadX509KeyPair(identity.ca.AddrCertFile, identity.ca.AddrKeyFile)
		if err != nil {
			t.Fatal(err)
		}
		conf := EndpointTLS(EndpointTLSConfig{
			Domain: identity.literal,
			WebPKI: &tls.Config{
				Certificates: []tls.Certificate{pair},
				MinVersion:   tls.VersionTLS13,
				NextProtos:   []string{"h3"},
			},
			Credentials: f.engine,
			Key:         f.engine.Key,
		})
		client, server := net.Pipe()
		served := make(chan error, 1)
		go func() { served <- tls.Server(server, conf).Handshake() }()
		clt := tls.Client(client, &tls.Config{
			ServerName: identity.literal,
			RootCAs:    identity.ca.Pool,
			MinVersion: tls.VersionTLS13,
			NextProtos: []string{"h3"},
		})
		if err := clt.Handshake(); err != nil {
			t.Errorf("the bootstrap handshake against %s: %v", identity.literal, err)
		} else if err := <-served; err != nil {
			t.Errorf("the endpoint's side of the %s handshake: %v", identity.literal, err)
		}
		_ = client.Close()
		_ = server.Close()
	}

	// A domain identity keeps its rule: the nameless hello is the native
	// channel's, whose client-certificate demand refuses the handshake.
	domain := EndpointTLS(EndpointTLSConfig{
		Domain:      webpkitest.Domain,
		WebPKI:      webPKI,
		Credentials: f.engine,
		Key:         f.engine.Key,
	})
	got, err := domain.GetConfigForClient(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if got == webPKI || got.ClientAuth != tls.RequireAnyClientCert {
		t.Fatal("a nameless ClientHello against a domain identity did not get " +
			"the SCION-native channel")
	}
	client, server := net.Pipe()
	defer func() { _ = client.Close(); _ = server.Close() }()
	go func() { _ = tls.Server(server, domain).Handshake() }()
	clt := tls.Client(client, &tls.Config{MinVersion: tls.VersionTLS13})
	if err := clt.Handshake(); err == nil {
		t.Error("a nameless handshake against a domain identity completed")
	}
}

// TestNativeCertFromEngine checks the certificate the endpoint presents: the
// node's AS chain with the AS key.
func TestNativeCertFromEngine(t *testing.T) {
	f := newMTLSFixture(t)
	cert, err := nativeCert(f.engine, f.engine.Key)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := f.engine.Chain(context.Background())
	if err != nil || len(chain) == 0 {
		t.Fatalf("no chain: %v", err)
	}
	if len(cert.Certificate) != 2 {
		t.Fatalf("certificate chain = %d entries, want 2", len(cert.Certificate))
	}
	if ia, err := cppki.ExtractIA(chain[0].Subject); err != nil || !ia.Equal(nodeIATest) {
		t.Errorf("certificate subject = %v, want %v", ia, nodeIATest)
	}
}
