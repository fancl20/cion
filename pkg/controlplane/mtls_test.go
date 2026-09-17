package controlplane

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"path/filepath"
	"testing"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/trust"
	"github.com/fancl20/cion/pkg/trust/impl/bbolt"
)

// mtlsFixture is a core with a TRC and two enrolled nodes: the local node
// whose engine serves the endpoint, and a peer.
type mtlsFixture struct {
	db     trust.DB
	engine *trust.Engine
	peer   *trust.Engine
}

func newMTLSFixture(t *testing.T) *mtlsFixture {
	t.Helper()
	dir := t.TempDir()
	db, err := bbolt.New(filepath.Join(dir, "trust.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	keys, err := trust.LoadOrCreateCoreKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	trc, err := trust.Genesis(context.Background(), db, coreIATest, keys)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := trust.NewIssuer(coreIATest, keys, trc)
	if err != nil {
		t.Fatal(err)
	}
	provider := &trust.NetworkProvider{DB: db}
	newEngine := func(ia addr.IA) *trust.Engine {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		csr, err := trust.CreateCSR(ia, key)
		if err != nil {
			t.Fatal(err)
		}
		chain, err := issuer.IssueChain(csr)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.InsertChain(context.Background(), chain); err != nil {
			t.Fatal(err)
		}
		return trust.NewEngine(ia, key, provider)
	}
	return &mtlsFixture{
		db:     db,
		engine: newEngine(nodeIATest),
		peer:   newEngine(iaLineC),
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
	dir := t.TempDir()
	db, err := bbolt.New(filepath.Join(dir, "trust.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	keys, err := trust.LoadOrCreateCoreKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	foreignIA := addr.MustIAFrom(21, 0xff0000000001)
	trc, err := trust.Genesis(context.Background(), db, foreignIA, keys)
	if err != nil {
		t.Fatal(err)
	}
	foreignIssuer, err := trust.NewIssuer(foreignIA, keys, trc)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := trust.CreateCSR(foreignIA, key)
	if err != nil {
		t.Fatal(err)
	}
	foreignChain, err := foreignIssuer.IssueChain(csr)
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
	db, err := bbolt.New(filepath.Join(t.TempDir(), "trust.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
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
		Domain: testDomain,
		WebPKI: webPKI,
		Engine: f.engine,
	})

	native, err := conf.GetConfigForClient(&tls.ClientHelloInfo{ServerName: testDomain})
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
	coreless := EndpointTLS(EndpointTLSConfig{Engine: f.engine})
	got, err := coreless.GetConfigForClient(&tls.ClientHelloInfo{ServerName: testDomain})
	if err != nil {
		t.Fatal(err)
	}
	if got.ClientAuth != tls.RequireAnyClientCert {
		t.Error("non-core endpoint did not serve the SCION-native channel")
	}
}

// TestNativeCertFromEngine checks the certificate the endpoint presents: the
// node's AS chain with the AS key.
func TestNativeCertFromEngine(t *testing.T) {
	f := newMTLSFixture(t)
	cert, err := nativeCert(f.engine)
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
