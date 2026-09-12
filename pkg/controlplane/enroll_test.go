package controlplane

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/trust"
	"github.com/fancl20/cion/pkg/trust/impl/bbolt"
)

// testDomain is the DNS identity of the core endpoint in tests; its
// certificate is signed by a test CA that stands in for the WebPKI.
const testDomain = "cion-core.test"

// webPKI is the test certificate authority anchoring the endpoint's TLS
// certificate.
type webPKI struct {
	pool     *x509.CertPool
	certFile string
	keyFile  string
}

// newTestWebPKI creates the CA and the server certificate for testDomain,
// returning the certificate files and the pool trusting the CA.
func newTestWebPKI(t *testing.T) *webPKI {
	t.Helper()
	dir := t.TempDir()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "cion test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: testDomain},
		DNSNames:     []string{testDomain},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTmpl, caCert,
		serverKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	serverKeyDER, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(
		&pem.Block{Type: "EC PRIVATE KEY", Bytes: serverKeyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return &webPKI{pool: pool, certFile: certFile, keyFile: keyFile}
}

// serveCore brings up the core's control endpoint: trust stack, TLS
// certificate, HTTP/3 over the SCION connection.
func serveCore(t *testing.T, n *testNode, wpki *webPKI) *trustFixture {
	t.Helper()
	f := newTrustFixture(t)

	tlsConf, err := ManageTLSCert(context.Background(), TLSCertConfig{
		Domain:   testDomain,
		CertFile: wpki.certFile,
		KeyFile:  wpki.keyFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	svc := &TrustService{DB: f.db, Issuer: f.issuer}
	go func() {
		if err := ServeHTTP3(n.newConn(t, EndpointPort), NewServer(svc).Handler,
			tlsConf); err != nil {

			t.Logf("control endpoint exited: %v", err)
		}
	}()
	return f
}

// enrollNode runs the enrollment a deployed non-core node performs: wait for
// the core's greeting, aim the client at its endpoint, enroll.
func enrollNode(
	ctx context.Context,
	t *testing.T,
	n *testNode,
	domain string,
	rootCAs *x509.CertPool,
	db trust.DB,
	key crypto.Signer,
) error {

	core := waitNeighbor(t, n.discovery)
	client, err := NewCoreClient(CoreClientConfig{
		Domain:  domain,
		Conn:    n.newConn(t, 0),
		RootCAs: rootCAs,
	})
	if err != nil {
		return err
	}
	defer client.Close() //nolint:errcheck
	client.SetCore(core.IA,
		netip.AddrPortFrom(core.ControlAddr.Addr(), EndpointPort))
	_, enrollErr := trust.Enroll(ctx, db, client, n.ia, key)
	return enrollErr
}

// TestEnrollmentTwoNodes is the integration test of the trust bootstrap: a
// core and a normal node discover each other, the normal node fetches the
// TRC and enrolls over the one-hop SCION channel with TLS verified against
// the core's domain, and both trust DBs converge.
func TestEnrollmentTwoNodes(t *testing.T) {
	iaCore := addr.MustIAFrom(20, 0xff0000000001)
	iaNode := addr.MustIAFrom(20, 0xff0000000002)
	wpki := newTestWebPKI(t)
	extA, extB := freeUDPAddr(t), freeUDPAddr(t)
	core := startTestNode(t, iaCore, iaNode, extA, extB)
	node := startTestNode(t, iaNode, iaCore, extB, extA)

	f := serveCore(t, core, wpki)

	nodeDir := t.TempDir()
	nodeDB, err := bbolt.New(filepath.Join(nodeDir, "trust.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer nodeDB.Close() //nolint:errcheck
	asKey, err := trust.LoadOrCreateASKey(nodeDir)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := enrollNode(ctx, t, node, testDomain, wpki.pool, nodeDB, asKey); err != nil {
		t.Fatalf("enrollment failed: %v", err)
	}

	// The node's DB holds the TRC and its own chain, and the two DBs agree.
	trc, err := nodeDB.SignedTRC(ctx, cppki.TRCID{ISD: iaNode.ISD(), Base: 1, Serial: 1})
	if err != nil {
		t.Fatalf("node TRC: %v", err)
	}
	if trc.TRC.ID != f.trc.TRC.ID {
		t.Errorf("node TRC %v, core TRC %v", trc.TRC.ID, f.trc.TRC.ID)
	}
	nodeChains, err := nodeDB.Chains(ctx, trust.ChainQuery{IA: iaNode})
	if err != nil {
		t.Fatal(err)
	}
	if len(nodeChains) != 1 {
		t.Fatalf("node chains = %d, want 1", len(nodeChains))
	}
	coreChains, err := f.db.Chains(ctx, trust.ChainQuery{IA: iaNode})
	if err != nil {
		t.Fatal(err)
	}
	if len(coreChains) != 1 || !coreChains[0][0].Equal(nodeChains[0][0]) {
		t.Error("core and node DBs did not converge")
	}
	if err := cppki.VerifyChain(nodeChains[0], cppki.VerifyOptions{
		TRC: []*cppki.TRC{&f.trc.TRC},
	}); err != nil {
		t.Errorf("enrolled chain does not verify against TRC: %v", err)
	}

	// The network-backed provider serves the fetched material from the DB.
	provider := &trust.NetworkProvider{DB: nodeDB, Remote: nilRemote{}}
	chains, err := provider.GetChains(ctx, trust.ChainQuery{IA: iaNode})
	if err != nil {
		t.Fatal(err)
	}
	if len(chains) != 1 {
		t.Errorf("provider chains = %d, want 1 (served from DB)", len(chains))
	}
}

// TestEnrollmentWrongDomain checks the TLS verification of the bootstrap
// channel: an endpoint presenting a certificate for another domain is
// refused.
func TestEnrollmentWrongDomain(t *testing.T) {
	iaCore := addr.MustIAFrom(20, 0xff0000000001)
	iaNode := addr.MustIAFrom(20, 0xff0000000002)
	wpki := newTestWebPKI(t)
	extA, extB := freeUDPAddr(t), freeUDPAddr(t)
	core := startTestNode(t, iaCore, iaNode, extA, extB)
	node := startTestNode(t, iaNode, iaCore, extB, extA)

	serveCore(t, core, wpki)

	nodeDir := t.TempDir()
	nodeDB, err := bbolt.New(filepath.Join(nodeDir, "trust.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer nodeDB.Close() //nolint:errcheck
	asKey, err := trust.LoadOrCreateASKey(nodeDir)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// The client trusts the CA but expects another domain.
	err = enrollNode(ctx, t, node, "other.test", wpki.pool, nodeDB, asKey)
	if err == nil {
		t.Fatal("enrollment against endpoint with wrong-domain certificate succeeded")
	}
	// Nothing was stored.
	chains, err := nodeDB.Chains(ctx, trust.ChainQuery{IA: iaNode})
	if err != nil {
		t.Fatal(err)
	}
	if len(chains) != 0 {
		t.Errorf("stored chains = %d, want 0", len(chains))
	}
}

// nilRemote fails every fetch; used to prove the provider serves from the DB.
type nilRemote struct{}

var errNilRemote = errors.New("no remote")

func (nilRemote) TRC(ctx context.Context, id cppki.TRCID) (cppki.SignedTRC, error) {
	return cppki.SignedTRC{}, errNilRemote
}

func (nilRemote) Chains(ctx context.Context, q trust.ChainQuery) ([][]*x509.Certificate, error) {
	return nil, errNilRemote
}

func (nilRemote) RenewChain(ctx context.Context, csr *x509.CertificateRequest,
	key crypto.Signer) ([]*x509.Certificate, error) {

	return nil, errNilRemote
}
