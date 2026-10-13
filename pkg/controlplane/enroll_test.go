package controlplane

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/modules/trustdb"
	"github.com/fancl20/cion/pkg/trust"
	"github.com/fancl20/cion/pkg/trust/trusttest"
	"github.com/fancl20/cion/pkg/webpki"
	"github.com/fancl20/cion/pkg/webpki/webpkitest"
)

// serveCore brings up the core's control endpoint: trust stack, TLS
// certificate, HTTP/3 over the SCION connection.
func serveCore(t *testing.T, n *testNode, wpki *webpkitest.CA) *trusttest.Founder {
	t.Helper()
	f := newFounder(t)

	certMgr, err := webpki.PrepareTLSCert(webpki.TLSCertConfig{
		Domain:   webpkitest.Domain,
		CertFile: wpki.CertFile,
		KeyFile:  wpki.KeyFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	tlsConf := certMgr.TLSConfig()
	svc := &TrustService{DB: f.DB, Issuer: f.Issuer}
	// The server outlives the test's own thread — it serves until the test's
	// context ends, just before cleanup — so it reports through the package
	// logger and its cleanup waits for the exit.
	done := make(chan error, 1)
	t.Cleanup(func() {
		select {
		case err := <-done:
			if err != nil {
				slog.Debug("control endpoint exited", "err", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("the control endpoint did not stop with the test's context")
		}
	})
	endpoint := n.newConn(t, EndpointPort)
	go func() {
		done <- ServeHTTP3(t.Context(), endpoint, NewServer(svc).Handler, tlsConf)
	}()
	return f
}

// enrollNode runs the enrollment a deployed non-core node performs: resolve
// the core's control service through the drafts' exchange — the request the
// endpoint answers beside its own protocol — aim the client at the answered
// address, enroll.
func enrollNode(
	ctx context.Context,
	t *testing.T,
	n *testNode,
	domain string,
	rootCAs *x509.CertPool,
	db trustdb.DB,
	key crypto.Signer,
) error {

	resolved, err := ResolveService(ctx, n.newConn(t, 0),
		&scion.Addr{IA: n.neighbor, Service: addr.SvcCS})
	if err != nil {
		return err
	}
	core := &scion.Addr{IA: n.neighbor, Addr: resolved}
	client, err := webpki.NewCoreClient(webpki.CoreClientConfig{
		Domain:  domain,
		Conn:    n.newConn(t, 0),
		RootCAs: rootCAs,
		Locator: func() *scion.Addr { return core },
	})
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	_, enrollErr := trust.RenewChain(ctx, db, client, n.ia, key)
	return enrollErr
}

// TestEnrollmentTwoNodes is the integration test of the trust bootstrap: a
// core and a normal node, the normal node resolving the core's control
// service through the drafts' exchange, fetching the TRC and enrolling over
// the one-hop SCION channel with TLS verified against the core's domain, and
// both trust DBs converging.
func TestEnrollmentTwoNodes(t *testing.T) {
	iaCore := addr.MustIAFrom(20, 0xff0000000001)
	iaNode := addr.MustIAFrom(20, 0xff0000000002)
	wpki := webpkitest.New(t)
	extA, extB := freeUDPAddr(t), freeUDPAddr(t)
	core := startTestNode(t, iaCore, iaNode, extA, extB)
	node := startTestNode(t, iaNode, iaCore, extB, extA)

	f := serveCore(t, core, wpki)

	nodeDir := t.TempDir()
	nodeDB := openTrustDB(t, nodeDir)
	asKey, err := trust.LoadOrCreateASKey(nodeDir)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := enrollNode(ctx, t, node, webpkitest.Domain, wpki.Pool, nodeDB, asKey); err != nil {
		t.Fatalf("enrollment failed: %v", err)
	}

	// The node's DB holds the TRC and its own chain, and the two DBs agree.
	trc, err := nodeDB.SignedTRC(ctx, cppki.TRCID{ISD: iaNode.ISD(), Base: 1, Serial: 1})
	if err != nil {
		t.Fatalf("node TRC: %v", err)
	}
	if trc.TRC.ID != f.TRC.TRC.ID {
		t.Errorf("node TRC %v, core TRC %v", trc.TRC.ID, f.TRC.TRC.ID)
	}
	nodeChains, err := nodeDB.Chains(ctx, trustdb.ChainQuery{IA: iaNode})
	if err != nil {
		t.Fatal(err)
	}
	if len(nodeChains) != 1 {
		t.Fatalf("node chains = %d, want 1", len(nodeChains))
	}
	coreChains, err := f.DB.Chains(ctx, trustdb.ChainQuery{IA: iaNode})
	if err != nil {
		t.Fatal(err)
	}
	if len(coreChains) != 1 || !coreChains[0][0].Equal(nodeChains[0][0]) {
		t.Error("core and node DBs did not converge")
	}
	if err := cppki.VerifyChain(nodeChains[0], cppki.VerifyOptions{
		TRC: []*cppki.TRC{&f.TRC.TRC},
	}); err != nil {
		t.Errorf("enrolled chain does not verify against TRC: %v", err)
	}

	// The network-backed provider serves the fetched material from the DB.
	provider := &trust.NetworkProvider{DB: nodeDB, Remote: nilRemote{}}
	chains, err := provider.GetChains(ctx, trustdb.ChainQuery{IA: iaNode})
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
	wpki := webpkitest.New(t)
	extA, extB := freeUDPAddr(t), freeUDPAddr(t)
	core := startTestNode(t, iaCore, iaNode, extA, extB)
	node := startTestNode(t, iaNode, iaCore, extB, extA)

	serveCore(t, core, wpki)

	nodeDir := t.TempDir()
	nodeDB := openTrustDB(t, nodeDir)
	asKey, err := trust.LoadOrCreateASKey(nodeDir)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// The client trusts the CA but expects another domain.
	err = enrollNode(ctx, t, node, "other.test", wpki.Pool, nodeDB, asKey)
	if err == nil {
		t.Fatal("enrollment against endpoint with wrong-domain certificate succeeded")
	}
	// Nothing was stored.
	chains, err := nodeDB.Chains(ctx, trustdb.ChainQuery{IA: iaNode})
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

func (nilRemote) Chains(ctx context.Context, q trustdb.ChainQuery) ([][]*x509.Certificate, error) {
	return nil, errNilRemote
}

func (nilRemote) RenewChain(ctx context.Context, csr *x509.CertificateRequest,
	key crypto.Signer) ([]*x509.Certificate, error) {

	return nil, errNilRemote
}
