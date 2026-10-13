package services

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"path/filepath"
	"testing"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/modules/links"
	"github.com/fancl20/cion/pkg/modules/trustdb"
	"github.com/fancl20/cion/pkg/modules/trustdb/impl/bbolt"
	"github.com/fancl20/cion/pkg/trust"
)

// coreRemote answers a node's trust fetches from its core's database,
// counting the chain fetches; fail makes every chain fetch fail.
type coreRemote struct {
	db      trustdb.DB
	fail    bool
	fetches int
}

func (r *coreRemote) TRC(ctx context.Context, id cppki.TRCID) (cppki.SignedTRC, error) {
	return r.db.SignedTRC(ctx, id)
}

func (r *coreRemote) Chains(
	ctx context.Context, q trustdb.ChainQuery,
) ([][]*x509.Certificate, error) {

	r.fetches++
	if r.fail {
		return nil, errors.New("the core does not answer")
	}
	return r.db.Chains(ctx, q)
}

func (r *coreRemote) RenewChain(
	context.Context, *x509.CertificateRequest, crypto.Signer,
) ([]*x509.Certificate, error) {

	return nil, errors.New("no renewal in this test")
}

// openTrustDB opens a trust database in a fresh directory, closed at
// cleanup.
func openTrustDB(t *testing.T) trustdb.DB {
	t.Helper()
	db, err := bbolt.New(filepath.Join(t.TempDir(), "trust.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// TestLinkEvidenceAsksTheCore checks a non-issuing node's evidence: a
// candidate whose chain the node's database lacks is proven by the chain
// its core issued, fetched once and cached; an un-enrolled node asks its
// core nothing; and a peer the core never admitted, or a core that does not
// answer, proves nothing without failing the read.
func TestLinkEvidenceAsksTheCore(t *testing.T) {
	ctx := context.Background()
	iaCore := addr.MustIAFrom(20, 0xff0000000001)
	iaNode := addr.MustIAFrom(20, 0xff0000000002)
	iaPeer := addr.MustIAFrom(20, 0xff0000000003)
	iaLate := addr.MustIAFrom(20, 0xff0000000004)
	iaStranger := addr.MustIAFrom(20, 0xff0000000005)

	coreDB := openTrustDB(t)
	keys, err := trust.LoadOrCreateCoreKeys(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	trc, err := trust.Genesis(ctx, coreDB, iaCore, keys)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := trust.NewIssuer(iaCore, keys, trc)
	if err != nil {
		t.Fatal(err)
	}
	// issue enrolls the ISD-AS at the core, which keeps the chain it issues.
	issue := func(ia addr.IA) (crypto.Signer, []*x509.Certificate) {
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
		if _, err := coreDB.InsertChain(ctx, chain); err != nil {
			t.Fatal(err)
		}
		return key, chain
	}
	nodeKey, nodeChain := issue(iaNode)
	issue(iaPeer)
	issue(iaLate)

	nodeDB := openTrustDB(t)
	remote := &coreRemote{db: coreDB}
	n := &node{
		trustDB: nodeDB,
		engine: trust.NewEngine(iaNode, nodeKey,
			&trust.NetworkProvider{DB: nodeDB, Remote: remote}),
		remote: remote,
	}
	evidence := func(ia addr.IA) bool {
		t.Helper()
		proven, err := n.linkEvidence(ctx, &links.Link{NeighborIA: ia})
		if err != nil {
			t.Fatalf("the evidence read for %v failed: %v", ia, err)
		}
		return proven
	}

	// Before its own enrollment the node asks its core nothing.
	if evidence(iaPeer) {
		t.Error("an un-enrolled node proved the peer")
	}
	if remote.fetches != 0 {
		t.Errorf("an un-enrolled node asked its core %d times", remote.fetches)
	}

	// Enrolled, the node proves the peer by the chain its core issued, and
	// the next read answers from the cache.
	if _, err := nodeDB.InsertTRC(ctx, trc); err != nil {
		t.Fatal(err)
	}
	if _, err := nodeDB.InsertChain(ctx, nodeChain); err != nil {
		t.Fatal(err)
	}
	if !evidence(iaPeer) {
		t.Error("the peer the core admitted is not proven")
	}
	fetches := remote.fetches
	if !evidence(iaPeer) || remote.fetches != fetches {
		t.Errorf("the proven peer was asked again: %d fetches, want %d", remote.fetches, fetches)
	}

	// A peer the core never admitted proves nothing.
	if evidence(iaStranger) {
		t.Error("a peer the core never admitted is proven")
	}

	// A core that does not answer proves nothing this pass, and the read
	// does not fail.
	remote.fail = true
	if evidence(iaLate) {
		t.Error("a peer is proven while the core does not answer")
	}
}
