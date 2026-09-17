package trust_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"path/filepath"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/pkg/scrypto/signed"

	"github.com/fancl20/cion/pkg/trust"
	"github.com/fancl20/cion/pkg/trust/impl/bbolt"
)

var (
	iaCore = addr.MustIAFrom(20, 0xff0000000001)
	iaNode = addr.MustIAFrom(20, 0xff0000000002)
)

// engineFixture is a trust engine with a genesis TRC and an issued chain.
type engineFixture struct {
	db     trust.DB
	issuer *trust.Issuer
	trc    cppki.SignedTRC
	engine *trust.Engine
	asKey  *ecdsa.PrivateKey
	chain  []*x509.Certificate
}

func newEngineFixture(t *testing.T) *engineFixture {
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
	trc, err := trust.Genesis(context.Background(), db, iaCore, keys)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := trust.NewIssuer(iaCore, keys, trc)
	if err != nil {
		t.Fatal(err)
	}
	asKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := trust.CreateCSR(iaNode, asKey)
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
	engine := trust.NewEngine(iaNode, asKey, &trust.NetworkProvider{DB: db})
	return &engineFixture{
		db: db, issuer: issuer, trc: trc, engine: engine, asKey: asKey, chain: chain,
	}
}

// TestEngineSigner checks that the engine builds its signer from the DB
// chains: the algorithm selected for the P-256 key, the TRC ID from the ISD's
// base TRC, and the LastExpiring chain picked.
func TestEngineSigner(t *testing.T) {
	f := newEngineFixture(t)

	s, err := f.engine.Signer(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if s.Algorithm != signed.ECDSAWithSHA256 {
		t.Errorf("algorithm = %v, want ECDSAWithSHA256", s.Algorithm)
	}
	if s.TRCID != f.trc.TRC.ID {
		t.Errorf("TRC ID = %v, want %v", s.TRCID, f.trc.TRC.ID)
	}
	if !s.IA.Equal(iaNode) {
		t.Errorf("IA = %v, want %v", s.IA, iaNode)
	}
	if string(s.SubjectKeyID) != string(f.chain[0].SubjectKeyId) {
		t.Error("subject key ID does not match the chain")
	}
	if !s.Expiration.Equal(f.chain[0].NotAfter) {
		t.Errorf("expiration = %v, want %v", s.Expiration, f.chain[0].NotAfter)
	}
}

// TestEngineSignerPicksLastExpiring checks the LastExpiring selection: with
// an older and a newer chain, the signer uses the later expiration.
func TestEngineSignerPicksLastExpiring(t *testing.T) {
	f := newEngineFixture(t)

	// Issue a second chain; the issuer's CA cert is fresh, so both chains
	// are valid now.
	csr, err := trust.CreateCSR(iaNode, f.asKey)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := f.issuer.IssueChain(csr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.InsertChain(context.Background(), fresh); err != nil {
		t.Fatal(err)
	}
	s, err := f.engine.Signer(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !s.Expiration.Equal(fresh[0].NotAfter) {
		t.Errorf("signer expiration = %v, want the newest chain's %v",
			s.Expiration, fresh[0].NotAfter)
	}
}

// TestEngineSignVerify checks the sign/verify round trip with associated
// data, and that tampering fails.
func TestEngineSignVerify(t *testing.T) {
	f := newEngineFixture(t)
	ctx := context.Background()

	msg := []byte("ping")
	ad := [][]byte{[]byte("associated"), []byte("data")}
	signedMsg, err := f.engine.Sign(ctx, msg, ad...)
	if err != nil {
		t.Fatal(err)
	}
	m, err := f.engine.Verify(ctx, signedMsg, ad...)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if string(m.Body) != "ping" {
		t.Errorf("body = %q, want %q", m.Body, "ping")
	}

	if _, err := f.engine.Verify(ctx, signedMsg, []byte("other")); err == nil {
		t.Error("verification with wrong associated data succeeded")
	}
	signedMsg.HeaderAndBody[len(signedMsg.HeaderAndBody)-1] ^= 0xff
	if _, err := f.engine.Verify(ctx, signedMsg, ad...); err == nil {
		t.Error("verification of tampered body succeeded")
	}
}

// TestEngineVerifyForeignSignature checks the bound verifier: a signature
// from another IA fails even though its chain verifies against the TRC.
func TestEngineVerifyForeignSignature(t *testing.T) {
	f := newEngineFixture(t)
	ctx := context.Background()

	foreignKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := trust.CreateCSR(iaCore, foreignKey)
	if err != nil {
		t.Fatal(err)
	}
	foreignChain, err := f.issuer.IssueChain(csr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.InsertChain(ctx, foreignChain); err != nil {
		t.Fatal(err)
	}
	foreign := trust.NewEngine(iaCore, foreignKey, &trust.NetworkProvider{DB: f.db})
	signedMsg, err := foreign.Sign(ctx, []byte("foreign"))
	if err != nil {
		t.Fatal(err)
	}

	v := trust.Verifier{BoundIA: iaNode, Engine: &trust.NetworkProvider{DB: f.db}}
	if _, err := v.Verify(ctx, signedMsg); err == nil {
		t.Error("bound verifier accepted a foreign-IA signature")
	}
	unbound := trust.Verifier{Engine: &trust.NetworkProvider{DB: f.db}}
	if _, err := unbound.Verify(ctx, signedMsg); err != nil {
		t.Errorf("unbound verifier rejected a TRC-anchored signature: %v", err)
	}
}

// TestEngineVerifyUnanchored checks that signatures whose chains are unknown
// to the TRC-anchored database fail.
func TestEngineVerifyUnanchored(t *testing.T) {
	f := newEngineFixture(t)
	ctx := context.Background()

	rogueKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signedMsg, err := signed.Sign(signed.Header{
		SignatureAlgorithm: signed.ECDSAWithSHA256,
	}, []byte("rogue"), rogueKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.engine.Verify(ctx, signedMsg); err == nil {
		t.Error("verification of an unanchored signature succeeded")
	}
}

// TestEngineChainWithoutEnrollment checks that a node without a chain cannot
// sign: the engine demands enrollment.
func TestEngineChainWithoutEnrollment(t *testing.T) {
	f := newEngineFixture(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fresh := trust.NewEngine(addr.MustIAFrom(20, 0xff0000000007), key,
		&trust.NetworkProvider{DB: f.db})
	if _, err := fresh.Signer(context.Background()); err == nil {
		t.Error("signer built without enrollment")
	}
	chain, err := fresh.Chain(context.Background())
	if err != nil {
		t.Fatalf("Chain: %v", err)
	}
	if chain != nil {
		t.Errorf("chain = %v, want nil without enrollment", chain[0].Subject)
	}
}

// TestNewestChain checks the newest-chain helper the lifecycle loop reads.
func TestNewestChain(t *testing.T) {
	f := newEngineFixture(t)
	ctx := context.Background()

	chain, err := trust.NewestChain(ctx, f.db, iaNode, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if chain == nil {
		t.Fatal("newest chain = nil, want the issued chain")
	}
	if !chain[0].Equal(f.chain[0]) {
		t.Error("newest chain is not the issued one")
	}
	chain, err = trust.NewestChain(ctx, f.db, iaNode, time.Now().Add(72*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if chain != nil {
		t.Errorf("chain valid past its expiry = %v, want nil", chain[0].NotAfter)
	}
}
