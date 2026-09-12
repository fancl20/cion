package controlplane

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"path/filepath"
	"testing"

	"connectrpc.com/connect"
	"github.com/scionproto/scion/pkg/addr"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/trust"
	"github.com/fancl20/cion/pkg/trust/impl/bbolt"
)

var (
	coreIATest = addr.MustIAFrom(20, 0xff0000000001)
	nodeIATest = addr.MustIAFrom(20, 0xff0000000002)
)

// trustFixture is a serving-side trust stack: DB with a genesis TRC and an
// issuer.
type trustFixture struct {
	db     trust.DB
	issuer *trust.Issuer
	trc    cppki.SignedTRC
}

func newTrustFixture(t *testing.T) *trustFixture {
	t.Helper()
	dir := t.TempDir()
	db, err := bbolt.New(filepath.Join(dir, "trust.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() }) //nolint:errcheck
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
	return &trustFixture{db: db, issuer: issuer, trc: trc}
}

// newCSR returns a CSR for a freshly generated AS key.
func newCSR(t *testing.T, ia addr.IA) (*x509.CertificateRequest, crypto.Signer) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := trust.CreateCSR(ia, key)
	if err != nil {
		t.Fatal(err)
	}
	return csr, key
}

func TestTrustServiceTRC(t *testing.T) {
	f := newTrustFixture(t)
	svc := &TrustService{DB: f.db, Issuer: f.issuer}

	for name, req := range map[string]*cppb.TRCRequest{
		"exact":  {Isd: uint32(coreIATest.ISD()), Base: 1, Serial: 1},
		"latest": {Isd: uint32(coreIATest.ISD())},
	} {
		resp, err := svc.TRC(context.Background(), connect.NewRequest(req))
		if err != nil {
			t.Fatal(err)
		}
		got, err := cppki.DecodeSignedTRC(resp.Msg.Trc)
		if err != nil {
			t.Fatal(err)
		}
		if got.TRC.ID != f.trc.TRC.ID {
			t.Errorf("%s: served TRC %v, want %v", name, got.TRC.ID, f.trc.TRC.ID)
		}
	}

	_, err := svc.TRC(context.Background(), connect.NewRequest(&cppb.TRCRequest{
		Isd: uint32(coreIATest.ISD()), Base: 4, Serial: 9,
	}))
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("unknown TRC error code = %v, want NotFound", connect.CodeOf(err))
	}
}

func TestTrustServiceChains(t *testing.T) {
	f := newTrustFixture(t)
	svc := &TrustService{DB: f.db, Issuer: f.issuer}

	csr, _ := newCSR(t, nodeIATest)
	chain, err := f.issuer.IssueChain(csr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.InsertChain(context.Background(), chain); err != nil {
		t.Fatal(err)
	}

	resp, err := svc.Chains(context.Background(), connect.NewRequest(&cppb.ChainsRequest{
		IsdAs: uint64(nodeIATest),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Msg.Chains) != 1 {
		t.Fatalf("served chains = %d, want 1", len(resp.Msg.Chains))
	}
	asCert, err := x509.ParseCertificate(resp.Msg.Chains[0].AsCert)
	if err != nil {
		t.Fatal(err)
	}
	if !asCert.Equal(chain[0]) {
		t.Error("served chain differs from stored chain")
	}
}

func TestTrustServiceChainRenewal(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		f := newTrustFixture(t)
		svc := &TrustService{DB: f.db, Issuer: f.issuer}

		csr, key := newCSR(t, nodeIATest)
		req, err := trust.BuildRenewalRequest(csr, key)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := svc.ChainRenewal(context.Background(), connect.NewRequest(
			&cppb.ChainRenewalRequest{CmsSignedRequest: req}))
		if err != nil {
			t.Fatal(err)
		}
		chain, err := trust.ParseRenewalResponse(resp.Msg.CmsSignedResponse)
		if err != nil {
			t.Fatal(err)
		}
		if err := cppki.VerifyChain(chain, cppki.VerifyOptions{
			TRC: []*cppki.TRC{&f.trc.TRC},
		}); err != nil {
			t.Fatalf("renewed chain does not verify: %v", err)
		}
		// The issued chain is also in the core's DB.
		chains, err := f.db.Chains(context.Background(), trust.ChainQuery{IA: nodeIATest})
		if err != nil {
			t.Fatal(err)
		}
		if len(chains) != 1 {
			t.Fatalf("core DB chains = %d, want 1", len(chains))
		}
	})

	t.Run("allowlist", func(t *testing.T) {
		f := newTrustFixture(t)
		svc := &TrustService{DB: f.db, Issuer: f.issuer,
			AllowAS: map[addr.IA]bool{addr.MustIAFrom(20, 0xff0000000abc): true}}

		csr, key := newCSR(t, nodeIATest)
		req, err := trust.BuildRenewalRequest(csr, key)
		if err != nil {
			t.Fatal(err)
		}
		_, err = svc.ChainRenewal(context.Background(), connect.NewRequest(
			&cppb.ChainRenewalRequest{CmsSignedRequest: req}))
		if connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Errorf("allowlisted-out error code = %v, want PermissionDenied",
				connect.CodeOf(err))
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		f := newTrustFixture(t)
		svc := &TrustService{DB: f.db, Issuer: f.issuer}

		// Wrapper signed by a different key than the CSR's subject.
		csr, _ := newCSR(t, nodeIATest)
		other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		req, err := trust.BuildRenewalRequest(csr, other)
		if err != nil {
			t.Fatal(err)
		}
		_, err = svc.ChainRenewal(context.Background(), connect.NewRequest(
			&cppb.ChainRenewalRequest{CmsSignedRequest: req}))
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("wrong-key error code = %v, want InvalidArgument", connect.CodeOf(err))
		}
	})

	t.Run("unsigned csr", func(t *testing.T) {
		f := newTrustFixture(t)
		svc := &TrustService{DB: f.db, Issuer: f.issuer}

		csr, key := newCSR(t, nodeIATest)
		// Corrupt the CSR's signature in its DER form; parsing the request
		// already refuses it.
		bad := *csr
		bad.Raw = append([]byte(nil), csr.Raw...)
		bad.Raw[len(bad.Raw)-1] ^= 0xff
		req, err := trust.BuildRenewalRequest(&bad, key)
		if err != nil {
			t.Fatal(err)
		}
		_, err = svc.ChainRenewal(context.Background(), connect.NewRequest(
			&cppb.ChainRenewalRequest{CmsSignedRequest: req}))
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("unsigned-CSR error code = %v, want InvalidArgument", connect.CodeOf(err))
		}
	})
}
