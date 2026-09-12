package trust

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
)

var nodeIA = addr.MustIAFrom(20, 0xff0000000002)

func newTestASKey(t *testing.T) crypto.Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestIssueChain(t *testing.T) {
	f := newGenesisFixture(t)
	issuer, err := NewIssuer(coreIA, f.keys, f.trc)
	if err != nil {
		t.Fatal(err)
	}
	key := newTestASKey(t)
	csr, err := CreateCSR(nodeIA, key)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := issuer.IssueChain(csr)
	if err != nil {
		t.Fatal(err)
	}
	// The chain verifies against the TRC's root pool; this also checks the
	// two-certificate shape.
	if err := cppki.VerifyChain(chain,
		cppki.VerifyOptions{TRC: []*cppki.TRC{&f.trc.TRC}}); err != nil {

		t.Fatalf("issued chain does not verify against TRC: %v", err)
	}
	if got, err := cppki.ExtractIA(chain[0].Subject); err != nil || !got.Equal(nodeIA) {
		t.Fatalf("chain subject = %v (%v), want %v", got, err, nodeIA)
	}
	// The CA certificate is not part of the TRC.
	for _, cert := range f.trc.TRC.Certificates {
		if cert.Equal(chain[1]) {
			t.Error("CA certificate leaked into the TRC")
		}
	}
}

// TestIssueChainRejectsForeignCSR checks that CSRs of another ISD and CSRs
// without a subject ISD-AS are rejected.
func TestIssueChainRejectsForeignCSR(t *testing.T) {
	f := newGenesisFixture(t)
	issuer, err := NewIssuer(coreIA, f.keys, f.trc)
	if err != nil {
		t.Fatal(err)
	}
	key := newTestASKey(t)
	foreign, err := CreateCSR(addr.MustIAFrom(21, nodeIA.AS()), key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.IssueChain(foreign); err == nil {
		t.Error("issuing for a foreign ISD succeeded, want rejection")
	}
	bareDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	bare, err := x509.ParseCertificateRequest(bareDER)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.IssueChain(bare); err == nil {
		t.Error("issuing for a CSR without ISD-AS succeeded, want rejection")
	}
}

// TestIssueChainRejectsUnsignedCSR checks that a CSR whose signature does
// not match the subject key — no proof of possession — is rejected.
func TestIssueChainRejectsUnsignedCSR(t *testing.T) {
	f := newGenesisFixture(t)
	issuer, err := NewIssuer(coreIA, f.keys, f.trc)
	if err != nil {
		t.Fatal(err)
	}
	good, err := CreateCSR(nodeIA, newTestASKey(t))
	if err != nil {
		t.Fatal(err)
	}
	bad := *good
	bad.Signature = append([]byte(nil), good.Signature...)
	bad.Signature[len(bad.Signature)-1] ^= 0xff
	if _, err := issuer.IssueChain(&bad); err == nil {
		t.Error("issuing for a CSR with broken signature succeeded, want rejection")
	}
}

// TestIssuerReissuesCACert checks that the CA certificate is reissued once
// it no longer covers a full AS certificate validity, and that both the old
// and the new CA anchor in the TRC root.
func TestIssuerReissuesCACert(t *testing.T) {
	f := newGenesisFixture(t)
	issuer, err := NewIssuer(coreIA, f.keys, f.trc)
	if err != nil {
		t.Fatal(err)
	}
	first, err := issuer.CACert()
	if err != nil {
		t.Fatal(err)
	}
	// Move time forward beyond the CA certificate's remaining usefulness
	// for a three-day AS certificate.
	issuer.now = func() time.Time {
		return time.Now().Add(CAValidity - ASValidity + time.Hour)
	}
	second, err := issuer.CACert()
	if err != nil {
		t.Fatal(err)
	}
	if second.Equal(first) {
		t.Fatal("CA certificate was not reissued")
	}
	if !second.NotAfter.After(issuer.now().Add(ASValidity)) {
		t.Errorf("reissued CA expires %v, too early for a full AS validity",
			second.NotAfter)
	}
	// Chains issued under the fresh CA still verify against the TRC.
	key := newTestASKey(t)
	csr, err := CreateCSR(nodeIA, key)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := issuer.IssueChain(csr)
	if err != nil {
		t.Fatal(err)
	}
	opts := cppki.VerifyOptions{
		TRC:         []*cppki.TRC{&f.trc.TRC},
		CurrentTime: issuer.now().Add(time.Minute),
	}
	if err := cppki.VerifyChain(chain, opts); err != nil {
		t.Fatalf("chain under reissued CA does not verify: %v", err)
	}
}
