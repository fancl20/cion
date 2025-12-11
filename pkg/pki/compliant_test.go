package pki

import (
	"crypto"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
)

func TestGenerateRootCert(t *testing.T) {
	ia := addr.MustParseIA("1-ff00:0:110")
	validity := cppki.Validity{
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}
	cert, privKey, err := generateRootCert(ia, "Test Root", validity)
	if err != nil {
		t.Fatalf("failed to generate compliant root cert: %v", err)
	}
	// Print OIDs for debugging
	fmt.Printf("UnknownExtKeyUsage OIDs: %v\n", cert.UnknownExtKeyUsage)
	fmt.Printf("OIDExtKeyUsageRoot: %v\n", cppki.OIDExtKeyUsageRoot)
	// Check classification
	ct, err := cppki.ValidateCert(cert)
	if err != nil {
		t.Errorf("ValidateCert failed: %v", err)
	}
	if ct != cppki.Root {
		t.Errorf("expected Root classification, got %v", ct)
	}
	// Verify IA extraction
	subjectIA, err := cppki.ExtractIA(cert.Subject)
	if err != nil {
		t.Errorf("ExtractIA from Subject failed: %v", err)
	}
	if subjectIA != ia {
		t.Errorf("subject IA mismatch: got %v, want %v", subjectIA, ia)
	}
	issuerIA, err := cppki.ExtractIA(cert.Issuer)
	if err != nil {
		t.Errorf("ExtractIA from Issuer failed: %v", err)
	}
	if issuerIA != ia {
		t.Errorf("issuer IA mismatch: got %v, want %v", issuerIA, ia)
	}
	// Verify self-signed
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Errorf("self-signature verification failed: %v", err)
	}
	// Verify public key matches
	if !reflect.DeepEqual(cert.PublicKey, privKey.(crypto.Signer).Public()) {
		t.Error("public key mismatch")
	}
}
