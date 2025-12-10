package pki

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
)

func TestGenerateAndValidateTRC(t *testing.T) {
	// Define TRC parameters
	isd := 1
	version := 1
	baseVersion := 1
	description := "Test TRC for CION PoC"
	validity := cppki.Validity{
		NotBefore: time.Now().Truncate(time.Second),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour).Truncate(time.Second),
	}
	coreASes := []addr.AS{addr.MustParseAS("ff00:0:110")}
	authoritativeASes := []addr.AS{addr.MustParseAS("ff00:0:110")}

	// Generate TRC
	trc, privKey, err := GenerateTRC(isd, version, baseVersion, description, validity, coreASes, authoritativeASes)
	if err != nil {
		t.Fatalf("TRC generation failed: %v", err)
	}
	if trc == nil {
		t.Fatal("Generated TRC is nil")
	}
	if privKey == nil {
		t.Fatal("Generated private key is nil")
	}

	// Assert basic TRC fields (without full cppki validation)
	if got, want := trc.ID.ISD, addr.ISD(isd); got != want {
		t.Errorf("TRC ISD mismatch: got %v, want %v", got, want)
	}
	if got, want := trc.ID.Serial, scrypto.Version(version); got != want {
		t.Errorf("TRC Serial version mismatch: got %v, want %v", got, want)
	}
	if got, want := trc.ID.Base, scrypto.Version(baseVersion); got != want {
		t.Errorf("TRC Base version mismatch: got %v, want %v", got, want)
	}
	if got, want := trc.Description, description; got != want {
		t.Errorf("TRC Description mismatch: got %v, want %v", got, want)
	}

	// Verify root certificate within TRC
	if len(trc.Certificates) != 1 {
		t.Fatalf("TRC should contain exactly one root certificate, got %d", len(trc.Certificates))
	}
	rootCert := trc.Certificates[0]
	if !rootCert.PublicKey.(ed25519.PublicKey).Equal(privKey.Public().(ed25519.PublicKey)) {
		t.Error("Root cert public key should match generated private key")
	}
	if err := rootCert.CheckSignatureFrom(rootCert); err != nil {
		t.Errorf("Root cert should be self-signed and verifiable: %v", err)
	}

	// Check validity
	if !trc.Validity.NotBefore.Equal(validity.NotBefore) {
		t.Errorf("TRC NotBefore mismatch: got %v, want %v", trc.Validity.NotBefore, validity.NotBefore)
	}
	if !trc.Validity.NotAfter.Equal(validity.NotAfter) {
		t.Errorf("TRC NotAfter mismatch: got %v, want %v", trc.Validity.NotAfter, validity.NotAfter)
	}
}

func TestGenerateSelfSignedCert(t *testing.T) {
	// Generate keys
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	// Define IA and Common Name
	ia := addr.MustParseIA("1-ff00:0:111")
	commonName := "test-as-111"

	// Generate certificate
	cert, err := GenerateSelfSignedCert(ia, commonName, priv)
	if err != nil {
		t.Fatalf("Certificate generation failed: %v", err)
	}
	if cert == nil {
		t.Fatal("Generated certificate is nil")
	}

	// Verify certificate properties
	if !cert.PublicKey.(ed25519.PublicKey).Equal(pub) {
		t.Error("Public key mismatch")
	}
	if cert.Subject.CommonName != commonName {
		t.Errorf("Common Name mismatch: got %q, want %q", cert.Subject.CommonName, commonName)
	}
	if !cert.IsCA {
		t.Error("Certificate should be a CA cert")
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Errorf("Certificate should be self-signed: %v", err)
	}

	// cppki.ExtractIA should now work for generic certs, but we are not relying on it for TRC classification.
	// Test that it does NOT contain the SCION OID, and thus ExtractIA should fail.
	if _, err := cppki.ExtractIA(cert.Subject); err == nil {
		t.Error("ExtractIA should fail for a generic self-signed certificate without SCION OID")
	}
}
