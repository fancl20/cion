package pki

import (
	"crypto"
	"crypto/x509"
	"reflect"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
)

func TestTRCsNew(t *testing.T) {
	trcs := NewTRCs(1)
	if trcs == nil {
		t.Fatal("NewTRCs returned nil")
	}
	_, err := trcs.Current()
	if err != ErrNoTRC {
		t.Errorf("Expected ErrNoTRC, got %v", err)
	}
	if pending := trcs.Pending(); len(pending) != 0 {
		t.Errorf("Expected empty pending, got %d", len(pending))
	}
}

func TestTRCsUpdateBaseTRC(t *testing.T) {
	pool := NewCertificates()
	trcs := NewTRCs(1)

	// Generate a base TRC for ISD 1
	validity := cppki.Validity{
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}
	coreAS := []addr.AS{addr.MustParseAS("ff00:0:110")}
	authAS := []addr.AS{addr.MustParseAS("ff00:0:111")}
	trc, _, err := GenerateBaseTRC(1, 1, 1, "Test base TRC", validity, coreAS, authAS)
	if err != nil {
		t.Fatalf("GenerateBaseTRC failed: %v", err)
	}

	// Update should succeed
	if err := trcs.Update(trc); err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	// Current should return the installed TRC
	current, err := trcs.Current()
	if err != nil {
		t.Fatalf("Current failed: %v", err)
	}
	if current.ID.Serial != 1 || current.ID.Base != 1 {
		t.Errorf("Unexpected TRC ID: %v", current.ID)
	}

	// Verify TRC contains expected certificates (pool is separate and should remain empty)
	roots, err := trcs.RootCertificates()
	if err != nil {
		t.Fatalf("RootCertificates failed: %v", err)
	}
	if len(roots) != 1 {
		t.Errorf("expected 1 root certificate, got %d", len(roots))
	}
	voters, err := trcs.VotingCertificates()
	if err != nil {
		t.Fatalf("VotingCertificates failed: %v", err)
	}
	if len(voters) != 2 {
		t.Errorf("expected 2 voting certificates, got %d", len(voters))
	}
	// Pool should remain empty (no automatic addition)
	if pool.HasCertificate() {
		t.Error("pool should not have any certificate")
	}
}

func TestTRCsUpdateWrongISD(t *testing.T) {
	trcs := NewTRCs(1)

	// Generate a TRC for ISD 2
	validity := cppki.Validity{
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}
	coreAS := []addr.AS{addr.MustParseAS("ff00:0:110")}
	authAS := []addr.AS{addr.MustParseAS("ff00:0:111")}
	trc, _, err := GenerateBaseTRC(2, 1, 1, "Test TRC ISD2", validity, coreAS, authAS)
	if err != nil {
		t.Fatalf("GenerateBaseTRC failed: %v", err)
	}

	// Update should fail with ErrISDMismatch
	if err := trcs.Update(trc); err != ErrISDMismatch {
		t.Errorf("Expected ErrISDMismatch, got %v", err)
	}
}

func TestTRCsUpdateNonBaseAsFirst(t *testing.T) {
	trcs := NewTRCs(1)

	// Generate a TRC with serial != base (simulate update)
	validity := cppki.Validity{
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}
	coreAS := []addr.AS{addr.MustParseAS("ff00:0:110")}
	authAS := []addr.AS{addr.MustParseAS("ff00:0:111")}
	// serial 2, base 1
	trc, _, err := GenerateBaseTRC(1, 2, 1, "Test update TRC", validity, coreAS, authAS)
	if err != nil {
		t.Fatalf("GenerateBaseTRC failed: %v", err)
	}

	// Update should fail with ErrTRCUpdateUnsupported (since serial != base)
	if err := trcs.Update(trc); err != ErrTRCUpdateUnsupported {
		t.Errorf("Expected ErrTRCUpdateUnsupported, got %v", err)
	}
}

func TestTRCsUpdateUpdateRejected(t *testing.T) {
	trcs := NewTRCs(1)

	// Update base TRC first
	validity := cppki.Validity{
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}
	coreAS := []addr.AS{addr.MustParseAS("ff00:0:110")}
	authAS := []addr.AS{addr.MustParseAS("ff00:0:111")}
	baseTRC, _, err := GenerateBaseTRC(1, 1, 1, "Base TRC", validity, coreAS, authAS)
	if err != nil {
		t.Fatalf("GenerateBaseTRC failed: %v", err)
	}
	if err := trcs.Update(baseTRC); err != nil {
		t.Fatalf("Update base failed: %v", err)
	}

	// Attempt to install an update (higher serial, same base)
	// GenerateBaseTRC cannot produce a proper update (would need votes), but we can
	// still generate a TRC with serial 2, base 1. It will lack proper votes,
	// but our PoC logic rejects all updates anyway.
	updateTRC, _, err := GenerateBaseTRC(1, 2, 1, "Update TRC", validity, coreAS, authAS)
	if err != nil {
		t.Fatalf("GenerateBaseTRC for update failed: %v", err)
	}
	// Update should fail with ErrTRCUpdateUnsupported
	if err := trcs.Update(updateTRC); err != ErrTRCUpdateUnsupported {
		t.Errorf("Expected ErrTRCUpdateUnsupported, got %v", err)
	}
}

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
	trc, privKey, err := GenerateBaseTRC(isd, version, baseVersion, description, validity, coreASes, authoritativeASes)
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

	// Verify certificates within TRC (root, sensitive voting, regular voting)
	if len(trc.Certificates) != 3 {
		t.Fatalf("TRC should contain exactly three certificates, got %d", len(trc.Certificates))
	}
	// Classify each certificate
	var rootCert, sensitiveCert, regularCert *x509.Certificate
	for _, cert := range trc.Certificates {
		class, err := cppki.ValidateCert(cert)
		if err != nil {
			t.Errorf("Certificate validation failed: %v", err)
			continue
		}
		switch class {
		case cppki.Root:
			if rootCert != nil {
				t.Error("Multiple root certificates found")
			}
			rootCert = cert
		case cppki.Sensitive:
			if sensitiveCert != nil {
				t.Error("Multiple sensitive voting certificates found")
			}
			sensitiveCert = cert
		case cppki.Regular:
			if regularCert != nil {
				t.Error("Multiple regular voting certificates found")
			}
			regularCert = cert
		default:
			t.Errorf("Unexpected certificate classification: %v", class)
		}
	}
	if rootCert == nil {
		t.Fatal("Root certificate not found")
	}
	if sensitiveCert == nil {
		t.Fatal("Sensitive voting certificate not found")
	}
	if regularCert == nil {
		t.Fatal("Regular voting certificate not found")
	}
	// Verify root cert public key matches generated private key
	if !reflect.DeepEqual(rootCert.PublicKey, privKey.(crypto.Signer).Public()) {
		t.Error("Root cert public key should match generated private key")
	}
	// Verify root certificate is self-signed
	if err := rootCert.CheckSignatureFrom(rootCert); err != nil {
		t.Errorf("Root certificate should be self-signed and verifiable: %v", err)
	}

	// Check validity
	if !trc.Validity.NotBefore.Equal(validity.NotBefore) {
		t.Errorf("TRC NotBefore mismatch: got %v, want %v", trc.Validity.NotBefore, validity.NotBefore)
	}
	if !trc.Validity.NotAfter.Equal(validity.NotAfter) {
		t.Errorf("TRC NotAfter mismatch: got %v, want %v", trc.Validity.NotAfter, validity.NotAfter)
	}
}
