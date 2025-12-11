package pki

import (
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
)

func TestCertificatesCreateRoot(t *testing.T) {
	certs := NewCertificates()
	ia := addr.MustParseIA("1-ff00:0:110")
	validity := cppki.Validity{
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}

	// Create root certificate
	if err := certs.Create(ia, "Test Root", VotingRoleRoot, validity); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Verify certificate is stored
	if !certs.HasCertificate() {
		t.Error("HasCertificate returned false after Create")
	}
	cert := certs.Certificate()
	if cert == nil {
		t.Fatal("Certificate returned nil")
	}

	// Verify classification
	ct, err := cppki.ValidateCert(cert)
	if err != nil {
		t.Fatalf("ValidateCert failed: %v", err)
	}
	if ct != cppki.Root {
		t.Errorf("expected Root classification, got %v", ct)
	}
}

func TestCertificatesCreateSensitive(t *testing.T) {
	certs := NewCertificates()
	ia := addr.MustParseIA("1-ff00:0:110")
	validity := cppki.Validity{
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}

	// Create sensitive voting certificate
	if err := certs.Create(ia, "Sensitive Voting", VotingRoleSensitive, validity); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Verify certificate is stored
	if !certs.HasCertificate() {
		t.Error("HasCertificate returned false after Create")
	}
	cert := certs.Certificate()
	if cert == nil {
		t.Fatal("Certificate returned nil")
	}

	// Verify classification
	ct, err := cppki.ValidateCert(cert)
	if err != nil {
		t.Fatalf("ValidateCert failed: %v", err)
	}
	if ct != cppki.Sensitive {
		t.Errorf("expected Sensitive classification, got %v", ct)
	}
}

func TestCertificatesCreateRegular(t *testing.T) {
	certs := NewCertificates()
	ia := addr.MustParseIA("1-ff00:0:110")
	validity := cppki.Validity{
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}

	// Create regular voting certificate
	if err := certs.Create(ia, "Regular Voting", VotingRoleRegular, validity); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Verify certificate is stored
	if !certs.HasCertificate() {
		t.Error("HasCertificate returned false after Create")
	}
	cert := certs.Certificate()
	if cert == nil {
		t.Fatal("Certificate returned nil")
	}

	// Verify classification
	ct, err := cppki.ValidateCert(cert)
	if err != nil {
		t.Fatalf("ValidateCert failed: %v", err)
	}
	if ct != cppki.Regular {
		t.Errorf("expected Regular classification, got %v", ct)
	}
}

func TestCertificatesCreateReplacesExisting(t *testing.T) {
	certs := NewCertificates()
	ia := addr.MustParseIA("1-ff00:0:110")
	validity := cppki.Validity{
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}

	// Create root certificate
	if err := certs.Create(ia, "First Root", VotingRoleRoot, validity); err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	firstCert := certs.Certificate()

	// Create sensitive certificate (should replace root)
	if err := certs.Create(ia, "Sensitive Voting", VotingRoleSensitive, validity); err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	secondCert := certs.Certificate()

	if firstCert == secondCert {
		t.Error("Create did not replace existing certificate")
	}

	// Verify new certificate is sensitive
	ct, err := cppki.ValidateCert(secondCert)
	if err != nil {
		t.Fatalf("ValidateCert failed: %v", err)
	}
	if ct != cppki.Sensitive {
		t.Errorf("expected Sensitive classification after replacement, got %v", ct)
	}
}

func TestCertificatesEmpty(t *testing.T) {
	certs := NewCertificates()
	if certs.HasCertificate() {
		t.Error("HasCertificate returned true for empty Certificates")
	}
	if certs.Certificate() != nil {
		t.Error("Certificate returned non-nil for empty Certificates")
	}
}
