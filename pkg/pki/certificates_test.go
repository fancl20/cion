package pki

import (
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
)

func TestCertificatesCreateCore(t *testing.T) {
	certs := NewCertificates()
	ia := addr.MustParseIA("1-ff00:0:110")
	validity := cppki.Validity{
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}

	// Create Core AS - should generate Root, Sensitive, and Regular certs
	if err := certs.Create(ia, ASTypeCore, validity); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Verify Root certificate
	rootCert, ok := certs.certs[CertTypeRoot]
	if !ok {
		t.Error("Root certificate not found in certs.certs map")
	}
	ct, err := cppki.ValidateCert(rootCert)
	if err != nil {
		t.Fatalf("ValidateCert(Root) failed: %v", err)
	}
	if ct != cppki.Root {
		t.Errorf("expected Root classification, got %v", ct)
	}

	// Verify Sensitive certificate
	sensitiveCert, ok := certs.certs[CertTypeSensitive]
	if !ok {
		t.Error("Sensitive certificate not found in certs.certs map")
	}
	ct, err = cppki.ValidateCert(sensitiveCert)
	if err != nil {
		t.Fatalf("ValidateCert(Sensitive) failed: %v", err)
	}
	if ct != cppki.Sensitive {
		t.Errorf("expected Sensitive classification, got %v", ct)
	}

	// Verify Regular certificate
	regularCert, ok := certs.certs[CertTypeRegular]
	if !ok {
		t.Error("Regular certificate not found in certs.certs map")
	}
	ct, err = cppki.ValidateCert(regularCert)
	if err != nil {
		t.Fatalf("ValidateCert(Regular) failed: %v", err)
	}
	if ct != cppki.Regular {
		t.Errorf("expected Regular classification, got %v", ct)
	}
}

func TestCertificatesCreateAuthoritative(t *testing.T) {
	certs := NewCertificates()
	ia := addr.MustParseIA("1-ff00:0:110")
	validity := cppki.Validity{
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}

	// Create Authoritative AS - should generate ONLY Regular cert
	if err := certs.Create(ia, ASTypeAuthoritative, validity); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Verify Regular certificate
	if _, ok := certs.certs[CertTypeRegular]; !ok {
		t.Error("Regular certificate not found after Create(ASTypeAuthoritative)")
	}
	// Verify NO Root/Sensitive
	if _, ok := certs.certs[CertTypeRoot]; ok {
		t.Error("Root certificate found after Create(ASTypeAuthoritative)")
	}
	if _, ok := certs.certs[CertTypeSensitive]; ok {
		t.Error("Sensitive certificate found after Create(ASTypeAuthoritative)")
	}
}

func TestCertificatesCreateNormal(t *testing.T) {
	certs := NewCertificates()
	ia := addr.MustParseIA("1-ff00:0:110")
	validity := cppki.Validity{
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}

	// Create Normal AS - should generate NO TRC certs
	if err := certs.Create(ia, ASTypeNormal, validity); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if _, ok := certs.certs[CertTypeRoot]; ok {
		t.Error("Root certificate found after Create(ASTypeNormal)")
	}
	if _, ok := certs.certs[CertTypeSensitive]; ok {
		t.Error("Sensitive certificate found after Create(ASTypeNormal)")
	}
	if _, ok := certs.certs[CertTypeRegular]; ok {
		t.Error("Regular certificate found after Create(ASTypeNormal)")
	}
}

func TestCertificatesCreateReplacesExisting(t *testing.T) {
	certs := NewCertificates()
	ia := addr.MustParseIA("1-ff00:0:110")
	validity := cppki.Validity{
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}

	// Create Core AS
	if err := certs.Create(ia, ASTypeCore, validity); err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	firstCert := certs.certs[CertTypeRoot]

	// Create Core AS again (should replace)
	if err := certs.Create(ia, ASTypeCore, validity); err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	secondCert := certs.certs[CertTypeRoot]

	if firstCert == secondCert {
		t.Error("Create did not replace existing certificate")
	}

	// Verify classification still Root
	ct, err := cppki.ValidateCert(secondCert)
	if err != nil {
		t.Fatalf("ValidateCert failed: %v", err)
	}
	if ct != cppki.Root {
		t.Errorf("expected Root classification after replacement, got %v", ct)
	}
}

func TestCertificatesEmpty(t *testing.T) {
	certs := NewCertificates()
	if len(certs.certs) != 0 {
		t.Error("certs.certs map is not empty for new Certificates instance")
	}
	if certs.certs[CertTypeRoot] != nil {
		t.Error("certs.certs[CertTypeRoot] returned non-nil for empty Certificates")
	}
}
