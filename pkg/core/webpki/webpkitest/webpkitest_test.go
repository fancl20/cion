package webpkitest

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"testing"
)

// TestMintVerifies checks the minted files: the server certificate loads
// with its key and verifies under the pool for Domain and for the loopback
// address, and the CA file holds the CA the pool trusts.
func TestMintVerifies(t *testing.T) {
	ca := New(t)
	pair, err := tls.LoadX509KeyPair(ca.CertFile, ca.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{Domain, "127.0.0.1"} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: ca.Pool, DNSName: name}); err != nil {
			t.Errorf("verifying the server certificate for %s: %v", name, err)
		}
	}
	raw, err := os.ReadFile(ca.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	fromFile := x509.NewCertPool()
	if !fromFile.AppendCertsFromPEM(raw) {
		t.Fatal("the CA file holds no certificate")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: fromFile, DNSName: Domain}); err != nil {
		t.Errorf("verifying the server certificate under the CA file: %v", err)
	}
}

// TestMintAddressCertVerifies checks the address identity's certificate: it
// loads with its key, verifies under the pool for the address alone, and
// names nothing else — no DNS name, no common name — the shape the
// shortlived profile issues.
func TestMintAddressCertVerifies(t *testing.T) {
	ca := New(t)
	pair, err := tls.LoadX509KeyPair(ca.AddrCertFile, ca.AddrKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: ca.Pool, DNSName: Address}); err != nil {
		t.Errorf("verifying the address certificate for %s: %v", Address, err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: ca.Pool, DNSName: Domain}); err == nil {
		t.Error("the address certificate verified for the domain")
	}
	if len(leaf.DNSNames) != 0 || leaf.Subject.CommonName != "" {
		t.Errorf("the address certificate names %q beyond its addresses, want none",
			append(leaf.DNSNames, leaf.Subject.CommonName))
	}
}
