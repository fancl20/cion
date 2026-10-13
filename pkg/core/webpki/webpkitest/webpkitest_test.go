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
