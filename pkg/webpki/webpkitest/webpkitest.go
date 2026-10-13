// Package webpkitest mints the test certificate authority that stands in for
// the WebPKI: a CA and a server certificate for Domain, written to files the
// core's endpoint loads. A test-support library on the standard library
// alone, so any package's tests can import it, pkg/webpki's own among them.
package webpkitest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Domain is the DNS identity of the core endpoint in tests; its certificate
// is signed by the test CA.
const Domain = "cion-core.test"

// CA is the test certificate authority anchoring the endpoint's TLS
// certificate: the pool trusting it, the server certificate and key files
// for Domain, and the CA's own certificate file.
type CA struct {
	Pool     *x509.CertPool
	CertFile string
	KeyFile  string
	CAFile   string
}

// New mints the CA and the server certificate in a fresh temporary
// directory.
func New(t testing.TB) *CA {
	t.Helper()
	ca, err := Mint(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

// Mint mints the CA and the server certificate in dir, for callers with no
// test at hand, such as TestMain. The server certificate names Domain and
// the loopback address 127.0.0.1, which clients that dial the endpoint by
// address verify.
func Mint(dir string) (*CA, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "cion test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caKey.Public(), caKey)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serverTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: Domain},
		DNSNames:     []string{Domain},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTmpl, caCert,
		serverKey.Public(), caKey)
	if err != nil {
		return nil, err
	}
	serverKeyDER, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		return nil, err
	}
	ca := &CA{
		Pool:     x509.NewCertPool(),
		CertFile: filepath.Join(dir, "cert.pem"),
		KeyFile:  filepath.Join(dir, "key.pem"),
		CAFile:   filepath.Join(dir, "ca.pem"),
	}
	ca.Pool.AddCert(caCert)
	for _, f := range []struct {
		path  string
		block *pem.Block
	}{
		{ca.CertFile, &pem.Block{Type: "CERTIFICATE", Bytes: serverDER}},
		{ca.KeyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: serverKeyDER}},
		{ca.CAFile, &pem.Block{Type: "CERTIFICATE", Bytes: caDER}},
	} {
		if err := os.WriteFile(f.path, pem.EncodeToMemory(f.block), 0o600); err != nil {
			return nil, err
		}
	}
	return ca, nil
}
