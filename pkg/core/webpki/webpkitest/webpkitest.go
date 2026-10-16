// Package webpkitest mints the test certificate authority that stands in for
// the WebPKI: a CA and a server certificate for Domain, written to files the
// core's endpoint loads. A test-support library on the standard library
// alone, so any package's tests can import it, pkg/core/webpki's own among
// them.
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
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Domain is the DNS identity of the core endpoint in tests; its certificate
// is signed by the test CA.
const Domain = "cion-core.test"

// Address is the address identity the CA mints a certificate for beside
// the domain's: the loopback address, the host an address-shaped lab's core
// sits on.
const Address = "127.0.0.1"

// CA is the test certificate authority anchoring the endpoint's TLS
// certificates: the pool trusting it, the domain's server certificate and
// key files, the address identity's beside them, and the CA's own
// certificate file.
type CA struct {
	Pool     *x509.CertPool
	CertFile string
	KeyFile  string
	// AddrCertFile and AddrKeyFile hold the address identity's certificate
	// — SANs carrying the address alone, the common name omitted, the
	// shape the shortlived profile issues.
	AddrCertFile string
	AddrKeyFile  string
	CAFile       string
}

// New mints the CA and the server certificates — the domain's and the
// loopback address's — in a fresh temporary directory.
func New(t testing.TB) *CA {
	t.Helper()
	ca, err := mint(t.TempDir(), netip.MustParseAddr(Address))
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

// NewFor is New with the address identity's own address, for the labs whose
// core sits on a host of their own drawing.
func NewFor(t testing.TB, address netip.Addr) *CA {
	t.Helper()
	ca, err := mint(t.TempDir(), address)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

// Mint mints the CA and the server certificates in dir, for callers with no
// test at hand, such as TestMain.
func Mint(dir string) (*CA, error) {
	return mint(dir, netip.MustParseAddr(Address))
}

// mint mints the CA and the two server certificates in dir. The domain's
// names Domain and the loopback address 127.0.0.1, which clients that dial
// the endpoint by address verify; the address identity's carries address
// alone.
func mint(dir string, address netip.Addr) (*CA, error) {
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

	addrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	addrTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		IPAddresses:  []net.IP{address.AsSlice()},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	addrDER, err := x509.CreateCertificate(rand.Reader, addrTmpl, caCert,
		addrKey.Public(), caKey)
	if err != nil {
		return nil, err
	}
	addrKeyDER, err := x509.MarshalECPrivateKey(addrKey)
	if err != nil {
		return nil, err
	}
	ca := &CA{
		Pool:         x509.NewCertPool(),
		CertFile:     filepath.Join(dir, "cert.pem"),
		KeyFile:      filepath.Join(dir, "key.pem"),
		AddrCertFile: filepath.Join(dir, "addr-cert.pem"),
		AddrKeyFile:  filepath.Join(dir, "addr-key.pem"),
		CAFile:       filepath.Join(dir, "ca.pem"),
	}
	ca.Pool.AddCert(caCert)
	for _, f := range []struct {
		path  string
		block *pem.Block
	}{
		{ca.CertFile, &pem.Block{Type: "CERTIFICATE", Bytes: serverDER}},
		{ca.KeyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: serverKeyDER}},
		{ca.AddrCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: addrDER}},
		{ca.AddrKeyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: addrKeyDER}},
		{ca.CAFile, &pem.Block{Type: "CERTIFICATE", Bytes: caDER}},
	} {
		if err := os.WriteFile(f.path, pem.EncodeToMemory(f.block), 0o600); err != nil {
			return nil, err
		}
	}
	return ca, nil
}
