package webpki

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json/v2"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/v3"
	"github.com/mholt/acmez/v3/acme"
)

// testDomain is the DNS identity of the test core's certificate.
const testDomain = "cion-core.test"

// idPEACMEIdentifierV1 is the certificate extension an ACME TLS-ALPN
// challenge certificate carries (RFC 8737 §6.1).
var idPEACMEIdentifierV1 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}

// mintCertFiles writes a self-signed certificate pair for testDomain and
// 127.0.0.1, the tests' stand-in for the WebPKI, returning the files and
// the pool trusting the certificate.
func mintCertFiles(t *testing.T) (certFile, keyFile string, pool *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: testDomain},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:     []string{testDomain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(
		&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	pool = x509.NewCertPool()
	pool.AddCert(cert)
	return certFile, keyFile, pool
}

// serveHTTPS serves the manager's HTTPS server on the listener under the
// test's supervision.
func serveHTTPS(t *testing.T, m *CertManager, ln net.Listener, handler http.Handler) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.ServeHTTPS(ctx, ln, handler) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("ServeHTTPS(%v) = %v, want nil", ln.Addr(), err)
			}
		case <-time.After(5 * time.Second):
			t.Error("the HTTPS server did not stop")
		}
	})
}

// TestServeHTTPSHTTP11 checks the serving half against a static-file
// identity: the bind returns with the port held, and a plain HTTP/1.1
// request reaches the mounted handler over the loaded certificate.
func TestServeHTTPSHTTP11(t *testing.T) {
	certFile, keyFile, pool := mintCertFiles(t)
	manager, err := PrepareTLSCert(context.Background(), TLSCertConfig{
		Domain:   testDomain,
		CertFile: certFile,
		KeyFile:  keyFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/mounted", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("mounted"))
	})
	ln, err := manager.ListenHTTPS("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	// The bind returns with the port held: the listener answers before
	// anything serves it, so the certificate maintenance can launch
	// against a listening server.
	probe, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("the port is not held after the bind: %v", err)
	}
	_ = probe.Close()
	serveHTTPS(t, manager, ln, mux)

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: pool,
	}}}
	resp, err := client.Get("https://" + ln.Addr().String() + "/mounted")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.Proto != "HTTP/1.1" {
		t.Errorf("the served protocol = %s, want HTTP/1.1", resp.Proto)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "mounted" {
		t.Errorf("the mounted handler's body = %q, want %q", body, "mounted")
	}
}

// TestServeHTTPSACMEChallenge checks the challenge answers on the mounted
// server — no dedicated listener: a client offering only acme-tls/1
// completes its handshake against certmagic's challenge certificate,
// served from the cache the challenge was seeded into, with the extension
// RFC 8737 names carried by the certificate itself.
func TestServeHTTPSACMEChallenge(t *testing.T) {
	manager, ln := acmeManager(t, testDomain)
	serveHTTPS(t, manager, ln, http.NotFoundHandler())

	// An ACME probe: SNI naming the domain, the challenge name the one
	// protocol offered. The challenge certificate is self-signed — the ACME
	// verifier reads the extension, not a chain — so the client verifies
	// nothing here.
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		NextProtos:         []string{acmez.ACMETLS1Protocol},
		ServerName:         testDomain,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("the challenge handshake against the mounted server: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if proto := conn.ConnectionState().NegotiatedProtocol; proto != acmez.ACMETLS1Protocol {
		t.Fatalf("the negotiated protocol = %q, want %q", proto, acmez.ACMETLS1Protocol)
	}
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		t.Fatal("the challenge handshake presented no certificate")
	}
	for _, ext := range certs[0].Extensions {
		if ext.Id.Equal(idPEACMEIdentifierV1) {
			return
		}
	}
	t.Errorf("the served certificate carries no ACME identifier extension, "+
		"want the challenge's (subject %q)", certs[0].Subject.CommonName)
}

// acmeManager builds a certmagic-backed identity — PrepareTLSCert's ACME
// arm without its port-80 listener, which the tests may not bind — with a
// solved TLS-ALPN challenge seeded into the cache the way a distributed
// solve stores it, and binds the node's HTTPS server for it.
func acmeManager(t *testing.T, domain string) (*CertManager, net.Listener) {
	t.Helper()
	storage := &certmagic.FileStorage{Path: t.TempDir()}
	var magic *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
			return magic, nil
		},
	})
	magic = certmagic.New(cache, certmagic.Config{Storage: storage})
	issuer, ok := magic.Issuers[0].(*certmagic.ACMEIssuer)
	if !ok {
		t.Fatal("certmagic did not configure an ACME issuer")
	}
	// The challenge certmagic's own solve would present: one solved
	// TLS-ALPN challenge for the domain, stored where the handshake's
	// cache read finds it.
	chal, err := json.Marshal(acme.Challenge{
		Type:             "tls-alpn-01",
		Token:            "token",
		KeyAuthorization: "key-authorization",
		Identifier:       acme.Identifier{Type: "dns", Value: domain},
	})
	if err != nil {
		t.Fatal(err)
	}
	tokenKey := filepath.Join("acme",
		certmagic.StorageKeys.Safe(issuer.IssuerKey()), "challenge_tokens",
		certmagic.StorageKeys.Safe(domain)+".json")
	if err := storage.Store(context.Background(), tokenKey, chal); err != nil {
		t.Fatal(err)
	}
	manager := &CertManager{
		tlsCfg: &tls.Config{
			GetCertificate: magic.GetCertificate,
			MinVersion:     tls.VersionTLS13,
		},
		magic:  magic,
		domain: domain,
	}
	ln, err := manager.ListenHTTPS("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return manager, ln
}
