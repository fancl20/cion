package services

import (
	"context"
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
	"strings"
	"testing"
	"time"

	"github.com/fancl20/cion/pkg/apps/coordination"
	"github.com/fancl20/cion/pkg/apps/wireguard"
	"github.com/fancl20/cion/pkg/webpki"
)

// mintCertFiles writes a self-signed certificate pair, the tests' stand-in
// for the WebPKI, returning the files.
func mintCertFiles(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "core.example.org"},
		DNSNames:     []string{"core.example.org"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(
		&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

// staticCertMgr prepares the static-file identity the bind tests stand on.
func staticCertMgr(t *testing.T) *webpki.CertManager {
	t.Helper()
	certFile, keyFile := mintCertFiles(t)
	manager, err := webpki.PrepareTLSCert(context.Background(), webpki.TLSCertConfig{
		Domain:   "core.example.org",
		CertFile: certFile,
		KeyFile:  keyFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

// testRegistry is an in-memory registry for the mounted application.
type testRegistry struct{}

func (testRegistry) List(context.Context) (wireguard.Directory, error) {
	return wireguard.Directory{}, nil
}

func (testRegistry) PublishHost(context.Context, wireguard.HostEntry) error {
	return nil
}

// TestAssembleHTTPSBind checks the bind at the harness's placement: the
// mounted application's handlers name the server, the listener is held
// when the phase returns, and the port answers before anything serves it.
func TestAssembleHTTPSBind(t *testing.T) {
	app, err := coordination.New(coordination.Config{
		Domain:   "core.example.org",
		Store:    testRegistry{},
		StateDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = app.Close() })
	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := reserved.Addr().String()
	_ = reserved.Close()
	n := &node{
		cfg:          NodeConfig{Coordination: &CoordinationOptions{Addr: addr}},
		certMgr:      staticCertMgr(t),
		coordination: app,
	}
	if err := n.assembleHTTPS(); err != nil {
		t.Fatalf("assembleHTTPS() = %v, want nil", err)
	}
	defer func() { _ = n.httpsLn.Close() }()
	if n.httpsHandler == nil {
		t.Fatal("the node assembled no handlers for the HTTPS server")
	}
	// The bind returned with the port held: the listener answers before
	// start serves it, so the certificate maintenance launches against a
	// listening server.
	conn, err := net.Dial("tcp", n.httpsLn.Addr().String())
	if err != nil {
		t.Fatalf("the port is not held after the bind: %v", err)
	}
	_ = conn.Close()
}

// TestAssembleHTTPSNoBind checks the bind decision's negative: a
// static-file identity on a core whose apps mount nothing leaves port 443
// unbound, as the tree behaves today, and a non-core holds no identity to
// serve at all.
func TestAssembleHTTPSNoBind(t *testing.T) {
	n := &node{cfg: NodeConfig{Control: "127.0.0.1:30044"}, certMgr: staticCertMgr(t)}
	if err := n.assembleHTTPS(); err != nil {
		t.Fatalf("assembleHTTPS() = %v, want nil", err)
	}
	if n.httpsLn != nil {
		t.Error("a static-file identity with nothing mounted bound the port")
	}
	if err := (&node{}).assembleHTTPS(); err != nil {
		t.Fatalf("assembleHTTPS() of a non-core = %v, want nil", err)
	}
}

// TestAssembleHTTPSWildcardRefused checks the wildcard refusal at the
// bind: a control address whose host no host could dial refuses the boot
// with the published-endpoint message.
func TestAssembleHTTPSWildcardRefused(t *testing.T) {
	app, err := coordination.New(coordination.Config{
		Domain:   "core.example.org",
		Store:    testRegistry{},
		StateDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = app.Close() })
	n := &node{
		cfg:          NodeConfig{Control: "0.0.0.0:30044"},
		certMgr:      staticCertMgr(t),
		coordination: app,
	}
	_, err = n.httpsBindAddr()
	if err == nil {
		t.Fatal("a wildcard control address named a bind, want refusal")
	}
	if want := "no host could dial"; !strings.Contains(err.Error(), want) {
		t.Errorf("the refusal = %q, want it to carry %q", err, want)
	}
}
