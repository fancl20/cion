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
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fancl20/cion/internal/supervise"
	"github.com/fancl20/cion/pkg/apps"
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
	manager, err := webpki.PrepareTLSCert(webpki.TLSCertConfig{
		Domain:   "core.example.org",
		CertFile: certFile,
		KeyFile:  keyFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

// resolvedNode builds a node from the minimal run arguments, the mutation
// applied before they resolve: the founding core when it changes no role
// argument.
func resolvedNode(t *testing.T, mutate func(*NodeConfig)) *node {
	t.Helper()
	cfg := nodeConfig()
	mutate(&cfg)
	rc, err := cfg.resolve()
	if err != nil {
		t.Fatal(err)
	}
	return &node{cfg: rc}
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
	t.Cleanup(app.Close)
	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := reserved.Addr().String()
	_ = reserved.Close()
	group, _ := supervise.New(context.Background())
	defer func() { _ = group.Stop() }()
	n := resolvedNode(t, func(c *NodeConfig) {
		c.Coordination = &CoordinationOptions{Addr: addr}
	})
	n.certMgr = staticCertMgr(t)
	n.apps = []apps.Loaded{{Name: "coordination", App: app}}
	n.group = group
	if err := n.assembleHTTPS(); err != nil {
		t.Fatalf("assembleHTTPS() = %v, want nil", err)
	}
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
// static-file identity on a founding core whose apps mount nothing leaves
// port 443 unbound, as the tree behaves today, and the authoritative core
// and the normal node hold no identity to serve at all.
func TestAssembleHTTPSNoBind(t *testing.T) {
	n := resolvedNode(t, func(*NodeConfig) {})
	n.certMgr = staticCertMgr(t)
	if err := n.assembleHTTPS(); err != nil {
		t.Fatalf("assembleHTTPS() = %v, want nil", err)
	}
	if n.httpsLn != nil {
		t.Error("a static-file identity with nothing mounted bound the port")
	}
	neighbor := []string{"192.0.2.7:30043"}
	for name, mutate := range map[string]func(*NodeConfig){
		"the authoritative core": func(c *NodeConfig) { c.Neighbors = neighbor },
		"the normal node":        func(c *NodeConfig) { c.Core = false; c.Neighbors = neighbor },
	} {
		n := resolvedNode(t, mutate)
		if err := n.assembleHTTPS(); err != nil {
			t.Fatalf("assembleHTTPS() of %s = %v, want nil", name, err)
		}
		if n.httpsLn != nil {
			t.Errorf("%s bound the port", name)
		}
	}
}

// rootApp is an application whose one surface is an HTTPS handler.
type rootApp struct{}

func (rootApp) Run(ctx context.Context) error { <-ctx.Done(); return nil }
func (rootApp) Close()                        {}
func (rootApp) HTTPSHandler() http.Handler    { return http.NotFoundHandler() }

// TestAssembleHTTPSRefusesSecondHandler checks the one-handler rule: two
// loaded applications contributing HTTPS handlers refuse the boot with both
// named, before the port binds.
func TestAssembleHTTPSRefusesSecondHandler(t *testing.T) {
	n := resolvedNode(t, func(*NodeConfig) {})
	n.certMgr = staticCertMgr(t)
	n.apps = []apps.Loaded{
		{Name: "first", App: rootApp{}},
		{Name: "second", App: rootApp{}},
	}
	err := n.assembleHTTPS()
	if err == nil {
		t.Fatal("two HTTPS handlers assembled, want refusal")
	}
	for _, name := range []string{"first", "second"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("the refusal = %q, want it to name %q", err, name)
		}
	}
	if n.httpsLn != nil {
		t.Error("the refused assembly bound the port")
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
	t.Cleanup(app.Close)
	n := resolvedNode(t, func(c *NodeConfig) { c.Control = "0.0.0.0:30042" })
	n.certMgr = staticCertMgr(t)
	n.apps = []apps.Loaded{{Name: "coordination", App: app}}
	_, err = n.httpsBindAddr()
	if err == nil {
		t.Fatal("a wildcard control address named a bind, want refusal")
	}
	if want := "no host could dial"; !strings.Contains(err.Error(), want) {
		t.Errorf("the refusal = %q, want it to carry %q", err, want)
	}
}
