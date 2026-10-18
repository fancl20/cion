package services

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/fancl20/cion/internal/supervise"
	"github.com/fancl20/cion/pkg/apps"
	"github.com/fancl20/cion/pkg/apps/coordination"
	"github.com/fancl20/cion/pkg/apps/wireguard"
	"github.com/fancl20/cion/pkg/core/webpki"
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
)

// staticCertMgr prepares the static-file identity the bind tests stand on.
func staticCertMgr(t *testing.T) *webpki.CertManager {
	t.Helper()
	ca := webpkitest.New(t)
	manager, err := webpki.PrepareTLSCert(webpki.TLSCertConfig{
		Domain:   webpkitest.Domain,
		CertFile: ca.CertFile,
		KeyFile:  ca.KeyFile,
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
		Domain:   webpkitest.Domain,
		Store:    testRegistry{},
		StateDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Close)
	group, _ := supervise.New(context.Background())
	defer func() { _ = group.Stop() }()
	n := resolvedNode(t, func(c *NodeConfig) {
		c.Coordination = &CoordinationOptions{Addr: "127.0.0.1:0"}
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

// TestAssembleHTTPSWildcardBinds checks the wildcard bind: a control
// address whose host is the wildcard names the HTTPS bind at the port,
// every interface of its family — the published coordination endpoint
// names the identity, not the bind host, and the CA's challenges want the
// port held everywhere.
func TestAssembleHTTPSWildcardBinds(t *testing.T) {
	n := resolvedNode(t, func(c *NodeConfig) { c.Control = "0.0.0.0" })
	if got, want := n.httpsBindAddr(), "0.0.0.0:443"; got != want {
		t.Errorf("httpsBindAddr() = %q, want the wildcard at the HTTPS port %q", got, want)
	}
	// The harness's placement still overrides the bind.
	n = resolvedNode(t, func(c *NodeConfig) {
		c.Control = "0.0.0.0"
		c.Coordination = &CoordinationOptions{Addr: "127.0.0.1:0"}
	})
	if got, want := n.httpsBindAddr(), "127.0.0.1:0"; got != want {
		t.Errorf("httpsBindAddr() = %q, want the placement %q", got, want)
	}
}
