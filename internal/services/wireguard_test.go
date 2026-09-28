package services

import (
	"testing"

	"github.com/fancl20/cion/pkg/apps/wireguard"
	"github.com/fancl20/cion/pkg/scion"
	"github.com/fancl20/cion/pkg/trust"
)

// wireguardConfigOf builds a bare node around the generated identity of a
// fresh state directory and builds the wireguard application's
// configuration from it.
func wireguardConfigOf(
	t *testing.T, cfg NodeConfig,
) (wireguard.Config, error) {

	t.Helper()
	ident, _, err := loadIdentity(cfg)
	if err != nil {
		t.Fatal(err)
	}
	n := &node{cfg: cfg, ident: ident,
		pathProvider: &scion.PathProvider{}, engine: trust.NewEngine(ident.ia, nil, nil)}
	return n.wireguardConfig()
}

// wireguardNodeConfig builds a minimal valid run-argument set with the
// shared host port.
func wireguardNodeConfig(t *testing.T, stateDir string) NodeConfig {
	t.Helper()
	return NodeConfig{
		Core:     true,
		Domain:   "core.example.org",
		State:    stateDir,
		Internal: DefaultInternal,
		Control:  DefaultControl,
		HostPort: 51820,
	}
}

// TestWireguardConfigFromArguments checks the configuration the run
// arguments build: the shared port carries into the application's
// configuration — no slice, the directory assigning it — and the relay
// presence deriving from the core's domain. The node is a core, so it takes
// the directory store and no core route.
func TestWireguardConfigFromArguments(t *testing.T) {
	cfg := wireguardNodeConfig(t, t.TempDir())
	parsed, err := wireguardConfigOf(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ListenPort != 51820 {
		t.Errorf("listen port = %d", parsed.ListenPort)
	}
	if parsed.DERP == nil || parsed.DERP.URL != "https://core.example.org/derp" {
		t.Errorf("relay presence = %+v, want the core's domain", parsed.DERP)
	}
	if parsed.CoreRoute != nil {
		t.Error("a core node got a core route")
	}
	if parsed.Store == nil {
		t.Error("a core node got no directory store")
	}
}

// TestNodeConfigHostPortAlone checks the port's pairing:
// --wireguard.host-port alone decides whether a node serves hosts,
// and no argument pairs with it.
func TestNodeConfigHostPortAlone(t *testing.T) {
	cfg := wireguardNodeConfig(t, t.TempDir())
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the host port alone: %v", err)
	}
	cfg.HostPort = 0
	if err := cfg.Validate(); err != nil {
		t.Fatalf("a node that sets no host port: %v", err)
	}
}
