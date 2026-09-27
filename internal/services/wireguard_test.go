package services

import (
	"net/netip"
	"testing"

	"github.com/fancl20/cion/pkg/apps/wireguard"
	"github.com/fancl20/cion/pkg/scion"
	"github.com/fancl20/cion/pkg/trust"
)

// parseSliceOf builds a bare node around the generated identity of a fresh
// state directory and builds the wireguard application's configuration from
// the given slice.
func parseSliceOf(
	t *testing.T, cfg NodeConfig, slice string,
) (wireguard.Config, error) {

	t.Helper()
	ident, _, err := loadIdentity(cfg)
	if err != nil {
		t.Fatal(err)
	}
	n := &node{cfg: cfg, ident: ident,
		pathProvider: &scion.PathProvider{}, engine: trust.NewEngine(ident.ia, nil, nil)}
	return n.wireguardConfig(netip.MustParsePrefix(slice))
}

// wireguardNodeConfig builds a minimal valid run-argument set with the
// wireguard slice.
func wireguardNodeConfig(t *testing.T, stateDir string) NodeConfig {
	t.Helper()
	return NodeConfig{
		Core:     true,
		Domain:   "core.example.org",
		State:    stateDir,
		Internal: "127.0.0.1:30042",
		Control:  "127.0.0.1:30043",
		Slice:    "100.64.1.0/24",
		HostPort: 51820,
	}
}

// TestWireguardConfigFromArguments checks the configuration the run
// arguments build (the retired file's fields, promoted): the slice and the
// shared port carry into the application's configuration, the relay
// presence deriving from the core's domain. The node is a core, so it takes
// the directory store and no core route.
func TestWireguardConfigFromArguments(t *testing.T) {
	cfg := wireguardNodeConfig(t, t.TempDir())
	parsed, err := parseSliceOf(t, cfg, cfg.Slice)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Subnet.String() != "100.64.1.0/24" {
		t.Errorf("subnet = %s", parsed.Subnet)
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

// TestWireguardConfigRejectsSlices checks the slice grammar the argument
// validates (the one the retired loader checked): malformed slices and ones
// outside the tailnet range stop the boot, not the application.
func TestWireguardConfigRejectsSlices(t *testing.T) {
	valid := func(t *testing.T) NodeConfig { return wireguardNodeConfig(t, t.TempDir()) }

	bad := map[string]func(*NodeConfig){
		"malformed slice":        func(c *NodeConfig) { c.Slice = "100.64.1.0" },
		"IPv6 slice":             func(c *NodeConfig) { c.Slice = "2001:db8::/64" },
		"outside the tailnet":    func(c *NodeConfig) { c.Slice = "10.64.1.0/24" },
		"wider than the tailnet": func(c *NodeConfig) { c.Slice = "100.0.0.0/8" },
		"missing host port":      func(c *NodeConfig) { c.HostPort = 0 },
		"port without slice": func(c *NodeConfig) {
			c.Slice = ""
			c.HostPort = 51820
		},
	}
	for name, mutate := range bad {
		t.Run(name, func(t *testing.T) {
			cfg := valid(t)
			mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Error("the malformed run arguments were accepted")
			}
		})
	}
}
