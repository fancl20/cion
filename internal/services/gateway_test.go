package services

import (
	"testing"

	"github.com/fancl20/cion/pkg/apps/wireguard"
	"github.com/fancl20/cion/pkg/scion"
	"github.com/fancl20/cion/pkg/trust"
)

// parseGatewayOf builds a bare node around the configuration's identity
// and parses its gateway section.
func parseGatewayOf(t *testing.T, cfg *Config) (wireguard.Config, error) {
	t.Helper()
	ident, err := parseIdentity(cfg)
	if err != nil {
		t.Fatal(err)
	}
	n := &node{cfg: cfg, ident: ident,
		provider: &scion.PathProvider{}, engine: trust.NewEngine(ident.ia, nil, nil)}
	return n.parseGatewayConfig()
}

// gatewayNodeConfig builds a minimal valid node configuration with the
// gateway section.
func gatewayNodeConfig(t *testing.T, stateDir string) *Config {
	t.Helper()
	return &Config{
		IA:       "20-ff00:0:1",
		ASType:   "normal",
		State:    stateDir,
		Internal: "127.0.0.1:30042",
		Control:  "127.0.0.1:30043",
		Key:      "000102030405060708090a0b0c0d0e0f",
		Gateway: &ConfigGateway{
			Subnet:     "10.64.1.0/24",
			ListenPort: 51820,
			Exits:      []string{"20-ff00:0:3"},
			Peers: []ConfigGatewayPeer{{
				PublicKey: "0101010101010101010101010101010101010101010101010101010101010101",
				Address:   "10.64.1.10",
				Exit:      "20-ff00:0:3",
			}},
		},
	}
}

// TestParseGatewayConfig checks the gateway section's decoding: the fields
// carry into the application's configuration.
func TestParseGatewayConfig(t *testing.T) {
	cfg := gatewayNodeConfig(t, t.TempDir())
	parsed, err := parseGatewayOf(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Subnet.String() != "10.64.1.0/24" {
		t.Errorf("subnet = %s", parsed.Subnet)
	}
	if parsed.ListenPort != 51820 {
		t.Errorf("listen port = %d", parsed.ListenPort)
	}
	if len(parsed.Exits) != 1 || len(parsed.Peers) != 1 {
		t.Errorf("exits = %v peers = %v", parsed.Exits, parsed.Peers)
	}
	if parsed.CoreRoute == nil {
		t.Error("a non-core node got no core route")
	}
	if parsed.Store != nil {
		t.Error("a non-core node got a directory store")
	}
}

// TestParseGatewayConfigRejects checks the section's validation: malformed
// subnets, ports, keys, and peers the node refuses.
func TestParseGatewayConfigRejects(t *testing.T) {
	valid := func(t *testing.T) *Config { return gatewayNodeConfig(t, t.TempDir()) }

	bad := map[string]func(*Config){
		"malformed subnet":    func(c *Config) { c.Gateway.Subnet = "10.64.1.0" },
		"missing listen port": func(c *Config) { c.Gateway.ListenPort = 0 },
		"IPv6 subnet":         func(c *Config) { c.Gateway.Subnet = "2001:db8::/64" },
		"malformed exit":      func(c *Config) { c.Gateway.Exits = []string{"nope"} },
		"short key":           func(c *Config) { c.Gateway.Peers[0].PublicKey = "0102" },
		"malformed address":   func(c *Config) { c.Gateway.Peers[0].Address = "10.64" },
		"malformed exit ia":   func(c *Config) { c.Gateway.Peers[0].Exit = "nope" },
	}
	for name, mutate := range bad {
		t.Run(name, func(t *testing.T) {
			cfg := valid(t)
			mutate(cfg)
			if _, err := parseGatewayOf(t, cfg); err == nil {
				t.Error("the malformed gateway section was accepted")
			}
		})
	}
}
