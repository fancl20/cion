package services

import (
	"testing"

	"github.com/fancl20/cion/pkg/apps/wireguard"
	"github.com/fancl20/cion/pkg/scion"
	"github.com/fancl20/cion/pkg/trust"
)

// parseWireguardOf builds a bare node around the configuration's identity
// and parses its wireguard section.
func parseWireguardOf(t *testing.T, cfg *Config) (wireguard.Config, error) {
	t.Helper()
	ident, err := parseIdentity(cfg)
	if err != nil {
		t.Fatal(err)
	}
	n := &node{cfg: cfg, ident: ident,
		provider: &scion.PathProvider{}, engine: trust.NewEngine(ident.ia, nil, nil)}
	return n.parseWireguardConfig()
}

// wireguardNodeConfig builds a minimal valid node configuration with the
// wireguard section.
func wireguardNodeConfig(t *testing.T, stateDir string) *Config {
	t.Helper()
	return &Config{
		IA:       "20-ff00:0:1",
		ASType:   "normal",
		State:    stateDir,
		Internal: "127.0.0.1:30042",
		Control:  "127.0.0.1:30043",
		Key:      "000102030405060708090a0b0c0d0e0f",
		Wireguard: &ConfigWireguard{
			Subnet:     "10.64.1.0/24",
			ListenPort: 51820,
			Exits:      []string{"20-ff00:0:3"},
			Peers: []ConfigWireguardPeer{{
				PublicKey: "0101010101010101010101010101010101010101010101010101010101010101",
				Address:   "10.64.1.10",
				Exit:      "20-ff00:0:3",
			}},
		},
	}
}

// TestParseWireguardConfig checks the wireguard section's decoding: the
// fields carry into the application's configuration.
func TestParseWireguardConfig(t *testing.T) {
	cfg := wireguardNodeConfig(t, t.TempDir())
	parsed, err := parseWireguardOf(t, cfg)
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

// TestParseWireguardConfigRejects checks the section's validation: malformed
// subnets, ports, keys, and peers the node refuses.
func TestParseWireguardConfigRejects(t *testing.T) {
	valid := func(t *testing.T) *Config { return wireguardNodeConfig(t, t.TempDir()) }

	bad := map[string]func(*Config){
		"malformed subnet":    func(c *Config) { c.Wireguard.Subnet = "10.64.1.0" },
		"missing listen port": func(c *Config) { c.Wireguard.ListenPort = 0 },
		"IPv6 subnet":         func(c *Config) { c.Wireguard.Subnet = "2001:db8::/64" },
		"malformed exit":      func(c *Config) { c.Wireguard.Exits = []string{"nope"} },
		"short key":           func(c *Config) { c.Wireguard.Peers[0].PublicKey = "0102" },
		"malformed address":   func(c *Config) { c.Wireguard.Peers[0].Address = "10.64" },
		"malformed exit ia":   func(c *Config) { c.Wireguard.Peers[0].Exit = "nope" },
	}
	for name, mutate := range bad {
		t.Run(name, func(t *testing.T) {
			cfg := valid(t)
			mutate(cfg)
			if _, err := parseWireguardOf(t, cfg); err == nil {
				t.Error("the malformed wireguard section was accepted")
			}
		})
	}
}
