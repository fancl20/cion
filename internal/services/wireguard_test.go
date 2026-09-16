package services

import (
	"testing"

	"github.com/fancl20/cion/pkg/apps/wireguard"
	"github.com/fancl20/cion/pkg/scion"
	"github.com/fancl20/cion/pkg/trust"
)

// parseWireguardOf builds a bare node around the generated identity of a
// fresh state directory and parses the wireguard configuration.
func parseWireguardOf(
	t *testing.T, cfg NodeConfig, wg *ConfigWireguard,
) (wireguard.Config, error) {

	t.Helper()
	ident, _, err := loadIdentity(cfg)
	if err != nil {
		t.Fatal(err)
	}
	n := &node{cfg: cfg, ident: ident,
		pathProvider: &scion.PathProvider{}, engine: trust.NewEngine(ident.ia, nil, nil)}
	return n.parseWireguardConfig(wg)
}

// wireguardSection builds the application's configuration section.
func wireguardSection() *ConfigWireguard {
	return &ConfigWireguard{
		Subnet:     "10.64.1.0/24",
		ListenPort: 51820,
		Exits:      []string{"20-ff00:0:3"},
		Peers: []ConfigWireguardPeer{{
			PublicKey: "0101010101010101010101010101010101010101010101010101010101010101",
			Address:   "10.64.1.10",
			Exit:      "20-ff00:0:3",
		}},
	}
}

// wireguardNodeConfig builds a minimal valid run-argument set with the
// wireguard section.
func wireguardNodeConfig(t *testing.T, stateDir string) NodeConfig {
	t.Helper()
	return NodeConfig{
		Core:     true,
		Domain:   "core.example.org",
		State:    stateDir,
		Internal: "127.0.0.1:30042",
		Control:  "127.0.0.1:30043",
	}
}

// TestParseWireguardConfig checks the wireguard file's decoding: the fields
// carry into the application's configuration. The node is a core, so it
// takes the directory store and no core route.
func TestParseWireguardConfig(t *testing.T) {
	cfg := wireguardNodeConfig(t, t.TempDir())
	parsed, err := parseWireguardOf(t, cfg, wireguardSection())
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
	if parsed.CoreRoute != nil {
		t.Error("a core node got a core route")
	}
	if parsed.Store == nil {
		t.Error("a core node got no directory store")
	}
}

// TestParseWireguardConfigRejects checks the file's validation: malformed
// subnets, ports, keys, and peers the node refuses.
func TestParseWireguardConfigRejects(t *testing.T) {
	valid := func(t *testing.T) NodeConfig { return wireguardNodeConfig(t, t.TempDir()) }

	bad := map[string]func(*ConfigWireguard){
		"malformed subnet":    func(wg *ConfigWireguard) { wg.Subnet = "10.64.1.0" },
		"missing listen port": func(wg *ConfigWireguard) { wg.ListenPort = 0 },
		"IPv6 subnet":         func(wg *ConfigWireguard) { wg.Subnet = "2001:db8::/64" },
		"malformed exit":      func(wg *ConfigWireguard) { wg.Exits = []string{"nope"} },
		"short key":           func(wg *ConfigWireguard) { wg.Peers[0].PublicKey = "0102" },
		"malformed address":   func(wg *ConfigWireguard) { wg.Peers[0].Address = "10.64" },
		"malformed exit ia":   func(wg *ConfigWireguard) { wg.Peers[0].Exit = "nope" },
	}
	for name, mutate := range bad {
		t.Run(name, func(t *testing.T) {
			wg := wireguardSection()
			mutate(wg)
			if _, err := parseWireguardOf(t, valid(t), wg); err == nil {
				t.Error("the malformed wireguard configuration was accepted")
			}
		})
	}
}
