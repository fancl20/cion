package services

import (
	"os"
	"path/filepath"
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
		Subnet:     "100.64.1.0/24",
		ListenPort: 51820,
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
// carry into the application's configuration, the relay presence deriving
// from the core's domain. The node is a core, so it takes the directory
// store and no core route.
func TestParseWireguardConfig(t *testing.T) {
	cfg := wireguardNodeConfig(t, t.TempDir())
	parsed, err := parseWireguardOf(t, cfg, wireguardSection())
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

// TestParseWireguardConfigRejects checks the file's validation: malformed
// subnets and ports, a slice outside the tailnet range, and the retired
// fields' names the node refuses.
func TestParseWireguardConfigRejects(t *testing.T) {
	valid := func(t *testing.T) NodeConfig { return wireguardNodeConfig(t, t.TempDir()) }

	bad := map[string]func(*ConfigWireguard){
		"malformed subnet":       func(wg *ConfigWireguard) { wg.Subnet = "100.64.1.0" },
		"missing listen port":    func(wg *ConfigWireguard) { wg.ListenPort = 0 },
		"IPv6 subnet":            func(wg *ConfigWireguard) { wg.Subnet = "2001:db8::/64" },
		"outside the tailnet":    func(wg *ConfigWireguard) { wg.Subnet = "10.64.1.0/24" },
		"wider than the tailnet": func(wg *ConfigWireguard) { wg.Subnet = "100.0.0.0/8" },
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

	// A file still naming a retired field stops the boot — the coordinated
	// upgrade's bookkeeping, RejectUnknownMembers doing the retirement's
	// accounting.
	for name, extra := range map[string]string{
		"peers": `{"publicKey":"01","address":"100.64.1.10","exit":"20-ff00:0:3"}`,
		"exits": `["20-ff00:0:3"]`,
	} {
		t.Run("retired "+name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "wireguard.json")
			raw := `{"subnet":"100.64.1.0/24","listenPort":51820,"` + name + `":` + extra + `}`
			if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadWireguardConfig(path); err == nil {
				t.Errorf("a file naming the retired %q loaded, want refusal", name)
			}
		})
	}
}
