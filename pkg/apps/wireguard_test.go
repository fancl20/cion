package apps

import (
	"testing"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/scion"
	"github.com/fancl20/cion/pkg/trust"
)

// wireguardEnvironment builds the environment the entry's configuration
// derivation reads, on the core or a joiner.
func wireguardEnvironment(t *testing.T, core bool) *Environment {
	t.Helper()
	ia := addr.MustIAFrom(20, 0xff0000000301)
	return &Environment{
		Arguments:   Arguments{Wireguard: WireguardArguments{HostPort: DefaultHostPort}},
		IA:          ia,
		Core:        core,
		StateRoot:   t.TempDir(),
		ControlHost: "127.0.0.1:30042",
		Domain:      "core.example.org",
		Engine:      trust.NewEngine(ia, nil, nil),
		Provider:    &scion.PathProvider{},
	}
}

// TestWireguardConfigFromEnvironment checks the configuration the entry
// derives: the shared port its arguments name — no slice, the directory
// assigning it — the relay presence from the core's domain, and the
// core's own store beside the joiner's core route.
func TestWireguardConfigFromEnvironment(t *testing.T) {
	cfg, err := wireguardConfig(wireguardEnvironment(t, true))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenPort != DefaultHostPort {
		t.Errorf("listen port = %d", cfg.ListenPort)
	}
	if cfg.DERP == nil || cfg.DERP.URL != "https://core.example.org/derp" {
		t.Errorf("relay presence = %+v, want the core's domain", cfg.DERP)
	}
	if cfg.CoreRoute != nil {
		t.Error("the core node got a core route")
	}
	if cfg.Store == nil {
		t.Error("the core node got no directory store")
	}

	cfg, err = wireguardConfig(wireguardEnvironment(t, false))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Store != nil {
		t.Error("the joiner got a directory store")
	}
	if cfg.CoreRoute == nil {
		t.Error("the joiner got no core route")
	}
}

// TestWireguardRelayPlacement checks the harness's relay placement
// standing in for the production derivation from the domain.
func TestWireguardRelayPlacement(t *testing.T) {
	env := wireguardEnvironment(t, false)
	env.Relay = RelayPlacement{
		URL:      "https://127.0.0.1:4430/derp",
		IPv4:     "127.0.0.1",
		CertName: "sha256-raw:8f7a",
	}
	cfg, err := wireguardConfig(env)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DERP == nil || cfg.DERP.URL != env.Relay.URL ||
		cfg.DERP.IPv4 != env.Relay.IPv4 ||
		cfg.DERP.CertName != env.Relay.CertName {

		t.Errorf("relay presence = %+v, want the placement carried", cfg.DERP)
	}
}

// TestCoordinationRelayAdvertisement checks the advertisement's two
// derivations: the domain's own, and the harness's placement with the
// port its URL spells.
func TestCoordinationRelayAdvertisement(t *testing.T) {
	derp, err := relayAdvertisement("core.example.org", RelayPlacement{})
	if err != nil {
		t.Fatal(err)
	}
	if derp.HostName != "core.example.org" || derp.Port != 0 {
		t.Errorf("the production derivation = %+v, want the domain alone", derp)
	}

	derp, err = relayAdvertisement("core.example.org", RelayPlacement{
		URL:  "https://127.0.0.1:4430/derp",
		IPv4: "127.0.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if derp.HostName != "127.0.0.1" || derp.Port != 4430 || derp.IPv4 != "127.0.0.1" {
		t.Errorf("the placement's derivation = %+v, want its host and port", derp)
	}
}
