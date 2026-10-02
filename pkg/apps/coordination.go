package apps

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strconv"

	"github.com/fancl20/cion/pkg/apps/coordination"
	"github.com/fancl20/cion/pkg/apps/wireguard"
)

// coordinationEntry is the coordination application: the network's
// headscale, minimal by decision — registration behind the admission
// seam, the netmap, the relay — whose surfaces mount on the node's HTTPS
// server. The core alone loads it, and it requires the WireGuard
// application whose registry it borrows.
var coordinationEntry = Entry{
	Name:     "coordination",
	CoreOnly: true,
	Requires: []string{"wireguard"},
	New:      newCoordination,
}

// newCoordination adapts the environment into the coordination
// application's configuration and assembles it beside the WireGuard
// application whose registry it borrows. The requirement's check has
// already made the missing owner a refused boot, and table order has
// already constructed it.
func newCoordination(env *Environment, loaded []Loaded) (Application, error) {
	wg, _ := AppOf(loaded, "wireguard").(*wireguard.App)
	relay, err := relayAdvertisement(env.Domain, env.Relay)
	if err != nil {
		return nil, err
	}
	return coordination.New(coordination.Config{
		Domain: env.Domain,
		Store:  wg.Registry(),
		// The selected policy's verdict — open where none loads, the
		// gate answering what the node admits.
		Authorizer: env.Authorizer,
		DERP:       relay,
		StateDir:   filepath.Join(env.StateRoot, "coordination"),
		RelayOnly:  env.Relay.RelayOnly,
	})
}

// relayAdvertisement names the relay the netmap carries: the core's
// coordination endpoint on its own identity, the one region every host's
// map holds. The production derivation is the core's domain at the HTTPS
// port; the harness's placement overrides it.
func relayAdvertisement(domain string, relay RelayPlacement) (coordination.DERPConfig, error) {
	derp := coordination.DERPConfig{HostName: domain}
	if relay.URL != "" {
		parsed, err := url.Parse(relay.URL)
		if err != nil {
			return coordination.DERPConfig{}, fmt.Errorf(
				"parsing the relay URL: %w", err)
		}
		derp.HostName = parsed.Hostname()
		if port, err := strconv.Atoi(parsed.Port()); err == nil {
			derp.Port = port
		}
		derp.IPv4 = relay.IPv4
		derp.CertName = relay.CertName
	}
	return derp, nil
}
