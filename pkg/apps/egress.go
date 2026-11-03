package apps

import (
	"github.com/fancl20/cion/pkg/apps/egress"
	"github.com/fancl20/cion/pkg/apps/wireguard"
)

// egressEntry is the egress application: the node's netstack, ending the
// flows the hosts send to the internet and serving the node's own address,
// on the router the WireGuard application lends. Any node loads it beside
// the WireGuard application — every node an exit by default.
var egressEntry = Entry{
	Name:     "egress",
	Requires: []string{"wireguard"},
	New:      newEgress,
}

// newEgress assembles the egress beside the WireGuard application whose
// router it borrows, the node's own address read from the tailnet topic
// the WireGuard application publishes and the outbound legs reaching where
// the harness's internet, when it stands, maps each destination. The
// requirement's check has already made the missing owner a refused boot,
// and table order has already constructed it.
func newEgress(env *Environment, loaded []Loaded) (Application, error) {
	wg := AppOf(loaded, "wireguard").(*wireguard.App)
	app, err := egress.New(egress.Config{
		Router:   wg.Router(),
		Tailnet:  env.Bus.Tailnet(),
		Internet: env.Internet,
	})
	if err != nil {
		return nil, err
	}
	return app, nil
}
