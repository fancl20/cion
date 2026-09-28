package apps

import (
	"github.com/fancl20/cion/pkg/apps/socks"
	"github.com/fancl20/cion/pkg/apps/wireguard"
)

// socksEntry is the SOCKS application: internet egress as a service the
// node's own tailnet address names, served on the router the WireGuard
// application lends. Any node loads it beside the WireGuard application;
// its construction is a publication's answer, so the constructor returns
// the waiting form.
var socksEntry = Entry{
	Name:     "socks",
	Requires: []string{"wireguard"},
	New:      newSocks,
}

// newSocks stands the application's serving form beside the WireGuard
// application whose router and assigned slice it borrows. The
// requirement's check has already made the missing owner a refused boot,
// and table order has already constructed it.
func newSocks(_ *Environment, loaded []Loaded) (Application, error) {
	wg, _ := AppOf(loaded, "wireguard").(*wireguard.App)
	return socks.NewServer(wg), nil
}
