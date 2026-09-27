package services

import (
	"fmt"

	"github.com/fancl20/cion/pkg/apps/socks"
)

// setupSocks assembles the SOCKS application (ADR-0012, proposal 0024)
// beside the WireGuard application, borrowing its router: the netstack
// claims the slice's first address — the node's own, which the allocator
// never issues — the SOCKS listener binds it, and the address stands
// delivered to the application's inbound path exactly while the application
// runs. Without the WireGuard application there is nothing to borrow, and
// this application does not assemble — a node that serves no hosts serves
// no one. Every node offers by default: which applications a node runs is
// the applications architecture record's to decide, and this application
// decides nothing about selection itself.
func (n *node) setupSocks() error {
	if n.wireguard == nil {
		return nil
	}
	app, err := socks.New(socks.Config{
		Subnet: n.subnet,
		Router: n.wireguard.Router(),
	})
	if err != nil {
		return fmt.Errorf("assembling the SOCKS application: %w", err)
	}
	n.socks = app
	return nil
}
