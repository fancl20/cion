package services

import (
	"context"
	"fmt"

	"github.com/fancl20/cion/pkg/apps/socks"
)

// serveSocks assembles the SOCKS application beside the WireGuard
// application when the directory's assignment arrives — the publication's
// answer — borrowing the application's router: the netstack claims the
// slice's first address — the node's own, which the allocator never issues —
// the SOCKS listener binds it, and the address stands delivered to the
// application's inbound path exactly while the application runs, one
// publication later than the WireGuard application's own assembly. Without
// that application there is nothing to borrow, and this application does not
// assemble — a node that serves no hosts serves no one. Every node offering
// by default is the applications architecture record's to decide, and this
// application decides nothing about selection itself.
func (n *node) serveSocks(ctx context.Context) error {
	subnet, err := n.wireguard.Subnet(ctx)
	if err != nil {
		// The node's cancellation ended the wait; nothing assembled.
		return nil
	}
	app, err := socks.New(socks.Config{
		Subnet: subnet,
		Router: n.wireguard.Router(),
	})
	if err != nil {
		return fmt.Errorf("assembling the SOCKS application: %w", err)
	}
	n.socksMtx.Lock()
	n.socks = app
	n.socksMtx.Unlock()
	return app.Run(ctx)
}
