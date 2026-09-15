package services

import (
	"fmt"

	"github.com/fancl20/cion/pkg/apps/ping"
	"github.com/fancl20/cion/pkg/dataplane"
)

// assembleResponder binds the node's SCMP echo responder — proposal 0005's
// first application beside the control plane, and the network's health
// probe — to the control address's host on the endhost port, sending
// through the internal link. start runs it alongside the control-plane
// loops; proposal 0006's WireGuard application is the next function in this
// file's pattern, activated by its configuration section.
func (n *node) assembleResponder() error {
	conn, err := n.scionConn(dataplane.EndhostPort)
	if err != nil {
		return fmt.Errorf("binding the ping responder (the control address's host must not share the internal link's port): %w", err)
	}
	n.responder = &ping.Responder{Conn: conn}
	return nil
}
