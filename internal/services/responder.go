package services

import (
	"fmt"

	"github.com/fancl20/cion/pkg/core/responder"
	"github.com/fancl20/cion/pkg/libs/underlay"
)

// assembleResponder binds the node's SCMP echo responder to the control
// address's host on the endhost port, sending through the internal link, and
// hands the congestion module each echo request a neighbor sends across a
// link.
func (n *node) assembleResponder() error {
	conn, err := n.controlConn(underlay.EndhostPort)
	if err != nil {
		return fmt.Errorf("binding the echo responder (the control address's host must not share the internal link's port): %w", err)
	}
	n.group.Own("responder conn", conn.Close)
	n.responder = responder.New(conn, n.congestion.Requested)
	return nil
}
