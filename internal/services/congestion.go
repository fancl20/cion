package services

import (
	"fmt"

	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/modules/congestion/impl/brake"
)

// assembleCongestion binds the brake's conns and builds it over the node's
// link state: its policy paces and marks every generation's links' egress
// queues, and its loop sends the echoes the policy calls for.
func (n *node) assembleCongestion() error {
	b, err := brake.NewResident(brake.ResidentConfig{
		Links:   n.bus.Links(),
		NewConn: func() (*scion.Conn, error) { return n.scionConn(0) },
	})
	if err != nil {
		return fmt.Errorf("binding the brake's conns: %w", err)
	}
	n.group.Own("brake conns", func() error {
		b.Close()
		return nil
	})
	n.congestion = b
	return nil
}
