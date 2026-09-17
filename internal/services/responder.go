package services

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/fancl20/cion/pkg/dataplane"
	"github.com/fancl20/cion/pkg/scion"
)

// assembleResponder binds the node's SCMP echo responder to the control
// address's host on the endhost port, sending through the internal link.
// The responder is core, not application (ADR 0007): every node's selection
// baseline is an echo its peers must answer — a node that could decline the
// responder silently disables the comparator on every neighbor — so it runs
// beside the control-plane loops in every node, the one capability that
// moved out of an application into the core. SCMP echo's read and write
// stay in pkg/scion, the vocabulary the pinger and the responder share.
func (n *node) assembleResponder() error {
	conn, err := n.scionConn(dataplane.EndhostPort)
	if err != nil {
		return fmt.Errorf("binding the echo responder (the control address's host must not share the internal link's port): %w", err)
	}
	n.responder = &responder{conn: conn}
	return nil
}

// responder answers SCMP echo requests with echo replies, each on its
// reversed arrival path — the network's health probe. One conn serves it,
// bound to the endhost port the data plane delivers echo requests to.
type responder struct {
	conn *scion.Conn
}

// Run serves echo replies until the context is canceled or the socket
// fails.
func (r *responder) Run(ctx context.Context) {
	go func() {
		<-ctx.Done()
		_ = r.conn.Close()
	}()
	for {
		echo, from, err := r.conn.ReadEchoFrom()
		if err != nil {
			if ctx.Err() == nil {
				slog.Error("Echo responder exited", "err", err)
			}
			return
		}
		if echo.Reply {
			continue
		}
		if err := r.conn.WriteEchoReplyTo(from, echo.Identifier, echo.Seq,
			echo.Payload); err != nil {
			slog.Warn("Sending echo reply", "peer", from, "err", err)
		}
	}
}
