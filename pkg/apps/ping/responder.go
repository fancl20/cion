// Package ping is CION's SCMP-echo application: the network's health probe
// and the first resident of the pkg/apps namespace — a consumer of the path
// library (pkg/scion) beside the control plane. A responder answers echo
// requests on the node's endhost port; a pinger resolves the freshest path
// to a destination, sends a count of requests, and reports per-reply RTT,
// the reply's path hops, and a loss summary.
package ping

import (
	"context"
	"log/slog"

	"github.com/fancl20/cion/pkg/scion"
)

// Responder answers SCMP echo requests with echo replies, each on its
// reversed arrival path. One Conn serves it, bound to the endhost port the
// data plane delivers echo requests to.
type Responder struct {
	// Conn is the socket echo requests arrive on.
	Conn *scion.Conn
}

// Run serves echo replies until the context is canceled or the socket
// fails.
func (r *Responder) Run(ctx context.Context) {
	go func() {
		<-ctx.Done()
		r.Conn.Close() //nolint:errcheck
	}()
	for {
		echo, from, err := r.Conn.ReadEchoFrom()
		if err != nil {
			if ctx.Err() == nil {
				slog.Error("Ping responder exited", "err", err)
			}
			return
		}
		if echo.Reply {
			continue
		}
		if err := r.Conn.WriteEchoReplyTo(from, echo.Identifier, echo.Seq,
			echo.Payload); err != nil {
			slog.Warn("Sending echo reply", "peer", from, "err", err)
		}
	}
}
