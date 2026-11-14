// Package responder is the node's SCMP echo responder, part of its core: it
// answers every echo request the node receives, each on its reversed arrival
// path.
package responder

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/fancl20/cion/pkg/libs/scion"
)

// Responder answers SCMP echo requests with echo replies, each on its
// reversed arrival path: every peer's probe of a path through the node, and
// every neighbor's echo across a link to it. It runs in every node: the
// probes and the brake of each neighbor read echoes the node must answer, so
// a node that declined the responder would leave both blind. One conn serves
// it, bound to the endhost port the data plane delivers echo requests to.
type Responder struct {
	conn *scion.Conn
}

// New returns a responder that answers on the conn, which it owns.
func New(conn *scion.Conn) *Responder {
	return &Responder{conn: conn}
}

// Run serves echo replies until the context is canceled, returning nil, or
// until the socket's read fails, returning the failure. The context's end
// closes the socket, failing the read; Run returns with the socket closed
// and released either way, waiting on a close already under way, for a
// second Close returns before the first's release finishes.
func (r *Responder) Run(ctx context.Context) error {
	release := sync.OnceValue(r.conn.Close)
	stop := context.AfterFunc(ctx, func() { _ = release() })
	defer func() {
		stop()
		_ = release()
	}()
	for {
		echo, from, err := r.conn.ReadEchoFrom()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("reading echo requests: %w", err)
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
