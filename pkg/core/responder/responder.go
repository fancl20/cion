// Package responder is the node's SCMP echo responder, part of its core: it
// answers every echo request the node receives, each on its reversed arrival
// path, and hands on each that crossed one link to the node.
package responder

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/fancl20/cion/pkg/libs/scion"
)

// Responder answers SCMP echo requests with echo replies, each on its
// reversed arrival path: every peer's probe of a path through the node, and
// every neighbor's echo across a link to it. It runs in every node: the
// probes and the brake of each neighbor read echoes the node must answer, so
// a node that declined the responder would leave both blind. A request that
// crossed one link to the node, over a one-hop path, is a neighbor's echo
// across the link: the responder hands it on, its link and arrival, which
// keeps the link's session in demand mode up. One conn serves it, bound to
// the endhost port the data plane delivers echo requests to.
type Responder struct {
	conn      *scion.Conn
	requested func(ifID uint16, at time.Time)
}

// New returns a responder that answers on the conn, which it owns, and hands
// requested each echo request a neighbor sends across a link.
func New(conn *scion.Conn, requested func(ifID uint16, at time.Time)) *Responder {
	return &Responder{conn: conn, requested: requested}
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
		// Only a request over a one-hop path names the link it came in on.
		if from.IfID != 0 {
			r.requested(from.IfID, time.Now())
		}
		if err := r.conn.WriteEchoReplyTo(from, echo.Identifier, echo.Seq,
			echo.Payload); err != nil {
			slog.Warn("Sending echo reply", "peer", from, "err", err)
		}
	}
}
