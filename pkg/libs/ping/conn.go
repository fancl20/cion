package ping

import (
	"context"
	"net/netip"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/underlay"
)

// repliesQueued is how many replies wait for the caller's loop.
const repliesQueued = 64

// Reply is one echo reply to a conn's own request: its sequence number,
// whether it came back marked, and when it arrived.
type Reply struct {
	Seq    uint16
	Marked bool
	At     time.Time
}

// Conn sends a caller's echo requests on a SCION conn and delivers the
// replies to them, which ReadReplies reads off the conn on a goroutine of
// the caller's.
type Conn struct {
	conn    *scion.Conn
	replies chan Reply
}

// NewConn returns a Conn over the conn, which nothing else may read: a
// reply read elsewhere is lost to it.
func NewConn(conn *scion.Conn) *Conn {
	return &Conn{conn: conn, replies: make(chan Reply, repliesQueued)}
}

// Send sends an echo request under the sequence number to the responder host
// in dst over the path.
func (c *Conn) Send(dst addr.IA, host netip.Addr, path *spath.Decoded, seq uint16) error {
	return c.conn.WriteEchoRequestTo(&scion.Addr{
		IA:   dst,
		Addr: netip.AddrPortFrom(host, underlay.EndhostPort),
		Path: path,
	}, seq, nil)
}

// SendOver sends an echo request under the sequence number to the responder
// host in the neighbor over the one-hop path out of the link.
func (c *Conn) SendOver(neighbor addr.IA, host netip.Addr, ifID, seq uint16) error {
	return c.conn.WriteEchoRequestTo(&scion.Addr{
		IA:   neighbor,
		Addr: netip.AddrPortFrom(host, underlay.EndhostPort),
		IfID: ifID,
	}, seq, nil)
}

// Replies delivers each reply to the conn's own requests.
func (c *Conn) Replies() <-chan Reply {
	return c.replies
}

// ReadReplies reads the conn until ctx ends, whose end moves the read
// deadline to the past, delivering each reply to the conn's own requests on
// Replies. It returns nil once ctx ended, or the read's failure.
func (c *Conn) ReadReplies(ctx context.Context) error {
	stop := context.AfterFunc(ctx, func() { _ = c.conn.SetReadDeadline(time.Now()) })
	defer stop()
	for {
		echo, _, err := c.conn.ReadEchoFrom()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if !echo.Reply || echo.Identifier != c.conn.LocalPort() {
			continue
		}
		select {
		case c.replies <- Reply{Seq: echo.Seq, Marked: echo.Marked, At: time.Now()}:
		case <-ctx.Done():
			return nil
		}
	}
}
