package scionrpc

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/scionproto/scion/pkg/proto/control_plane"
	"google.golang.org/protobuf/proto"

	"github.com/fancl20/cion/pkg/libs/scion"
)

// quicConfig caps the packet size so a QUIC datagram wrapped in a SCION
// header still fits a standard 1500-byte MTU; the SCION conn does not
// support the don't-fragment capability, so QUIC never grows beyond the
// initial size.
var quicConfig = &quic.Config{InitialPacketSize: 1200}

// ServeHTTP3 serves the handler with HTTP/3 (QUIC) on conn, answering the
// drafts' service resolution beside it (control plane draft, Section 5),
// until the context ends or conn fails, and returns with conn closed and
// every request's handler returned. QUIC answers a read deadline by reading
// again, so the context's end closes conn; the close ends every connection,
// canceling its requests' contexts, and the server's Close waits for their
// handlers. The return waits on a close already under way, for a second
// Close returns before the first's release finishes. The TLS configuration
// must carry the certificate for the served domain.
func ServeHTTP3(
	ctx context.Context,
	conn *scion.Conn,
	handler http.Handler,
	tlsConf *tls.Config,
) error {

	release := sync.OnceValue(conn.Close)
	stop := context.AfterFunc(ctx, func() { _ = release() })
	defer func() {
		stop()
		_ = release()
	}()
	transport := &quic.Transport{Conn: &resolutionConn{conn: conn}}
	ln, err := transport.Listen(tlsConf, quicConfig)
	if err != nil {
		return err
	}
	server := &http3.Server{
		Handler:    handler,
		TLSConfig:  tlsConf,
		QUICConfig: quicConfig,
	}
	err = server.ServeListener(ln)
	// Close fails only on listeners the server opened itself, and it opened
	// none.
	_ = server.Close()
	return err
}

// resolutionConn demuxes the endpoint's socket: QUIC datagrams pass to the
// transport reading them, and everything else arriving at the registered
// control service — a resolution request is an empty UDP payload — is
// answered on the spot. The endpoint socket is the registered control
// service the data plane's service routing delivers to, so the drafts'
// exchange rides beside the endpoint's own protocol on the one socket.
type resolutionConn struct {
	conn *scion.Conn
}

// ReadFrom returns the next QUIC datagram, answering resolution requests as
// they surface instead of returning them to the transport that cannot parse
// them.
func (c *resolutionConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, from, err := c.conn.ReadFrom(b)
		if err != nil {
			return 0, nil, err
		}
		if isQUICDatagram(b[:n]) {
			return n, from, nil
		}
		c.answer(from)
	}
}

func (c *resolutionConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	return c.conn.WriteTo(b, addr)
}

func (c *resolutionConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *resolutionConn) Close() error                       { return c.conn.Close() }
func (c *resolutionConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *resolutionConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *resolutionConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

// answer replies to one resolution request with the endpoint's QUIC
// transport address: the socket the request arrived on, the address the
// registered service maps to — the advertised host at its port when the
// bind names no host a peer could dial, and nothing while none has
// resolved, the requester's retry re-asking.
func (c *resolutionConn) answer(from net.Addr) {
	local, ok := c.conn.AdvertisedAddr()
	if !ok {
		slog.Debug("Answering service resolution without a host", "peer", from)
		return
	}
	resp, err := proto.Marshal(&control_plane.ServiceResolutionResponse{
		Transports: map[string]*control_plane.Transport{
			TransportQUIC: {Address: local.String()},
		},
	})
	if err != nil {
		slog.Debug("Marshaling the resolution reply", "peer", from, "err", err)
		return
	}
	if _, err := c.conn.WriteTo(resp, from); err != nil {
		slog.Debug("Answering service resolution", "peer", from, "err", err)
	}
}

// isQUICDatagram reports whether the datagram begins as a QUIC packet — the
// two header-form bits set, the same discrimination quic-go's own transport
// applies. The empty request of the resolution exchange and every other
// non-QUIC payload fail it.
func isQUICDatagram(b []byte) bool {
	return len(b) > 0 && b[0]&0xc0 != 0
}
