package controlplane

import (
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/proto/control_plane/v1/control_planeconnect"
	"google.golang.org/protobuf/proto"

	"github.com/fancl20/cion/pkg/peeria"
	"github.com/fancl20/cion/pkg/scion"
)

// ControlPlane covers all control plane RPCs.
type ControlPlane interface {
	control_planeconnect.SegmentCreationServiceHandler
	control_planeconnect.TrustMaterialServiceHandler
	control_planeconnect.SegmentRegistrationServiceHandler
	control_planeconnect.SegmentLookupServiceHandler
	control_planeconnect.ChainRenewalServiceHandler
}

// Mount is one handler a loaded application serves on the control endpoint
// (ADR 0009): the pattern the HTTP mux mounts the handler at, the handler
// itself behind the peer-identity middleware. The core learns no type of the
// application that built it.
type Mount struct {
	// Pattern is the mux pattern the handler mounts at.
	Pattern string
	// Handler serves the pattern.
	Handler http.Handler
}

// Services composes the trust and segment services into one ControlPlane;
// the segment service's methods take precedence over the trust service's
// unimplemented embeds. Mounts are the handlers a loaded application — the
// topology provider foremost — serves behind the peer-authenticating
// middleware, mounted beside the drafts' services; empty when none loads.
type Services struct {
	*TrustService
	*SegmentService
	// Mounts are the application mounts the endpoint serves.
	Mounts []Mount
}

var _ ControlPlane = (*Services)(nil)

// Server implements the control plane server.
type Server struct {
	Handler http.Handler
}

// NewServer creates a new control plane server.
func NewServer(svc ControlPlane) *Server {
	mux := http.NewServeMux()

	mux.Handle(control_planeconnect.NewSegmentCreationServiceHandler(svc))
	mux.Handle(control_planeconnect.NewTrustMaterialServiceHandler(svc))
	mux.Handle(control_planeconnect.NewSegmentRegistrationServiceHandler(svc))
	mux.Handle(control_planeconnect.NewSegmentLookupServiceHandler(svc))
	mux.Handle(control_planeconnect.NewChainRenewalServiceHandler(svc))

	if s, ok := svc.(*Services); ok {
		for _, m := range s.Mounts {
			mux.Handle(m.Pattern, peeria.Authenticate(m.Handler))
		}
	}

	return &Server{
		Handler: mux,
	}
}

// quicConfig caps the packet size so a QUIC datagram wrapped in a SCION
// header still fits a standard 1500-byte MTU; the SCION conn does not
// support the don't-fragment capability, so QUIC never grows beyond the
// initial size.
var quicConfig = &quic.Config{InitialPacketSize: 1200}

// ServeHTTP3 serves the handler with HTTP/3 (QUIC) on conn, answering the
// drafts' service resolution beside it (control plane draft, Section 5). The
// TLS configuration must carry the certificate for the served domain.
func ServeHTTP3(conn *scion.Conn, handler http.Handler, tlsConf *tls.Config) error {
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
	return server.ServeListener(ln)
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
// registered service maps to.
func (c *resolutionConn) answer(from net.Addr) {
	local := c.conn.LocalAddr().(*scion.Addr).Addr
	resp, err := proto.Marshal(&control_plane.ServiceResolutionResponse{
		Transports: map[string]*control_plane.Transport{
			TransportQUIC: {Address: local.String()},
		},
	})
	if err != nil {
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
