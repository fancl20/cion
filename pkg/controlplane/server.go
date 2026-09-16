package controlplane

import (
	"crypto/tls"
	"net/http"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/scionproto/scion/pkg/proto/control_plane/v1/control_planeconnect"

	"github.com/fancl20/cion/pkg/scion"
	nodev1connect "github.com/fancl20/cion/proto/node/v1/nodev1connect"
)

// ControlPlane covers all control plane RPCs.
type ControlPlane interface {
	control_planeconnect.SegmentCreationServiceHandler
	control_planeconnect.TrustMaterialServiceHandler
	control_planeconnect.SegmentRegistrationServiceHandler
	control_planeconnect.SegmentLookupServiceHandler
	control_planeconnect.ChainRenewalServiceHandler
}

// Services composes the trust and segment services into one ControlPlane;
// the segment service's methods take precedence over the trust service's
// unimplemented embeds. Link and Directory are CION's own services of
// proposal 0008 — served on the same endpoint behind the peer-authenticating
// middleware when set, absent when the node runs none.
type Services struct {
	*TrustService
	*SegmentService
	// Link establishes links in-band.
	Link *LinkService
	// Directory serves the node directory, on the core.
	Directory *DirectoryService
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
		if s.Link != nil {
			path, handler := nodev1connect.NewLinkServiceHandler(s.Link)
			mux.Handle(path, Authenticate(handler))
		}
		if s.Directory != nil {
			path, handler := nodev1connect.NewDirectoryServiceHandler(s.Directory)
			mux.Handle(path, Authenticate(handler))
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

// ServeHTTP3 serves the handler with HTTP/3 (QUIC) on conn. The TLS
// configuration must carry the certificate for the served domain.
func ServeHTTP3(conn *scion.Conn, handler http.Handler, tlsConf *tls.Config) error {
	server := &http3.Server{
		Handler:    handler,
		TLSConfig:  tlsConf,
		QUICConfig: quicConfig,
	}
	return server.Serve(conn)
}
