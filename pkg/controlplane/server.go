package controlplane

import (
	"crypto/tls"
	"net/http"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/scionproto/scion/pkg/proto/control_plane/v1/control_planeconnect"

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
// (ADR 0007): the pattern the HTTP mux mounts the handler at, the handler
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
