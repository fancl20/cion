package controlplane

import (
	"net/http"

	"github.com/quic-go/quic-go/http3"
	"github.com/scionproto/scion/pkg/proto/control_plane/v1/control_planeconnect"
)

// ControlPlane covers all control plane RPCs.
type ControlPlane interface {
	control_planeconnect.SegmentCreationServiceHandler
	control_planeconnect.TrustMaterialServiceHandler
	control_planeconnect.SegmentRegistrationServiceHandler
	control_planeconnect.SegmentLookupServiceHandler
	control_planeconnect.ChainRenewalServiceHandler
}

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

	return &Server{
		Handler: mux,
	}
}

// ListenAndServe starts the HTTP/3 server.
func (s *Server) ListenAndServe(addr string, certFile, keyFile string) error {
	return http3.ListenAndServeQUIC(addr, certFile, keyFile, s.Handler)
}
