// Package controlplane implements the node core's control service:
// beaconing and the drafts' services — segment creation, registration, and
// lookup, trust material and chain renewal — with the server that composes
// the services and the peer client that calls its peers', every protocol
// the core speaks the drafts' own. Both ride the SCION-native channel of
// pkg/libs/scionrpc, which carries the drafts' RPC over SCION paths and
// answers their service resolution, as it does any application's.
package controlplane

import (
	"net/http"

	"github.com/scionproto/scion/pkg/proto/control_plane/v1/control_planeconnect"

	"github.com/fancl20/cion/pkg/libs/peeria"
	"github.com/fancl20/cion/pkg/libs/scionrpc"
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
// unimplemented embeds. Mounts are the handlers a loaded application — the
// topology provider and the voting application among them — serves behind
// the peer-authenticating middleware, mounted beside the drafts' services;
// empty when none loads.
type Services struct {
	*TrustService
	*SegmentService
	// Mounts are the application mounts the endpoint serves.
	Mounts []scionrpc.Mount
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
