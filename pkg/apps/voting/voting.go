// Package voting is the TRC voting application: the resident application a
// founding core hosts for the cores of its ISD to submit TRC updates on. A
// core that enrolled as a normal node submits the successor it assembled and
// signed — its proofs of possession, and its own vote when it rolls by
// regular update — and the application hands the submission to the control
// plane's decision, which pins what verifies as submitted and casts the
// founder's sensitive vote itself where the update needs it: the application
// decides nothing, and the control plane serves no submission of its own.
// Nothing else depends on the application — the network serves the drafts'
// control plane, enrollment, and paths with or without it — and a joining
// core whose founder hosts none stops itself rather than wait, for no voting
// power can be obtained that way.
package voting

import (
	"context"
	"log/slog"
	"net/http"
	"net/netip"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/libs/peeria"
	"github.com/fancl20/cion/pkg/libs/scionrpc"
	votingv1 "github.com/fancl20/cion/proto/voting/v1"
	votingv1connect "github.com/fancl20/cion/proto/voting/v1/votingv1connect"
)

// Decider is the decision the submissions are handed to: the control
// plane's own update of the pinned TRC — the founder asking its gates,
// pinning what verifies as submitted, and casting its sensitive vote on its
// admission policy's allow — answered with the TRC it pinned. The presenter
// is the ISD-AS the application's channel verified, never a claim, and the
// source is the address the submission arrived from.
type Decider interface {
	DecideTRC(ctx context.Context, presenter addr.IA, source netip.AddrPort,
		trc cppki.SignedTRC) (cppki.SignedTRC, error)
}

// Config configures the voting application.
type Config struct {
	// IA is the node's ISD-AS.
	IA addr.IA
	// Decide is the control plane's decision the submissions are handed
	// to: the founding core's, the one role the application loads on.
	Decide Decider
	// MountControlEndpoint mounts one of the application's handlers on the
	// node's control endpoint, behind the peer-identity middleware.
	MountControlEndpoint func(pattern string, handler http.Handler)
}

// App is the voting application: its submission service mounted on the
// control endpoint, every submission identified by the verified chain of the
// channel it arrived on and handed to the control plane's decision.
type App struct {
	cfg Config
}

var _ interface {
	Run(context.Context) error
	Close()
} = (*App)(nil)

// New mounts the application's submission service on the control endpoint:
// the service registered on a connect server, which connecthttp.Mount
// spreads over a private mux mounted at the service name's canonical
// pattern.
func New(cfg Config) *App {
	server := connect.NewServer()
	votingv1connect.RegisterVotingServiceHandler(server, &service{decide: cfg.Decide})
	mux := http.NewServeMux()
	connecthttp.Mount(mux, server)
	cfg.MountControlEndpoint("/"+votingv1connect.VotingServiceName+"/", mux)
	slog.Info("Serving the TRC voting application", "isd_as", cfg.IA)
	return &App{cfg: cfg}
}

// Run serves until the context is canceled: the control endpoint serves the
// mounted submission service, so the application runs no loop of its own.
func (a *App) Run(ctx context.Context) error {
	<-ctx.Done()
	return nil
}

// Close releases the application; the endpoint releases its mount.
func (a *App) Close() {}

// service implements the application's submission RPC.
type service struct {
	decide Decider
}

// Submit hands the submitted successor to the control plane's decision and
// answers with the TRC it pinned. The submitter is the ISD-AS the channel
// verified; the decision is the control plane's alone.
func (s *service) Submit(
	ctx context.Context,
	req *votingv1.SubmitRequest,
) (*votingv1.SubmitResponse, error) {

	presenter := peeria.AuthenticatedIA(ctx)
	if presenter.IsZero() {
		return nil, connect.NewError(connect.CodePermissionDenied,
			"no authenticated ISD-AS: the channel verified no chain")
	}
	if len(req.Trc) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			"the submission carries no TRC")
	}
	trc, err := cppki.DecodeSignedTRC(req.Trc)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			"parsing the submitted TRC").WithCause(err)
	}
	pinned, err := s.decide.DecideTRC(ctx, presenter, scionrpc.RemoteUnderlay(ctx), trc)
	if err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			"the control plane's decision refused the submission").WithCause(err)
	}
	// The pinned bytes, so every holder of the pinned TRC holds the same DER
	// the control plane verified.
	return &votingv1.SubmitResponse{Trc: pinned.Raw}, nil
}
