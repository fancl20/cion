package voting

import (
	"context"
	"errors"
	"net/http"
	"sync"

	"connectrpc.com/connect"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/controlplane"
	"github.com/fancl20/cion/pkg/scion"
	"github.com/fancl20/cion/pkg/trust"
	votingv1 "github.com/fancl20/cion/proto/voting/v1"
	votingv1connect "github.com/fancl20/cion/proto/voting/v1/votingv1connect"
)

// Submitter sends TRC update submissions to the core's voting application
// over the node's verified peer channel — the node's chain presented, the
// core's verified against the pinned TRC — so the submission arrives
// identified by the chain the decision binds the new voter to.
type Submitter struct {
	// hclt is the verified peer channel's HTTP client, the node's peer
	// client's own.
	hclt *http.Client
	// coreRoute resolves the core's endpoint, the route the drafts' RPCs
	// already take.
	coreRoute func() *scion.Addr

	mtx sync.Mutex
	// clt serves the current core endpoint; the authority it is keyed by
	// replaces it when the core's route moves.
	clt       votingv1connect.VotingServiceClient
	authority string
}

// NewSubmitter builds the submitter over the verified peer channel.
func NewSubmitter(hclt *http.Client, coreRoute func() *scion.Addr) *Submitter {
	return &Submitter{hclt: hclt, coreRoute: coreRoute}
}

// SubmitTRC hands the partially signed successor to the core's voting
// application and answers with the TRC its control plane completed and
// pinned. A submission nothing answers — the endpoint replies that no such
// application is mounted — is the core hosting no voting application, the
// terminal condition the caller stops the node on.
func (s *Submitter) SubmitTRC(
	ctx context.Context,
	trc cppki.SignedTRC,
) (cppki.SignedTRC, error) {

	core := s.coreRoute()
	if core == nil {
		return cppki.SignedTRC{}, errors.New("no route to the core yet")
	}
	authority := controlplane.PeerAuthority(core)
	s.mtx.Lock()
	if s.clt == nil || s.authority != authority {
		s.clt = votingv1connect.NewVotingServiceClient(s.hclt, "https://"+authority)
		s.authority = authority
	}
	clt := s.clt
	s.mtx.Unlock()
	resp, err := clt.Submit(ctx, connect.NewRequest(&votingv1.SubmitRequest{Trc: trc.Raw}))
	if err != nil {
		// The endpoint answered, but no voting application is mounted on
		// it: the drafts' services and the mounted ones share the socket,
		// so an absent application is a refused route, not a silent one.
		if code := connect.CodeOf(err); code == connect.CodeNotFound ||
			code == connect.CodeUnimplemented {
			return cppki.SignedTRC{}, trust.ErrNoVotingApp
		}
		return cppki.SignedTRC{}, err
	}
	return cppki.DecodeSignedTRC(resp.Msg.Trc)
}
