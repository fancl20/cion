package controlplane

import (
	"context"

	"connectrpc.com/connect"
	"github.com/quic-go/quic-go/http3"
	"github.com/scionproto/scion/pkg/private/serrors"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/proto/control_plane/v1/control_planeconnect"

	"github.com/fancl20/cion/pkg/segment"
)

// SegmentService implements the segment RPCs of the control endpoint
// (ADR-0004): beacon reception on SegmentCreationService, down-segment
// registration on SegmentRegistrationService, and the source-AS
// segment-request handler on SegmentLookupService.
type SegmentService struct {
	// Beaconer receives and verifies beacons and registrations.
	Beaconer *Beaconer
	// Lookup serves segment requests.
	Lookup *LookupService
}

var _ control_planeconnect.SegmentCreationServiceHandler = (*SegmentService)(nil)
var _ control_planeconnect.SegmentRegistrationServiceHandler = (*SegmentService)(nil)
var _ control_planeconnect.SegmentLookupServiceHandler = (*SegmentService)(nil)

// Beacon receives a propagated PCB (draft Section 2.3.5.3), applying the
// reception checks of Section 2.3.1 before anything is stored. Beacons
// terminate on each node's control service, so every node serves this RPC.
func (s *SegmentService) Beacon(
	ctx context.Context,
	req *connect.Request[cppb.BeaconRequest],
) (*connect.Response[cppb.BeaconResponse], error) {

	if req.Msg.Segment == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			serrors.New("beacon request carries no segment"))
	}
	pcb, err := segment.ParsePCB(req.Msg.Segment)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			serrors.Wrap("parsing beacon", err))
	}
	ingress, err := arrivalInterface(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	}
	if err := s.Beaconer.HandleBeacon(ctx, pcb, ingress); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	return connect.NewResponse(&cppb.BeaconResponse{}), nil
}

// SegmentsRegistration receives down segments registered by a non-core
// (Sections 4.1.3 and 4.3); the receiving core verifies each registered
// segment as on beacon reception.
func (s *SegmentService) SegmentsRegistration(
	ctx context.Context,
	req *connect.Request[cppb.SegmentsRegistrationRequest],
) (*connect.Response[cppb.SegmentsRegistrationResponse], error) {

	downs, ok := req.Msg.Segments[int32(cppb.SegmentType_SEGMENT_TYPE_DOWN)]
	if !ok {
		return connect.NewResponse(&cppb.SegmentsRegistrationResponse{}), nil
	}
	for _, pb := range downs.Segments {
		if err := s.Beaconer.HandleRegistration(ctx, pb); err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
	}
	return connect.NewResponse(&cppb.SegmentsRegistrationResponse{}), nil
}

// Segments serves a segment request (Section 5).
func (s *SegmentService) Segments(
	ctx context.Context,
	req *connect.Request[cppb.SegmentsRequest],
) (*connect.Response[cppb.SegmentsResponse], error) {

	return s.Lookup.Segments(ctx, req)
}

// arrivalInterface extracts the interface a beacon arrived on from the
// connection's remote address: the router recorded it in the one-hop path's
// second hop when the packet entered this AS.
func arrivalInterface(ctx context.Context) (uint16, error) {
	remote, ok := ctx.Value(http3.RemoteAddrContextKey).(*Addr)
	if !ok || remote == nil {
		return 0, serrors.New("peer address unavailable in request context")
	}
	if remote.IfID == 0 {
		return 0, serrors.New("arrival interface unknown",
			"peer", remote.IA, "addr", remote.Addr)
	}
	return remote.IfID, nil
}
