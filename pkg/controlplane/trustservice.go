package controlplane

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"time"

	"connectrpc.com/connect"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/proto/control_plane/v1/control_planeconnect"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"google.golang.org/protobuf/proto"

	"github.com/fancl20/cion/pkg/trust"
)

// TrustService implements the trust material and chain renewal RPCs of the
// control endpoint. The segment service RPCs it embeds unimplemented come
// from SegmentService, which takes precedence in the Services composition.
type TrustService struct {
	control_planeconnect.UnimplementedSegmentCreationServiceHandler
	control_planeconnect.UnimplementedSegmentRegistrationServiceHandler
	control_planeconnect.UnimplementedSegmentLookupServiceHandler

	// DB serves trust material from the local trust database.
	DB trust.DB
	// Issuer signs certificate chains. It is nil on nodes that do not issue
	// chains — everything but the founding core, in this milestone.
	Issuer *trust.Issuer
	// AllowAS optionally restricts enrollment to the listed ISD-ASes; nil
	// means open enrollment.
	AllowAS map[addr.IA]bool
}

var _ ControlPlane = (*TrustService)(nil)

// TRC serves a signed TRC. A request without base and serial numbers asks
// for the latest TRC of the ISD, which in a base-TRC-only milestone is the
// base TRC.
func (s *TrustService) TRC(
	ctx context.Context,
	req *connect.Request[cppb.TRCRequest],
) (*connect.Response[cppb.TRCResponse], error) {

	r := req.Msg
	id := cppki.TRCID{
		ISD:    addr.ISD(r.Isd),
		Base:   scrypto.Version(r.Base),
		Serial: scrypto.Version(r.Serial),
	}
	if id.Base == 0 && id.Serial == 0 {
		// The request asks for the latest TRC of the ISD.
		id.Base, id.Serial = scrypto.LatestVer, scrypto.LatestVer
	}
	trc, err := s.DB.SignedTRC(ctx, id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if trc.IsZero() {
		return nil, connect.NewError(connect.CodeNotFound,
			serrors.New("TRC not found", "id", id))
	}
	raw, err := trc.Encode()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&cppb.TRCResponse{Trc: raw}), nil
}

// checkNameTaken rejects a renewal for an ISD-AS that already holds an
// unexpired chain under a different subject key: the name is taken (ADR-0006's
// enrollment gate). A same-key renewal — the chain's own holder — passes.
func (s *TrustService) checkNameTaken(
	ctx context.Context,
	ia addr.IA,
	csr *x509.CertificateRequest,
	now time.Time,
) error {

	chains, err := s.DB.Chains(ctx, trust.ChainQuery{
		IA:       ia,
		Validity: cppki.Validity{NotBefore: now, NotAfter: now},
	})
	if err != nil {
		return connect.NewError(connect.CodeInternal,
			serrors.Wrap("querying the ISD-AS's chains", err))
	}
	if len(chains) == 0 {
		return nil
	}
	skid, err := cppki.SubjectKeyID(csr.PublicKey)
	if err != nil {
		return connect.NewError(connect.CodeInvalidArgument,
			serrors.Wrap("computing the CSR subject key", err))
	}
	for _, chain := range chains {
		if bytes.Equal(chain[0].SubjectKeyId, skid) {
			return nil // the current holder renewing its own chain
		}
	}
	slog.Warn("Rejecting chain renewal of a taken ISD-AS",
		"isd_as", ia, "holder", chains[0][0].SubjectKeyId)
	return connect.NewError(connect.CodeAlreadyExists,
		serrors.New("ISD-AS already holds a chain under another key", "isd_as", ia))
}

// Chains serves the certificate chains matching the request.
func (s *TrustService) Chains(
	ctx context.Context,
	req *connect.Request[cppb.ChainsRequest],
) (*connect.Response[cppb.ChainsResponse], error) {

	r := req.Msg
	now := time.Now()
	// The request may pin a validity window; unset bounds default to "valid
	// now" on that side.
	query := trust.ChainQuery{
		IA:           addr.IA(r.IsdAs),
		SubjectKeyID: r.SubjectKeyId,
		Validity:     cppki.Validity{NotBefore: now, NotAfter: now},
	}
	if r.AtLeastValidSince != nil {
		query.Validity.NotBefore = r.AtLeastValidSince.AsTime()
	}
	if r.AtLeastValidUntil != nil {
		query.Validity.NotAfter = r.AtLeastValidUntil.AsTime()
	}
	chains, err := s.DB.Chains(ctx, query)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	resp := &cppb.ChainsResponse{}
	for _, chain := range chains {
		resp.Chains = append(resp.Chains, &cppb.Chain{
			AsCert: chain[0].Raw,
			CaCert: chain[1].Raw,
		})
	}
	return connect.NewResponse(resp), nil
}

// ChainRenewal issues a certificate chain for the CSR carried by the
// request. First-issuance requests ride a CMS wrapper signed by the CSR's
// subject key itself — proof of possession of that key (PKI draft,
// Section 4.3) — since a fresh node has no certificate chain yet. The signed
// wrapper the reference implementation verifies against the requester's
// existing chain is honored for renewals only, which do not exist in this
// milestone.
func (s *TrustService) ChainRenewal(
	ctx context.Context,
	req *connect.Request[cppb.ChainRenewalRequest],
) (*connect.Response[cppb.ChainRenewalResponse], error) {

	if s.Issuer == nil {
		return nil, connect.NewError(connect.CodeUnimplemented,
			errors.New("this node does not issue certificate chains"))
	}
	if len(req.Msg.CmsSignedRequest) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("missing CMS-signed request"))
	}

	signed, err := trust.ParseCMS(req.Msg.CmsSignedRequest)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	var body cppb.ChainRenewalRequestBody
	if err := proto.Unmarshal(signed.Payload, &body); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			serrors.Wrap("parsing renewal request body", err))
	}
	csr, err := x509.ParseCertificateRequest(body.Csr)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			serrors.Wrap("parsing CSR", err))
	}
	ia, err := cppki.ExtractIA(csr.Subject)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			serrors.Wrap("extracting ISD-AS from CSR", err))
	}
	if s.AllowAS != nil && !s.AllowAS[ia] {
		slog.Warn("Rejecting chain renewal of unlisted ISD-AS", "isd_as", ia)
		return nil, connect.NewError(connect.CodePermissionDenied,
			serrors.New("ISD-AS is not allowlisted", "isd_as", ia))
	}
	// The enrollment gate of self-picked ISD-ASes (ADR-0006): a name that
	// already holds an unexpired chain under a different subject key is
	// taken. Renewals by the same key pass untouched.
	now := time.Now()
	if err := s.checkNameTaken(ctx, ia, csr, now); err != nil {
		return nil, err
	}
	// The wrapper must be signed by the same key the CSR certifies; the
	// CSR's self-signature alone is checked by the issuer.
	if !signed.SignedBy(csr.PublicKey) {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("request is not signed by the CSR subject key"))
	}

	chain, err := s.Issuer.IssueChain(csr)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			serrors.Wrap("issuing chain", err))
	}
	if _, err := s.DB.InsertChain(ctx, chain); err != nil {
		return nil, connect.NewError(connect.CodeInternal,
			serrors.Wrap("storing issued chain", err))
	}
	respBody, err := proto.Marshal(&cppb.ChainRenewalResponseBody{
		Chain: &cppb.Chain{AsCert: chain[0].Raw, CaCert: chain[1].Raw},
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	cmsRes, err := s.Issuer.SignResponse(respBody)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal,
			serrors.Wrap("signing renewal response", err))
	}
	return connect.NewResponse(&cppb.ChainRenewalResponse{
		CmsSignedResponse: cmsRes,
	}), nil
}
