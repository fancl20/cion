package controlplane

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/proto/control_plane/v1/control_planeconnect"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"google.golang.org/protobuf/proto"

	"github.com/fancl20/cion/pkg/core/trust"
	"github.com/fancl20/cion/pkg/libs/ratelimit"
	"github.com/fancl20/cion/pkg/libs/scionrpc"
	"github.com/fancl20/cion/pkg/modules/enrollauth"
	"github.com/fancl20/cion/pkg/modules/trustdb"
)

// EnrollmentMinInterval is the chain-renewal door's rate cap: the least pause
// between admissions of one source — the rendezvous acceptor's own cap the
// shape.
const EnrollmentMinInterval = time.Second

// TrustService implements the trust material and chain renewal RPCs of the
// control endpoint. The segment service RPCs it embeds unimplemented come from
// SegmentService, which takes precedence in the Services composition.
// Admission is the provider's alone: enrollment is reachable only over paths,
// paths exist only over established links, and the loaded provider admits
// every link — the acceptor's policy is where the decision lives, and this
// service's own check is the name's binding to its key.
type TrustService struct {
	control_planeconnect.UnimplementedSegmentCreationServiceHandler
	control_planeconnect.UnimplementedSegmentRegistrationServiceHandler
	control_planeconnect.UnimplementedSegmentLookupServiceHandler

	// DB serves trust material from the local trust database, and holds the
	// founding core's bindings of names to keys.
	DB trustdb.DB
	// Issuer signs certificate chains: a core's, nil on a normal node. An
	// authoritative core's issues once its root lands in the TRC.
	Issuer *trust.Issuer
	// Enrolls marks the founding core's service, the one that serves first
	// issuance; every other issuer renews on the requester's chain alone.
	Enrolls bool
	// Authorizer gates first issuance: it is asked exactly when possession is
	// verified and the name is bound to no key, never on a renewal or a bound
	// holder's re-enrollment. The same seam answers host registration on the
	// coordination application. Nil is open admission — the zero-conf default.
	Authorizer enrollauth.AdmissionAuthorizer
	// MinInterval is the least pause between admissions of one source at the
	// renewal door; zero uses the default.
	MinInterval time.Duration

	limiterOnce sync.Once
	byAddr      *ratelimit.Keyed[netip.AddrPort]
	byIA        *ratelimit.Keyed[addr.IA]
	// renewalMtx serializes the renewal transaction — the binding check, the
	// authorizer's question, the binding, the issuance, and the insert hold it
	// together — so two concurrent first issuances of one free name cannot
	// both pass the check.
	// A Telegram prompt's send holds a later renewal behind it for as long as its
	// timeout; issuance is rare enough that the queue is the honest price of one
	// name, one chain.
	renewalMtx sync.Mutex
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
	// The stored bytes, so every holder of one TRC ID holds the same DER.
	return connect.NewResponse(&cppb.TRCResponse{Trc: trc.Raw}), nil
}

// checkRenewal checks that the requester's chain authorizes the renewal (PKI
// draft, Section 4.3), whichever issuer signed it: the chain verifies
// against the pinned anchor pool now, and its AS certificate names the CSR's
// ISD-AS and certifies the CSR's key. A renewal checks no binding and asks no
// policy.
func (s *TrustService) checkRenewal(
	ctx context.Context,
	ia addr.IA,
	csr *x509.CertificateRequest,
	chain []*x509.Certificate,
) error {

	pool, err := trust.PinnedPool(ctx, s.DB, ia.ISD())
	if err != nil {
		return connect.NewError(connect.CodeInternal,
			serrors.Wrap("reading the pinned TRCs", err))
	}
	if err := cppki.VerifyChain(chain, cppki.VerifyOptions{TRC: pool}); err != nil {
		return connect.NewError(connect.CodePermissionDenied,
			serrors.Wrap("the requester's chain does not verify against the TRC", err))
	}
	if certIA, err := cppki.ExtractIA(chain[0].Subject); err != nil || !certIA.Equal(ia) {
		return connect.NewError(connect.CodePermissionDenied,
			serrors.New("the requester's chain names another ISD-AS", "isd_as", ia))
	}
	skid, err := cppki.SubjectKeyID(csr.PublicKey)
	if err != nil {
		return connect.NewError(connect.CodeInvalidArgument,
			serrors.Wrap("computing the CSR subject key", err))
	}
	if !bytes.Equal(chain[0].SubjectKeyId, skid) {
		return connect.NewError(connect.CodeInvalidArgument,
			serrors.New("the CSR certifies another key than the requester's chain", "isd_as", ia))
	}
	return nil
}

// checkFirstIssuance gates a request no chain authorizes, its wrapper signed
// by the CSR's own key: the founding core alone serves one. A name bound to
// the key re-enrolls its holder, a free name asks the authorizer and is bound
// to the key on its allow, and a name bound to another key is taken.
func (s *TrustService) checkFirstIssuance(
	ctx context.Context,
	ia addr.IA,
	csr *x509.CertificateRequest,
	signed *trust.CMSSigned,
) error {

	if !s.Enrolls {
		return connect.NewError(connect.CodeFailedPrecondition,
			errors.New("first issuance takes the founding core; a renewal carries "+
				"the requester's chain"))
	}
	// The wrapper must be signed by the same key the CSR certifies; the
	// CSR's self-signature alone is checked by the issuer.
	if !signed.SignedBy(csr.PublicKey) {
		return connect.NewError(connect.CodeInvalidArgument,
			errors.New("request is not signed by the CSR subject key"))
	}
	skid, err := cppki.SubjectKeyID(csr.PublicKey)
	if err != nil {
		return connect.NewError(connect.CodeInvalidArgument,
			serrors.Wrap("computing the CSR subject key", err))
	}
	bound, err := s.DB.BoundKey(ctx, ia)
	if err != nil {
		return connect.NewError(connect.CodeInternal,
			serrors.Wrap("reading the ISD-AS's binding", err))
	}
	switch {
	case bound == nil:
		if err := s.authorizeFirstIssuance(ctx, ia, csr); err != nil {
			return err
		}
		if err := s.DB.BindKey(ctx, ia, skid); err != nil {
			return connect.NewError(connect.CodeInternal,
				serrors.Wrap("binding the ISD-AS to the key", err))
		}
		return nil
	case bytes.Equal(bound, skid):
		return nil // the name's holder re-enrolling
	default:
		slog.Warn("Rejecting chain renewal of a taken ISD-AS",
			"isd_as", ia, "holder", hex.EncodeToString(bound))
		return connect.NewError(connect.CodeAlreadyExists,
			serrors.New("ISD-AS is bound to another key", "isd_as", ia))
	}
}

// authorizeFirstIssuance asks the authorizer's one question at its moment:
// possession verified, the name free, the verdict on the facts
// the exchange established decides. Allow returns nil, deny answers
// PermissionDenied, and pending Unavailable — a verdict the joiner's
// enrollment retry loop consumes without change. Both refusals are logged
// with the facts beside them, so the node's log mirrors the operator's
// phone.
func (s *TrustService) authorizeFirstIssuance(
	ctx context.Context,
	ia addr.IA,
	csr *x509.CertificateRequest,
) error {

	if s.Authorizer == nil {
		return nil
	}
	skid, err := cppki.SubjectKeyID(csr.PublicKey)
	if err != nil {
		return connect.NewError(connect.CodeInvalidArgument,
			serrors.Wrap("computing the CSR subject key", err))
	}
	facts := enrollauth.AdmissionFacts{
		Boundary: enrollauth.BoundaryEnrollment,
		Keys:     []string{hex.EncodeToString(skid)},
		Source:   scionrpc.RemoteUnderlay(ctx),
		Claim:    ia,
	}
	answer := s.Authorizer.Authorize(ctx, facts)
	logFacts := []any{
		"isd_as", ia, "key", facts.Keys[0], "source", facts.Source}
	switch answer.Admission {
	case enrollauth.AdmissionAllow:
		return nil
	case enrollauth.AdmissionPending:
		slog.Info("Enrollment pending a decision", logFacts...)
		return connect.NewError(connect.CodeUnavailable,
			serrors.New("enrollment pending", "isd_as", ia, "source", facts.Source))
	default:
		slog.Warn("Denying enrollment", logFacts...)
		return connect.NewError(connect.CodePermissionDenied,
			serrors.New("enrollment denied", "isd_as", ia, "source", facts.Source))
	}
}

// admit spends one rate slot of the renewal door: one admission per interval
// keyed by the request's SCION source address — the return-routable fact the
// context carries — with the claimed ISD-AS as the key when the context
// carries no address. The cap's work is bounding, not authenticating; each
// invented identity costs its slot, and no second request is in flight.
func (s *TrustService) admit(ctx context.Context, ia addr.IA) bool {
	s.limiterOnce.Do(func() {
		interval := s.MinInterval
		if interval == 0 {
			interval = EnrollmentMinInterval
		}
		s.byAddr = ratelimit.NewKeyed[netip.AddrPort](interval)
		s.byIA = ratelimit.NewKeyed[addr.IA](interval)
	})
	if src := scionrpc.RemoteUnderlay(ctx); src.IsValid() {
		return s.byAddr.Admit(src)
	}
	return s.byIA.Admit(ia)
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
	query := trustdb.ChainQuery{
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
// request. A request whose CMS wrapper carries the requester's chain is a
// renewal: the chain's key signed it (PKI draft, Section 4.3), and any issuer
// serves it. One signed by the CSR's subject key itself — proof of
// possession, for a fresh node has no chain yet — is a first issuance, which
// the founding core alone serves. An issuer whose root no pinned TRC carries
// yet answers Unavailable.
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
	chain, err := trust.RequestChain(signed)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	// The door's rate cap, ahead of the work and the mutex: one admission per
	// interval per source bounds the unauthenticated exchange whatever it asks.
	if !s.admit(ctx, ia) {
		return nil, connect.NewError(connect.CodeResourceExhausted,
			serrors.New("source exceeds the enrollment admission rate", "isd_as", ia))
	}
	// The renewal transaction: the checks, the authorizer's question, the
	// binding, the issuance, and the insert hold the mutex together, whatever
	// the authorizer's latency.
	s.renewalMtx.Lock()
	defer s.renewalMtx.Unlock()
	if chain != nil {
		err = s.checkRenewal(ctx, ia, csr, chain)
	} else {
		err = s.checkFirstIssuance(ctx, ia, csr, signed)
	}
	if err != nil {
		return nil, err
	}

	// The chain and the response carrying it come from one snapshot of the
	// CA material: the client requires the response signed by the chain's
	// CA certificate, which a rekey between the two would replace.
	ca, err := s.Issuer.CA()
	if errors.Is(err, trust.ErrUnanchored) {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal,
			serrors.Wrap("reading the CA material", err))
	}
	issued, err := ca.IssueChain(csr)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			serrors.Wrap("issuing chain", err))
	}
	if _, err := s.DB.InsertChain(ctx, issued); err != nil {
		return nil, connect.NewError(connect.CodeInternal,
			serrors.Wrap("storing issued chain", err))
	}
	respBody, err := proto.Marshal(&cppb.ChainRenewalResponseBody{
		Chain: &cppb.Chain{AsCert: issued[0].Raw, CaCert: issued[1].Raw},
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	cmsRes, err := ca.SignResponse(respBody)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal,
			serrors.Wrap("signing renewal response", err))
	}
	return connect.NewResponse(&cppb.ChainRenewalResponse{
		CmsSignedResponse: cmsRes,
	}), nil
}
