package trust

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"log/slog"
	"net/netip"
	"slices"
	"sync"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/scrypto/cms/protocol"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/modules/enrollauth"
	"github.com/fancl20/cion/pkg/modules/trustdb"
)

// TRCDecider is the control plane's decision on a submitted TRC update, with
// no network of its own: the voting application hands each submission over,
// and the decision is made here. A submission that changes the presenter's
// own material alone, and verifies against the newest pinned TRC as
// submitted, pins with the founder's signature beside the presenter's; a
// sensitive update short of the founder's vote gets the vote only on the
// admission policy's allow. The completed artifact verifies against the
// newest pinned TRC before it pins. The founder's own casts run through
// CastLocal and RemoveCore instead.
type TRCDecider struct {
	// DB serves and pins the founder's TRCs.
	DB trustdb.DB
	// IA is the founding core's ISD-AS, the ISD the updates belong to.
	IA addr.IA
	// Sensitive casts the founder's vote with the sensitive voting key of
	// the newest pinned TRC's certificate set. The decision exists on the
	// founding core alone, built with its sensitive key.
	Sensitive crypto.Signer
	// Authorizer is the policy asked before the founder's sensitive vote on
	// a submission. Nil denies every such vote: the run arguments left the
	// policy unset.
	Authorizer enrollauth.AdmissionAuthorizer

	// mtx serializes the decision: each one reads the sensitive signer and
	// the newest pinned TRC under it, so serials stay monotone under
	// concurrent submissions, only a verified update ever advances the pin,
	// and a roll's reassignment of Sensitive lands between decisions.
	mtx sync.Mutex
}

// DecideTRC decides whether the founder accepts the successor a core
// submitted. A submission whose landing the newest pinned TRC already
// carries is answered with that TRC — the idempotent re-presentation, read
// from what the submission holds, never from the presenter's name. Otherwise
// the update must classify against the newest pinned TRC, the presenter must
// be the channel's verified peer — the channel admits a chain only if it
// verifies against the founder's pinned TRC, whichever core issued it — and
// the submission must change nothing but the presenter's own material. Past
// those gates a submission that verifies as submitted, or a sensitive update
// the admission policy allows the founder's vote, pins with the founder's
// signature added; anything else is refused. What refuses pins nothing.
func (c *TRCDecider) DecideTRC(
	ctx context.Context,
	presenter addr.IA,
	source netip.AddrPort,
	trc cppki.SignedTRC,
) (cppki.SignedTRC, error) {

	c.mtx.Lock()
	defer c.mtx.Unlock()
	if presenter.IsZero() {
		return cppki.SignedTRC{}, serrors.New("the submission carries no verified presenter")
	}
	newest, err := c.newestTRC(ctx)
	if err != nil {
		return cppki.SignedTRC{}, err
	}
	if landed(trc.TRC, newest.TRC) {
		// The submission already landed, whether here or before a restart:
		// the newest carries it, and nothing is decided again.
		return newest, nil
	}
	// The submitted successor must classify against the newest pinned TRC:
	// the serial increments it and noTrustReset stands. A submission built
	// on an older view is refused — the submitter resolves the newest TRC
	// and submits again.
	update, err := trc.TRC.ValidateUpdate(&newest.TRC)
	if err != nil {
		return cppki.SignedTRC{}, serrors.Wrap("the submitted update does not classify "+
			"against the newest pinned TRC", err, "submitted", trc.TRC.ID,
			"predecessor", newest.TRC.ID)
	}
	if err := presentersOwn(trc, newest.TRC, presenter); err != nil {
		return cppki.SignedTRC{}, err
	}
	// A submission carrying every signature its update requires — a regular
	// update its voters signed — takes the founder's signature alone; a
	// sensitive update short of a vote asks for the founder's, the policy's
	// allow its only gate.
	if verifyErr := trc.Verify(&newest.TRC); verifyErr != nil {
		if update.Type != cppki.SensitiveUpdate {
			return cppki.SignedTRC{}, serrors.Wrap("the submitted update does not verify "+
				"against the newest pinned TRC", verifyErr, "id", trc.TRC.ID)
		}
		if err := c.authorizeVoting(ctx, presenter, source, novelCerts(trc.TRC, newest.TRC)); err != nil {
			return cppki.SignedTRC{}, err
		}
	}
	sensitiveCert, err := SignerCert(newest.TRC, cppki.Sensitive)
	if err != nil {
		return cppki.SignedTRC{}, err
	}
	completed, err := CoSign(trc, c.Sensitive, sensitiveCert)
	if err != nil {
		return cppki.SignedTRC{}, serrors.Wrap("signing as the founder", err, "id", trc.TRC.ID)
	}
	if err := pinSuccessor(ctx, c.DB, newest, completed); err != nil {
		return cppki.SignedTRC{}, err
	}
	slog.Info("Pinned a core's TRC update with the founder's signature", "presenter", presenter,
		"type", update.Type, "trc", completed.TRC.ID, "predecessor", newest.TRC.ID)
	return completed, nil
}

// landed reports whether the newest TRC already carries the submission's
// landing: at or past its serial, holding every certificate the submission
// holds.
func landed(sub, newest cppki.TRC) bool {
	if sub.ID.ISD != newest.ID.ISD || sub.ID.Base != newest.ID.Base ||
		sub.ID.Serial > newest.ID.Serial {

		return false
	}
	for _, cert := range sub.Certificates {
		if !slices.ContainsFunc(newest.Certificates, cert.Equal) {
			return false
		}
	}
	return true
}

// presentersOwn checks that the submission changes nothing but its
// presenter's own material: its certificates and its AS entries. Every
// certificate of another holder stands as the predecessor carries it, so the
// founder's sensitive voting certificate stays the one, and the quorum cppki
// bounds by it stays. The presenter holds at most a regular voting and a root
// certificate — an onboarding adds them, a roll replaces them, and nothing
// drops one — and every root certificate it adds signed the submission, its
// proof of possession (PKI draft, Section 3.5.6), for cppki checks a new
// voter's alone. Each AS list stands, or appends the presenter's AS to a list
// that lacks it.
func presentersOwn(sub cppki.SignedTRC, pred cppki.TRC, presenter addr.IA) error {
	refuse := func(what string) error {
		return serrors.New("the submission "+what, "presenter", presenter, "submitted", sub.TRC.ID)
	}
	others := func(trc cppki.TRC) []*x509.Certificate {
		return slices.DeleteFunc(slices.Clone(trc.Certificates), func(cert *x509.Certificate) bool {
			certIA, err := cppki.ExtractIA(cert.Subject)
			return err == nil && certIA.Equal(presenter)
		})
	}
	if !slices.EqualFunc(others(sub.TRC), others(pred), (*x509.Certificate).Equal) {
		return refuse("changes a certificate of another ISD-AS")
	}
	held := map[cppki.CertType]int{}
	for _, cert := range CertsOf(sub.TRC, presenter) {
		ct, err := cppki.ValidateCert(cert)
		if err != nil || (ct != cppki.Regular && ct != cppki.Root) {
			return refuse("adds a certificate of a class a core does not hold")
		}
		if held[ct]++; held[ct] > 1 {
			return refuse("holds two certificates of one class for the presenter")
		}
		if ct == cppki.Root && !slices.ContainsFunc(pred.Certificates, cert.Equal) &&
			!signedBy(sub, cert) {

			return refuse("adds a root certificate that did not sign it")
		}
	}
	for _, cert := range CertsOf(pred, presenter) {
		if ct, err := cppki.ValidateCert(cert); err != nil || held[ct] == 0 {
			return refuse("drops a certificate of the presenter")
		}
	}
	if !ownEntries(pred.CoreASes, sub.TRC.CoreASes, presenter.AS()) ||
		!ownEntries(pred.AuthoritativeASes, sub.TRC.AuthoritativeASes, presenter.AS()) {

		return refuse("changes an AS list beyond the presenter's entry")
	}
	return nil
}

// ownEntries reports whether the submitted AS list stands as the
// predecessor's, or appends as to a predecessor's list that lacks it.
func ownEntries(pred, sub []addr.AS, as addr.AS) bool {
	return slices.Equal(pred, sub) ||
		!slices.Contains(pred, as) && slices.Equal(append(slices.Clone(pred), as), sub)
}

// signedBy reports whether a signature over the signed TRC verifies under
// the certificate.
func signedBy(signed cppki.SignedTRC, cert *x509.Certificate) bool {
	return slices.ContainsFunc(signed.SignerInfos, func(si protocol.SignerInfo) bool {
		if _, err := si.FindCertificate([]*x509.Certificate{cert}); err != nil {
			return false
		}
		return verifySignerInfo(si, cert, signed.TRC.Raw) == nil
	})
}

// novelCerts returns the certificates the successor holds that the
// predecessor does not, in the successor's order.
func novelCerts(sub, pred cppki.TRC) []*x509.Certificate {
	var novel []*x509.Certificate
	for _, cert := range sub.Certificates {
		if !slices.ContainsFunc(pred.Certificates, cert.Equal) {
			novel = append(novel, cert)
		}
	}
	return novel
}

// authorizeVoting asks the admission policy before the founder's sensitive
// vote, with the presenter, the fingerprints of the certificates the
// successor adds, and the channel's source. Allow returns nil; deny and
// pending refuse the submission, the verdict logged with the facts beside
// it, and the submitter's retry asks again — the operator's answer lands on
// the next submission. With no policy configured the vote is denied.
func (c *TRCDecider) authorizeVoting(
	ctx context.Context,
	presenter addr.IA,
	source netip.AddrPort,
	added []*x509.Certificate,
) error {

	if c.Authorizer == nil {
		slog.Warn("Denying voting submission: no admission policy is configured",
			"isd_as", presenter, "source", source)
		return serrors.New("voting submission denied: no admission policy is configured",
			"isd_as", presenter, "source", source)
	}
	keys := make([]string, 0, len(added))
	for _, cert := range added {
		skid, err := cppki.SubjectKeyID(cert.PublicKey)
		if err != nil {
			return serrors.Wrap("computing an added key's fingerprint", err,
				"subject", cert.Subject)
		}
		keys = append(keys, hex.EncodeToString(skid))
	}
	facts := enrollauth.AdmissionFacts{
		Boundary: enrollauth.BoundaryVoting,
		Keys:     keys,
		Source:   source,
		Claim:    presenter,
	}
	answer := c.Authorizer.Authorize(ctx, facts)
	logFacts := []any{"isd_as", presenter, "keys", keys, "source", source}
	switch answer.Admission {
	case enrollauth.AdmissionAllow:
		return nil
	case enrollauth.AdmissionPending:
		slog.Info("Voting submission pending a decision", logFacts...)
		return serrors.New("voting submission pending",
			"isd_as", presenter, "source", source)
	default:
		slog.Warn("Denying voting submission", logFacts...)
		return serrors.New("voting submission denied",
			"isd_as", presenter, "source", source)
	}
}

// newestTRC returns the newest pinned TRC of the founder's ISD.
func (c *TRCDecider) newestTRC(ctx context.Context) (cppki.SignedTRC, error) {
	trc, err := c.DB.SignedTRC(ctx, NewestTRCID(c.IA.ISD()))
	if err != nil {
		return cppki.SignedTRC{}, serrors.Wrap("reading the newest pinned TRC", err)
	}
	if trc.IsZero() {
		return cppki.SignedTRC{}, serrors.New("no TRC of the ISD is pinned", "isd", c.IA.ISD())
	}
	return trc, nil
}

// CastLocal runs the founder's own cast under the decision's mutex: the
// founder's roll reads the newest pinned TRC and completes its successor on
// the same lock the submissions decide under, so the serials stay monotone
// whichever path a successor takes — a submission the cast overlaps is
// refused on the older view and retried onto the new newest. The cast may
// reassign the decision's sensitive signer, the roll's pin landing on it;
// only the mutex's holders touch the field.
func (c *TRCDecider) CastLocal(
	ctx context.Context,
	cast func(newest cppki.SignedTRC) error,
) error {

	c.mtx.Lock()
	defer c.mtx.Unlock()
	newest, err := c.newestTRC(ctx)
	if err != nil {
		return err
	}
	return cast(newest)
}
