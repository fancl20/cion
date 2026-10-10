package controlplane

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/modules/enrollauth"
	"github.com/fancl20/cion/pkg/modules/trustdb"
	"github.com/fancl20/cion/pkg/trust"
)

// TRCDecider is the control plane's decision on a submitted TRC update, with
// no network of its own: the voting application hands each submission over,
// and the decision is made here. A submission that verifies against the
// newest pinned TRC as submitted pins as it is, and a sensitive update short
// of the founder's vote gets the vote only on the admission policy's allow,
// the completed artifact verified against the newest pinned TRC before it
// pins. The founder's own casts run through CastLocal instead.
type TRCDecider struct {
	// DB serves and pins the founder's TRCs and chains.
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
// the update must classify against the newest pinned TRC and the presenter
// must be the channel's verified peer holding an enrolled chain. Past those
// gates a submission that verifies as submitted pins as it is, the founder
// signing nothing; a sensitive update that does not verify yet gets the
// founder's vote on the admission policy's allow; anything else is refused.
// What refuses pins nothing.
func (c *TRCDecider) DecideTRC(
	ctx context.Context,
	presenter addr.IA,
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
	// The enrolled core's gate: the submission is an enrolled core's, never
	// the enrollment's shortcut.
	chains, err := c.DB.Chains(ctx, trustdb.ChainQuery{
		IA:       presenter,
		Validity: cppki.Validity{NotBefore: time.Now(), NotAfter: time.Now()},
	})
	if err != nil {
		return cppki.SignedTRC{}, serrors.Wrap("querying the presenter's chains", err)
	}
	if len(chains) == 0 {
		return cppki.SignedTRC{}, serrors.New("the submitting core holds no chain yet; "+
			"enroll before submitting", "presenter", presenter)
	}
	// A submission carrying every signature its update requires — a regular
	// update its voters signed — pins as submitted.
	verifyErr := trc.Verify(&newest.TRC)
	if verifyErr == nil {
		if _, err := c.DB.InsertTRC(ctx, trc); err != nil {
			return cppki.SignedTRC{}, serrors.Wrap("pinning the submitted update", err,
				"id", trc.TRC.ID)
		}
		slog.Info("Pinned a core's TRC update", "presenter", presenter,
			"type", update.Type, "trc", trc.TRC.ID, "predecessor", newest.TRC.ID)
		return trc, nil
	}
	if update.Type != cppki.SensitiveUpdate {
		return cppki.SignedTRC{}, serrors.Wrap("the submitted update does not verify "+
			"against the newest pinned TRC", verifyErr, "id", trc.TRC.ID)
	}
	// A sensitive update short of a vote asks for the founder's: the
	// policy's allow is its only gate.
	if err := c.authorizeVoting(ctx, presenter, novelCerts(trc.TRC, newest.TRC)); err != nil {
		return cppki.SignedTRC{}, err
	}
	sensitiveCert, err := trust.SignerCert(newest.TRC, cppki.Sensitive)
	if err != nil {
		return cppki.SignedTRC{}, err
	}
	completed, err := trust.CoSign(trc, c.Sensitive, sensitiveCert)
	if err != nil {
		return cppki.SignedTRC{}, serrors.Wrap("casting the founder's vote", err, "id", trc.TRC.ID)
	}
	if err := completed.Verify(&newest.TRC); err != nil {
		return cppki.SignedTRC{}, serrors.Wrap("the completed update does not verify "+
			"against the newest pinned TRC", err, "id", completed.TRC.ID)
	}
	if _, err := c.DB.InsertTRC(ctx, completed); err != nil {
		return cppki.SignedTRC{}, serrors.Wrap("pinning the completed update", err,
			"id", completed.TRC.ID)
	}
	slog.Info("Cast the founder's vote on a core's sensitive update", "presenter", presenter,
		"trc", completed.TRC.ID, "predecessor", newest.TRC.ID)
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
	added []*x509.Certificate,
) error {

	source := remoteUnderlay(ctx)
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
	trc, err := c.DB.SignedTRC(ctx, cppki.TRCID{
		ISD:    c.IA.ISD(),
		Base:   scrypto.LatestVer,
		Serial: scrypto.LatestVer,
	})
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
