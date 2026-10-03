package controlplane

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"errors"
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

// TRCDecider is the control plane's decision on a submitted TRC update: the
// founder's own step of the sensitive update's casting, with no network of
// its own — the voting application hands each submission over, and the
// decision is made here. It validates the partially signed successor a
// joining core presented — the proof of possession over its new voting
// certificate among the checks, and the presenter bound to the new voter by
// the application's verified channel — asks the admission policy the
// voting question, casts the founder's sensitive vote beside the submitted
// signature, verifies the completed artifact against the newest pinned
// TRC, and pins it.
type TRCDecider struct {
	// DB serves and pins the founder's TRCs and chains.
	DB trustdb.DB
	// IA is the founding core's ISD-AS, the ISD the updates belong to.
	IA addr.IA
	// Sensitive casts the founder's vote with the sensitive voting key of
	// the newest pinned TRC's certificate set. Nil where this node decides
	// nothing — every node but the founding core.
	Sensitive crypto.Signer
	// Authorizer is the policy asked the voting question — whether the
	// submitter gains voting power — once the mechanical gates pass. Nil is
	// open admission, the gate the run arguments leave unset.
	Authorizer enrollauth.AdmissionAuthorizer

	// mtx serializes the decision: each one reads the newest pinned TRC
	// under it, so serials stay monotone under concurrent submissions and
	// only a completed update ever advances the pin.
	mtx sync.Mutex
}

// DecideTRC casts the founder's vote on the successor a core submitted. A
// submission whose landing the newest pinned TRC already carries is answered
// with that TRC — the idempotent re-presentation of a cast that completed,
// read from what the submission changes, never from the presenter's name
// alone, for a rolling presenter is already named. Everything else is
// refused unless it holds: the update classifies against the newest pinned
// TRC, the presenter is the channel's verified peer holding an enrolled
// chain, and what the submission changes is one of the two shapes the
// channel serves — an onboarding of the presenter alone, asked the
// admission policy's voting question, or a roll of the presenter's own
// certificate, which grants no power the presenter lacked and asks nothing.
// What refuses pins nothing.
func (c *TRCDecider) DecideTRC(
	ctx context.Context,
	presenter addr.IA,
	trc cppki.SignedTRC,
) (cppki.SignedTRC, error) {

	if c.Sensitive == nil {
		return cppki.SignedTRC{}, errors.New("this control plane casts no TRC updates: " +
			"the founding core alone holds the sensitive key")
	}
	if presenter.IsZero() {
		return cppki.SignedTRC{}, serrors.New("the submission carries no verified presenter")
	}

	c.mtx.Lock()
	defer c.mtx.Unlock()
	newest, err := c.newestTRC(ctx)
	if err != nil {
		return cppki.SignedTRC{}, err
	}
	if landed(trc.TRC, newest.TRC) {
		// The cast already completed, whether here or before a restart: the
		// newest carries its landing, and nothing is cast again.
		return newest, nil
	}
	// The submitted successor must classify against the newest pinned TRC:
	// the serial increments it, the quorum and noTrustReset stand, and the
	// votes name sensitive voters. A submission built on an older view is
	// refused — the submitter resolves the newest TRC and submits again.
	if _, err := trc.TRC.ValidateUpdate(&newest.TRC); err != nil {
		return cppki.SignedTRC{}, serrors.Wrap("the submitted update does not classify "+
			"against the newest pinned TRC", err, "submitted", trc.TRC.ID,
			"predecessor", newest.TRC.ID)
	}
	// What the submission changes tells the roll from the onboarding: one
	// certificate the predecessor's certificates' ISD-ASes do not cover is a
	// fresh voter onboarding; one they cover is a changed certificate
	// rolling.
	novel := novelCerts(trc.TRC, newest.TRC)
	if len(novel) != 1 {
		if len(novel) == 0 {
			return cppki.SignedTRC{}, serrors.New("the submission changes nothing")
		}
		return cppki.SignedTRC{}, serrors.New("the submission changes more than one certificate",
			"changed", len(novel))
	}
	novelIA, err := cppki.ExtractIA(novel[0].Subject)
	if err != nil {
		return cppki.SignedTRC{}, serrors.Wrap("reading the changed certificate's ISD-AS", err)
	}
	roll := iaCovered(newest.TRC, novelIA)
	// The enrolled core's gate: the cast is the enrolled core's, never the
	// enrollment's shortcut.
	chains, err := c.DB.Chains(ctx, trustdb.ChainQuery{
		IA:       presenter,
		Validity: cppki.Validity{NotBefore: time.Now(), NotAfter: time.Now()},
	})
	if err != nil {
		return cppki.SignedTRC{}, serrors.Wrap("querying the presenter's chains", err)
	}
	if len(chains) == 0 {
		return cppki.SignedTRC{}, serrors.New("the submitting core holds no chain yet; "+
			"enroll before seeking voting power", "presenter", presenter)
	}
	if !novelIA.Equal(presenter) {
		if roll {
			return cppki.SignedTRC{}, serrors.New("the roll replaces another core's certificate",
				"presenter", presenter, "certificate", novel[0].Subject)
		}
		return cppki.SignedTRC{}, serrors.New("the update onboards another ISD-AS than its presenter",
			"presenter", presenter, "voter", novel[0].Subject)
	}
	if roll {
		// The roll's narrower shape: exactly one certificate changed, naming
		// the presenter's own ISD-AS, with the quorum and both AS lists as
		// they were — a roll changes keys, never membership — and it asks no
		// authorizer question, for it grants no power the presenter lacked.
		if trc.TRC.Quorum != newest.TRC.Quorum {
			return cppki.SignedTRC{}, serrors.New("a roll leaves the quorum as it was",
				"submitted", trc.TRC.Quorum, "predecessor", newest.TRC.Quorum)
		}
		if err := equalASes(trc.TRC.CoreASes, newest.TRC.CoreASes); err != nil {
			return cppki.SignedTRC{}, serrors.Wrap("a roll leaves the core ASes as they were", err)
		}
		if err := equalASes(trc.TRC.AuthoritativeASes, newest.TRC.AuthoritativeASes); err != nil {
			return cppki.SignedTRC{}, serrors.Wrap(
				"a roll leaves the authoritative ASes as they were", err)
		}
	} else if err := c.authorizeVoting(ctx, presenter, novel[0]); err != nil {
		// The update onboards exactly its presenter: the one new voter is
		// the peer the application's channel verified, asked the voting
		// question.
		return cppki.SignedTRC{}, err
	}
	// The vote: the founder's sensitive voting certificate signing beside
	// the submitted proof of possession, the completed artifact verified
	// against the newest pinned TRC before anything pins.
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
	if roll {
		slog.Info("Cast the sensitive update rolling a core's certificate",
			"core", presenter, "trc", completed.TRC.ID, "predecessor", newest.TRC.ID)
	} else {
		slog.Info("Cast the sensitive update onboarding a core",
			"joiner", presenter, "trc", completed.TRC.ID, "predecessor", newest.TRC.ID)
	}
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
// predecessor does not — the changes the submission carries.
func novelCerts(sub, pred cppki.TRC) []*x509.Certificate {
	var novel []*x509.Certificate
	for _, cert := range sub.Certificates {
		if !slices.ContainsFunc(pred.Certificates, cert.Equal) {
			novel = append(novel, cert)
		}
	}
	return novel
}

// iaCovered reports whether one of the TRC's certificates names the ISD-AS.
func iaCovered(trc cppki.TRC, ia addr.IA) bool {
	for _, cert := range trc.Certificates {
		if certIA, err := cppki.ExtractIA(cert.Subject); err == nil && certIA.Equal(ia) {
			return true
		}
	}
	return false
}

// equalASes reports whether the AS sequences are equal.
func equalASes(a, b []addr.AS) error {
	if slices.Equal(a, b) {
		return nil
	}
	return serrors.New("the sequences differ", "submitted", a, "predecessor", b)
}

// authorizeVoting asks the policy the voting question — whether the
// presenter gains the power the successor would grant it. Allow returns
// nil; deny and pending refuse the submission, the verdict logged with the
// facts beside it, and the joiner's retry asks again — the operator's
// answer lands on the next submission.
func (c *TRCDecider) authorizeVoting(
	ctx context.Context,
	presenter addr.IA,
	votingCert *x509.Certificate,
) error {

	if c.Authorizer == nil {
		return nil
	}
	skid, err := cppki.SubjectKeyID(votingCert.PublicKey)
	if err != nil {
		return serrors.Wrap("computing the voting key's fingerprint", err)
	}
	facts := enrollauth.AdmissionFacts{
		Boundary:   enrollauth.BoundaryVoting,
		Keys:       []string{hex.EncodeToString(skid)},
		Source:     remoteUnderlay(ctx),
		Claim:      presenter,
		VotingCert: votingCert,
	}
	answer := c.Authorizer.Authorize(ctx, facts)
	logFacts := []any{
		"isd_as", presenter, "key", facts.Keys[0], "source", facts.Source}
	switch answer.Admission {
	case enrollauth.AdmissionAllow:
		return nil
	case enrollauth.AdmissionPending:
		slog.Info("Voting submission pending a decision", logFacts...)
		return serrors.New("voting submission pending",
			"isd_as", presenter, "source", facts.Source)
	default:
		slog.Warn("Denying voting submission", logFacts...)
		return serrors.New("voting submission denied",
			"isd_as", presenter, "source", facts.Source)
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

	if c.Sensitive == nil {
		return errors.New("this control plane casts no TRC updates: " +
			"the founding core alone holds the sensitive key")
	}
	c.mtx.Lock()
	defer c.mtx.Unlock()
	newest, err := c.newestTRC(ctx)
	if err != nil {
		return err
	}
	return cast(newest)
}
