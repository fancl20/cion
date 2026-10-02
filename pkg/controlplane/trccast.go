package controlplane

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"log/slog"
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
// submitter the newest TRC already names is answered with that TRC as
// pinned — the idempotent re-presentation of a join that landed — and
// everything else is refused unless it holds: the update classifies against
// the newest pinned TRC as an onboarding of the presenter alone, the
// presenter is the channel's verified peer and holds an enrolled chain, and
// the admission policy allows the voting question. What refuses pins
// nothing.
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
	if trust.CoreNamed(newest.TRC, presenter) {
		// The join already landed; hand back what is pinned so a retry pins
		// it too, and cast nothing.
		return newest, nil
	}
	// The submitted successor must classify against the newest pinned TRC:
	// the serial increments it, the quorum and noTrustReset stand, and the
	// votes name sensitive voters. A submission built on an older view is
	// refused — the submitter resolves the newest TRC and submits again.
	update, err := trc.TRC.ValidateUpdate(&newest.TRC)
	if err != nil {
		return cppki.SignedTRC{}, serrors.Wrap("the submitted update does not classify "+
			"against the newest pinned TRC", err, "submitted", trc.TRC.ID,
			"predecessor", newest.TRC.ID)
	}
	// The update onboards exactly its presenter: the one new voter is the
	// peer the application's channel verified, and the proof of possession
	// over that voter's certificate is the submitter's own signature.
	if len(update.NewVoters) != 1 {
		return cppki.SignedTRC{}, serrors.New("an onboarding update carries exactly one new voter",
			"new_voters", len(update.NewVoters))
	}
	voter, err := cppki.ExtractIA(update.NewVoters[0].Subject)
	if err != nil || !voter.Equal(presenter) {
		return cppki.SignedTRC{}, serrors.New("the update onboards another ISD-AS than its presenter",
			"presenter", presenter, "voter", update.NewVoters[0].Subject)
	}
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
	if err := c.authorizeVoting(ctx, presenter, update.NewVoters[0]); err != nil {
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
	slog.Info("Cast the sensitive update onboarding a core",
		"joiner", presenter, "trc", completed.TRC.ID, "predecessor", newest.TRC.ID)
	return completed, nil
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
