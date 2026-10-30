package trust_test

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"net/netip"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/core/trust"
	"github.com/fancl20/cion/pkg/core/trust/trusttest"
	"github.com/fancl20/cion/pkg/modules/enrollauth"
	"github.com/fancl20/cion/pkg/modules/enrollauth/impl/authtest"
	"github.com/fancl20/cion/pkg/modules/trustdb"
)

// joinerIATest is the joining core the decision tests onboard.
var joinerIATest = addr.MustIAFrom(20, 0xff0000000f01)

// deciderFixture is a founder holding the decision — its trust fixture, the
// sensitive key beside the decider, and an admission policy that allows
// unless the test says otherwise — and the joiner's voting and root
// material. The founder's database holds no chain of the joiner: the
// channel's verification is the presenter's one gate.
type deciderFixture struct {
	tf      *trusttest.Founder
	decider *trust.TRCDecider
	auth    *authtest.Recorder
	db      trustdb.DB
	pred    cppki.SignedTRC

	joiner struct {
		ia           addr.IA
		voting, root trust.KeyCert
	}
}

// newDeciderFixture brings up the founder's decision and the joiner's
// material.
func newDeciderFixture(t *testing.T) *deciderFixture {
	t.Helper()
	f := newFounder(t)
	c := &deciderFixture{tf: f, db: f.DB, pred: f.TRC}
	c.auth = &authtest.Recorder{Verdict: enrollauth.AdmissionAllow}
	c.decider = &trust.TRCDecider{
		DB:         f.DB,
		IA:         coreIATest,
		Sensitive:  f.Keys.Sensitive,
		Authorizer: c.auth,
	}
	c.joiner.ia = joinerIATest
	c.joiner.voting, c.joiner.root = coreMaterial(t, c.joiner.ia)
	return c
}

// coreMaterial returns a core's fresh voting and root material naming the
// IA, the shapes the loaders persist.
func coreMaterial(t *testing.T, ia addr.IA) (voting, root trust.KeyCert) {
	t.Helper()
	state := t.TempDir()
	votingKey, err := trust.LoadOrCreateVotingKey(state)
	if err != nil {
		t.Fatal(err)
	}
	votingCert, err := trust.LoadOrCreateVotingCert(state, ia, votingKey)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := trust.LoadOrCreateIssuerKeys(state)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := trust.LoadOrCreateRootCert(state, ia, keys.Root)
	if err != nil {
		t.Fatal(err)
	}
	return trust.KeyCert{Key: votingKey, Cert: votingCert},
		trust.KeyCert{Key: keys.Root, Cert: rootCert}
}

// fingerprint is the hex subject key ID the decision names a key by.
func fingerprint(kc trust.KeyCert) string {
	return hex.EncodeToString(kc.Cert.SubjectKeyId)
}

// submission returns the joiner's successor over the given predecessor,
// onboarding it with its voting and root certificates, signed by the
// signers.
func (c *deciderFixture) submission(
	t *testing.T,
	pred cppki.SignedTRC,
	signers ...trust.KeyCert,
) cppki.SignedTRC {

	t.Helper()
	trc, err := trust.AssembleOnboarding(pred, c.joiner.ia, c.joiner.voting.Cert,
		c.joiner.root.Cert)
	if err != nil {
		t.Fatal(err)
	}
	partial, err := trust.SignUpdate(trc, signers...)
	if err != nil {
		t.Fatal(err)
	}
	return partial
}

// onboarding returns the joiner's onboarding over the fixture's
// predecessor, signed with both of its keys.
func (c *deciderFixture) onboarding(t *testing.T) cppki.SignedTRC {
	t.Helper()
	return c.submission(t, c.pred, c.joiner.voting, c.joiner.root)
}

// TestTRCDeciderOnboards checks the founder's decision on a joiner's
// submission: the founder's vote lands beside the proofs of possession, the
// completed TRC verifies against the newest pin and pins, and a joiner
// re-presenting itself is answered with that pin unchanged — it casts
// nothing. The founder's database holds no chain of the joiner: the channel
// verified it, whichever core issued its chain.
func TestTRCDeciderOnboards(t *testing.T) {
	c := newDeciderFixture(t)
	ctx := context.Background()

	partial := c.onboarding(t)
	completed, err := c.decider.DecideTRC(ctx, c.joiner.ia, netip.AddrPort{}, partial)
	if err != nil {
		t.Fatal(err)
	}
	if want := (cppki.TRCID{ISD: coreIATest.ISD(), Base: 1, Serial: 2}); completed.TRC.ID != want {
		t.Fatalf("the decided TRC = %v, want the successor %v", completed.TRC.ID, want)
	}
	if len(completed.SignerInfos) != 3 {
		t.Errorf("the decided TRC carries %d signer infos, want the vote and the two "+
			"possession proofs", len(completed.SignerInfos))
	}
	if err := completed.Verify(&c.pred.TRC); err != nil {
		t.Errorf("the decided TRC does not verify against the predecessor: %v", err)
	}
	if !trust.Onboarded(completed.TRC, c.joiner.ia) {
		t.Error("the decided TRC does not carry the joiner with its root")
	}
	pinned, err := c.db.SignedTRC(ctx, completed.TRC.ID)
	if err != nil {
		t.Fatal(err)
	}
	if pinned.IsZero() || string(pinned.Raw) != string(completed.Raw) {
		t.Error("the decided TRC did not pin as completed")
	}
	if chains, err := c.db.Chains(ctx, trustdb.ChainQuery{IA: c.joiner.ia}); err != nil ||
		len(chains) != 0 {

		t.Errorf("the founder's database holds %d chains of the joiner (%v), want none",
			len(chains), err)
	}

	// The re-presentation decides nothing: the same TRC comes back.
	again, err := c.decider.DecideTRC(ctx, c.joiner.ia, netip.AddrPort{}, partial)
	if err != nil {
		t.Fatal(err)
	}
	if again.TRC.ID != pinned.TRC.ID || string(again.Raw) != string(pinned.Raw) {
		t.Errorf("the re-presented decision returned %v, want the pinned TRC unchanged",
			again.TRC.ID)
	}
}

// TestTRCDeciderAsksAdmission checks the question before the founder's vote:
// once the mechanical gates pass, the decision asks the admission policy
// with the voting boundary, the presenter as the claim, the fingerprints of
// the keys the successor adds in its order — the voting key's and the root
// key's — and the channel's source, and an allowance is what the vote lands
// on. A join already landed asks nothing: the re-presentation is answered
// with the pin whatever the policy would say.
func TestTRCDeciderAsksAdmission(t *testing.T) {
	c := newDeciderFixture(t)

	partial := c.onboarding(t)
	completed, err := c.decider.DecideTRC(context.Background(), c.joiner.ia, askSource, partial)
	if err != nil {
		t.Fatal(err)
	}
	if want := (cppki.TRCID{ISD: coreIATest.ISD(), Base: 1, Serial: 2}); completed.TRC.ID != want {
		t.Fatalf("the decided TRC = %v, want the successor %v", completed.TRC.ID, want)
	}
	if len(c.auth.Asked) != 1 {
		t.Fatalf("the authorizer was asked %d times, want 1", len(c.auth.Asked))
	}
	got := c.auth.Asked[0]
	if got.Boundary != enrollauth.BoundaryVoting {
		t.Errorf("asked boundary = %v, want the voting one", got.Boundary)
	}
	if got.Claim != c.joiner.ia {
		t.Errorf("asked claim = %v, want the presenter %v", got.Claim, c.joiner.ia)
	}
	want := []string{fingerprint(c.joiner.voting), fingerprint(c.joiner.root)}
	if diff := cmp.Diff(want, got.Keys); diff != "" {
		t.Errorf("asked keys (-want +got):\n%s", diff)
	}
	if want := netip.MustParseAddrPort("198.51.100.7:41234"); got.Source != want {
		t.Errorf("asked source = %v, want the context's %v", got.Source, want)
	}

	c.auth.Verdict = enrollauth.AdmissionDeny
	if _, err := c.decider.DecideTRC(context.Background(), c.joiner.ia, askSource, partial); err != nil {
		t.Fatalf("the re-presentation was refused: %v", err)
	}
	if len(c.auth.Asked) != 1 {
		t.Errorf("the authorizer was asked %d times after the re-presentation, want still 1",
			len(c.auth.Asked))
	}
}

// TestTRCDeciderRefusesWhatIsNotThePresenters checks the gates on what a
// submission adds: a certificate naming another ISD-AS than the presenter,
// and a root certificate that did not sign the submission, refuse it before
// any question, and nothing pins.
func TestTRCDeciderRefusesWhatIsNotThePresenters(t *testing.T) {
	c := newDeciderFixture(t)
	other := addr.MustIAFrom(coreIATest.ISD(), joinerIATest.AS()+1)
	otherVoting, otherRoot := coreMaterial(t, other)
	otherTRC, err := trust.AssembleOnboarding(c.pred, other, otherVoting.Cert, otherRoot.Cert)
	if err != nil {
		t.Fatal(err)
	}
	otherSubmission, err := trust.SignUpdate(otherTRC, otherVoting, otherRoot)
	if err != nil {
		t.Fatal(err)
	}
	for name, submission := range map[string]cppki.SignedTRC{
		"another ISD-AS's certificates": otherSubmission,
		"a root that did not sign":      c.submission(t, c.pred, c.joiner.voting),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := c.decider.DecideTRC(context.Background(), c.joiner.ia, askSource,
				submission); err == nil {

				t.Fatal("the submission was decided")
			}
			if len(c.auth.Asked) != 0 {
				t.Errorf("the authorizer was asked %d times, want none behind a refused gate",
					len(c.auth.Asked))
			}
			if stored := pinnedAt(t, c.db, 2); !stored.IsZero() {
				t.Error("the refused submission pinned something")
			}
		})
	}
}

// TestTRCDeciderRefusesDenied checks the policy's refusals: a deny and a
// pending alike answer the submission with the refusal and pin nothing —
// the joiner's retry asks again.
func TestTRCDeciderRefusesDenied(t *testing.T) {
	for _, tc := range []struct {
		name    string
		verdict enrollauth.AdmissionVerdict
	}{
		{"a denied submission", enrollauth.AdmissionDeny},
		{"a pending submission", enrollauth.AdmissionPending},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newDeciderFixture(t)
			c.auth.Verdict = tc.verdict

			if _, err := c.decider.DecideTRC(context.Background(), c.joiner.ia, askSource,
				c.onboarding(t)); err == nil {

				t.Fatal("the submission was decided against the policy's answer")
			}
			if stored := pinnedAt(t, c.db, 2); !stored.IsZero() {
				t.Error("the refused submission pinned something")
			}
		})
	}
}

// TestTRCDeciderDeniesWithoutAuthorizer checks the unset policy: with no
// authorizer the founder casts no vote, so an onboarding is refused and
// nothing pins.
func TestTRCDeciderDeniesWithoutAuthorizer(t *testing.T) {
	c := newDeciderFixture(t)
	c.decider.Authorizer = nil

	if _, err := c.decider.DecideTRC(context.Background(), c.joiner.ia, askSource,
		c.onboarding(t)); err == nil {

		t.Fatal("the founder voted with no admission policy configured")
	}
	if stored := pinnedAt(t, c.db, 2); !stored.IsZero() {
		t.Error("the refused submission pinned something")
	}
}

// TestTRCDeciderRefusesStalePredecessor checks the submission built on an
// older view: the founder has onboarded another core since, and the decision
// refuses what does not increment its newest pin — the submitter resolves
// the newest TRC and submits again.
func TestTRCDeciderRefusesStalePredecessor(t *testing.T) {
	c := newDeciderFixture(t)
	ctx := context.Background()

	// Another core joins first: the founder's newest advances.
	other := addr.MustIAFrom(coreIATest.ISD(), joinerIATest.AS()+1)
	otherVoting, otherRoot := coreMaterial(t, other)
	otherTRC, err := trust.AssembleOnboarding(c.pred, other, otherVoting.Cert, otherRoot.Cert)
	if err != nil {
		t.Fatal(err)
	}
	otherPartial, err := trust.SignUpdate(otherTRC, otherVoting, otherRoot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.decider.DecideTRC(ctx, other, netip.AddrPort{}, otherPartial); err != nil {
		t.Fatalf("the first join was refused: %v", err)
	}

	// The joiner's submission still builds on the base and is refused.
	if _, err := c.decider.DecideTRC(ctx, c.joiner.ia, netip.AddrPort{},
		c.onboarding(t)); err == nil {

		t.Fatal("a submission over a stale predecessor was decided")
	}
	if stored := pinnedAt(t, c.db, 3); !stored.IsZero() {
		t.Error("the stale submission pinned a second successor")
	}
}

// TestTRCDeciderRefusesUnsigned checks the voting key's possession proof's
// absence: a successor the joiner's voting key did not sign is completed by
// the vote and then fails the verification, pinning nothing.
func TestTRCDeciderRefusesUnsigned(t *testing.T) {
	c := newDeciderFixture(t)

	// Signed by a voting key the update does not carry: the new voter's
	// proof of possession never rides it.
	stranger, _ := coreMaterial(t, c.joiner.ia)
	unsigned := c.submission(t, c.pred, stranger, c.joiner.root)
	if _, err := c.decider.DecideTRC(context.Background(), c.joiner.ia, netip.AddrPort{},
		unsigned); err == nil {

		t.Fatal("an update without the presenter's signature was decided")
	}
	if stored := pinnedAt(t, c.db, 2); !stored.IsZero() {
		t.Error("the unsigned submission pinned something")
	}
}

// TestTRCDeciderRefusesUnverifiedPresenter checks the submission no channel
// verified: a zero presenter is refused, pinning nothing.
func TestTRCDeciderRefusesUnverifiedPresenter(t *testing.T) {
	c := newDeciderFixture(t)

	if _, err := c.decider.DecideTRC(context.Background(), addr.IA(0), netip.AddrPort{},
		c.onboarding(t)); err == nil {

		t.Error("a submission without a verified presenter was decided")
	}
	if stored := pinnedAt(t, c.db, 2); !stored.IsZero() {
		t.Error("the unverified submission pinned something")
	}
}

// TestTRCDeciderSignerSwapUnderCast checks a decision arriving while the
// founder's cast holds the mutex and reassigns the sensitive signer: the
// decision waits for the cast and decides with the signer it left. The
// decision's one ordering with the cast's write is the mutex, so the race
// detector reports a read of the signer outside it however the goroutines
// are scheduled.
func TestTRCDeciderSignerSwapUnderCast(t *testing.T) {
	c := newDeciderFixture(t)
	ctx := context.Background()
	partial := c.onboarding(t)

	held, release := make(chan struct{}), make(chan struct{})
	cast := make(chan error, 1)
	go func() {
		cast <- c.decider.CastLocal(ctx, func(cppki.SignedTRC) error {
			close(held)
			<-release
			c.decider.Sensitive = c.tf.Keys.Sensitive
			return nil
		})
	}()
	select {
	case <-held:
	case err := <-cast:
		t.Fatalf("the cast returned before it ran: %v", err)
	}
	decided := make(chan error, 1)
	go func() {
		_, err := c.decider.DecideTRC(ctx, c.joiner.ia, netip.AddrPort{}, partial)
		decided <- err
	}()
	close(release)
	if err := <-cast; err != nil {
		t.Fatal(err)
	}
	if err := <-decided; err != nil {
		t.Fatalf("the decision overlapping the cast was refused: %v", err)
	}
}

// rollFixture is a founder whose decision has onboarded the joiner — the
// pinned successor the joiner's roll replaces its own certificates on — with
// the onboarding's question cleared from the policy's record.
type rollFixture struct {
	deciderFixture
	// rolled is the pinned successor naming the joiner a core.
	rolled cppki.SignedTRC
}

func newRollFixture(t *testing.T) *rollFixture {
	t.Helper()
	c := newDeciderFixture(t)
	completed, err := c.decider.DecideTRC(context.Background(), c.joiner.ia, netip.AddrPort{},
		c.onboarding(t))
	if err != nil {
		t.Fatal(err)
	}
	c.auth.Asked = nil
	return &rollFixture{deciderFixture: *c, rolled: completed}
}

// roll returns the joiner's roll over the fixture's pinned successor: fresh
// voting and root material replacing the certificates the successor names
// for it, the voter given, signed by the signers the fresh material chooses.
func (c *rollFixture) roll(
	t *testing.T,
	voter *x509.Certificate,
	signers func(freshVoting, freshRoot trust.KeyCert) []trust.KeyCert,
) (submitted cppki.SignedTRC, freshVoting, freshRoot trust.KeyCert) {

	t.Helper()
	freshVoting, freshRoot = coreMaterial(t, c.joiner.ia)
	trc, err := trust.AssembleRotation(c.rolled, voter,
		[]*x509.Certificate{freshVoting.Cert, freshRoot.Cert})
	if err != nil {
		t.Fatal(err)
	}
	submitted, err = trust.SignUpdate(trc, signers(freshVoting, freshRoot)...)
	if err != nil {
		t.Fatal(err)
	}
	return submitted, freshVoting, freshRoot
}

// TestTRCDeciderRolls checks the decision on a routine roll: the regular
// update the presenter's live voting key voted on, its live root key
// acknowledging the root it replaces and both fresh keys proving possession,
// verifies as submitted and pins exactly as submitted — the founder signing
// nothing and asking no policy, not even one that would deny — and its
// re-presentation is answered with the pin, casting nothing.
func TestTRCDeciderRolls(t *testing.T) {
	c := newRollFixture(t)
	c.auth.Verdict = enrollauth.AdmissionDeny

	submitted, freshVoting, freshRoot := c.roll(t, c.joiner.voting.Cert,
		func(freshVoting, freshRoot trust.KeyCert) []trust.KeyCert {
			return []trust.KeyCert{freshVoting, c.joiner.voting, freshRoot, c.joiner.root}
		})
	pinned, err := c.decider.DecideTRC(context.Background(), c.joiner.ia, askSource, submitted)
	if err != nil {
		t.Fatal(err)
	}
	if string(pinned.Raw) != string(submitted.Raw) {
		t.Error("the decided roll is not the submission as submitted")
	}
	update, err := pinned.TRC.ValidateUpdate(&c.rolled.TRC)
	if err != nil {
		t.Fatal(err)
	}
	if update.Type != cppki.RegularUpdate {
		t.Errorf("the decided roll's update type = %v, want a regular update", update.Type)
	}
	if diff := cmp.Diff([]*x509.Certificate{freshVoting.Cert, freshRoot.Cert},
		trust.CertsOf(pinned.TRC, c.joiner.ia)); diff != "" {

		t.Errorf("the decided roll's certificates of the presenter (-want +got):\n%s", diff)
	}
	if len(c.auth.Asked) != 0 {
		t.Errorf("the authorizer was asked %d times, want none behind a routine roll",
			len(c.auth.Asked))
	}
	if stored := pinnedAt(t, c.db, 3); string(stored.Raw) != string(submitted.Raw) {
		t.Error("the decided roll did not pin as submitted")
	}

	// The re-presentation of the landed roll is answered with the pin.
	again, err := c.decider.DecideTRC(context.Background(), c.joiner.ia, askSource, submitted)
	if err != nil {
		t.Fatalf("the re-presented roll was refused: %v", err)
	}
	if string(again.Raw) != string(submitted.Raw) {
		t.Errorf("the re-presented roll returned %v, want the pinned TRC unchanged",
			again.TRC.ID)
	}
	if stored := pinnedAt(t, c.db, 4); !stored.IsZero() {
		t.Error("the re-presented roll cast a second successor")
	}
}

// TestTRCDeciderLostKeyRoll checks the roll whose live keys cannot sign: the
// sensitive update the founder's sensitive certificate is the voter of,
// signed by the fresh keys alone, asks the policy with the fresh keys'
// fingerprints — refused and pinning nothing on deny, pinned with the
// founder's vote beside the possession proofs on allow.
func TestTRCDeciderLostKeyRoll(t *testing.T) {
	c := newRollFixture(t)
	sensitive, err := trust.SignerCert(c.rolled.TRC, cppki.Sensitive)
	if err != nil {
		t.Fatal(err)
	}
	submitted, freshVoting, freshRoot := c.roll(t, sensitive,
		func(freshVoting, freshRoot trust.KeyCert) []trust.KeyCert {
			return []trust.KeyCert{freshVoting, freshRoot}
		})

	c.auth.Verdict = enrollauth.AdmissionDeny
	if _, err := c.decider.DecideTRC(context.Background(), c.joiner.ia, askSource, submitted); err == nil {
		t.Fatal("a denied lost-key roll was decided")
	}
	if stored := pinnedAt(t, c.db, 3); !stored.IsZero() {
		t.Error("the denied lost-key roll pinned something")
	}
	if len(c.auth.Asked) != 1 {
		t.Fatalf("the authorizer was asked %d times, want 1", len(c.auth.Asked))
	}
	want := []string{fingerprint(freshVoting), fingerprint(freshRoot)}
	if diff := cmp.Diff(want, c.auth.Asked[0].Keys); diff != "" {
		t.Errorf("asked keys (-want +got):\n%s", diff)
	}

	c.auth.Verdict = enrollauth.AdmissionAllow
	completed, err := c.decider.DecideTRC(context.Background(), c.joiner.ia, askSource, submitted)
	if err != nil {
		t.Fatalf("the allowed lost-key roll was refused: %v", err)
	}
	if len(completed.SignerInfos) != 3 {
		t.Errorf("the decided roll carries %d signer infos, want the vote and the two "+
			"possession proofs", len(completed.SignerInfos))
	}
	if err := completed.Verify(&c.rolled.TRC); err != nil {
		t.Errorf("the decided roll does not verify against the predecessor: %v", err)
	}
	if stored := pinnedAt(t, c.db, 3); string(stored.Raw) != string(completed.Raw) {
		t.Error("the decided roll did not pin as completed")
	}
}

// TestTRCDeciderRefusesIncompleteRolls checks the regular updates short of a
// signature: a roll the replaced voting certificate's key did not vote on,
// and a roll whose fresh root did not sign, are refused without a question —
// the founder's vote completes no regular update — and pin nothing.
func TestTRCDeciderRefusesIncompleteRolls(t *testing.T) {
	for _, tc := range []struct {
		name    string
		signers func(c *rollFixture, freshVoting, freshRoot trust.KeyCert) []trust.KeyCert
	}{
		{"unvoted", func(c *rollFixture, freshVoting, freshRoot trust.KeyCert) []trust.KeyCert {
			return []trust.KeyCert{freshVoting, freshRoot, c.joiner.root}
		}},
		{"no root proof", func(c *rollFixture, freshVoting, _ trust.KeyCert) []trust.KeyCert {
			return []trust.KeyCert{freshVoting, c.joiner.voting, c.joiner.root}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newRollFixture(t)
			submitted, _, _ := c.roll(t, c.joiner.voting.Cert,
				func(freshVoting, freshRoot trust.KeyCert) []trust.KeyCert {
					return tc.signers(c, freshVoting, freshRoot)
				})
			if _, err := c.decider.DecideTRC(context.Background(), c.joiner.ia, askSource,
				submitted); err == nil {

				t.Fatal("the incomplete roll was decided")
			}
			if len(c.auth.Asked) != 0 {
				t.Errorf("the authorizer was asked %d times, want none for a regular update",
					len(c.auth.Asked))
			}
			if stored := pinnedAt(t, c.db, 3); !stored.IsZero() {
				t.Error("the incomplete roll pinned something")
			}
		})
	}
}
