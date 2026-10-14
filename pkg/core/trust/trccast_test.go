package trust_test

import (
	"context"
	"crypto"
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
// unless the test says otherwise — and the joiner's voting material, with
// the joiner enrolled unless the test says otherwise.
type deciderFixture struct {
	tf      *trusttest.Founder
	decider *trust.TRCDecider
	auth    *authtest.Recorder
	db      trustdb.DB
	pred    cppki.SignedTRC

	joiner struct {
		ia   addr.IA
		key  crypto.Signer
		cert *x509.Certificate
	}
}

// newDeciderFixture brings up the founder's decision and the joiner's voting
// material, enrolling the joiner unless enroll is false.
func newDeciderFixture(t *testing.T, enroll bool) *deciderFixture {
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
	c.joiner.key, c.joiner.cert = votingMaterial(t, c.joiner.ia)
	if enroll {
		c.enroll(t, c.joiner.ia)
	}
	return c
}

// enroll issues and stores a chain for the IA, the gate the decision asks.
func (c *deciderFixture) enroll(t *testing.T, ia addr.IA) {
	t.Helper()
	csr, _ := trusttest.NewCSR(t, ia)
	chain, err := c.tf.Issuer.IssueChain(csr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.db.InsertChain(context.Background(), chain); err != nil {
		t.Fatal(err)
	}
}

// votingMaterial returns fresh voting material naming the IA.
func votingMaterial(t *testing.T, ia addr.IA) (crypto.Signer, *x509.Certificate) {
	t.Helper()
	key, err := trust.LoadOrCreateVotingKey(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cert, err := trust.LoadOrCreateVotingCert(t.TempDir(), ia, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

// fingerprint is the hex subject key ID the decision names a key by.
func fingerprint(cert *x509.Certificate) string {
	return hex.EncodeToString(cert.SubjectKeyId)
}

// submission returns the joiner's partially signed successor over the given
// predecessor.
func (c *deciderFixture) submission(
	t *testing.T,
	pred cppki.SignedTRC,
	presenter func() (crypto.Signer, *x509.Certificate),
) cppki.SignedTRC {

	t.Helper()
	trc, err := trust.AssembleOnboarding(pred, c.joiner.ia, c.joiner.cert)
	if err != nil {
		t.Fatal(err)
	}
	key, cert := presenter()
	partial, err := trust.SignUpdate(trc, key, cert)
	if err != nil {
		t.Fatal(err)
	}
	return partial
}

// TestTRCDeciderOnboards checks the founder's decision on an enrolled
// joiner's submission: the founder's vote lands beside the proof of
// possession, the completed TRC verifies against the newest pin and pins,
// and a joiner re-presenting itself is answered with that pin unchanged —
// it casts nothing.
func TestTRCDeciderOnboards(t *testing.T) {
	c := newDeciderFixture(t, true)
	ctx := context.Background()

	partial := c.submission(t, c.pred, func() (crypto.Signer, *x509.Certificate) {
		return c.joiner.key, c.joiner.cert
	})
	completed, err := c.decider.DecideTRC(ctx, c.joiner.ia, netip.AddrPort{}, partial)
	if err != nil {
		t.Fatal(err)
	}
	if want := (cppki.TRCID{ISD: coreIATest.ISD(), Base: 1, Serial: 2}); completed.TRC.ID != want {
		t.Fatalf("the decided TRC = %v, want the successor %v", completed.TRC.ID, want)
	}
	if len(completed.SignerInfos) != 2 {
		t.Errorf("the decided TRC carries %d signer infos, want the vote and the possession proof",
			len(completed.SignerInfos))
	}
	if err := completed.Verify(&c.pred.TRC); err != nil {
		t.Errorf("the decided TRC does not verify against the predecessor: %v", err)
	}
	pinned, err := c.db.SignedTRC(ctx, completed.TRC.ID)
	if err != nil {
		t.Fatal(err)
	}
	if pinned.IsZero() || string(pinned.Raw) != string(completed.Raw) {
		t.Error("the decided TRC did not pin as completed")
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

// TestTRCDeciderRequiresEnrollment checks the gate: a joiner that holds no
// chain yet — never having enrolled — is refused, and nothing pins.
func TestTRCDeciderRequiresEnrollment(t *testing.T) {
	c := newDeciderFixture(t, false)

	_, err := c.decider.DecideTRC(context.Background(), c.joiner.ia, netip.AddrPort{},
		c.submission(t, c.pred, func() (crypto.Signer, *x509.Certificate) {
			return c.joiner.key, c.joiner.cert
		}))
	if err == nil {
		t.Fatal("the unenrolled joiner's submission was decided, want refusal")
	}
	if stored := pinnedAt(t, c.db, 2); !stored.IsZero() {
		t.Error("the unenrolled joiner's submission pinned something")
	}
}

// TestTRCDeciderAsksAdmission checks the question before the founder's vote:
// once the mechanical gates pass, the decision asks the admission policy
// with the voting boundary, the presenter as the claim, the fingerprint of
// the key the successor adds, and the channel's source, and an allowance is
// what the vote lands on. A join already landed asks nothing: the
// re-presentation is answered with the pin whatever the policy would say.
func TestTRCDeciderAsksAdmission(t *testing.T) {
	c := newDeciderFixture(t, true)

	partial := c.submission(t, c.pred, func() (crypto.Signer, *x509.Certificate) {
		return c.joiner.key, c.joiner.cert
	})
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
	if diff := cmp.Diff([]string{fingerprint(c.joiner.cert)}, got.Keys); diff != "" {
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

// TestTRCDeciderAsksForEveryAddedKey checks the facts of a successor adding
// two certificates: the policy is asked once, with the presenter as the
// claim and both fingerprints in the successor's order, a deny refusing the
// whole submission and an allow pinning it with the vote.
func TestTRCDeciderAsksForEveryAddedKey(t *testing.T) {
	c := newDeciderFixture(t, true)
	second := addr.MustIAFrom(coreIATest.ISD(), joinerIATest.AS()+1)
	secondKey, secondCert := votingMaterial(t, second)

	trc, err := trust.AssembleOnboarding(c.pred, c.joiner.ia, c.joiner.cert)
	if err != nil {
		t.Fatal(err)
	}
	trc.CoreASes = append(trc.CoreASes, second.AS())
	trc.AuthoritativeASes = append(trc.AuthoritativeASes, second.AS())
	trc.Certificates = append(trc.Certificates, secondCert)
	if secondCert.NotBefore.After(trc.Validity.NotBefore) {
		trc.Validity.NotBefore = secondCert.NotBefore
	}
	if secondCert.NotAfter.Before(trc.Validity.NotAfter) {
		trc.Validity.NotAfter = secondCert.NotAfter
	}
	partial, err := trust.SignRotation(trc,
		[]crypto.Signer{c.joiner.key, secondKey},
		[]*x509.Certificate{c.joiner.cert, secondCert})
	if err != nil {
		t.Fatal(err)
	}

	c.auth.Verdict = enrollauth.AdmissionDeny
	if _, err := c.decider.DecideTRC(context.Background(), c.joiner.ia, askSource, partial); err == nil {
		t.Fatal("a denied submission adding two certificates was decided")
	}
	if stored := pinnedAt(t, c.db, 2); !stored.IsZero() {
		t.Error("the denied submission pinned something")
	}
	if len(c.auth.Asked) != 1 {
		t.Fatalf("the authorizer was asked %d times, want 1", len(c.auth.Asked))
	}
	got := c.auth.Asked[0]
	if got.Claim != c.joiner.ia {
		t.Errorf("asked claim = %v, want the presenter %v", got.Claim, c.joiner.ia)
	}
	want := []string{fingerprint(c.joiner.cert), fingerprint(secondCert)}
	if diff := cmp.Diff(want, got.Keys); diff != "" {
		t.Errorf("asked keys (-want +got):\n%s", diff)
	}

	c.auth.Verdict = enrollauth.AdmissionAllow
	completed, err := c.decider.DecideTRC(context.Background(), c.joiner.ia, askSource, partial)
	if err != nil {
		t.Fatalf("the allowed submission was refused: %v", err)
	}
	if !trust.CoreNamed(completed.TRC, c.joiner.ia) || !trust.CoreNamed(completed.TRC, second) {
		t.Error("the decided TRC does not name both added cores")
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
			c := newDeciderFixture(t, true)
			c.auth.Verdict = tc.verdict

			if _, err := c.decider.DecideTRC(context.Background(), c.joiner.ia, askSource,
				c.submission(t, c.pred, func() (crypto.Signer, *x509.Certificate) {
					return c.joiner.key, c.joiner.cert
				})); err == nil {

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
	c := newDeciderFixture(t, true)
	c.decider.Authorizer = nil

	if _, err := c.decider.DecideTRC(context.Background(), c.joiner.ia, askSource,
		c.submission(t, c.pred, func() (crypto.Signer, *x509.Certificate) {
			return c.joiner.key, c.joiner.cert
		})); err == nil {

		t.Fatal("the founder voted with no admission policy configured")
	}
	if stored := pinnedAt(t, c.db, 2); !stored.IsZero() {
		t.Error("the refused submission pinned something")
	}
}

// TestTRCDeciderAsksAfterTheGates checks the ask's place: a submission the
// mechanical gates refuse — the presenter holds no chain — reaches no
// question.
func TestTRCDeciderAsksAfterTheGates(t *testing.T) {
	c := newDeciderFixture(t, false)

	if _, err := c.decider.DecideTRC(context.Background(), c.joiner.ia, askSource,
		c.submission(t, c.pred, func() (crypto.Signer, *x509.Certificate) {
			return c.joiner.key, c.joiner.cert
		})); err == nil {

		t.Fatal("the unenrolled joiner's submission was decided")
	}
	if len(c.auth.Asked) != 0 {
		t.Errorf("the authorizer was asked %d times, want none behind a refused gate",
			len(c.auth.Asked))
	}
}

// TestTRCDeciderRefusesStalePredecessor checks the submission built on an
// older view: the founder has onboarded another core since, and the decision
// refuses what does not increment its newest pin — the submitter resolves
// the newest TRC and submits again.
func TestTRCDeciderRefusesStalePredecessor(t *testing.T) {
	c := newDeciderFixture(t, true)
	ctx := context.Background()

	// Another core joins first: the founder's newest advances.
	other := addr.MustIAFrom(coreIATest.ISD(), joinerIATest.AS()+1)
	otherKey, otherCert := votingMaterial(t, other)
	c.enroll(t, other)
	otherTRC, err := trust.AssembleOnboarding(c.pred, other, otherCert)
	if err != nil {
		t.Fatal(err)
	}
	otherPartial, err := trust.SignUpdate(otherTRC, otherKey, otherCert)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.decider.DecideTRC(ctx, other, netip.AddrPort{}, otherPartial); err != nil {
		t.Fatalf("the first join was refused: %v", err)
	}

	// The joiner's submission still builds on the base and is refused.
	if _, err := c.decider.DecideTRC(ctx, c.joiner.ia, netip.AddrPort{},
		c.submission(t, c.pred, func() (crypto.Signer, *x509.Certificate) {
			return c.joiner.key, c.joiner.cert
		})); err == nil {

		t.Fatal("a submission over a stale predecessor was decided")
	}
	if stored := pinnedAt(t, c.db, 3); !stored.IsZero() {
		t.Error("the stale submission pinned a second successor")
	}
}

// TestTRCDeciderRefusesUnsigned checks the possession proof's absence: a
// successor the presenter did not sign is completed by the vote and then
// fails the verification, pinning nothing.
func TestTRCDeciderRefusesUnsigned(t *testing.T) {
	c := newDeciderFixture(t, true)

	trc, err := trust.AssembleOnboarding(c.pred, c.joiner.ia, c.joiner.cert)
	if err != nil {
		t.Fatal(err)
	}
	// Signed by a key the update does not carry: the new voter's proof of
	// possession never rides it.
	strangerKey, strangerCert := votingMaterial(t, c.joiner.ia)
	unsigned, err := trust.SignUpdate(trc, strangerKey, strangerCert)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.decider.DecideTRC(context.Background(), c.joiner.ia, netip.AddrPort{}, unsigned); err == nil {
		t.Fatal("an update without the presenter's signature was decided")
	}
	if stored := pinnedAt(t, c.db, 2); !stored.IsZero() {
		t.Error("the unsigned submission pinned something")
	}
}

// TestTRCDeciderRefusesUnverifiedPresenter checks the submission no channel
// verified: a zero presenter is refused, pinning nothing.
func TestTRCDeciderRefusesUnverifiedPresenter(t *testing.T) {
	c := newDeciderFixture(t, true)

	if _, err := c.decider.DecideTRC(context.Background(), addr.IA(0), netip.AddrPort{},
		c.submission(t, c.pred, func() (crypto.Signer, *x509.Certificate) {
			return c.joiner.key, c.joiner.cert
		})); err == nil {

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
	c := newDeciderFixture(t, true)
	ctx := context.Background()
	partial := c.submission(t, c.pred, func() (crypto.Signer, *x509.Certificate) {
		return c.joiner.key, c.joiner.cert
	})

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
// pinned successor the joiner's roll replaces its own certificate on — with
// the onboarding's question cleared from the policy's record.
type rollFixture struct {
	deciderFixture
	// rolled is the pinned successor naming the joiner a core.
	rolled cppki.SignedTRC
}

func newRollFixture(t *testing.T) *rollFixture {
	t.Helper()
	c := newDeciderFixture(t, true)
	completed, err := c.decider.DecideTRC(context.Background(), c.joiner.ia, netip.AddrPort{},
		c.submission(t, c.pred, func() (crypto.Signer, *x509.Certificate) {
			return c.joiner.key, c.joiner.cert
		}))
	if err != nil {
		t.Fatal(err)
	}
	c.auth.Asked = nil
	return &rollFixture{deciderFixture: *c, rolled: completed}
}

// rollSubmission returns the joiner's routine roll over the given
// predecessor: a fresh voting pair replacing the certificate the predecessor
// names for it, by the regular update the replaced certificate's key votes
// on beside the fresh key's proof of possession.
func (c *rollFixture) rollSubmission(
	t *testing.T,
	pred cppki.SignedTRC,
) (cppki.SignedTRC, *x509.Certificate) {

	t.Helper()
	key, cert := votingMaterial(t, c.joiner.ia)
	trc, err := trust.AssembleRotation(pred, c.joiner.cert, []*x509.Certificate{cert})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := trust.SignRotation(trc,
		[]crypto.Signer{key, c.joiner.key},
		[]*x509.Certificate{cert, c.joiner.cert})
	if err != nil {
		t.Fatal(err)
	}
	return signed, cert
}

// TestTRCDeciderRolls checks the decision on a routine roll: the regular
// update the presenter's current key voted on verifies as submitted and
// pins exactly as submitted — the founder signing nothing and asking no
// policy, not even one that would deny — and its re-presentation is
// answered with the pin, casting nothing.
func TestTRCDeciderRolls(t *testing.T) {
	c := newRollFixture(t)
	c.auth.Verdict = enrollauth.AdmissionDeny

	submitted, freshCert := c.rollSubmission(t, c.rolled)
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
	if !trust.CertsOf(pinned.TRC, c.joiner.ia)[0].Equal(freshCert) {
		t.Error("the decided roll does not carry the presenter's fresh certificate")
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

// TestTRCDeciderLostKeyRoll checks the roll whose current key cannot vote:
// the sensitive update the founder's sensitive certificate is the voter of,
// signed by the fresh key alone, asks the policy with the fresh key's
// fingerprint — refused and pinning nothing on deny, pinned with the
// founder's vote beside the possession proof on allow.
func TestTRCDeciderLostKeyRoll(t *testing.T) {
	c := newRollFixture(t)
	key, cert := votingMaterial(t, c.joiner.ia)
	sensitive, err := trust.SignerCert(c.rolled.TRC, cppki.Sensitive)
	if err != nil {
		t.Fatal(err)
	}
	trc, err := trust.AssembleRotation(c.rolled, sensitive, []*x509.Certificate{cert})
	if err != nil {
		t.Fatal(err)
	}
	submitted, err := trust.SignRotation(trc,
		[]crypto.Signer{key}, []*x509.Certificate{cert})
	if err != nil {
		t.Fatal(err)
	}

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
	if diff := cmp.Diff([]string{fingerprint(cert)}, c.auth.Asked[0].Keys); diff != "" {
		t.Errorf("asked keys (-want +got):\n%s", diff)
	}

	c.auth.Verdict = enrollauth.AdmissionAllow
	completed, err := c.decider.DecideTRC(context.Background(), c.joiner.ia, askSource, submitted)
	if err != nil {
		t.Fatalf("the allowed lost-key roll was refused: %v", err)
	}
	if len(completed.SignerInfos) != 2 {
		t.Errorf("the decided roll carries %d signer infos, want the vote and the possession proof",
			len(completed.SignerInfos))
	}
	if err := completed.Verify(&c.rolled.TRC); err != nil {
		t.Errorf("the decided roll does not verify against the predecessor: %v", err)
	}
	if stored := pinnedAt(t, c.db, 3); string(stored.Raw) != string(completed.Raw) {
		t.Error("the decided roll did not pin as completed")
	}
}

// TestTRCDeciderRefusesUnvotedRegularUpdate checks a regular update short of
// its vote: the roll the replaced certificate's key did not sign is refused
// without a question — the founder's vote completes no regular update — and
// pins nothing.
func TestTRCDeciderRefusesUnvotedRegularUpdate(t *testing.T) {
	c := newRollFixture(t)
	key, cert := votingMaterial(t, c.joiner.ia)
	trc, err := trust.AssembleRotation(c.rolled, c.joiner.cert, []*x509.Certificate{cert})
	if err != nil {
		t.Fatal(err)
	}
	unvoted, err := trust.SignRotation(trc,
		[]crypto.Signer{key}, []*x509.Certificate{cert})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := c.decider.DecideTRC(context.Background(), c.joiner.ia, askSource, unvoted); err == nil {
		t.Fatal("a regular update without its vote was decided")
	}
	if len(c.auth.Asked) != 0 {
		t.Errorf("the authorizer was asked %d times, want none for a regular update",
			len(c.auth.Asked))
	}
	if stored := pinnedAt(t, c.db, 3); !stored.IsZero() {
		t.Error("the unvoted roll pinned something")
	}
}
