package controlplane

import (
	"context"
	"crypto"
	"crypto/x509"
	"net/netip"
	"testing"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/modules/enrollauth"
	"github.com/fancl20/cion/pkg/modules/trustdb"
	"github.com/fancl20/cion/pkg/trust"
)

// joinerIATest is the joining core the decision tests onboard.
var joinerIATest = addr.MustIAFrom(20, 0xff0000000f01)

// deciderFixture is a founder holding the decision — its trust fixture and
// the sensitive key beside the decider — and the joiner's voting material,
// with the joiner enrolled unless the test says otherwise.
type deciderFixture struct {
	tf      *trustFixture
	decider *TRCDecider
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
	f := newTrustFixture(t)
	c := &deciderFixture{tf: f, db: f.db, pred: f.trc}
	c.decider = &TRCDecider{DB: f.db, IA: coreIATest, Sensitive: f.keys.Sensitive}
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
	csr, _ := newCSR(t, ia)
	chain, err := c.tf.issuer.IssueChain(csr)
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
	completed, err := c.decider.DecideTRC(ctx, c.joiner.ia, partial)
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
	again, err := c.decider.DecideTRC(ctx, c.joiner.ia, partial)
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

	_, err := c.decider.DecideTRC(context.Background(), c.joiner.ia,
		c.submission(t, c.pred, func() (crypto.Signer, *x509.Certificate) {
			return c.joiner.key, c.joiner.cert
		}))
	if err == nil {
		t.Fatal("the unenrolled joiner's submission was decided, want refusal")
	}
	if pinned, err := c.db.SignedTRC(context.Background(),
		cppki.TRCID{ISD: coreIATest.ISD(), Base: 1, Serial: 2}); err != nil || !pinned.IsZero() {
		t.Errorf("the unenrolled joiner's submission pinned something (%v)", err)
	}
}

// TestTRCDeciderAsksAdmission checks the voting question: the decision asks
// the admission policy once the mechanical gates pass — the voting boundary,
// the presenter, the certificate the successor carries — and an allowance is
// what the vote lands on. A join already landed asks nothing: the
// re-presentation is answered with the pin whatever the policy would say.
func TestTRCDeciderAsksAdmission(t *testing.T) {
	c := newDeciderFixture(t, true)
	auth := &askAuthorizer{verdict: enrollauth.AdmissionAllow}
	c.decider.Authorizer = auth

	partial := c.submission(t, c.pred, func() (crypto.Signer, *x509.Certificate) {
		return c.joiner.key, c.joiner.cert
	})
	completed, err := c.decider.DecideTRC(askContext(), c.joiner.ia, partial)
	if err != nil {
		t.Fatal(err)
	}
	if want := (cppki.TRCID{ISD: coreIATest.ISD(), Base: 1, Serial: 2}); completed.TRC.ID != want {
		t.Fatalf("the decided TRC = %v, want the successor %v", completed.TRC.ID, want)
	}
	if len(auth.asked) != 1 {
		t.Fatalf("the authorizer was asked %d times, want 1", len(auth.asked))
	}
	got := auth.asked[0]
	if got.Boundary != enrollauth.BoundaryVoting {
		t.Errorf("asked boundary = %v, want the voting one", got.Boundary)
	}
	if got.Claim != c.joiner.ia {
		t.Errorf("asked claim = %v, want the presenter %v", got.Claim, c.joiner.ia)
	}
	if got.VotingCert == nil || !got.VotingCert.Equal(c.joiner.cert) {
		t.Errorf("asked voting certificate = %v, want the successor's", got.VotingCert)
	}
	if want := netip.MustParseAddrPort("198.51.100.7:41234"); got.Source != want {
		t.Errorf("asked source = %v, want the context's %v", got.Source, want)
	}

	auth.verdict = enrollauth.AdmissionDeny
	if _, err := c.decider.DecideTRC(askContext(), c.joiner.ia, partial); err != nil {
		t.Fatalf("the re-presentation was refused: %v", err)
	}
	if len(auth.asked) != 1 {
		t.Errorf("the authorizer was asked %d times after the re-presentation, want still 1",
			len(auth.asked))
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
			auth := &askAuthorizer{verdict: tc.verdict}
			c.decider.Authorizer = auth

			if _, err := c.decider.DecideTRC(askContext(), c.joiner.ia,
				c.submission(t, c.pred, func() (crypto.Signer, *x509.Certificate) {
					return c.joiner.key, c.joiner.cert
				})); err == nil {

				t.Fatal("the submission was decided against the policy's answer")
			}
			if pinned, err := c.db.SignedTRC(context.Background(),
				cppki.TRCID{ISD: coreIATest.ISD(), Base: 1, Serial: 2}); err != nil || !pinned.IsZero() {
				t.Errorf("the refused submission pinned something (%v)", err)
			}
		})
	}
}

// TestTRCDeciderAsksAfterTheGates checks the ask's place: a submission the
// mechanical gates refuse — the presenter holds no chain — reaches no
// question.
func TestTRCDeciderAsksAfterTheGates(t *testing.T) {
	c := newDeciderFixture(t, false)
	auth := &askAuthorizer{verdict: enrollauth.AdmissionAllow}
	c.decider.Authorizer = auth

	if _, err := c.decider.DecideTRC(askContext(), c.joiner.ia,
		c.submission(t, c.pred, func() (crypto.Signer, *x509.Certificate) {
			return c.joiner.key, c.joiner.cert
		})); err == nil {

		t.Fatal("the unenrolled joiner's submission was decided")
	}
	if len(auth.asked) != 0 {
		t.Errorf("the authorizer was asked %d times, want none behind a refused gate",
			len(auth.asked))
	}
}

// TestTRCDeciderBindsPresenter checks the channel's fact: a submission
// onboarding one ISD-AS under another's presentation is refused — the
// decision is the presenter's own onboarding alone.
func TestTRCDeciderBindsPresenter(t *testing.T) {
	c := newDeciderFixture(t, true)

	stranger := addr.MustIAFrom(coreIATest.ISD(), joinerIATest.AS()+1)
	if _, err := c.decider.DecideTRC(context.Background(), stranger,
		c.submission(t, c.pred, func() (crypto.Signer, *x509.Certificate) {
			return c.joiner.key, c.joiner.cert
		})); err == nil {

		t.Fatal("a submission onboarding another ISD-AS than its presenter was decided")
	}
	if pinned, err := c.db.SignedTRC(context.Background(),
		cppki.TRCID{ISD: coreIATest.ISD(), Base: 1, Serial: 2}); err != nil || !pinned.IsZero() {
		t.Errorf("the stranger's submission pinned something (%v)", err)
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
	if _, err := c.decider.DecideTRC(ctx, other, otherPartial); err != nil {
		t.Fatalf("the first join was refused: %v", err)
	}

	// The joiner's submission still builds on the base and is refused.
	if _, err := c.decider.DecideTRC(ctx, c.joiner.ia,
		c.submission(t, c.pred, func() (crypto.Signer, *x509.Certificate) {
			return c.joiner.key, c.joiner.cert
		})); err == nil {

		t.Fatal("a submission over a stale predecessor was decided")
	}
	if pinned, err := c.db.SignedTRC(ctx,
		cppki.TRCID{ISD: coreIATest.ISD(), Base: 1, Serial: 3}); err != nil || !pinned.IsZero() {
		t.Errorf("the stale submission pinned a second successor (%v)", err)
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
	if _, err := c.decider.DecideTRC(context.Background(), c.joiner.ia, unsigned); err == nil {
		t.Fatal("an update without the presenter's signature was decided")
	}
	if pinned, err := c.db.SignedTRC(context.Background(),
		cppki.TRCID{ISD: coreIATest.ISD(), Base: 1, Serial: 2}); err != nil || !pinned.IsZero() {
		t.Errorf("the unsigned submission pinned something (%v)", err)
	}
}

// TestTRCDeciderWithoutSensitiveKey checks the node that decides nothing:
// every submission is refused.
func TestTRCDeciderWithoutSensitiveKey(t *testing.T) {
	c := newDeciderFixture(t, true)
	c.decider = &TRCDecider{DB: c.db, IA: coreIATest}

	if _, err := c.decider.DecideTRC(context.Background(), c.joiner.ia,
		c.submission(t, c.pred, func() (crypto.Signer, *x509.Certificate) {
			return c.joiner.key, c.joiner.cert
		})); err == nil {

		t.Error("a node without the sensitive key decided a submission")
	}
	if _, err := c.decider.DecideTRC(context.Background(), addr.IA(0),
		c.pred); err == nil {

		t.Error("a submission without a verified presenter was decided")
	}
}
