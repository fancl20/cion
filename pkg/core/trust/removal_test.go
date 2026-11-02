package trust_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"net/netip"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/core/trust"
	"github.com/fancl20/cion/pkg/core/trust/trusttest"
	"github.com/fancl20/cion/pkg/modules/trustdb"
)

// joinerIssuer returns an issuer of chains under the onboarded joiner's
// root, its CA key fresh, anchored in the TRC that carries the root.
func joinerIssuer(t *testing.T, c *rollFixture) *trust.Issuer {
	t.Helper()
	ca, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := trust.NewIssuer(c.joiner.ia, trust.IssuerKeys{Root: c.joiner.root.Key, CA: ca}, c.rolled)
	if err != nil {
		t.Fatal(err)
	}
	if !issuer.Anchored() {
		t.Fatal("the joiner's issuer is not anchored in the TRC carrying its root")
	}
	return issuer
}

// issueFor issues ia a chain for key at the issuer.
func issueFor(t *testing.T, issuer *trust.Issuer, ia addr.IA, key crypto.Signer) []*x509.Certificate {
	t.Helper()
	csr, err := trust.CreateCSR(ia, key)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := issuer.IssueChain(csr)
	if err != nil {
		t.Fatal(err)
	}
	return chain
}

// successorOf returns the TRC that succeeds the signed one unchanged but for
// its serial, its vote the founder's sensitive voting certificate's index —
// the shape a sensitive update a test then changes starts from.
func successorOf(t *testing.T, pred cppki.SignedTRC) cppki.TRC {
	t.Helper()
	trc := pred.TRC
	trc.Raw = nil
	trc.ID.Serial++
	trc.Certificates = slices.Clone(pred.TRC.Certificates)
	trc.CoreASes = slices.Clone(pred.TRC.CoreASes)
	trc.AuthoritativeASes = slices.Clone(pred.TRC.AuthoritativeASes)
	trc.Votes = nil
	for i, cert := range pred.TRC.Certificates {
		if ct, err := cppki.ValidateCert(cert); err == nil && ct == cppki.Sensitive {
			trc.Votes = []int{i}
		}
	}
	return trc
}

// coverCerts narrows the TRC's validity to the span every certificate it
// carries covers, as its encoding asks: a certificate minted after the
// predecessor's, even a second later, starts after the predecessor's
// validity.
func coverCerts(trc *cppki.TRC) {
	for _, cert := range trc.Certificates {
		if cert.NotBefore.After(trc.Validity.NotBefore) {
			trc.Validity.NotBefore = cert.NotBefore
		}
		if cert.NotAfter.Before(trc.Validity.NotAfter) {
			trc.Validity.NotAfter = cert.NotAfter
		}
	}
}

// TestRemoveCore checks the founder's removal of an onboarded core, without
// a grace period and with the roll's: the successor drops the core's
// certificates and both its AS entries and keeps the rest, starts its
// validity at the cast an hour after every certificate it carries, carries
// the grace period, and pins as a sensitive update the founder's vote alone
// signs. Removing the core again casts nothing.
func TestRemoveCore(t *testing.T) {
	for _, grace := range []time.Duration{0, trust.ASValidity} {
		t.Run(grace.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				testRemoveCore(t, grace)
			})
		})
	}
}

func testRemoveCore(t *testing.T, grace time.Duration) {
	c := newRollFixture(t)
	ctx := context.Background()
	time.Sleep(time.Hour)
	cast := time.Now().Add(-2 * time.Minute)

	if err := c.decider.RemoveCore(ctx, c.joiner.ia, grace); err != nil {
		t.Fatal(err)
	}
	removal := pinnedAt(t, c.db, 3)
	if removal.IsZero() {
		t.Fatal("the removal pinned nothing")
	}
	kept := slices.DeleteFunc(slices.Clone(c.rolled.TRC.Certificates), func(cert *x509.Certificate) bool {
		return slices.ContainsFunc(trust.CertsOf(c.rolled.TRC, c.joiner.ia), cert.Equal)
	})
	if diff := cmp.Diff(kept, removal.TRC.Certificates); diff != "" {
		t.Errorf("the removal's certificates (-want +got):\n%s", diff)
	}
	base := c.tf.TRC.TRC
	if diff := cmp.Diff(base.CoreASes, removal.TRC.CoreASes); diff != "" {
		t.Errorf("the removal's core ASes (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(base.AuthoritativeASes, removal.TRC.AuthoritativeASes); diff != "" {
		t.Errorf("the removal's authoritative ASes (-want +got):\n%s", diff)
	}
	if removal.TRC.GracePeriod != grace {
		t.Errorf("the removal's grace period = %v, want %v", removal.TRC.GracePeriod, grace)
	}
	if removal.TRC.Validity.NotBefore.Before(cast) {
		t.Errorf("the removal's validity starts at %v, before the cast", removal.TRC.Validity.NotBefore)
	}
	update, err := removal.TRC.ValidateUpdate(&c.rolled.TRC)
	if err != nil {
		t.Fatal(err)
	}
	if update.Type != cppki.SensitiveUpdate {
		t.Errorf("the removal's update type = %v, want a sensitive update", update.Type)
	}
	if len(removal.SignerInfos) != 1 {
		t.Errorf("the removal carries %d signer infos, want the founder's vote alone",
			len(removal.SignerInfos))
	}
	if err := removal.Verify(&c.rolled.TRC); err != nil {
		t.Errorf("the removal does not verify against its predecessor: %v", err)
	}

	if err := c.decider.RemoveCore(ctx, c.joiner.ia, grace); err != nil {
		t.Fatalf("removing the removed core again: %v", err)
	}
	if stored := pinnedAt(t, c.db, 4); !stored.IsZero() {
		t.Error("removing the removed core cast a second removal")
	}
}

// TestRemoveCoreRefusesTheFounder checks that the founder removes no core of
// its own, and pins nothing.
func TestRemoveCoreRefusesTheFounder(t *testing.T) {
	c := newDeciderFixture(t)
	if err := c.decider.RemoveCore(context.Background(), coreIATest, 0); err == nil {
		t.Fatal("the founder removed itself")
	}
	if stored := pinnedAt(t, c.db, 2); !stored.IsZero() {
		t.Error("the founder's removal of itself pinned something")
	}
}

// TestRemovedRootLeavesThePool checks what the anchor pool anchors once a
// removal pins: a chain under the removed core's root verifies before;
// without a grace period it verifies no more, and with the roll's it
// verifies until the grace period, three days from the cast, ends.
func TestRemovedRootLeavesThePool(t *testing.T) {
	for _, tc := range []struct {
		grace    time.Duration
		verifies bool
	}{
		{0, false},
		{trust.ASValidity, true},
	} {
		t.Run(tc.grace.String(), func(t *testing.T) {
			c := newRollFixture(t)
			ctx := context.Background()
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			chain := issueFor(t, joinerIssuer(t, c), nodeIATest, key)
			anchors := func() bool {
				t.Helper()
				pool, err := trust.PinnedPool(ctx, c.db, coreIATest.ISD())
				if err != nil {
					t.Fatal(err)
				}
				return cppki.VerifyChain(chain, cppki.VerifyOptions{TRC: pool}) == nil
			}
			if !anchors() {
				t.Fatal("the chain under the core's root does not verify before the removal")
			}
			if err := c.decider.RemoveCore(ctx, c.joiner.ia, tc.grace); err != nil {
				t.Fatal(err)
			}
			if got := anchors(); got != tc.verifies {
				t.Errorf("the chain under the removed root verifies = %v, want %v", got, tc.verifies)
			}
			removal := pinnedAt(t, c.db, 3).TRC
			if removal.InGracePeriod(removal.Validity.NotBefore.Add(tc.grace + time.Second)) {
				t.Errorf("the removal's grace period runs past %v from the cast", tc.grace)
			}
		})
	}
}

// TestTRCDeciderRefusesChangesBeyondThePresenters checks the founder's gate
// on what a core's submission changes, with a second core onboarded beside
// the presenter: a sensitive update that removes the other core, adds a
// sensitive voting certificate of the presenter's — raising the quorum beside
// it or not — appends another AS, or drops the presenter's own root is
// refused before any question, and nothing pins.
func TestTRCDeciderRefusesChangesBeyondThePresenters(t *testing.T) {
	c := newRollFixture(t)
	ctx := context.Background()
	other := addr.MustIAFrom(coreIATest.ISD(), joinerIATest.AS()+1)
	otherVoting, otherRoot := coreMaterial(t, other)
	otherTRC, err := trust.AssembleOnboarding(c.rolled, other, otherVoting.Cert, otherRoot.Cert)
	if err != nil {
		t.Fatal(err)
	}
	otherPartial, err := trust.SignUpdate(otherTRC, otherVoting, otherRoot)
	if err != nil {
		t.Fatal(err)
	}
	newest, err := c.decider.DecideTRC(ctx, other, netip.AddrPort{}, otherPartial)
	if err != nil {
		t.Fatal(err)
	}
	c.auth.Asked = nil

	removal, err := trust.AssembleRemoval(newest, other, 0, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// A sensitive voting certificate naming the presenter: a founding
	// core's of its ISD-AS, founded apart.
	apart := trusttest.NewFounder(t, openTrustDB(t, t.TempDir()), c.joiner.ia)
	sensitiveCert, err := trust.SignerCert(apart.TRC.TRC, cppki.Sensitive)
	if err != nil {
		t.Fatal(err)
	}
	sensitive := successorOf(t, newest)
	sensitive.Certificates = append(sensitive.Certificates, sensitiveCert)
	coverCerts(&sensitive)
	appended := successorOf(t, newest)
	appended.CoreASes = append(appended.CoreASes, other.AS()+1)
	dropped := successorOf(t, newest)
	dropped.Certificates = slices.DeleteFunc(dropped.Certificates, c.joiner.root.Cert.Equal)
	quorum := sensitive
	quorum.Quorum = 2
	sensitiveSigner := []trust.KeyCert{{Key: apart.Keys.Sensitive, Cert: sensitiveCert}}
	_, freshOtherRoot := coreMaterial(t, other)
	rolledOther := successorOf(t, newest)
	for i, cert := range rolledOther.Certificates {
		if cert.Equal(otherRoot.Cert) {
			rolledOther.Certificates[i] = freshOtherRoot.Cert
		}
	}
	coverCerts(&rolledOther)

	for name, sub := range map[string]struct {
		trc     cppki.TRC
		signers []trust.KeyCert
	}{
		"removing another core":          {removal, nil},
		"rolling another core's root":    {rolledOther, []trust.KeyCert{freshOtherRoot}},
		"adding a sensitive certificate": {sensitive, sensitiveSigner},
		"appending another AS":           {appended, nil},
		"dropping the presenter's root":  {dropped, nil},
		"raising the quorum beside it":   {quorum, sensitiveSigner},
	} {
		t.Run(name, func(t *testing.T) {
			signed, err := trust.SignUpdate(sub.trc, sub.signers...)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.decider.DecideTRC(ctx, c.joiner.ia, askSource, signed); err == nil {
				t.Fatal("the submission was decided")
			}
			if len(c.auth.Asked) != 0 {
				t.Errorf("the authorizer was asked %d times, want none behind a refused gate",
					len(c.auth.Asked))
			}
			if stored := pinnedAt(t, c.db, scrypto.Version(newest.TRC.ID.Serial+1)); !stored.IsZero() {
				t.Error("the refused submission pinned something")
			}
		})
	}
}

// TestRemovedCoreRenewsAsANode checks the removed core's renewal: its newest
// chain, self-issued under the removed root, anchors in the removal no more,
// so the pass renews at the issuers, resting on the chain the founder
// issued, and self-issues nothing.
func TestRemovedCoreRenewsAsANode(t *testing.T) {
	c := newRollFixture(t)
	ctx := context.Background()
	if err := c.decider.RemoveCore(ctx, c.joiner.ia, 0); err != nil {
		t.Fatal(err)
	}
	removal := pinnedAt(t, c.db, 3)
	lf := newLifecycleFixture(t, c.tf)
	for serial := scrypto.Version(1); serial <= 3; serial++ {
		if _, err := lf.db.InsertTRC(ctx, pinnedAt(t, c.db, serial)); err != nil {
			t.Fatal(err)
		}
	}
	member := issueFor(t, c.tf.Issuer, c.joiner.ia, lf.key)
	issuer := joinerIssuer(t, c)
	issuer.ChainValidity = trust.ASValidity + time.Hour
	own := issueFor(t, issuer, c.joiner.ia, lf.key)
	for _, chain := range [][]*x509.Certificate{member, own} {
		if _, err := lf.db.InsertChain(ctx, chain); err != nil {
			t.Fatal(err)
		}
	}
	issuers := &fakeCore{issuer: c.tf.Issuer, trc: removal}
	cfg := lf.cfg
	cfg.IA = c.joiner.ia
	cfg.Renewal = trust.AuthoritativeRenewal(lf.core, issuers, absentVoting{}, c.joiner.voting,
		c.joiner.root, issuer)

	enrollPassOf(t, ctx, cfg)
	if issuers.renewals() != 1 {
		t.Fatalf("the issuers renewed %d times, want one renewal off the removed chain",
			issuers.renewals())
	}
	if diff := cmp.Diff(member, issuers.restsOn[0]); diff != "" {
		t.Errorf("the renewal rested on another chain than the founder's (-want +got):\n%s", diff)
	}
	now := time.Now()
	chains, err := lf.db.Chains(ctx, trustdb.ChainQuery{
		IA:       c.joiner.ia,
		Validity: cppki.Validity{NotBefore: now, NotAfter: now},
	})
	if err != nil {
		t.Fatal(err)
	}
	selfIssued := slices.DeleteFunc(chains, func(chain []*x509.Certificate) bool {
		caIA, err := cppki.ExtractIA(chain[1].Subject)
		return err != nil || !caIA.Equal(c.joiner.ia)
	})
	if len(selfIssued) != 1 {
		t.Errorf("the core holds %d self-issued chains, want the one before the removal",
			len(selfIssued))
	}
}

// TestNodeFallsBackOnItsMembership checks the node whose newest chain the
// removed core issued: before the removal pins, the engine presents that
// chain; once it pins, the engine presents the chain the founder issued and
// the anchored chain reads the same, and the enrollment renews at the
// issuers resting on it.
func TestNodeFallsBackOnItsMembership(t *testing.T) {
	c := newRollFixture(t)
	ctx := context.Background()
	lf := newLifecycleFixture(t, c.tf)
	for serial := scrypto.Version(1); serial <= 2; serial++ {
		if _, err := lf.db.InsertTRC(ctx, pinnedAt(t, c.db, serial)); err != nil {
			t.Fatal(err)
		}
	}
	lf.enroll(t)
	member, err := trust.NewestChain(ctx, lf.db, nodeIATest, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	issuer := joinerIssuer(t, c)
	issuer.ChainValidity = trust.ASValidity + time.Hour
	removed := issueFor(t, issuer, nodeIATest, lf.key)
	if _, err := lf.db.InsertChain(ctx, removed); err != nil {
		t.Fatal(err)
	}
	engine := trust.NewEngine(nodeIATest, lf.key, &trust.NetworkProvider{DB: lf.db}, trusttest.Unchecked{})
	presented := func() []*x509.Certificate {
		t.Helper()
		chain, err := engine.Chain(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return chain
	}
	if diff := cmp.Diff(removed, presented()); diff != "" {
		t.Fatalf("before the removal, the engine presents another chain than the newest "+
			"(-want +got):\n%s", diff)
	}

	if err := c.decider.RemoveCore(ctx, c.joiner.ia, 0); err != nil {
		t.Fatal(err)
	}
	removal := pinnedAt(t, c.db, 3)
	if _, err := lf.db.InsertTRC(ctx, removal); err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(member, presented()); diff != "" {
		t.Errorf("once the removal pins, the engine presents another chain than the "+
			"founder's (-want +got):\n%s", diff)
	}
	anchored, err := trust.AnchoredChain(ctx, lf.db, nodeIATest, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(member, anchored); diff != "" {
		t.Errorf("the anchored chain is not the founder's (-want +got):\n%s", diff)
	}
	issuers := &fakeCore{issuer: c.tf.Issuer, trc: removal}
	lf.cfg.Renewal = trust.NormalRenewal(lf.core, issuers)
	enrollPassOf(t, ctx, lf.cfg)
	if issuers.renewals() != 1 {
		t.Fatalf("the issuers renewed %d times, want one renewal off the removed chain",
			issuers.renewals())
	}
	if diff := cmp.Diff(member, issuers.restsOn[0]); diff != "" {
		t.Errorf("the renewal rested on another chain than the founder's (-want +got):\n%s", diff)
	}
}
