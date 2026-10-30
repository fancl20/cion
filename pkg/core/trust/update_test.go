package trust

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/modules/trustdb"
)

// joinerIA is the joining core the assembly tests onboard.
var joinerIA = addr.MustIAFrom(20, 0xff0000000f01)

// castFixture is a founder with its base TRC pinned and the joiner's voting
// and root material beside it.
type castFixture struct {
	founder *genesisFixture
	joiner  struct {
		voting, root KeyCert
	}
}

func newCastFixture(t *testing.T) *castFixture {
	t.Helper()
	f := &castFixture{founder: newGenesisFixture(t)}
	f.joiner.voting, f.joiner.root = newJoinerMaterialOf(t, joinerIA)
	return f
}

// newSuccessorFixture builds the base TRC, the joiner's partially signed
// successor, and the founder-completed TRC, in the exchange's own order: the
// joiner assembles and signs the proofs of possession, the founder adds its
// sensitive vote.
func (f *castFixture) successor(
	t *testing.T,
) (base, partial, completed cppki.SignedTRC) {

	t.Helper()
	base = f.founder.trc
	trc, err := AssembleOnboarding(base, joinerIA, f.joiner.voting.Cert, f.joiner.root.Cert)
	if err != nil {
		t.Fatal(err)
	}
	partial, err = SignUpdate(trc, f.joiner.voting, f.joiner.root)
	if err != nil {
		t.Fatal(err)
	}
	return base, partial, f.vote(t, base, partial)
}

// vote completes the partially signed successor with the founder's
// sensitive vote over the predecessor.
func (f *castFixture) vote(t *testing.T, pred, partial cppki.SignedTRC) cppki.SignedTRC {
	t.Helper()
	sensitiveCert, err := signerCert(pred.TRC, cppki.Sensitive)
	if err != nil {
		t.Fatal(err)
	}
	completed, err := CoSign(partial, f.founder.keys.Sensitive, sensitiveCert)
	if err != nil {
		t.Fatal(err)
	}
	return completed
}

// rootless returns the founder-completed successor that onboards the joiner
// the way cores were onboarded before they held roots: the AS lists grown by
// the joiner and the certificate set by its voting certificate alone.
func (f *castFixture) rootless(t *testing.T) cppki.SignedTRC {
	t.Helper()
	base := f.founder.trc
	trc, err := AssembleOnboarding(base, joinerIA, f.joiner.voting.Cert, f.joiner.root.Cert)
	if err != nil {
		t.Fatal(err)
	}
	trc.Certificates = trc.Certificates[:len(trc.Certificates)-1]
	trc.Validity = coveredValidity(trc.Certificates)
	partial, err := SignUpdate(trc, f.joiner.voting)
	if err != nil {
		t.Fatal(err)
	}
	completed := f.vote(t, base, partial)
	if err := completed.Verify(&base.TRC); err != nil {
		t.Fatal(err)
	}
	return completed
}

// TestAssembleOnboarding checks the successor the joiner assembles from the
// newest pinned TRC: the serial incremented on the same base, both AS lists
// grown by the joiner, the certificate set grown by its regular voting
// certificate and its root certificate, the quorum untouched, a validity
// bounded by the earliest expiry the set carries, and cppki reading the
// result as a sensitive update that verifies against the predecessor.
func TestAssembleOnboarding(t *testing.T) {
	f := newCastFixture(t)
	pred := f.founder.trc

	trc, err := AssembleOnboarding(pred, joinerIA, f.joiner.voting.Cert, f.joiner.root.Cert)
	if err != nil {
		t.Fatal(err)
	}
	if have, want := trc.ID, (cppki.TRCID{
		ISD: pred.TRC.ID.ISD, Base: pred.TRC.ID.Base, Serial: pred.TRC.ID.Serial + 1,
	}); have != want {
		t.Errorf("successor ID = %v, want %v", have, want)
	}
	for name, list := range map[string][]addr.AS{
		"core ASes": trc.CoreASes, "authoritative ASes": trc.AuthoritativeASes,
	} {
		if len(list) != len(pred.TRC.CoreASes)+1 || list[len(list)-1] != joinerIA.AS() {
			t.Errorf("%s = %v, want the predecessor's list grown by %v", name, list, joinerIA)
		}
	}
	if len(trc.Certificates) != len(pred.TRC.Certificates)+2 {
		t.Fatalf("certificates = %d, want the predecessor's set grown by two",
			len(trc.Certificates))
	}
	grown := trc.Certificates[len(pred.TRC.Certificates):]
	if !grown[0].Equal(f.joiner.voting.Cert) || !grown[1].Equal(f.joiner.root.Cert) {
		t.Error("the grown certificates are not the joiner's voting and root certificates")
	}
	if trc.Quorum != pred.TRC.Quorum {
		t.Errorf("quorum = %d, want the predecessor's %d", trc.Quorum, pred.TRC.Quorum)
	}
	if trc.NoTrustReset != pred.TRC.NoTrustReset {
		t.Error("noTrustReset changed")
	}
	// The validity is the window every carried certificate still covers: it
	// starts no earlier than the joiner's fresh certificate and ends no later
	// than the earliest expiry the founder's carried ones hold.
	earliest := pred.TRC.Certificates[0].NotAfter
	for _, cert := range pred.TRC.Certificates[1:] {
		if cert.NotAfter.Before(earliest) {
			earliest = cert.NotAfter
		}
	}
	if !trc.Validity.NotAfter.Equal(earliest) {
		t.Errorf("validity ends at %v, want the set's earliest expiry %v",
			trc.Validity.NotAfter, earliest)
	}
	for _, cert := range grown {
		if trc.Validity.NotBefore.Before(cert.NotBefore) {
			t.Errorf("validity starts at %v, before the joiner's certificates cover",
				trc.Validity.NotBefore)
		}
	}

	// cppki reads the successor as a sensitive update against its
	// predecessor, the vote naming the founder's sensitive certificate.
	update, err := trc.ValidateUpdate(&pred.TRC)
	if err != nil {
		t.Fatalf("cppki refuses the assembled successor: %v", err)
	}
	if update.Type != cppki.SensitiveUpdate {
		t.Errorf("update type = %v, want a sensitive update", update.Type)
	}
	if len(update.NewVoters) != 1 || !update.NewVoters[0].Equal(f.joiner.voting.Cert) {
		t.Errorf("new voters = %v, want the joiner's voting certificate alone", update.NewVoters)
	}
}

// TestAssembleOnboardingAddsTheRoot checks the assembly for a core onboarded
// before cores held roots: the predecessor names it a core without its root,
// and the successor grows the certificate set by the root alone, the AS lists
// untouched, cppki reading it as a sensitive update that verifies once the
// founder votes.
func TestAssembleOnboardingAddsTheRoot(t *testing.T) {
	f := newCastFixture(t)
	pred := f.rootless(t)

	trc, err := AssembleOnboarding(pred, joinerIA, f.joiner.voting.Cert, f.joiner.root.Cert)
	if err != nil {
		t.Fatal(err)
	}
	if len(trc.Certificates) != len(pred.TRC.Certificates)+1 ||
		!trc.Certificates[len(trc.Certificates)-1].Equal(f.joiner.root.Cert) {

		t.Error("the certificate set did not grow by the joiner's root alone")
	}
	if !slices.Equal(trc.CoreASes, pred.TRC.CoreASes) ||
		!slices.Equal(trc.AuthoritativeASes, pred.TRC.AuthoritativeASes) {

		t.Errorf("AS lists = %v and %v, want the predecessor's", trc.CoreASes,
			trc.AuthoritativeASes)
	}
	update, err := trc.ValidateUpdate(&pred.TRC)
	if err != nil {
		t.Fatalf("cppki refuses the assembled successor: %v", err)
	}
	if update.Type != cppki.SensitiveUpdate {
		t.Errorf("update type = %v, want a sensitive update", update.Type)
	}
	partial, err := SignUpdate(trc, f.joiner.root)
	if err != nil {
		t.Fatal(err)
	}
	completed := f.vote(t, pred, partial)
	if err := completed.Verify(&pred.TRC); err != nil {
		t.Errorf("the completed successor does not verify: %v", err)
	}
	if !Onboarded(trc, joinerIA) || Onboarded(pred.TRC, joinerIA) {
		t.Error("Onboarded does not tell the successor carrying the root from the predecessor")
	}
}

// TestAssembleOnboardingRefusals checks the assembly's fail-fast checks: a
// joiner outside the ISD, a voting certificate that is not the regular
// voting shape, a root certificate that is not a root, either naming another
// ISD-AS, and a joiner the TRC already carries with its root.
func TestAssembleOnboardingRefusals(t *testing.T) {
	f := newCastFixture(t)
	voting, root := f.joiner.voting.Cert, f.joiner.root.Cert

	outside := addr.MustIAFrom(joinerIA.ISD()+1, joinerIA.AS())
	if _, err := AssembleOnboarding(f.founder.trc, outside, voting, root); err == nil {
		t.Error("a joiner outside the ISD was assembled")
	}
	now := time.Now().UTC().Add(signingBackdate).Truncate(time.Second)
	sensitiveCert, err := createVotingCert(joinerIA, f.joiner.voting.Key, true, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AssembleOnboarding(f.founder.trc, joinerIA, sensitiveCert, root); err == nil {
		t.Error("a sensitive voting certificate was assembled in")
	}
	if _, err := AssembleOnboarding(f.founder.trc, joinerIA, voting, voting); err == nil {
		t.Error("a voting certificate was assembled in as the root")
	}
	otherIA := addr.MustIAFrom(joinerIA.ISD(), joinerIA.AS()+1)
	otherIACert, err := createVotingCert(otherIA, f.joiner.voting.Key, false, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AssembleOnboarding(f.founder.trc, joinerIA, otherIACert, root); err == nil {
		t.Error("a voting certificate naming another ISD-AS was assembled in")
	}
	otherIARoot, err := createRootCert(otherIA, f.joiner.root.Key, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AssembleOnboarding(f.founder.trc, joinerIA, voting, otherIARoot); err == nil {
		t.Error("a root certificate naming another ISD-AS was assembled in")
	}
	_, _, completed := f.successor(t)
	if _, err := AssembleOnboarding(completed, joinerIA, voting, root); err == nil {
		t.Error("a joiner the TRC already carries with its root was assembled in again")
	}
}

// TestSignUpdateAndCompletion checks the artifacts the exchange builds in its
// order: the submission carries exactly the joiner's proofs of possession and
// fails the predecessor's verification for want of the vote, the completion
// carries the vote beside them and verifies.
func TestSignUpdateAndCompletion(t *testing.T) {
	f := newCastFixture(t)
	base, partial, completed := f.successor(t)

	if len(partial.SignerInfos) != 2 {
		t.Errorf("the submission carries %d signer infos, want the possession proofs alone",
			len(partial.SignerInfos))
	}
	if err := partial.Verify(&base.TRC); err == nil {
		t.Error("the partially signed update alone verified, want the missing vote refused")
	}
	if len(completed.SignerInfos) != 3 {
		t.Errorf("the completed TRC carries %d signer infos, want the vote and the possession proofs",
			len(completed.SignerInfos))
	}
	if err := completed.Verify(&base.TRC); err != nil {
		t.Errorf("the completed TRC does not verify against the predecessor: %v", err)
	}
}

// fakeCaster stands in for the founder's voting application the JoinCore
// and RollCoreMaterial tests submit to: it decides each submission the control
// plane's own shape — one that verifies as submitted pinned as it is, a
// classifying one voted and pinned — with the holds flag refusing
// everything, the submission that never lands.
type fakeCaster struct {
	keys  CoreKeys
	db    trustdb.DB
	holds bool
	// loses, when set, fails each answer after its decision pinned, the
	// answer lost on its way back.
	loses bool
	// served, when set, is answered in place of the decision, standing in
	// for a founder that completes what it should refuse.
	served cppki.SignedTRC

	submissions int
	// votes counts the submissions the founder's sensitive key co-signed.
	votes int
}

func (c *fakeCaster) SubmitTRC(
	ctx context.Context,
	trc cppki.SignedTRC,
) (cppki.SignedTRC, error) {

	c.submissions++
	if c.holds {
		return cppki.SignedTRC{}, errors.New("the submission was refused")
	}
	if !c.served.IsZero() {
		return c.served, nil
	}
	newest, err := c.db.SignedTRC(ctx, NewestTRCID(coreIA.ISD()))
	if err != nil {
		return cppki.SignedTRC{}, err
	}
	if newest.IsZero() {
		return cppki.SignedTRC{}, errors.New("the founder pinned no TRC")
	}
	if err := trc.Verify(&newest.TRC); err == nil {
		if _, err := c.db.InsertTRC(ctx, trc); err != nil {
			return cppki.SignedTRC{}, err
		}
		return c.answer(trc)
	}
	if _, err := trc.TRC.ValidateUpdate(&newest.TRC); err != nil {
		return cppki.SignedTRC{}, err
	}
	sensitiveCert, err := signerCert(newest.TRC, cppki.Sensitive)
	if err != nil {
		return cppki.SignedTRC{}, err
	}
	completed, err := CoSign(trc, c.keys.Sensitive, sensitiveCert)
	if err != nil {
		return cppki.SignedTRC{}, err
	}
	if err := completed.Verify(&newest.TRC); err != nil {
		return cppki.SignedTRC{}, err
	}
	if _, err := c.db.InsertTRC(ctx, completed); err != nil {
		return cppki.SignedTRC{}, err
	}
	c.votes++
	return c.answer(completed)
}

// answer returns the pinned decision, or fails it when answers are lost.
func (c *fakeCaster) answer(trc cppki.SignedTRC) (cppki.SignedTRC, error) {
	if c.loses {
		return cppki.SignedTRC{}, errors.New("the answer was lost")
	}
	return trc, nil
}

// founderRemote serves the founder's pinned TRCs — the newest among them —
// to the joiner's resolution.
type founderRemote struct {
	db trustdb.DB
}

func (r founderRemote) TRC(
	ctx context.Context,
	id cppki.TRCID,
) (cppki.SignedTRC, error) {

	return r.db.SignedTRC(ctx, id)
}

func (r founderRemote) Chains(
	ctx context.Context,
	q trustdb.ChainQuery,
) ([][]*x509.Certificate, error) {

	return nil, nil
}

func (r founderRemote) RenewChain(
	ctx context.Context,
	csr *x509.CertificateRequest,
	key crypto.Signer,
	chain []*x509.Certificate,
) ([]*x509.Certificate, error) {

	return nil, errors.New("the JoinCore tests enroll beforehand")
}

// newJoinFixture is the joiner with its voting and root material, a founder pinned at
// the base, and the caster between them; the joiner's DB holds whatever it
// resolved.
func newJoinFixture(
	t *testing.T,
) (f *castFixture, joinerDB, founderDB trustdb.DB, caster *fakeCaster) {

	t.Helper()
	f = newCastFixture(t)
	founder := newTestDB(t)
	if _, err := founder.InsertTRC(context.Background(), f.founder.trc); err != nil {
		t.Fatal(err)
	}
	joiner := newTestDB(t)
	if _, err := joiner.InsertTRC(context.Background(), f.founder.trc); err != nil {
		t.Fatal(err)
	}
	return f, joiner, founder, &fakeCaster{keys: f.founder.keys, db: founder}
}

// TestJoinCore checks the onboarding dance end to end against the fake
// founder: the joiner submits its partially signed successor, the founder's
// completion pins on both sides, and a re-presented joiner submits nothing —
// the founder's newest already carries it with its root.
func TestJoinCore(t *testing.T) {
	f, joiner, founder, caster := newJoinFixture(t)
	ctx := context.Background()

	if err := JoinCore(ctx, joiner, founderRemote{db: founder}, caster,
		joinerIA, f.joiner.voting, f.joiner.root); err != nil {

		t.Fatalf("the join failed: %v", err)
	}
	wantID := cppki.TRCID{ISD: coreIA.ISD(), Base: 1, Serial: 2}
	for name, db := range map[string]trustdb.DB{
		"the joiner": joiner, "the founder": founder,
	} {
		pinned, err := db.SignedTRC(ctx, wantID)
		if err != nil {
			t.Fatal(err)
		}
		if pinned.IsZero() {
			t.Fatalf("%s pinned no successor TRC", name)
		}
		if !Onboarded(pinned.TRC, joinerIA) {
			t.Errorf("the TRC %s pinned does not carry the joiner with its root", name)
		}
	}
	if caster.submissions != 1 {
		t.Errorf("submissions = %d, want 1", caster.submissions)
	}

	// The re-presentation: the joiner runs the dance again and submits
	// nothing, the resolved newest already carrying it.
	if err := JoinCore(ctx, joiner, founderRemote{db: founder}, caster,
		joinerIA, f.joiner.voting, f.joiner.root); err != nil {

		t.Fatalf("the re-presented join failed: %v", err)
	}
	if caster.submissions != 1 {
		t.Errorf("submissions after the re-presentation = %d, want still 1",
			caster.submissions)
	}
}

// TestJoinCoreRefused checks the join whose submission never lands: nothing
// pins on either side, and the retry submits again and lands.
func TestJoinCoreRefused(t *testing.T) {
	f, joiner, founder, caster := newJoinFixture(t)
	caster.holds = true
	ctx := context.Background()

	if err := JoinCore(ctx, joiner, founderRemote{db: founder}, caster,
		joinerIA, f.joiner.voting, f.joiner.root); err == nil {

		t.Fatal("the refused join succeeded")
	}
	successor := cppki.TRCID{ISD: coreIA.ISD(), Base: 1, Serial: 2}
	for name, db := range map[string]trustdb.DB{
		"the joiner": joiner, "the founder": founder,
	} {
		pinned, err := db.SignedTRC(ctx, successor)
		if err != nil {
			t.Fatal(err)
		}
		if !pinned.IsZero() {
			t.Errorf("%s pinned something anyway", name)
		}
	}

	// The retry, with the founder taking submissions again, lands.
	caster.holds = false
	if err := JoinCore(ctx, joiner, founderRemote{db: founder}, caster,
		joinerIA, f.joiner.voting, f.joiner.root); err != nil {

		t.Fatalf("the retried join failed: %v", err)
	}
	pinned, err := joiner.SignedTRC(ctx, successor)
	if err != nil {
		t.Fatal(err)
	}
	if pinned.IsZero() || !CoreNamed(pinned.TRC, joinerIA) {
		t.Error("the retried join pinned no successor naming the joiner")
	}
}

// TestJoinCoreBehindAnotherJoin checks the joiner whose view is stale: the
// founder has onboarded another core since the joiner's pin, and the joiner
// resolves the founder's newest — the drafts' numbers-less ask — assembling
// its successor on top of it, not its own stale pin.
func TestJoinCoreBehindAnotherJoin(t *testing.T) {
	f, joiner, founder, caster := newJoinFixture(t)
	ctx := context.Background()

	// Another core joins first: serial 2 on the founder.
	otherIA := addr.MustIAFrom(coreIA.ISD(), joinerIA.AS()+1)
	otherVoting, otherRoot := newJoinerMaterialOf(t, otherIA)
	if err := JoinCore(ctx, newTestDB(t), founderRemote{db: founder}, caster,
		otherIA, otherVoting, otherRoot); err != nil {

		t.Fatalf("the first join failed: %v", err)
	}

	// The joiner holds only the base and joins over the founder's newest.
	if err := JoinCore(ctx, joiner, founderRemote{db: founder}, caster,
		joinerIA, f.joiner.voting, f.joiner.root); err != nil {

		t.Fatalf("the join behind another failed: %v", err)
	}
	pinned, err := joiner.SignedTRC(ctx, cppki.TRCID{ISD: coreIA.ISD(), Base: 1, Serial: 3})
	if err != nil {
		t.Fatal(err)
	}
	if pinned.IsZero() || !CoreNamed(pinned.TRC, joinerIA) {
		t.Error("the join behind another pinned no serial-3 successor naming the joiner")
	}
	if !CoreNamed(pinned.TRC, otherIA) {
		t.Error("the successor dropped the earlier-joined core")
	}
}

// TestJoinCoreRefusesRegularVote checks the forgery the sensitive rules
// exist for: a successor whose vote a regular voting certificate cast reads
// as a regular update that changed the core ASes, and pins nowhere.
func TestJoinCoreRefusesRegularVote(t *testing.T) {
	f, joiner, founder, _ := newJoinFixture(t)
	pred := f.founder.trc
	ctx := context.Background()

	trc, err := AssembleOnboarding(pred, joinerIA, f.joiner.voting.Cert, f.joiner.root.Cert)
	if err != nil {
		t.Fatal(err)
	}
	regularCert, err := signerCert(pred.TRC, cppki.Regular)
	if err != nil {
		t.Fatal(err)
	}
	for i, cert := range pred.TRC.Certificates {
		if cert.Equal(regularCert) {
			trc.Votes = []int{i}
		}
	}
	// The founder's regular voting certificate signs beside the joiner's
	// possession proofs, raw-signed over the forged votes.
	forged, err := signTRCPayload(trc,
		[]*x509.Certificate{f.joiner.voting.Cert, f.joiner.root.Cert, regularCert},
		[]crypto.Signer{f.joiner.voting.Key, f.joiner.root.Key, f.founder.keys.Regular})
	if err != nil {
		t.Fatal(err)
	}
	caster := &fakeCaster{keys: f.founder.keys, db: founder}
	caster.served = forged
	if err := JoinCore(ctx, joiner, founderRemote{db: founder}, caster,
		joinerIA, f.joiner.voting, f.joiner.root); err == nil {

		t.Fatal("a successor voted by a regular certificate was accepted")
	}
	for _, db := range []trustdb.DB{joiner, founder} {
		pinned, err := db.SignedTRC(ctx, trc.ID)
		if err != nil {
			t.Fatal(err)
		}
		if !pinned.IsZero() {
			t.Error("the forged successor pinned")
		}
	}
}

// TestJoinCoreAddsTheRoot checks the onboarding owed by a core onboarded
// before cores held roots: the founder's newest names it without its root,
// and the join submits the root alone, the founder's vote completing it,
// both sides pinning a successor that carries the core with its root.
func TestJoinCoreAddsTheRoot(t *testing.T) {
	f, joiner, founder, caster := newJoinFixture(t)
	ctx := context.Background()
	rootless := f.rootless(t)
	for _, db := range []trustdb.DB{joiner, founder} {
		if _, err := db.InsertTRC(ctx, rootless); err != nil {
			t.Fatal(err)
		}
	}

	if err := JoinCore(ctx, joiner, founderRemote{db: founder}, caster,
		joinerIA, f.joiner.voting, f.joiner.root); err != nil {

		t.Fatalf("the join failed: %v", err)
	}
	if caster.submissions != 1 || caster.votes != 1 {
		t.Errorf("submissions = %d and votes = %d, want one voted submission",
			caster.submissions, caster.votes)
	}
	successor := cppki.TRCID{ISD: coreIA.ISD(), Base: 1, Serial: 3}
	for name, db := range map[string]trustdb.DB{
		"the joiner": joiner, "the founder": founder,
	} {
		pinned, err := db.SignedTRC(ctx, successor)
		if err != nil {
			t.Fatal(err)
		}
		if !Onboarded(pinned.TRC, joinerIA) {
			t.Errorf("the successor %s pinned does not carry the joiner's root", name)
		}
	}
}

// newJoinerMaterialOf returns a fresh regular voting key and a fresh root
// key with their self-signed certificates naming ia, the shapes
// LoadOrCreateVotingCert and LoadOrCreateRootCert persist.
func newJoinerMaterialOf(
	t *testing.T,
	ia addr.IA,
) (voting, root KeyCert) {

	t.Helper()
	for _, kc := range []*KeyCert{&voting, &root} {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		kc.Key = key
	}
	now := time.Now().UTC().Add(signingBackdate).Truncate(time.Second)
	var err error
	if voting.Cert, err = createVotingCert(ia, voting.Key, false, now); err != nil {
		t.Fatal(err)
	}
	if root.Cert, err = createRootCert(ia, root.Key, now); err != nil {
		t.Fatal(err)
	}
	return voting, root
}
