package trust

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/modules/trustdb"
)

// joinerIA is the joining core the assembly tests onboard.
var joinerIA = addr.MustIAFrom(20, 0xff0000000f01)

// newJoinerMaterial returns the joiner's regular voting key and self-signed
// certificate, the shape LoadOrCreateVotingCert persists.
func newJoinerMaterial(t *testing.T) (crypto.Signer, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Add(signingBackdate).Truncate(time.Second)
	cert, err := createVotingCert(joinerIA, key, false, now)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

// castFixture is a founder with its base TRC pinned and the joiner's voting
// material beside it.
type castFixture struct {
	founder *genesisFixture
	joiner  struct {
		key  crypto.Signer
		cert *x509.Certificate
	}
}

func newCastFixture(t *testing.T) *castFixture {
	t.Helper()
	f := &castFixture{founder: newGenesisFixture(t)}
	f.joiner.key, f.joiner.cert = newJoinerMaterial(t)
	return f
}

// newSuccessorFixture builds the base TRC, the joiner's partially signed
// successor, and the founder-completed TRC, in the exchange's own order: the
// joiner assembles and signs the proof of possession, the founder adds its
// sensitive vote.
func (f *castFixture) successor(
	t *testing.T,
) (base, partial, completed cppki.SignedTRC) {

	t.Helper()
	base = f.founder.trc
	trc, err := AssembleOnboarding(base, joinerIA, f.joiner.cert)
	if err != nil {
		t.Fatal(err)
	}
	partial, err = SignUpdate(trc, f.joiner.key, f.joiner.cert)
	if err != nil {
		t.Fatal(err)
	}
	sensitiveCert, err := signerCert(base.TRC, cppki.Sensitive)
	if err != nil {
		t.Fatal(err)
	}
	completed, err = CoSign(partial, f.founder.keys.Sensitive, sensitiveCert)
	if err != nil {
		t.Fatal(err)
	}
	return base, partial, completed
}

// TestAssembleOnboarding checks the successor the joiner assembles from the
// newest pinned TRC: the serial incremented on the same base, both AS lists
// grown by the joiner, the certificate set grown by its regular voting
// certificate, the quorum untouched, a validity bounded by the earliest
// expiry the set carries, and cppki reading the result as a sensitive update
// that verifies against the predecessor.
func TestAssembleOnboarding(t *testing.T) {
	f := newCastFixture(t)
	pred := f.founder.trc

	trc, err := AssembleOnboarding(pred, joinerIA, f.joiner.cert)
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
	if len(trc.Certificates) != len(pred.TRC.Certificates)+1 {
		t.Errorf("certificates = %d, want the predecessor's set grown by one",
			len(trc.Certificates))
	}
	if !trc.Certificates[len(trc.Certificates)-1].Equal(f.joiner.cert) {
		t.Error("the grown certificate is not the joiner's regular voting certificate")
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
	if trc.Validity.NotBefore.Before(f.joiner.cert.NotBefore) {
		t.Errorf("validity starts at %v, before the joiner's certificate covers",
			trc.Validity.NotBefore)
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
	if len(update.NewVoters) != 1 || !update.NewVoters[0].Equal(f.joiner.cert) {
		t.Errorf("new voters = %v, want the joiner's certificate alone", update.NewVoters)
	}
}

// TestAssembleOnboardingRefusals checks the assembly's fail-fast checks: a
// joiner outside the ISD, a certificate that is not the regular voting
// shape, one naming another ISD-AS, and a joiner the TRC already names.
func TestAssembleOnboardingRefusals(t *testing.T) {
	f := newCastFixture(t)

	outside := addr.MustIAFrom(joinerIA.ISD()+1, joinerIA.AS())
	if _, err := AssembleOnboarding(f.founder.trc, outside, f.joiner.cert); err == nil {
		t.Error("a joiner outside the ISD was assembled")
	}
	now := time.Now().UTC().Add(signingBackdate).Truncate(time.Second)
	sensitiveCert, err := createVotingCert(joinerIA, f.joiner.key, true, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AssembleOnboarding(f.founder.trc, joinerIA, sensitiveCert); err == nil {
		t.Error("a sensitive voting certificate was assembled in")
	}
	otherIACert, err := createVotingCert(
		addr.MustIAFrom(joinerIA.ISD(), joinerIA.AS()+1), f.joiner.key, false, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AssembleOnboarding(f.founder.trc, joinerIA, otherIACert); err == nil {
		t.Error("a certificate naming another ISD-AS was assembled in")
	}
	_, _, completed := f.successor(t)
	if _, err := AssembleOnboarding(completed, joinerIA, f.joiner.cert); err == nil {
		t.Error("a joiner the TRC already names was assembled in again")
	}
}

// TestSignUpdateAndCompletion checks the artifacts the exchange builds in its
// order: the submission carries exactly the joiner's proof of possession and
// fails the predecessor's verification for want of the vote, the completion
// carries the vote beside it and verifies.
func TestSignUpdateAndCompletion(t *testing.T) {
	f := newCastFixture(t)
	base, partial, completed := f.successor(t)

	if len(partial.SignerInfos) != 1 {
		t.Errorf("the submission carries %d signer infos, want the proof of possession alone",
			len(partial.SignerInfos))
	}
	if err := partial.Verify(&base.TRC); err == nil {
		t.Error("the partially signed update alone verified, want the missing vote refused")
	}
	if len(completed.SignerInfos) != 2 {
		t.Errorf("the completed TRC carries %d signer infos, want the vote and the possession proof",
			len(completed.SignerInfos))
	}
	if err := completed.Verify(&base.TRC); err != nil {
		t.Errorf("the completed TRC does not verify against the predecessor: %v", err)
	}
}

// fakeCaster stands in for the founder's voting application the JoinCore
// tests submit to: it decides each submission the control plane's own shape
// — the already-named answered with the pin, a classifying submission voted
// and pinned — with the holds flag refusing everything, the join whose
// submission never lands.
type fakeCaster struct {
	keys  CoreKeys
	db    trustdb.DB
	holds bool
	// served, when set, is answered in place of the decision, standing in
	// for a founder that completes what it should refuse.
	served cppki.SignedTRC

	submissions int
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
	newest, err := c.db.SignedTRC(ctx, newestTRCID(coreIA.ISD()))
	if err != nil {
		return cppki.SignedTRC{}, err
	}
	if newest.IsZero() {
		return cppki.SignedTRC{}, errors.New("the founder pinned no TRC")
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
	return completed, nil
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
) ([]*x509.Certificate, error) {

	return nil, errors.New("the JoinCore tests enroll beforehand")
}

// newJoinFixture is the joiner with its voting material, a founder pinned at
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
// the founder's newest already names it.
func TestJoinCore(t *testing.T) {
	f, joiner, founder, caster := newJoinFixture(t)
	ctx := context.Background()

	if err := JoinCore(ctx, joiner, founderRemote{db: founder}, caster,
		joinerIA, f.joiner.key, f.joiner.cert); err != nil {

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
		if !CoreNamed(pinned.TRC, joinerIA) {
			t.Errorf("the TRC %s pinned does not name the joiner", name)
		}
	}
	if caster.submissions != 1 {
		t.Errorf("submissions = %d, want 1", caster.submissions)
	}

	// The re-presentation: the joiner runs the dance again and submits
	// nothing, the resolved newest already naming it.
	if err := JoinCore(ctx, joiner, founderRemote{db: founder}, caster,
		joinerIA, f.joiner.key, f.joiner.cert); err != nil {

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
		joinerIA, f.joiner.key, f.joiner.cert); err == nil {

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
		joinerIA, f.joiner.key, f.joiner.cert); err != nil {

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
	otherKey, otherCert := newJoinerMaterialOf(t, otherIA)
	if err := JoinCore(ctx, newTestDB(t), founderRemote{db: founder}, caster,
		otherIA, otherKey, otherCert); err != nil {

		t.Fatalf("the first join failed: %v", err)
	}

	// The joiner holds only the base and joins over the founder's newest.
	if err := JoinCore(ctx, joiner, founderRemote{db: founder}, caster,
		joinerIA, f.joiner.key, f.joiner.cert); err != nil {

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

	trc, err := AssembleOnboarding(pred, joinerIA, f.joiner.cert)
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
	// possession proof, raw-signed over the forged votes.
	forged, err := signTRCPayload(trc,
		[]*x509.Certificate{f.joiner.cert, regularCert},
		[]crypto.Signer{f.joiner.key, f.founder.keys.Regular})
	if err != nil {
		t.Fatal(err)
	}
	caster := &fakeCaster{keys: f.founder.keys, db: founder}
	caster.served = forged
	if err := JoinCore(ctx, joiner, founderRemote{db: founder}, caster,
		joinerIA, f.joiner.key, f.joiner.cert); err == nil {

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

// newJoinerMaterialOf returns fresh voting material naming the given IA.
func newJoinerMaterialOf(
	t *testing.T,
	ia addr.IA,
) (crypto.Signer, *x509.Certificate) {

	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Add(signingBackdate).Truncate(time.Second)
	cert, err := createVotingCert(ia, key, false, now)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}
