package trust

import (
	"context"
	"crypto"
	"crypto/x509"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/modules/trustdb"
)

// stagedCoreMaterial mints the founder's fresh material: three certificates
// over freshly staged keys, the constructions the predecessor's own
// certificates carry.
func stagedCoreMaterial(
	t *testing.T,
) (CoreKeys, []*x509.Certificate) {

	t.Helper()
	keys, certs, err := stageCoreKeys(t.TempDir(), coreIA)
	if err != nil {
		t.Fatal(err)
	}
	return keys, certs
}

// rotationFixture is a founder whose base TRC has onboarded the joiner: the
// predecessor a roll carries unchanged material beside its own.
type rotationFixture struct {
	*castFixture
	// pred is the pinned successor the rolls assemble on: the base grown by
	// the joiner's onboarding.
	pred cppki.SignedTRC
}

func newRotationFixture(t *testing.T) *rotationFixture {
	t.Helper()
	f := &rotationFixture{castFixture: newCastFixture(t)}
	base, _, completed := f.successor(t)
	if err := completed.Verify(&base.TRC); err != nil {
		t.Fatal(err)
	}
	if _, err := f.founder.db.InsertTRC(context.Background(), completed); err != nil {
		t.Fatal(err)
	}
	f.pred = completed
	return f
}

// completedRotation returns the founder's fully signed rotation over the
// fixture's predecessor: the staged certificates signing beside the live
// sensitive key's vote.
func (f *rotationFixture) completedRotation(
	t *testing.T,
	keys CoreKeys,
	certs []*x509.Certificate,
) cppki.SignedTRC {

	t.Helper()
	pred := f.pred
	trc, err := AssembleRotation(pred, mustCert(t, pred, cppki.Sensitive), certs)
	if err != nil {
		t.Fatal(err)
	}
	partial, err := SignRotation(trc,
		[]crypto.Signer{keys.Sensitive, keys.Regular, keys.Root}, certs)
	if err != nil {
		t.Fatal(err)
	}
	sensitiveCert, err := SignerCert(pred.TRC, cppki.Sensitive)
	if err != nil {
		t.Fatal(err)
	}
	completed, err := CoSign(partial, f.founder.keys.Sensitive, sensitiveCert)
	if err != nil {
		t.Fatal(err)
	}
	return completed
}

// TestAssembleRotation checks the successor the founder's roll assembles
// from the pinned predecessor, its sensitive certificate the voter: the
// serial incremented on the same base, the staged certificates replacing
// their same-named counterparts over fresh keys, every other certificate
// carried unchanged, the quorum and both AS lists untouched, the grace
// period set to the AS certificate validity, and a validity bounded by the
// earliest expiry the carried set holds — cppki reading the result as a
// sensitive update that verifies against the predecessor with the vote and
// the staged certificates' signatures.
func TestAssembleRotation(t *testing.T) {
	f := newRotationFixture(t)
	pred := f.pred
	keys, certs := stagedCoreMaterial(t)

	trc, err := AssembleRotation(pred, mustCert(t, pred, cppki.Sensitive), certs)
	if err != nil {
		t.Fatal(err)
	}
	if have, want := trc.ID, (cppki.TRCID{
		ISD: pred.TRC.ID.ISD, Base: pred.TRC.ID.Base, Serial: pred.TRC.ID.Serial + 1,
	}); have != want {
		t.Errorf("successor ID = %v, want %v", have, want)
	}
	if trc.Quorum != pred.TRC.Quorum {
		t.Errorf("quorum = %d, want the predecessor's %d", trc.Quorum, pred.TRC.Quorum)
	}
	for name, lists := range map[string][2][]addr.AS{
		"core ASes":          {trc.CoreASes, pred.TRC.CoreASes},
		"authoritative ASes": {trc.AuthoritativeASes, pred.TRC.AuthoritativeASes},
	} {
		if lists[0] == nil || len(lists[0]) != len(lists[1]) {
			t.Errorf("%s = %v, want the predecessor's %v", name, lists[0], lists[1])
			continue
		}
		for i := range lists[0] {
			if lists[0][i] != lists[1][i] {
				t.Errorf("%s = %v, want the predecessor's %v", name, lists[0], lists[1])
				break
			}
		}
	}
	if got := trc.GracePeriod; got != ASValidity {
		t.Errorf("grace period = %v, want the AS certificate validity %v", got, ASValidity)
	}
	// The staged certificates replace their counterparts in place, over fresh
	// keys of the same class naming the same ISD-AS; the joiner's
	// certificates the predecessor carries ride unchanged.
	joinerCerts := CertsOf(pred.TRC, joinerIA)
	if len(joinerCerts) == 0 {
		t.Fatal("the predecessor carries no certificate of the joiner")
	}
	replaced := 0
	for i, cert := range trc.Certificates {
		switch {
		case slices.ContainsFunc(joinerCerts, cert.Equal):
			if pred.TRC.Certificates[i].Equal(cert) {
				continue // carried in place
			}
			t.Error("a carried certificate moved inside the set")
		case sameHolder(cert, pred.TRC.Certificates[i]):
			replaced++
			if cert.Equal(pred.TRC.Certificates[i]) {
				t.Error("the replaced certificate is the predecessor's own")
			}
			if string(cert.SubjectKeyId) == string(pred.TRC.Certificates[i].SubjectKeyId) {
				t.Error("the replaced certificate covers the predecessor's key")
			}
			if !KeyMatchesCert(keyOf(t, keys, cert), cert) {
				t.Error("the replaced certificate does not cover the staged key")
			}
		default:
			t.Errorf("position %d changed beyond the staged replacements", i)
		}
	}
	if replaced != len(certs) {
		t.Errorf("replaced %d certificates, want the %d staged", replaced, len(certs))
	}
	// The validity is the window every carried certificate still covers.
	earliest := trc.Certificates[0].NotAfter
	latest := trc.Certificates[0].NotBefore
	for _, cert := range trc.Certificates[1:] {
		if cert.NotAfter.Before(earliest) {
			earliest = cert.NotAfter
		}
		if cert.NotBefore.After(latest) {
			latest = cert.NotBefore
		}
	}
	if !trc.Validity.NotAfter.Equal(earliest) || !trc.Validity.NotBefore.Equal(latest) {
		t.Errorf("validity = %v, want the carried set's window [%v, %v]",
			trc.Validity, latest, earliest)
	}

	// cppki reads the successor as a sensitive update against its
	// predecessor, the vote naming the predecessor's sensitive certificate
	// and every changed voter a new one.
	update, err := trc.ValidateUpdate(&pred.TRC)
	if err != nil {
		t.Fatalf("cppki refuses the assembled successor: %v", err)
	}
	if update.Type != cppki.SensitiveUpdate {
		t.Errorf("update type = %v, want a sensitive update", update.Type)
	}
	if len(update.Votes) != 1 || !update.Votes[0].Equal(mustCert(t, pred, cppki.Sensitive)) {
		t.Errorf("votes = %v, want the predecessor's sensitive certificate", update.Votes)
	}
	completed := f.completedRotation(t, keys, certs)
	if err := completed.Verify(&pred.TRC); err != nil {
		t.Fatalf("the completed rotation does not verify: %v", err)
	}
}

// keyOf returns the staged key the replaced certificate covers.
func keyOf(t *testing.T, keys CoreKeys, cert *x509.Certificate) crypto.Signer {
	t.Helper()
	for _, key := range []crypto.Signer{keys.Sensitive, keys.Regular, keys.Root} {
		if KeyMatchesCert(key, cert) {
			return key
		}
	}
	t.Fatal("no staged key covers the certificate")
	return nil
}

// mustCert returns the predecessor's voting certificate of the type.
func mustCert(t *testing.T, trc cppki.SignedTRC, ct cppki.CertType) *x509.Certificate {
	t.Helper()
	cert, err := SignerCert(trc.TRC, ct)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// TestRotationSignatures checks the signatures the roll demands: the staged
// certificates' proofs of possession alone fail the predecessor's
// verification for want of the vote, the vote alone fails it for want of the
// possession, and only the two together verify.
func TestRotationSignatures(t *testing.T) {
	f := newRotationFixture(t)
	keys, certs := stagedCoreMaterial(t)
	pred := f.pred

	trc, err := AssembleRotation(pred, mustCert(t, pred, cppki.Sensitive), certs)
	if err != nil {
		t.Fatal(err)
	}
	possession, err := SignRotation(trc,
		[]crypto.Signer{keys.Sensitive, keys.Regular, keys.Root}, certs)
	if err != nil {
		t.Fatal(err)
	}
	if err := possession.Verify(&pred.TRC); err == nil {
		t.Error("the proofs of possession alone verified, want the missing vote refused")
	}
	voteOnly, err := signTRCPayload(trc,
		[]*x509.Certificate{mustCert(t, pred, cppki.Sensitive)},
		[]crypto.Signer{f.founder.keys.Sensitive})
	if err != nil {
		t.Fatal(err)
	}
	if err := voteOnly.Verify(&pred.TRC); err == nil {
		t.Error("the vote alone verified, want the missing possession refused")
	}
}

// TestAssembleRotationRefusals checks the assembly's fail-fast checks: no
// staged certificate, one with no counterpart in the predecessor, the
// predecessor's own certificate staged, and a voter the predecessor does not
// carry.
func TestAssembleRotationRefusals(t *testing.T) {
	f := newRotationFixture(t)
	voter := mustCert(t, f.pred, cppki.Sensitive)

	if _, err := AssembleRotation(f.pred, voter, nil); err == nil {
		t.Error("an empty staging was assembled")
	}
	key, err := generateKey()
	if err != nil {
		t.Fatal(err)
	}
	other, err := createVotingCert(
		addr.MustIAFrom(coreIA.ISD(), coreIA.AS()+7), key, false,
		time.Now().UTC().Add(signingBackdate).Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AssembleRotation(f.pred, voter, []*x509.Certificate{other}); err == nil {
		t.Error("a certificate with no counterpart was assembled in")
	}
	if _, err := AssembleRotation(f.pred, voter,
		[]*x509.Certificate{mustCert(t, f.pred, cppki.Root)}); err == nil {
		t.Error("the predecessor's own certificate was staged")
	}
	_, certs := stagedCoreMaterial(t)
	if _, err := AssembleRotation(f.pred, other, certs); err == nil {
		t.Error("a voter the predecessor does not carry was assembled in")
	}
}

// TestRotateCoreKeys checks the founder's own roll end to end: the staged set
// pins as a completed successor while the live files stay the predecessor's,
// promotion against the successor makes the staged keys live as a set and
// removes the staged file, and a live sensitive key the predecessor does not
// name refuses the cast, for the roll has no vote.
func TestRotateCoreKeys(t *testing.T) {
	f := newRotationFixture(t)
	state := f.founder.dir
	ctx := context.Background()

	fresh, completed, err := RotateCoreKeys(ctx, f.founder.db, state, coreIA, f.pred)
	if err != nil {
		t.Fatalf("the founder's roll failed: %v", err)
	}
	pinned, err := f.founder.db.SignedTRC(ctx, completed.TRC.ID)
	if err != nil {
		t.Fatal(err)
	}
	if pinned.IsZero() || string(pinned.Raw) != string(completed.Raw) {
		t.Fatal("the completed rotation did not pin")
	}
	checkCoreKeys(t, liveCoreKeys(t, state), f.founder.keys, "the predecessor's before promotion")
	promoteFounder(t, state, completed)
	checkCoreKeys(t, liveCoreKeys(t, state), fresh, "the staged one after promotion")
	if hasStaged(t, state) {
		t.Error("the staged file outlived its promotion")
	}

	// A live sensitive key the predecessor does not name cannot vote the
	// roll: the terminal corner.
	stranger, err := generateKey()
	if err != nil {
		t.Fatal(err)
	}
	writeKey(t, state, SensitiveKeyFile, stranger)
	if _, _, err := RotateCoreKeys(ctx, f.founder.db, state, coreIA, completed); err == nil {
		t.Error("a roll voted by a key the predecessor does not name succeeded")
	}
}

// sameKey reports whether two signers hold the same public half.
func sameKey(a, b crypto.Signer) bool {
	askid, err := cppki.SubjectKeyID(a.Public())
	if err != nil {
		return false
	}
	bskid, err := cppki.SubjectKeyID(b.Public())
	if err != nil {
		return false
	}
	return string(askid) == string(bskid)
}

// checkCoreKeys fails the test for each key of the set that is not the
// wanted set's, the description naming what the set should be.
func checkCoreKeys(t *testing.T, have, want CoreKeys, desc string) {
	t.Helper()
	for name, pair := range map[string][2]crypto.Signer{
		"sensitive": {have.Sensitive, want.Sensitive},
		"regular":   {have.Regular, want.Regular},
		"root":      {have.Root, want.Root},
		"ca":        {have.CA, want.CA},
	} {
		if !sameKey(pair[0], pair[1]) {
			t.Errorf("the %s key is not %s", name, desc)
		}
	}
}

// liveCoreKeys reads the founder's live keys.
func liveCoreKeys(t *testing.T, state string) CoreKeys {
	t.Helper()
	keys, err := LoadOrCreateCoreKeys(state)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

// newRollFixture brings up the joiner of an onboarded founder — the caster
// deciding on the founder's pinned newest — with the joiner's live voting and
// issuing material, and its issuer anchored in the founder's newest.
func newRollFixture(
	t *testing.T,
) (f *rotationFixture, joiner, founderDB trustdb.DB, caster *fakeCaster, state string,
	issuer *Issuer) {

	t.Helper()
	f = newRotationFixture(t)
	joiner = newTestDB(t)
	for _, trc := range []cppki.SignedTRC{f.founder.trc, f.pred} {
		if _, err := joiner.InsertTRC(context.Background(), trc); err != nil {
			t.Fatal(err)
		}
	}
	founderDB = newTestDB(t)
	for _, trc := range []cppki.SignedTRC{f.founder.trc, f.pred} {
		if _, err := founderDB.InsertTRC(context.Background(), trc); err != nil {
			t.Fatal(err)
		}
	}
	state = t.TempDir()
	ca, err := generateKey()
	if err != nil {
		t.Fatal(err)
	}
	writeVotingPair(t, state, f.joiner.voting.Key, f.joiner.voting.Cert)
	writeRootPair(t, state, f.joiner.root.Key, f.joiner.root.Cert)
	writeKey(t, state, CAKeyFile, ca)
	issuer, err = NewIssuer(joinerIA, IssuerKeys{Root: f.joiner.root.Key, CA: ca}, f.pred)
	if err != nil {
		t.Fatal(err)
	}
	if !issuer.Anchored() {
		t.Fatal("the joiner's issuer is not anchored in the TRC carrying its root")
	}
	caster = &fakeCaster{keys: f.founder.keys, db: founderDB}
	return f, joiner, founderDB, caster, state, issuer
}

// roll runs the joiner's roll against the fixture's founder.
func roll(
	t *testing.T,
	joiner, founderDB trustdb.DB,
	caster *fakeCaster,
	state string,
	issuer *Issuer,
) error {

	t.Helper()
	return RollCoreMaterial(context.Background(), joiner, founderRemote{db: founderDB}, caster,
		joinerIA, state, issuer)
}

// TestRollCoreMaterial checks the authoritative core's roll end to end: the
// submission resolves the founder's newest, the successor replaces exactly
// the joiner's voting and root certificates, both sides pin, the issuer
// issues under the fresh root, and the staged material becomes the live
// material. The routine roll is a regular update the joiner's live keys
// sign — the voting key's signature its vote, the root key's the
// acknowledgment the replaced root owes — the founder casting nothing; a
// live root key or a live voting key the newest TRC does not cover re-rolls
// by sensitive update, the founder voting.
func TestRollCoreMaterial(t *testing.T) {
	f, joiner, founderDB, caster, state, issuer := newRollFixture(t)
	ctx := context.Background()

	if err := roll(t, joiner, founderDB, caster, state, issuer); err != nil {
		t.Fatalf("the roll failed: %v", err)
	}
	successor := cppki.TRCID{ISD: coreIA.ISD(), Base: 1, Serial: f.pred.TRC.ID.Serial + 1}
	original := []*x509.Certificate{f.joiner.voting.Cert, f.joiner.root.Cert}
	for name, db := range map[string]trustdb.DB{
		"the joiner": joiner, "the founder": founderDB,
	} {
		pinned, err := db.SignedTRC(ctx, successor)
		if err != nil {
			t.Fatal(err)
		}
		if pinned.IsZero() {
			t.Fatalf("%s pinned no successor", name)
		}
		checkRolled(t, pinned, original)
		if !CoreNamed(pinned.TRC, coreIA) {
			t.Errorf("%s's successor dropped the founder's material", name)
		}
	}
	pinned, err := joiner.SignedTRC(ctx, successor)
	if err != nil {
		t.Fatal(err)
	}
	checkLiveMaterial(t, state, pinned)
	checkIssuesUnder(t, issuer, pinned)
	update, err := pinned.TRC.ValidateUpdate(&f.pred.TRC)
	if err != nil {
		t.Fatal(err)
	}
	if update.Type != cppki.RegularUpdate {
		t.Errorf("the routine roll's update type = %v, want a regular update", update.Type)
	}
	if len(update.RootAcknowledgments) != 1 ||
		!update.RootAcknowledgments[0].Equal(f.joiner.root.Cert) {

		t.Errorf("root acknowledgments = %v, want the replaced root's", update.RootAcknowledgments)
	}
	if len(pinned.SignerInfos) != 4 {
		t.Errorf("the routine roll carries %d signer infos, want the vote, the "+
			"acknowledgment, and the two possession proofs", len(pinned.SignerInfos))
	}
	if caster.votes != 0 {
		t.Errorf("the founder voted %d times on the routine roll, want none", caster.votes)
	}

	// The mismatch rolls: a live root key, then a live voting key, the
	// newest TRC's certificate does not cover — an operator's replacement —
	// each rolls again by sensitive update, and the rules accept the
	// successor.
	now := time.Now().UTC().Add(signingBackdate).Truncate(time.Second)
	for i, replace := range []func(key crypto.Signer){
		func(key crypto.Signer) {
			cert, err := createRootCert(joinerIA, key, now)
			if err != nil {
				t.Fatal(err)
			}
			writeRootPair(t, state, key, cert)
		},
		func(key crypto.Signer) {
			cert, err := createVotingCert(joinerIA, key, false, now)
			if err != nil {
				t.Fatal(err)
			}
			writeVotingPair(t, state, key, cert)
		},
	} {
		stranger, err := generateKey()
		if err != nil {
			t.Fatal(err)
		}
		replace(stranger)
		pred := pinned
		if err := roll(t, joiner, founderDB, caster, state, issuer); err != nil {
			t.Fatalf("mismatch roll %d failed: %v", i, err)
		}
		rerolled := cppki.TRCID{ISD: coreIA.ISD(), Base: 1, Serial: pred.TRC.ID.Serial + 1}
		pinned, err = joiner.SignedTRC(ctx, rerolled)
		if err != nil {
			t.Fatal(err)
		}
		if pinned.IsZero() {
			t.Fatalf("mismatch roll %d pinned no successor", i)
		}
		checkRolled(t, pinned, CertsOf(pred.TRC, joinerIA))
		checkLiveMaterial(t, state, pinned)
		checkIssuesUnder(t, issuer, pinned)
		update, err := pinned.TRC.ValidateUpdate(&pred.TRC)
		if err != nil {
			t.Fatal(err)
		}
		if update.Type != cppki.SensitiveUpdate {
			t.Errorf("mismatch roll %d's update type = %v, want a sensitive update", i, update.Type)
		}
		if caster.votes != i+1 {
			t.Errorf("the founder voted %d times after mismatch roll %d, want %d",
				caster.votes, i, i+1)
		}
	}
}

// TestRollCoreMaterialRefused checks the roll whose submission never lands:
// the live material is untouched, the fresh material stays staged, and
// nothing pins on either side; the retry with the founder taking submissions
// again submits the staged certificates and lands.
func TestRollCoreMaterialRefused(t *testing.T) {
	f, joiner, founderDB, caster, state, issuer := newRollFixture(t)
	caster.holds = true
	ctx := context.Background()

	before := liveMaterial(t, state)
	if err := roll(t, joiner, founderDB, caster, state, issuer); err == nil {
		t.Fatal("the refused roll succeeded")
	}
	if after := liveMaterial(t, state); string(before) != string(after) {
		t.Error("the refused roll replaced the live material")
	}
	staged := stagedVotingCert(t, state)
	successor := cppki.TRCID{ISD: coreIA.ISD(), Base: 1, Serial: f.pred.TRC.ID.Serial + 1}
	for name, db := range map[string]trustdb.DB{
		"the joiner": joiner, "the founder": founderDB,
	} {
		pinned, err := db.SignedTRC(ctx, successor)
		if err != nil {
			t.Fatal(err)
		}
		if !pinned.IsZero() {
			t.Errorf("%s pinned something anyway", name)
		}
	}

	caster.holds = false
	if err := roll(t, joiner, founderDB, caster, state, issuer); err != nil {
		t.Fatalf("the retried roll failed: %v", err)
	}
	pinned, err := joiner.SignedTRC(ctx, successor)
	if err != nil {
		t.Fatal(err)
	}
	if pinned.IsZero() {
		t.Fatal("the retried roll pinned no successor")
	}
	if !slices.ContainsFunc(CertsOf(pinned.TRC, joinerIA), staged.Equal) {
		t.Error("the retry did not submit the staged certificates")
	}
	checkLiveMaterial(t, state, pinned)
	checkIssuesUnder(t, issuer, pinned)
}

// TestRollCoreMaterialLostAnswer checks the roll whose answer is lost after
// the founder pinned it: the live material is untouched and the fresh
// material stays staged, and the next roll finds the founder's newest naming
// the staged material and promotes it without a submission, the issuer
// taking the promoted keys.
func TestRollCoreMaterialLostAnswer(t *testing.T) {
	f, joiner, founderDB, caster, state, issuer := newRollFixture(t)
	caster.loses = true
	ctx := context.Background()

	before := liveMaterial(t, state)
	if err := roll(t, joiner, founderDB, caster, state, issuer); err == nil {
		t.Fatal("the roll whose answer was lost succeeded")
	}
	if after := liveMaterial(t, state); string(before) != string(after) {
		t.Error("the roll whose answer was lost replaced the live material")
	}
	successor := cppki.TRCID{ISD: coreIA.ISD(), Base: 1, Serial: f.pred.TRC.ID.Serial + 1}
	landed, err := founderDB.SignedTRC(ctx, successor)
	if err != nil {
		t.Fatal(err)
	}
	if landed.IsZero() {
		t.Fatal("the founder pinned no successor")
	}
	if !slices.ContainsFunc(CertsOf(landed.TRC, joinerIA), stagedVotingCert(t, state).Equal) {
		t.Fatal("the founder's successor does not name the staged material")
	}

	// The caster still loses every answer: the roll completes without one.
	submissions := caster.submissions
	if err := roll(t, joiner, founderDB, caster, state, issuer); err != nil {
		t.Fatalf("the roll after the lost answer failed: %v", err)
	}
	if n := caster.submissions - submissions; n != 0 {
		t.Errorf("the roll after the lost answer submitted %d times, want none", n)
	}
	pinned, err := joiner.SignedTRC(ctx, successor)
	if err != nil {
		t.Fatal(err)
	}
	if string(pinned.Raw) != string(landed.Raw) {
		t.Fatal("the joiner did not pin the founder's successor")
	}
	checkLiveMaterial(t, state, pinned)
	checkIssuesUnder(t, issuer, pinned)
}

// liveMaterial reads the joiner's live key and certificate files, for the
// untouched-files check.
func liveMaterial(t *testing.T, state string) []byte {
	t.Helper()
	var raw []byte
	for _, file := range []string{RegularKeyFile, RegularVotingCertFile, RootKeyFile,
		RootCertFile, CAKeyFile} {

		b, err := os.ReadFile(filepath.Join(keyDir(state), file))
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, b...)
	}
	return raw
}

// checkRolled fails the test unless the TRC names two certificates of the
// joiner, neither among the replaced ones.
func checkRolled(t *testing.T, trc cppki.SignedTRC, replaced []*x509.Certificate) {
	t.Helper()
	rolled := CertsOf(trc.TRC, joinerIA)
	if len(rolled) != 2 {
		t.Fatalf("%v names %d certificates of the joiner, want 2", trc.TRC.ID, len(rolled))
	}
	for _, cert := range rolled {
		if slices.ContainsFunc(replaced, cert.Equal) {
			t.Errorf("%v carries a replaced certificate of the joiner", trc.TRC.ID)
		}
	}
}

// checkLiveMaterial fails the test unless the joiner's live voting pair and
// root pair load, each certificate the one the TRC names for the joiner, and
// no staged file remains.
func checkLiveMaterial(t *testing.T, state string, trc cppki.SignedTRC) {
	t.Helper()
	votingKey, err := LoadOrCreateVotingKey(state)
	if err != nil {
		t.Fatal(err)
	}
	votingCert, err := LoadOrCreateVotingCert(state, joinerIA, votingKey)
	if err != nil {
		t.Fatalf("the live voting pair does not load: %v", err)
	}
	keys, err := LoadOrCreateIssuerKeys(state)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := LoadOrCreateRootCert(state, joinerIA, keys.Root)
	if err != nil {
		t.Fatalf("the live root pair does not load: %v", err)
	}
	for _, cert := range []*x509.Certificate{votingCert, rootCert} {
		if !slices.ContainsFunc(CertsOf(trc.TRC, joinerIA), cert.Equal) {
			t.Errorf("the live certificate %s is not one %v names", cert.Subject, trc.TRC.ID)
		}
	}
	if hasStaged(t, state) {
		t.Error("the staged file outlived its promotion")
	}
}

// checkIssuesUnder fails the test unless a chain the issuer issues verifies
// against the TRC alone.
func checkIssuesUnder(t *testing.T, issuer *Issuer, trc cppki.SignedTRC) {
	t.Helper()
	csr, _ := newChainCSR(t, nodeIA)
	chain, err := issuer.IssueChain(csr)
	if err != nil {
		t.Fatal(err)
	}
	if err := cppki.VerifyChain(chain, cppki.VerifyOptions{
		TRC: []*cppki.TRC{&trc.TRC},
	}); err != nil {
		t.Errorf("the issued chain does not verify against %v alone: %v", trc.TRC.ID, err)
	}
}

// stagedVotingCert reads the voting certificate the joiner's roll staged.
func stagedVotingCert(t *testing.T, state string) *x509.Certificate {
	t.Helper()
	blocks, err := readStaged(state)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := stagedCert(blocks, RegularVotingCertFile)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// TestAnchorPoolRidesGrace checks the anchor pool the draft's grace defines:
// while the successor is within its grace period the predecessor's roots
// anchor chains beside the successor's — a chain issued under the replaced
// root keeps verifying — and past the window only the successor's do. A
// later rung inside the window resets it: its pool holds it and the rung
// before it, and no TRC before that. The chains issue under the fresh root
// from the pin on, and the engine's local pool matches at every step.
func TestAnchorPoolRidesGrace(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newGenesisFixture(t)
		ctx := context.Background()
		issuer, err := NewIssuer(coreIA, f.keys.IssuerKeys, f.trc)
		if err != nil {
			t.Fatal(err)
		}
		engine := NewEngine(coreIA, newTestASKey(t), &NetworkProvider{DB: f.db})
		// anchors returns the anchor pool, failing the test unless the
		// engine's local pool holds the same TRCs.
		anchors := func() []*cppki.TRC {
			t.Helper()
			pool, err := anchorPool(ctx, f.db, nil, coreIA.ISD())
			if err != nil {
				t.Fatal(err)
			}
			local, err := engine.AnchorPool()
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(trcIDs(pool), trcIDs(local)); diff != "" {
				t.Errorf("the engine's local pool differs (-provider +local):\n%s", diff)
			}
			return pool
		}
		// The chain issued under the replaced-to-be root.
		oldCSR, _ := newChainCSR(t, nodeIA)
		oldChain, err := issuer.IssueChain(oldCSR)
		if err != nil {
			t.Fatal(err)
		}
		fresh, completed, err := RotateCoreKeys(ctx, f.db, f.dir, coreIA, f.trc)
		if err != nil {
			t.Fatal(err)
		}
		if err := issuer.Rekey(fresh.IssuerKeys, completed); err != nil {
			t.Fatal(err)
		}
		promoteFounder(t, f.dir, completed)

		// In grace: the pool carries the predecessor beside the successor,
		// and the old chain verifies against it.
		pool := anchors()
		if len(pool) != 2 {
			t.Fatalf("the in-grace pool holds %d TRCs, want the successor and its predecessor",
				len(pool))
		}
		if err := cppki.VerifyChain(oldChain, cppki.VerifyOptions{TRC: pool}); err != nil {
			t.Errorf("the chain under the replaced root does not verify in grace: %v", err)
		}
		// The chains issue under the fresh root from the pin on.
		newCSR, _ := newChainCSR(t, nodeIA)
		newChain, err := issuer.IssueChain(newCSR)
		if err != nil {
			t.Fatal(err)
		}
		if err := cppki.VerifyChain(newChain, cppki.VerifyOptions{
			TRC: []*cppki.TRC{&completed.TRC},
		}); err != nil {
			t.Errorf("the chain under the fresh root does not verify against the successor: %v", err)
		}

		// A later rung lands inside the first window and resets it: its pool
		// holds it and the rung before it, so the rung-1 chain verifies
		// through it, and the base-root chain, a day short of its expiry, no
		// longer does.
		time.Sleep(2 * 24 * time.Hour)
		fresh2, completed2, err := RotateCoreKeys(ctx, f.db, f.dir, coreIA, completed)
		if err != nil {
			t.Fatal(err)
		}
		if err := issuer.Rekey(fresh2.IssuerKeys, completed2); err != nil {
			t.Fatal(err)
		}
		pool = anchors()
		if diff := cmp.Diff([]cppki.TRCID{completed2.TRC.ID, completed.TRC.ID},
			trcIDs(pool)); diff != "" {
			t.Fatalf("the later rung's pool, want it and the rung before it (-want +got):\n%s",
				diff)
		}
		if err := cppki.VerifyChain(newChain, cppki.VerifyOptions{TRC: pool}); err != nil {
			t.Errorf("the rung-1 chain does not verify through the later rung's grace: %v", err)
		}
		if err := cppki.VerifyChain(oldChain, cppki.VerifyOptions{TRC: pool}); err == nil {
			t.Error("the base-root chain verified past the later rung, want the window reset")
		}

		// Past the later rung's grace window: the predecessor's roots anchor
		// nothing, and the rung-1 chain no longer verifies — by then it has
		// expired as well, the arithmetic closing by construction.
		time.Sleep(ASValidity + time.Minute)
		pool = anchors()
		if len(pool) != 1 {
			t.Fatalf("the past-grace pool holds %d TRCs, want the successor alone", len(pool))
		}
		if err := cppki.VerifyChain(newChain, cppki.VerifyOptions{TRC: pool}); err == nil {
			t.Error("the rung-1 chain outlived the window that carried it")
		}
	})
}

// trcIDs returns the IDs of the TRCs, in order.
func trcIDs(trcs []*cppki.TRC) []cppki.TRCID {
	ids := make([]cppki.TRCID, 0, len(trcs))
	for _, trc := range trcs {
		ids = append(ids, trc.ID)
	}
	return ids
}

// newChainCSR returns a CSR for a freshly generated AS key naming the IA.
func newChainCSR(t *testing.T, ia addr.IA) (*x509.CertificateRequest, crypto.Signer) {
	t.Helper()
	key, err := generateKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := CreateCSR(ia, key)
	if err != nil {
		t.Fatal(err)
	}
	return csr, key
}

// TestFounderRootTakesTheHoldersName checks the founder's root minted under
// the name every root once shared: the roll pairs the fresh root with it by
// class and ISD-AS, and the successor carries the root under its holder's
// name, verifying against the predecessor.
func TestFounderRootTakesTheHoldersName(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	keys, err := LoadOrCreateCoreKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Add(signingBackdate).Truncate(time.Second)
	sensitive, err := createVotingCert(coreIA, keys.Sensitive, true, now)
	if err != nil {
		t.Fatal(err)
	}
	regular, err := createVotingCert(coreIA, keys.Regular, false, now)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := createRootCert(coreIA, keys.Root, now)
	if err != nil {
		t.Fatal(err)
	}
	// The root under the shared name: the same construction, renamed.
	tmpl := *shared
	tmpl.Subject, tmpl.RawSubject = subject(coreIA, "cp root"), nil
	legacy, err := createCertificate(&tmpl, &tmpl, keys.Root.Public(), keys.Root)
	if err != nil {
		t.Fatal(err)
	}
	if legacy.Subject.CommonName != "cp root" {
		t.Fatalf("the legacy root is named %q, want the shared name", legacy.Subject.CommonName)
	}
	base, err := signTRC(cppki.TRC{
		Version:           1,
		ID:                cppki.TRCID{ISD: coreIA.ISD(), Base: 1, Serial: 1},
		Validity:          cppki.Validity{NotBefore: now, NotAfter: now.Add(TRCValidity)},
		Quorum:            1,
		CoreASes:          []addr.AS{coreIA.AS()},
		AuthoritativeASes: []addr.AS{coreIA.AS()},
		Description:       "a base TRC from before roots named their holders",
		Certificates:      []*x509.Certificate{sensitive, regular, legacy},
	}, keys)
	if err != nil {
		t.Fatal(err)
	}
	db := newTestDB(t)
	if _, err := db.InsertTRC(ctx, base); err != nil {
		t.Fatal(err)
	}

	_, completed, err := RotateCoreKeys(ctx, db, dir, coreIA, base)
	if err != nil {
		t.Fatalf("the roll of the root under the shared name failed: %v", err)
	}
	root := heldCert(completed.TRC, coreIA, cppki.Root)
	if root == nil || root.Subject.CommonName != coreIA.String()+" cp root" {
		t.Errorf("the rolled root = %v, want it named after its holder", root)
	}
	if err := completed.Verify(&base.TRC); err != nil {
		t.Errorf("the successor does not verify against the predecessor: %v", err)
	}
}
