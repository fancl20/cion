package trust

import (
	"context"
	"crypto"
	"crypto/x509"
	"os"
	"path/filepath"
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
	// keys under the same distinguished names; the joiner's certificate the
	// predecessor carries rides unchanged.
	var joinerCert *x509.Certificate
	for _, cert := range pred.TRC.Certificates {
		if certIA, err := cppki.ExtractIA(cert.Subject); err == nil && certIA.Equal(joinerIA) {
			joinerCert = cert
		}
	}
	if joinerCert == nil {
		t.Fatal("the predecessor carries no certificate of the joiner")
	}
	replaced := 0
	for i, cert := range trc.Certificates {
		switch {
		case cert.Equal(joinerCert):
			if pred.TRC.Certificates[i].Equal(cert) {
				continue // carried in place
			}
			t.Error("the carried certificate moved inside the set")
		case sameSubject(cert.Subject, pred.TRC.Certificates[i].Subject):
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
// deciding on the founder's pinned newest — and the joiner's live voting
// pair.
func newRollFixture(
	t *testing.T,
) (f *rotationFixture, joiner, founderDB trustdb.DB, caster *fakeCaster, state string) {

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
	writeVotingPair(t, state, f.joiner.key, f.joiner.cert)
	return f, joiner, founderDB, &fakeCaster{keys: f.founder.keys, db: founderDB}, state
}

// TestRollVotingKey checks the authoritative core's roll end to end: the
// submission resolves the founder's newest, the successor replaces exactly
// the joiner's certificate, both sides pin, and the staged pair becomes the
// live pair. The routine roll is a regular update the joiner's live key
// votes on, the founder casting nothing; a live pair the newest TRC does not
// name re-rolls by sensitive update, the founder voting.
func TestRollVotingKey(t *testing.T) {
	f, joiner, founderDB, caster, state := newRollFixture(t)
	ctx := context.Background()

	if err := RollVotingKey(ctx, joiner, founderRemote{db: founderDB}, caster,
		joinerIA, state); err != nil {

		t.Fatalf("the roll failed: %v", err)
	}
	successor := cppki.TRCID{ISD: coreIA.ISD(), Base: 1, Serial: f.pred.TRC.ID.Serial + 1}
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
		rolled := CertsOf(pinned.TRC, joinerIA)
		if len(rolled) != 1 || rolled[0].Equal(f.joiner.cert) {
			t.Errorf("%s's successor carries the joiner's old certificate", name)
		}
		if !CoreNamed(pinned.TRC, coreIA) {
			t.Errorf("%s's successor dropped the founder's material", name)
		}
	}
	pinned, err := joiner.SignedTRC(ctx, successor)
	if err != nil {
		t.Fatal(err)
	}
	checkLivePair(t, state, pinned)
	update, err := pinned.TRC.ValidateUpdate(&f.pred.TRC)
	if err != nil {
		t.Fatal(err)
	}
	if update.Type != cppki.RegularUpdate {
		t.Errorf("the routine roll's update type = %v, want a regular update", update.Type)
	}
	if len(pinned.SignerInfos) != 2 {
		t.Errorf("the routine roll carries %d signer infos, want the vote and the possession proof",
			len(pinned.SignerInfos))
	}
	if caster.votes != 0 {
		t.Errorf("the founder voted %d times on the routine roll, want none", caster.votes)
	}

	// The mismatch roll: a live pair the newest TRC's certificate does not
	// cover — an operator's replacement — rolls again, and the rules accept
	// the successor.
	stranger, err := generateKey()
	if err != nil {
		t.Fatal(err)
	}
	strangerCert, err := createVotingCert(joinerIA, stranger, false,
		time.Now().UTC().Add(signingBackdate).Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	writeVotingPair(t, state, stranger, strangerCert)
	if err := RollVotingKey(ctx, joiner, founderRemote{db: founderDB}, caster,
		joinerIA, state); err != nil {

		t.Fatalf("the mismatch roll failed: %v", err)
	}
	rerolled := cppki.TRCID{ISD: coreIA.ISD(), Base: 1, Serial: successor.Serial + 1}
	repinned, err := joiner.SignedTRC(ctx, rerolled)
	if err != nil {
		t.Fatal(err)
	}
	if repinned.IsZero() {
		t.Fatal("the re-roll pinned no successor")
	}
	rolled := CertsOf(repinned.TRC, joinerIA)
	if len(rolled) != 1 || rolled[0].Equal(f.joiner.cert) {
		t.Error("the re-roll carried the joiner's original certificate")
	}
	checkLivePair(t, state, repinned)
	update, err = repinned.TRC.ValidateUpdate(&pinned.TRC)
	if err != nil {
		t.Fatal(err)
	}
	if update.Type != cppki.SensitiveUpdate {
		t.Errorf("the re-roll's update type = %v, want a sensitive update", update.Type)
	}
	if caster.votes != 1 {
		t.Errorf("the founder voted %d times after the re-roll, want 1", caster.votes)
	}
}

// TestRollVotingKeyRefused checks the roll whose submission never lands: the
// live pair is untouched, the fresh pair stays staged, and nothing pins on
// either side; the retry with the founder taking submissions again submits
// the staged certificate and lands.
func TestRollVotingKeyRefused(t *testing.T) {
	f, joiner, founderDB, caster, state := newRollFixture(t)
	caster.holds = true
	ctx := context.Background()

	before := livePair(t, state)
	if err := RollVotingKey(ctx, joiner, founderRemote{db: founderDB}, caster,
		joinerIA, state); err == nil {

		t.Fatal("the refused roll succeeded")
	}
	if after := livePair(t, state); string(before) != string(after) {
		t.Error("the refused roll replaced the live pair")
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
	if err := RollVotingKey(ctx, joiner, founderRemote{db: founderDB}, caster,
		joinerIA, state); err != nil {

		t.Fatalf("the retried roll failed: %v", err)
	}
	pinned, err := joiner.SignedTRC(ctx, successor)
	if err != nil {
		t.Fatal(err)
	}
	if pinned.IsZero() {
		t.Fatal("the retried roll pinned no successor")
	}
	if rolled := CertsOf(pinned.TRC, joinerIA); len(rolled) != 1 || !rolled[0].Equal(staged) {
		t.Error("the retry did not submit the staged certificate")
	}
	checkLivePair(t, state, pinned)
}

// TestRollVotingKeyLostAnswer checks the roll whose answer is lost after the
// founder pinned it: the live pair is untouched and the fresh pair stays
// staged, and the next roll finds the founder's newest naming the staged
// pair and promotes it without a submission.
func TestRollVotingKeyLostAnswer(t *testing.T) {
	f, joiner, founderDB, caster, state := newRollFixture(t)
	caster.loses = true
	ctx := context.Background()

	before := livePair(t, state)
	if err := RollVotingKey(ctx, joiner, founderRemote{db: founderDB}, caster,
		joinerIA, state); err == nil {

		t.Fatal("the roll whose answer was lost succeeded")
	}
	if after := livePair(t, state); string(before) != string(after) {
		t.Error("the roll whose answer was lost replaced the live pair")
	}
	successor := cppki.TRCID{ISD: coreIA.ISD(), Base: 1, Serial: f.pred.TRC.ID.Serial + 1}
	landed, err := founderDB.SignedTRC(ctx, successor)
	if err != nil {
		t.Fatal(err)
	}
	if landed.IsZero() {
		t.Fatal("the founder pinned no successor")
	}
	if rolled := CertsOf(landed.TRC, joinerIA); len(rolled) != 1 ||
		!rolled[0].Equal(stagedVotingCert(t, state)) {

		t.Fatal("the founder's successor does not name the staged pair")
	}

	// The caster still loses every answer: the roll completes without one.
	submissions := caster.submissions
	if err := RollVotingKey(ctx, joiner, founderRemote{db: founderDB}, caster,
		joinerIA, state); err != nil {

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
	checkLivePair(t, state, pinned)
}

// livePair reads the joiner's live key and certificate files, for the
// untouched-files check.
func livePair(t *testing.T, state string) []byte {
	t.Helper()
	var raw []byte
	for _, file := range []string{RegularKeyFile, RegularVotingCertFile} {
		b, err := os.ReadFile(filepath.Join(keyDir(state), file))
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, b...)
	}
	return raw
}

// checkLivePair fails the test unless the joiner's live key and certificate
// load as a pair, the certificate the one the TRC names for the joiner, and
// no staged file remains.
func checkLivePair(t *testing.T, state string, trc cppki.SignedTRC) {
	t.Helper()
	named := CertsOf(trc.TRC, joinerIA)
	if len(named) != 1 {
		t.Fatalf("%v names %d certificates of the joiner, want 1", trc.TRC.ID, len(named))
	}
	key, err := LoadOrCreateVotingKey(state)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := LoadOrCreateVotingCert(state, joinerIA, key)
	if err != nil {
		t.Fatalf("the live pair does not load: %v", err)
	}
	if !cert.Equal(named[0]) {
		t.Errorf("the live certificate is not the one %v names", trc.TRC.ID)
	}
	if hasStaged(t, state) {
		t.Error("the staged file outlived its promotion")
	}
}

// stagedVotingCert reads the certificate the joiner's roll staged.
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
		issuer, err := NewIssuer(coreIA, f.keys, f.trc)
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
		if err := issuer.Rekey(fresh, completed); err != nil {
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
		if err := issuer.Rekey(fresh2, completed2); err != nil {
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
