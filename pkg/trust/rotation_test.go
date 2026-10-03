package trust

import (
	"context"
	"crypto"
	"crypto/x509"
	"os"
	"testing"
	"testing/synctest"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/modules/trustdb"
)

// stagedCoreMaterial mints the founder's fresh material: three certificates
// over fresh keys, the constructions the predecessor's own certificates
// carry.
func stagedCoreMaterial(
	t *testing.T,
) (CoreKeys, []*x509.Certificate) {

	t.Helper()
	keys, certs, err := stageCoreKeys(coreIA, newGenesisFixture(t).trc)
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
// fixture's predecessor: the staged certificates signing beside the
// persisted sensitive key's vote.
func (f *rotationFixture) completedRotation(
	t *testing.T,
	keys CoreKeys,
	certs []*x509.Certificate,
) cppki.SignedTRC {

	t.Helper()
	pred := f.pred
	trc, err := AssembleRotation(pred, certs)
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

// TestAssembleRotation checks the successor a roll assembles from the pinned
// predecessor: the serial incremented on the same base, the staged
// certificates replacing their same-named counterparts over fresh keys,
// every other certificate carried unchanged, the quorum and both AS lists
// untouched, the grace period set to the AS certificate validity, and a
// validity bounded by the earliest expiry the carried set holds — cppki
// reading the result as a sensitive update that verifies against the
// predecessor with the vote and the staged certificates' signatures.
func TestAssembleRotation(t *testing.T) {
	f := newRotationFixture(t)
	pred := f.pred
	keys, certs := stagedCoreMaterial(t)

	trc, err := AssembleRotation(pred, certs)
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

	trc, err := AssembleRotation(pred, certs)
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
// staged certificate, one with no counterpart in the predecessor, and the
// predecessor's own certificate staged.
func TestAssembleRotationRefusals(t *testing.T) {
	f := newRotationFixture(t)

	if _, err := AssembleRotation(f.pred, nil); err == nil {
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
	if _, err := AssembleRotation(f.pred, []*x509.Certificate{other}); err == nil {
		t.Error("a certificate with no counterpart was assembled in")
	}
	if _, err := AssembleRotation(f.pred,
		[]*x509.Certificate{mustCert(t, f.pred, cppki.Root)}); err == nil {
		t.Error("the predecessor's own certificate was staged")
	}
}

// TestRotateCoreKeys checks the founder's own roll end to end: the staged set
// pins as a completed successor, the persisted files are replaced as a set
// with the fresh keys, and the persisted sensitive key the predecessor does
// not name refuses the cast, for the roll has no vote.
func TestRotateCoreKeys(t *testing.T) {
	f := newRotationFixture(t)
	state := t.TempDir()
	if err := PersistCoreKeys(state, f.founder.keys); err != nil {
		t.Fatal(err)
	}
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
	persisted, err := LoadOrCreateCoreKeys(state)
	if err != nil {
		t.Fatal(err)
	}
	for name, pair := range map[string][2]crypto.Signer{
		"sensitive": {persisted.Sensitive, fresh.Sensitive},
		"regular":   {persisted.Regular, fresh.Regular},
		"root":      {persisted.Root, fresh.Root},
		"ca":        {persisted.CA, fresh.CA},
	} {
		if !sameKey(pair[0], pair[1]) {
			t.Errorf("the persisted %s key is not the staged one", name)
		}
	}

	// A persisted sensitive key the predecessor does not name cannot vote the
	// roll: the terminal corner.
	stranger, err := generateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := PersistCoreKeys(state, CoreKeys{
		Sensitive: stranger, Regular: fresh.Regular, Root: fresh.Root, CA: fresh.CA,
	}); err != nil {
		t.Fatal(err)
	}
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

// newRollFixture brings up the joiner of an onboarded founder — the caster
// deciding on the founder's pinned newest — and the joiner's persisted voting
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
	if err := PersistVotingPair(state, f.joiner.key, f.joiner.cert); err != nil {
		t.Fatal(err)
	}
	return f, joiner, founderDB, &fakeCaster{keys: f.founder.keys, db: founderDB}, state
}

// TestRollVotingKey checks the authoritative core's roll end to end: the
// submission resolves the founder's newest, the successor replaces exactly
// the joiner's certificate, both sides pin, and the staged pair persists
// beside its key.
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
	key, err := LoadOrCreateVotingKey(state)
	if err != nil {
		t.Fatal(err)
	}
	pinned, err := joiner.SignedTRC(ctx, successor)
	if err != nil {
		t.Fatal(err)
	}
	if !KeyMatchesCert(key, CertsOf(pinned.TRC, joinerIA)[0]) {
		t.Error("the persisted key does not cover the successor's certificate")
	}

	// The mismatch roll: a persisted pair the newest TRC's certificate does
	// not cover — the crash between a pin and its persist, or an operator's
	// replacement — rolls again, and the rules accept the successor.
	stranger, err := generateKey()
	if err != nil {
		t.Fatal(err)
	}
	strangerCert, err := createVotingCert(joinerIA, stranger, false,
		time.Now().UTC().Add(signingBackdate).Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := PersistVotingPair(state, stranger, strangerCert); err != nil {
		t.Fatal(err)
	}
	if err := RollVotingKey(ctx, joiner, founderRemote{db: founderDB}, caster,
		joinerIA, state); err != nil {

		t.Fatalf("the mismatch roll failed: %v", err)
	}
	rerolled := cppki.TRCID{ISD: coreIA.ISD(), Base: 1, Serial: successor.Serial + 1}
	pinned, err = joiner.SignedTRC(ctx, rerolled)
	if err != nil {
		t.Fatal(err)
	}
	if pinned.IsZero() {
		t.Fatal("the re-roll pinned no successor")
	}
	rolled := CertsOf(pinned.TRC, joinerIA)
	if len(rolled) != 1 || rolled[0].Equal(f.joiner.cert) {
		t.Error("the re-roll carried the joiner's original certificate")
	}
	key, err = LoadOrCreateVotingKey(state)
	if err != nil {
		t.Fatal(err)
	}
	if !KeyMatchesCert(key, rolled[0]) {
		t.Error("the persisted key does not cover the re-roll's certificate")
	}
}

// TestRollVotingKeyRefused checks the roll whose submission never lands: the
// persisted pair is untouched and nothing pins on either side, and the retry
// with the founder taking submissions again lands.
func TestRollVotingKeyRefused(t *testing.T) {
	f, joiner, founderDB, caster, state := newRollFixture(t)
	caster.holds = true
	ctx := context.Background()

	before := persistedPair(t, state)
	if err := RollVotingKey(ctx, joiner, founderRemote{db: founderDB}, caster,
		joinerIA, state); err == nil {

		t.Fatal("the refused roll succeeded")
	}
	if after := persistedPair(t, state); string(before) != string(after) {
		t.Error("the refused roll replaced the persisted pair")
	}
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
}

// persistedPair reads the state directory's persisted voting certificate,
// for the untouched-files check.
func persistedPair(t *testing.T, state string) []byte {
	t.Helper()
	cert, err := os.ReadFile(votingCertPath(state))
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// TestAnchorPoolRidesGrace checks the anchor pool the draft's grace defines:
// while the successor is within its grace period the predecessor's roots
// anchor chains beside the successor's — a chain issued under the replaced
// root keeps verifying — and past the window only the successor's do; a
// later rung stands on its own predecessor the same way, and the chains
// issue under the fresh root from the pin on.
func TestAnchorPoolRidesGrace(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newGenesisFixture(t)
		ctx := context.Background()
		state := t.TempDir()
		if err := PersistCoreKeys(state, f.keys); err != nil {
			t.Fatal(err)
		}
		issuer, err := NewIssuer(coreIA, f.keys, f.trc)
		if err != nil {
			t.Fatal(err)
		}
		// The chain issued under the replaced-to-be root, and its holder's
		// empty database.
		oldCSR, _ := newChainCSR(t, nodeIA)
		oldChain, err := issuer.IssueChain(oldCSR)
		if err != nil {
			t.Fatal(err)
		}
		fresh, completed, err := RotateCoreKeys(ctx, f.db, state, coreIA, f.trc)
		if err != nil {
			t.Fatal(err)
		}
		if err := issuer.Rekey(fresh, completed); err != nil {
			t.Fatal(err)
		}

		// In grace: the pool carries the predecessor beside the successor,
		// and the old chain verifies against it.
		pool, err := anchorPool(ctx, f.db, nil, coreIA.ISD())
		if err != nil {
			t.Fatal(err)
		}
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

		// A later rung lands inside the first window: the windows compound,
		// so its pool carries every predecessor whose own grace still runs —
		// the rung-1 chain and the base-root chain both verify through it.
		time.Sleep(2 * 24 * time.Hour)
		fresh2, completed2, err := RotateCoreKeys(ctx, f.db, state, coreIA, completed)
		if err != nil {
			t.Fatal(err)
		}
		if err := issuer.Rekey(fresh2, completed2); err != nil {
			t.Fatal(err)
		}
		pool, err = anchorPool(ctx, f.db, nil, coreIA.ISD())
		if err != nil {
			t.Fatal(err)
		}
		if len(pool) != 3 {
			t.Fatalf("the later rung's pool holds %d TRCs, want it and both its predecessors",
				len(pool))
		}
		if err := cppki.VerifyChain(newChain, cppki.VerifyOptions{TRC: pool}); err != nil {
			t.Errorf("the rung-1 chain does not verify through the later rung's grace: %v", err)
		}
		if err := cppki.VerifyChain(oldChain, cppki.VerifyOptions{TRC: pool}); err != nil {
			t.Errorf("the base-root chain does not verify through the compounded window: %v", err)
		}

		// Past the later rung's grace window: the predecessors' roots anchor
		// nothing, and the old chains no longer verify — by then they have
		// expired as well, the arithmetic closing by construction.
		time.Sleep(ASValidity + time.Minute)
		pool, err = anchorPool(ctx, f.db, nil, coreIA.ISD())
		if err != nil {
			t.Fatal(err)
		}
		if len(pool) != 1 {
			t.Fatalf("the past-grace pool holds %d TRCs, want the successor alone", len(pool))
		}
		if err := cppki.VerifyChain(oldChain, cppki.VerifyOptions{TRC: pool}); err == nil {
			t.Error("the chain under the replaced root verified past the grace window")
		}
		if err := cppki.VerifyChain(newChain, cppki.VerifyOptions{TRC: pool}); err == nil {
			t.Error("the rung-1 chain outlived the window that carried it")
		}
	})
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
