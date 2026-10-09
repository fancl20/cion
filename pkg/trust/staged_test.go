package trust

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/modules/trustdb"
	"github.com/fancl20/cion/pkg/statefile"
)

// TestFounderBootWithoutStagedRoll checks the boot with no roll staged:
// nothing promotes, no key file changes, and the live keys anchor an issuer
// in the newest TRC.
func TestFounderBootWithoutStagedRoll(t *testing.T) {
	f := newGenesisFixture(t)
	before := keyFiles(t, f.dir)
	if bootFounder(t, f) {
		t.Error("the boot promoted with nothing staged")
	}
	if diff := cmp.Diff(before, keyFiles(t, f.dir)); diff != "" {
		t.Errorf("the boot changed the key files (-before +after):\n%s", diff)
	}
}

// TestFounderRollPinFails checks the roll stopped at its pin: the staged file
// stands beside the predecessor's live keys, the boot promotes nothing and
// anchors an issuer in the predecessor, and the next roll reuses the staged
// keys.
func TestFounderRollPinFails(t *testing.T) {
	f := newGenesisFixture(t)
	ctx := context.Background()
	live := keyFiles(t, f.dir)

	if _, _, err := RotateCoreKeys(ctx, failingPin{f.db}, f.dir, coreIA, f.trc); err == nil {
		t.Fatal("the roll whose pin failed succeeded")
	}
	if !hasStaged(t, f.dir) {
		t.Fatal("the roll staged nothing")
	}
	staged, err := stagedCoreKeys(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	if bootFounder(t, f) {
		t.Error("the boot promoted a roll that never pinned")
	}
	after := keyFiles(t, f.dir)
	delete(after, StagedFile)
	if diff := cmp.Diff(live, after); diff != "" {
		t.Errorf("the stopped roll changed the live key files (-before +after):\n%s", diff)
	}

	fresh, completed, err := RotateCoreKeys(ctx, f.db, f.dir, coreIA, f.trc)
	if err != nil {
		t.Fatalf("the next roll failed: %v", err)
	}
	checkCoreKeys(t, fresh, staged, "the one the stopped roll staged")
	promoteFounder(t, f.dir, completed)
}

// TestFounderBootPromotesPinnedRoll checks the boot after a roll that
// pinned and stopped before its promotion, partway through it, or before the
// staged file's removal: the boot promotes, the live keys are the staged set
// and anchor an issuer in the successor, and the staged file is gone.
func TestFounderBootPromotesPinnedRoll(t *testing.T) {
	for _, tc := range []struct {
		name string
		// written is the number of staged blocks the stopped promotion
		// wrote to their live files, of the four the founder stages.
		written int
	}{
		{name: "before the promotion", written: 0},
		{name: "partway through the promotion", written: 2},
		{name: "before the staged file's removal", written: 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newGenesisFixture(t)
			fresh, _, err := RotateCoreKeys(context.Background(), f.db, f.dir, coreIA, f.trc)
			if err != nil {
				t.Fatal(err)
			}
			writeStagedLive(t, f.dir, tc.written)
			if !bootFounder(t, f) {
				t.Fatal("the boot did not promote the pinned roll")
			}
			checkCoreKeys(t, liveCoreKeys(t, f.dir), fresh, "the staged one")
			if hasStaged(t, f.dir) {
				t.Error("the staged file outlived the promotion")
			}
		})
	}
}

// TestAuthoritativeBootCompletesPromotion checks the authoritative core
// stopped between the staged key's write and the certificate's: the live key
// and certificate belong to different rolls, which the loaders refuse as a
// pair, and the boot's promotion against the newest pinned TRC completes the
// pair.
func TestAuthoritativeBootCompletesPromotion(t *testing.T) {
	_, joiner, founderDB, caster, state := newRollFixture(t)
	caster.loses = true
	ctx := context.Background()

	if err := RollVotingKey(ctx, joiner, founderRemote{db: founderDB}, caster,
		joinerIA, state); err == nil {

		t.Fatal("the roll whose answer was lost succeeded")
	}
	// The joiner pins the founder's successor, and the promotion stops after
	// the key's write.
	landed, err := founderDB.SignedTRC(ctx, newestTRCID(coreIA.ISD()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := joiner.InsertTRC(ctx, landed); err != nil {
		t.Fatal(err)
	}
	writeStagedLive(t, state, 1)
	key, err := LoadOrCreateVotingKey(state)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateVotingCert(state, joinerIA, key); err == nil {
		t.Fatal("the loaders accepted a key and a certificate of different rolls")
	}

	// The boot: the promotion against the newest pinned TRC, then the
	// loaders.
	newest, err := joiner.SignedTRC(ctx, newestTRCID(coreIA.ISD()))
	if err != nil {
		t.Fatal(err)
	}
	promoted, err := PromoteStaged(state, joinerIA, newest.TRC)
	if err != nil {
		t.Fatal(err)
	}
	if !promoted {
		t.Fatal("the boot did not promote the pinned roll")
	}
	checkLivePair(t, state, newest)
}

// failingPin is a trust database whose pins fail.
type failingPin struct {
	trustdb.DB
}

func (failingPin) InsertTRC(context.Context, cppki.SignedTRC) (bool, error) {
	return false, errors.New("the pin failed")
}

// bootFounder boots the founder's trust material the way the node does: it
// promotes the staged roll against the newest pinned TRC, loads the live
// keys, and anchors an issuer in that TRC, whose chain must verify against
// it alone. It reports whether the boot promoted.
func bootFounder(t *testing.T, f *genesisFixture) bool {
	t.Helper()
	newest, err := f.db.SignedTRC(context.Background(), newestTRCID(coreIA.ISD()))
	if err != nil {
		t.Fatal(err)
	}
	promoted, err := PromoteStaged(f.dir, coreIA, newest.TRC)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := NewIssuer(coreIA, liveCoreKeys(t, f.dir), newest)
	if err != nil {
		t.Fatalf("the live keys anchor no issuer in %v: %v", newest.TRC.ID, err)
	}
	csr, _ := newChainCSR(t, nodeIA)
	chain, err := issuer.IssueChain(csr)
	if err != nil {
		t.Fatal(err)
	}
	if err := cppki.VerifyChain(chain, cppki.VerifyOptions{
		TRC: []*cppki.TRC{&newest.TRC},
	}); err != nil {
		t.Errorf("the issued chain does not verify against %v alone: %v", newest.TRC.ID, err)
	}
	return promoted
}

// promoteFounder promotes the founder's staged roll against the TRC,
// failing the test unless it promotes.
func promoteFounder(t *testing.T, state string, trc cppki.SignedTRC) {
	t.Helper()
	promoted, err := PromoteStaged(state, coreIA, trc.TRC)
	if err != nil {
		t.Fatal(err)
	}
	if !promoted {
		t.Fatalf("the staged roll did not promote against %v", trc.TRC.ID)
	}
}

// writeStagedLive writes the first n staged blocks to their live files, the
// state a promotion that stopped after n writes leaves.
func writeStagedLive(t *testing.T, state string, n int) {
	t.Helper()
	blocks, err := readStaged(state)
	if err != nil {
		t.Fatal(err)
	}
	for _, block := range blocks[:n] {
		if err := statefile.Write(filepath.Join(keyDir(state), block.Headers[stagedFileHeader]),
			pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: block.Bytes})); err != nil {

			t.Fatal(err)
		}
	}
}

// keyFiles reads every file in the state directory's keys folder.
func keyFiles(t *testing.T, state string) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(keyDir(state))
	if err != nil {
		t.Fatal(err)
	}
	files := make(map[string][]byte, len(entries))
	for _, entry := range entries {
		raw, err := os.ReadFile(filepath.Join(keyDir(state), entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		files[entry.Name()] = raw
	}
	return files
}

// hasStaged reports whether the state directory holds a staged file.
func hasStaged(t *testing.T, state string) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(keyDir(state), StagedFile))
	if errors.Is(err, fs.ErrNotExist) {
		return false
	}
	if err != nil {
		t.Fatal(err)
	}
	return true
}

// writeKey replaces the live key file with the key, the operator's
// replacement of the node's material.
func writeKey(t *testing.T, state, file string, key crypto.Signer) {
	t.Helper()
	block, err := keyBlock(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := statefile.Write(filepath.Join(keyDir(state), file),
		pem.EncodeToMemory(block)); err != nil {

		t.Fatal(err)
	}
}

// writeVotingPair replaces the authoritative core's live key and
// certificate.
func writeVotingPair(t *testing.T, state string, key crypto.Signer, cert *x509.Certificate) {
	t.Helper()
	writeKey(t, state, RegularKeyFile, key)
	if err := statefile.Write(filepath.Join(keyDir(state), RegularVotingCertFile),
		pem.EncodeToMemory(certBlock(cert))); err != nil {

		t.Fatal(err)
	}
}
