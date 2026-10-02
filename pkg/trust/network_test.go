package trust

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/modules/trustdb"
)

// fakeRemote serves trust material from memory and counts fetches.
type fakeRemote struct {
	trc    cppki.SignedTRC
	chains [][]*x509.Certificate
	issuer *Issuer
	// byID serves the TRCs an update chain asks for by exact ID; trc serves
	// every other ask, the numbers-less one among them.
	byID map[cppki.TRCID]cppki.SignedTRC

	trcFetches    int
	chainFetches  int
	renewalReqs   int
	failFollowing bool
}

func (r *fakeRemote) TRC(ctx context.Context, id cppki.TRCID) (cppki.SignedTRC, error) {
	r.trcFetches++
	if r.failFollowing {
		return cppki.SignedTRC{}, errors.New("remote gone")
	}
	if trc, ok := r.byID[id]; ok {
		return trc, nil
	}
	return r.trc, nil
}

func (r *fakeRemote) Chains(ctx context.Context, q trustdb.ChainQuery) ([][]*x509.Certificate, error) {
	r.chainFetches++
	if r.failFollowing {
		return nil, errors.New("remote gone")
	}
	return r.chains, nil
}

func (r *fakeRemote) RenewChain(ctx context.Context, csr *x509.CertificateRequest,
	key crypto.Signer) ([]*x509.Certificate, error) {

	r.renewalReqs++
	if r.failFollowing {
		return nil, errors.New("remote gone")
	}
	return r.issuer.IssueChain(csr)
}

func newFakeRemote(t *testing.T) *fakeRemote {
	t.Helper()
	f := newGenesisFixture(t)
	issuer, err := NewIssuer(coreIA, f.keys, f.trc)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeRemote{trc: f.trc, issuer: issuer}
}

// TestNetworkProviderFetchesOnMiss checks the DB-first behavior: a miss goes
// to the remote, verifies, and caches the result in the DB.
func TestNetworkProviderFetchesOnMiss(t *testing.T) {
	remote := newFakeRemote(t)
	db := newTestDB(t)
	provider := &NetworkProvider{DB: db, Remote: remote}

	trc, err := provider.GetSignedTRC(context.Background(), remote.trc.TRC.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := trc.Verify(nil); err != nil {
		t.Fatalf("fetched TRC does not verify: %v", err)
	}
	if remote.trcFetches != 1 {
		t.Fatalf("TRC fetches = %d, want 1", remote.trcFetches)
	}
	// Now served from the DB, even with the remote gone.
	remote.failFollowing = true
	if _, err := provider.GetSignedTRC(context.Background(), remote.trc.TRC.ID); err != nil {
		t.Fatalf("cached TRC not served from DB: %v", err)
	}
	if remote.trcFetches != 1 {
		t.Errorf("TRC fetches after cache = %d, want 1", remote.trcFetches)
	}
}

// TestEnroll checks the enrollment round trip against a fake remote: TRC
// fetch, chain request, verification, and storage; a second run is a no-op.
func TestEnroll(t *testing.T) {
	remote := newFakeRemote(t)
	db := newTestDB(t)
	key := newTestASKey(t)

	chain, err := Enroll(context.Background(), db, remote, nodeIA, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 2 {
		t.Fatalf("chain length = %d, want 2", len(chain))
	}
	if remote.trcFetches != 1 || remote.renewalReqs != 1 {
		t.Fatalf("fetches = (trc %d, renewal %d), want (1, 1)",
			remote.trcFetches, remote.renewalReqs)
	}

	// The TRC and chain are in the DB.
	trc, err := db.SignedTRC(context.Background(), remote.trc.TRC.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := trc.Verify(nil); err != nil {
		t.Errorf("stored TRC does not verify: %v", err)
	}
	chains, err := db.Chains(context.Background(), trustdb.ChainQuery{IA: nodeIA})
	if err != nil {
		t.Fatal(err)
	}
	if len(chains) != 1 {
		t.Fatalf("stored chains = %d, want 1", len(chains))
	}

	// A still-valid chain short-circuits the round trip.
	remote.failFollowing = true
	if _, err := Enroll(context.Background(), db, remote, nodeIA, key); err != nil {
		t.Fatalf("re-enrollment with valid chain failed: %v", err)
	}
	if remote.renewalReqs != 1 {
		t.Errorf("renewal requests after no-op = %d, want 1", remote.renewalReqs)
	}
}

// TestEnrollRejectsUnanchoredChain checks that a chain the fake remote's TRC
// does not anchor is refused: "stale or mismatched trust material is
// refused".
func TestEnrollRejectsUnanchoredChain(t *testing.T) {
	remote := newFakeRemote(t)
	db := newTestDB(t)

	// Issue with a DIFFERENT core's keys, so the chain does not verify
	// against the served TRC.
	other := newGenesisFixture(t)
	otherIssuer, err := NewIssuer(coreIA, other.keys, other.trc)
	if err != nil {
		t.Fatal(err)
	}
	remote.issuer = otherIssuer

	if _, err := Enroll(context.Background(), db, remote, nodeIA, newTestASKey(t)); err == nil {
		t.Error("enrollment with unanchored chain succeeded, want rejection")
	}
	// The bogus chain must not be stored.
	chains, err := db.Chains(context.Background(), trustdb.ChainQuery{IA: nodeIA})
	if err != nil {
		t.Fatal(err)
	}
	if len(chains) != 0 {
		t.Errorf("stored chains = %d, want 0", len(chains))
	}
}

// newSuccessorFixture is a fake remote of a founder that onboards a joiner:
// the base TRC served numbers-less, both TRCs served by exact ID. The
// fixture's founder keys cast whatever else the test forges.
func newSuccessorFixture(
	t *testing.T,
) (f *castFixture, base, successor cppki.SignedTRC, remote *fakeRemote) {

	t.Helper()
	f = newCastFixture(t)
	base, _, successor = f.successor(t)
	remote = newFakeRemote(t)
	remote.trc = base
	remote.byID = map[cppki.TRCID]cppki.SignedTRC{
		base.TRC.ID: base, successor.TRC.ID: successor,
	}
	return f, base, successor, remote
}

// TestFetchTRCVerifiesUpdate checks the predecessor-aware fetch: a successor
// verifies against its pinned predecessor and pins; a node holding only the
// base chains its way to it, fetching the missing predecessor first.
func TestFetchTRCVerifiesUpdate(t *testing.T) {
	_, base, successor, remote := newSuccessorFixture(t)

	t.Run("predecessor pinned", func(t *testing.T) {
		db := newTestDB(t)
		if _, err := db.InsertTRC(context.Background(), base); err != nil {
			t.Fatal(err)
		}
		provider := &NetworkProvider{DB: db, Remote: remote}
		got, err := provider.GetSignedTRC(context.Background(), successor.TRC.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.TRC.ID != successor.TRC.ID {
			t.Errorf("fetched TRC = %v, want %v", got.TRC.ID, successor.TRC.ID)
		}
		if pinned, err := db.SignedTRC(context.Background(), successor.TRC.ID); err != nil ||
			!bytes.Equal(pinned.Raw, successor.Raw) {
			t.Errorf("the verified successor did not pin: %v (%v)", pinned.TRC.ID, err)
		}
	})

	t.Run("chains from the base alone", func(t *testing.T) {
		db := newTestDB(t)
		provider := &NetworkProvider{DB: db, Remote: remote}
		if _, err := provider.GetSignedTRC(context.Background(), successor.TRC.ID); err != nil {
			t.Fatal(err)
		}
		for _, id := range []cppki.TRCID{base.TRC.ID, successor.TRC.ID} {
			if pinned, err := db.SignedTRC(context.Background(), id); err != nil || pinned.IsZero() {
				t.Errorf("TRC %v did not pin along the chain (%v)", id, err)
			}
		}
	})

	t.Run("base verifies as the base", func(t *testing.T) {
		db := newTestDB(t)
		provider := &NetworkProvider{DB: db, Remote: remote}
		if _, err := provider.GetSignedTRC(context.Background(), base.TRC.ID); err != nil {
			t.Fatalf("the base TRC no longer fetches: %v", err)
		}
	})
}

// TestFetchTRCRefusesForgeries checks the rules the fail-closed posture
// exists for: a serial that does not increment, a missing proof of
// possession, and a tampered payload pin nowhere.
func TestFetchTRCRefusesForgeries(t *testing.T) {
	f, base, successor, _ := newSuccessorFixture(t)

	forgeries := map[string]cppki.SignedTRC{}
	// A serial that jumps two: signed raw over both keys, for the assembly
	// itself refuses to build what the increment does not allow.
	jump, err := AssembleOnboarding(base, joinerIA, f.joiner.cert)
	if err != nil {
		t.Fatal(err)
	}
	jump.ID.Serial = successor.TRC.ID.Serial + 1
	sensitiveCert, err := signerCert(base.TRC, cppki.Sensitive)
	if err != nil {
		t.Fatal(err)
	}
	if forged, err := signTRCPayload(jump,
		[]*x509.Certificate{f.joiner.cert, sensitiveCert},
		[]crypto.Signer{f.joiner.key, f.founder.keys.Sensitive}); err == nil {
		forgeries["serial that does not increment"] = forged
	}
	// A missing proof of possession: the founder's vote alone, raw-signed
	// over the assembled payload.
	assembly, err := AssembleOnboarding(base, joinerIA, f.joiner.cert)
	if err != nil {
		t.Fatal(err)
	}
	voteOnly, err := signTRCPayload(assembly,
		[]*x509.Certificate{sensitiveCert}, []crypto.Signer{f.founder.keys.Sensitive})
	if err != nil {
		t.Fatal(err)
	}
	forgeries["missing proof of possession"] = voteOnly
	// A tampered payload: the successor's description rewritten and the
	// artifact re-encoded, its signatures left over the original bytes.
	rewritten := successor.TRC
	rewritten.Description = "a forged description"
	reencoded, err := (&cppki.SignedTRC{
		TRC: rewritten, SignerInfos: successor.SignerInfos,
	}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	tampered, err := cppki.DecodeSignedTRC(reencoded)
	if err != nil {
		t.Fatal(err)
	}
	forgeries["tampered payload"] = tampered

	for name, forged := range forgeries {
		t.Run(name, func(t *testing.T) {
			remote := newFakeRemote(t)
			remote.trc = base
			remote.byID = map[cppki.TRCID]cppki.SignedTRC{
				base.TRC.ID: base, forged.TRC.ID: forged,
			}
			db := newTestDB(t)
			if _, err := db.InsertTRC(context.Background(), base); err != nil {
				t.Fatal(err)
			}
			provider := &NetworkProvider{DB: db, Remote: remote}
			if _, err := provider.GetSignedTRC(context.Background(), forged.TRC.ID); err == nil {
				t.Error("the forged successor fetched, want refusal")
			}
			if pinned, err := db.SignedTRC(context.Background(), forged.TRC.ID); err != nil ||
				!pinned.IsZero() {
				t.Errorf("the forged successor pinned (%v)", err)
			}
		})
	}
}

// TestFetchTRCNewest checks the numbers-less ask: it returns the successor
// where the exact base lookup returns the base, and pins what it fetches.
func TestFetchTRCNewest(t *testing.T) {
	_, base, successor, remote := newSuccessorFixture(t)
	remote.trc = successor

	db := newTestDB(t)
	provider := &NetworkProvider{DB: db, Remote: remote}
	got, err := provider.GetSignedTRC(context.Background(), newestTRCID(base.TRC.ID.ISD))
	if err != nil {
		t.Fatal(err)
	}
	if got.TRC.ID != successor.TRC.ID {
		t.Errorf("numbers-less fetch = %v, want the successor %v", got.TRC.ID, successor.TRC.ID)
	}
	if pinned, err := db.SignedTRC(context.Background(), base.TRC.ID); err != nil || pinned.IsZero() {
		t.Errorf("the predecessor did not pin along the way (%v)", err)
	}
}
