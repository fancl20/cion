package trust

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/scionproto/scion/pkg/addr"
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

// TestGetChainsVerifiesStoredChains checks that the database answers only
// with chains the anchor pool verifies: a stored chain no pinned TRC anchors
// is passed over — none answered without a Remote, the Remote's chain
// fetched and cached with one — and the cached chain answers once the Remote
// is gone.
func TestGetChainsVerifiesStoredChains(t *testing.T) {
	ctx := context.Background()
	remote := newFakeRemote(t)
	db := newTestDB(t)
	if _, err := db.InsertTRC(ctx, remote.trc); err != nil {
		t.Fatal(err)
	}
	csr, err := CreateCSR(nodeIA, newTestASKey(t))
	if err != nil {
		t.Fatal(err)
	}
	// Issued with a DIFFERENT core's keys, so the stored chain does not
	// verify against the pinned TRC.
	other := newGenesisFixture(t)
	otherIssuer, err := NewIssuer(coreIA, other.keys, other.trc)
	if err != nil {
		t.Fatal(err)
	}
	unanchored, err := otherIssuer.IssueChain(csr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.InsertChain(ctx, unanchored); err != nil {
		t.Fatal(err)
	}
	q := trustdb.ChainQuery{IA: nodeIA}

	local := &NetworkProvider{DB: db}
	if chains, err := local.GetChains(ctx, q); err != nil || len(chains) != 0 {
		t.Fatalf("local-only chains = %d (%v), want none: the stored chain is unanchored",
			len(chains), err)
	}

	anchored, err := remote.issuer.IssueChain(csr)
	if err != nil {
		t.Fatal(err)
	}
	remote.chains = [][]*x509.Certificate{anchored}
	provider := &NetworkProvider{DB: db, Remote: remote}
	isAnchored := func(chains [][]*x509.Certificate) bool {
		return len(chains) == 1 && bytes.Equal(chains[0][0].Raw, anchored[0].Raw)
	}
	chains, err := provider.GetChains(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if !isAnchored(chains) || remote.chainFetches != 1 {
		t.Fatalf("chains = %d after %d remote fetches, want the anchored chain after 1",
			len(chains), remote.chainFetches)
	}

	remote.failFollowing = true
	if chains, err := provider.GetChains(ctx, q); err != nil || !isAnchored(chains) {
		t.Errorf("cached chains = %d (%v), want the anchored chain from the DB",
			len(chains), err)
	}
}

// TestRenewChain checks the renewal round trip against a fake remote: the
// chain request, the TRC pull, verification, and storage.
func TestRenewChain(t *testing.T) {
	remote := newFakeRemote(t)
	db := newTestDB(t)
	key := newTestASKey(t)

	chain, err := RenewChain(context.Background(), db, remote, nodeIA, key)
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
}

// TestRenewChainRejectsUnanchoredChain checks that a chain the fake
// remote's TRC does not anchor is refused: "stale or mismatched trust
// material is refused".
func TestRenewChainRejectsUnanchoredChain(t *testing.T) {
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

	if _, err := RenewChain(context.Background(), db, remote, nodeIA, newTestASKey(t)); err == nil {
		t.Error("renewal with unanchored chain succeeded, want rejection")
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

// TestRenewChainPullsTheNewestTRC checks the renewal's pull: a node holding
// only the base renews from a founder that rolled its root since, and the
// chain issued under the fresh root verifies against the successor the
// renewal pulled and pinned.
func TestRenewChainPullsTheNewestTRC(t *testing.T) {
	ctx := context.Background()
	f := newGenesisFixture(t)
	issuer, err := NewIssuer(coreIA, f.keys, f.trc)
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
	remote := &fakeRemote{trc: completed, issuer: issuer, byID: map[cppki.TRCID]cppki.SignedTRC{
		f.trc.TRC.ID: f.trc, completed.TRC.ID: completed,
	}}
	db := newTestDB(t)
	if _, err := db.InsertTRC(ctx, f.trc); err != nil {
		t.Fatal(err)
	}

	chain, err := RenewChain(ctx, db, remote, nodeIA, newTestASKey(t))
	if err != nil {
		t.Fatalf("renewing under the fresh root: %v", err)
	}
	if err := cppki.VerifyChain(chain, cppki.VerifyOptions{
		TRC: []*cppki.TRC{&completed.TRC},
	}); err != nil {
		t.Errorf("the renewed chain does not verify against the successor: %v", err)
	}
	if pinned, err := db.SignedTRC(ctx, completed.TRC.ID); err != nil ||
		!bytes.Equal(pinned.Raw, completed.Raw) {
		t.Errorf("the renewal did not pin the successor it pulled (%v)", err)
	}
}

// TestRenewChainRefusesAForeignNewestTRC checks the pull's ISD check: a
// remote answering the numbers-less ask with another ISD's TRC fails the
// renewal, which stores no chain and pins nothing, where verification alone
// would pin a base TRC, which vouches for itself.
func TestRenewChainRefusesAForeignNewestTRC(t *testing.T) {
	ctx := context.Background()
	remote := newFakeRemote(t)
	db := newTestDB(t)
	if _, err := db.InsertTRC(ctx, remote.trc); err != nil {
		t.Fatal(err)
	}
	foreign, err := Genesis(ctx, newTestDB(t), addr.MustIAFrom(21, coreIA.AS()),
		newTestCoreKeys(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	remote.trc = foreign

	if _, err := RenewChain(ctx, db, remote, nodeIA, newTestASKey(t)); err == nil {
		t.Error("the renewal succeeded on another ISD's newest TRC, want refusal")
	}
	if pinned, err := db.SignedTRC(ctx, foreign.TRC.ID); err != nil || !pinned.IsZero() {
		t.Errorf("the foreign TRC pinned (%v)", err)
	}
	chains, err := db.Chains(ctx, trustdb.ChainQuery{IA: nodeIA})
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
