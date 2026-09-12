package trust

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/scionproto/scion/pkg/scrypto/cppki"
)

// fakeRemote serves trust material from memory and counts fetches.
type fakeRemote struct {
	trc    cppki.SignedTRC
	chains [][]*x509.Certificate
	issuer *Issuer

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
	return r.trc, nil
}

func (r *fakeRemote) Chains(ctx context.Context, q ChainQuery) ([][]*x509.Certificate, error) {
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
	chains, err := db.Chains(context.Background(), ChainQuery{IA: nodeIA})
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
	chains, err := db.Chains(context.Background(), ChainQuery{IA: nodeIA})
	if err != nil {
		t.Fatal(err)
	}
	if len(chains) != 0 {
		t.Errorf("stored chains = %d, want 0", len(chains))
	}
}
