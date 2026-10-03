package controlplane

import (
	"context"
	"crypto"
	"crypto/x509"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/modules/trustdb"
	"github.com/fancl20/cion/pkg/modules/trustdb/impl/bbolt"
	"github.com/fancl20/cion/pkg/trust"
)

// trcRemote serves a trust database's pinned TRCs — the numbers-less ask
// among them — standing in for the founder's endpoint.
type trcRemote struct {
	db trustdb.DB
}

func (r trcRemote) TRC(ctx context.Context, id cppki.TRCID) (cppki.SignedTRC, error) {
	return r.db.SignedTRC(ctx, id)
}

func (r trcRemote) Chains(
	ctx context.Context, q trustdb.ChainQuery) ([][]*x509.Certificate, error) {

	return nil, serrors.New("the rotation watch tests fetch no chains")
}

func (r trcRemote) RenewChain(
	ctx context.Context, csr *x509.CertificateRequest,
	key crypto.Signer) ([]*x509.Certificate, error) {

	return nil, serrors.New("the rotation watch tests renew no chains")
}

// founderRotationFixture is a founder with its decision, issuer, persisted
// keys, and the watch over them.
type founderRotationFixture struct {
	trustFixture
	dir     string
	decider *TRCDecider
	cfg     RotationConfig
}

func newFounderRotationFixture(t *testing.T) *founderRotationFixture {
	t.Helper()
	f := newTrustFixture(t)
	dir := t.TempDir()
	// The fixture's keys persisted beside the database, the shape the node's
	// own assembly serves.
	if err := trust.PersistCoreKeys(dir, f.keys); err != nil {
		t.Fatal(err)
	}
	decider := &TRCDecider{DB: f.db, IA: coreIATest, Sensitive: f.keys.Sensitive}
	cfg := RotationConfig{
		IA:              coreIATest,
		DB:              f.db,
		State:           dir,
		Decider:         decider,
		Issuer:          f.issuer,
		RetryInterval:   time.Millisecond,
		InspectInterval: 7 * time.Minute,
	}
	return &founderRotationFixture{trustFixture: *f, dir: dir, decider: decider, cfg: cfg}
}

// pinnedAt returns the TRC pinned at the serial, zero when none is.
func pinnedAt(t *testing.T, db trustdb.DB, serial scrypto.Version) cppki.SignedTRC {
	t.Helper()
	trc, err := db.SignedTRC(context.Background(),
		cppki.TRCID{ISD: coreIATest.ISD(), Base: 1, Serial: serial})
	if err != nil {
		t.Fatal(err)
	}
	return trc
}

// TestFounderRotationPasses checks the founder's watch in a fake-time bubble:
// material beyond the threshold only inspects, material within it rolls
// exactly the founder's three certificates — the successor pinning, the
// staged set persisting, the issuer rekeying under the fresh root, and the
// decision voting with the fresh sensitive key — and the threshold field
// overriding the default.
func TestFounderRotationPasses(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFounderRotationFixture(t)
		ctx := context.Background()

		// Fresh material: a year of validity, well above the thirty-day
		// threshold — no roll, calm inspection interval.
		if got := f.cfg.rotationPass(ctx); got != 7*time.Minute {
			t.Errorf("pass interval = %v, want the inspection interval", got)
		}
		if pinned := pinnedAt(t, f.db, 2); !pinned.IsZero() {
			t.Error("a pass above the threshold rolled anyway")
		}

		// Approaching expiry: the clock advances past the threshold — the
		// founder's whole set rolls inside the cast it signs itself.
		time.Sleep(trust.VotingValidity - trust.RotationThreshold + time.Minute)
		if got := f.cfg.rotationPass(ctx); got != time.Millisecond {
			t.Errorf("pass interval = %v, want the retry interval", got)
		}
		pinned := pinnedAt(t, f.db, 2)
		if pinned.IsZero() {
			t.Fatal("the roll pinned no successor")
		}
		if err := pinned.Verify(&f.trc.TRC); err != nil {
			t.Errorf("the pinned successor does not verify against the base: %v", err)
		}
		rolled := trust.CertsOf(pinned.TRC, coreIATest)
		if len(rolled) != 3 {
			t.Fatalf("the successor names %d of the founder's certificates, want 3", len(rolled))
		}
		persisted, err := trust.LoadOrCreateCoreKeys(f.dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, cert := range rolled {
			if !trust.KeyMatchesCert(keyOfClass(t, persisted, cert), cert) {
				t.Error("a persisted key does not cover the successor's certificate")
			}
		}
		// The issuer rekeyed: a chain it issues now verifies against the
		// successor, anchored in the fresh root.
		csr, _ := newCSR(t, addr.MustIAFrom(coreIATest.ISD(), nodeIATest.AS()))
		chain, err := f.issuer.IssueChain(csr)
		if err != nil {
			t.Fatalf("the rekeyed issuer issues no chain: %v", err)
		}
		if err := cppki.VerifyChain(chain, cppki.VerifyOptions{
			TRC: []*cppki.TRC{&pinned.TRC}, CurrentTime: time.Now(),
		}); err != nil {
			t.Errorf("the issued chain does not verify against the successor: %v", err)
		}
		// The decision votes with the fresh sensitive key: the next roll's
		// vote lands on the successor the first pinned.
		time.Sleep(trust.VotingValidity - trust.RotationThreshold + time.Minute)
		if got := f.cfg.rotationPass(ctx); got != time.Millisecond {
			t.Errorf("second pass interval = %v, want the retry interval", got)
		}
		if second := pinnedAt(t, f.db, 3); second.IsZero() {
			t.Error("the second roll pinned no successor")
		}

		// The threshold field overrides the default: an unbreached window
		// under a larger threshold rolls at once.
		fresh := newFounderRotationFixture(t)
		fresh.cfg.Threshold = trust.VotingValidity + time.Hour
		if got := fresh.cfg.rotationPass(ctx); got != time.Millisecond {
			t.Errorf("overridden pass interval = %v, want the retry interval", got)
		}
		if pinned := pinnedAt(t, fresh.db, 2); pinned.IsZero() {
			t.Error("the overridden threshold rolled nothing")
		}
	})
}

// keyOfClass returns the persisted key of the certificate's class.
func keyOfClass(t *testing.T, keys trust.CoreKeys, cert *x509.Certificate) crypto.Signer {
	t.Helper()
	ct, err := cppki.ValidateCert(cert)
	if err != nil {
		t.Fatal(err)
	}
	switch ct {
	case cppki.Sensitive:
		return keys.Sensitive
	case cppki.Regular:
		return keys.Regular
	default:
		return keys.Root
	}
}

// TestFounderRotationMismatch checks the mismatch trigger on the founder: a
// persisted key the newest TRC's certificate no longer covers — the operator
// who replaced the node's voting material — rolls at the next pass whatever
// the calendar says, while a persisted sensitive key the newest does not name
// is the terminal corner: no roll, nothing pinned.
func TestFounderRotationMismatch(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFounderRotationFixture(t)
		ctx := context.Background()

		stranger, err := trust.LoadOrCreateVotingKey(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		// The regular key replaced, the sensitive one still the named voter:
		// the roll fires on the mismatch alone.
		if err := trust.PersistCoreKeys(f.dir, trust.CoreKeys{
			Sensitive: f.keys.Sensitive, Regular: stranger,
			Root: f.keys.Root, CA: f.keys.CA,
		}); err != nil {
			t.Fatal(err)
		}
		if got := f.cfg.rotationPass(ctx); got != time.Millisecond {
			t.Errorf("pass interval = %v, want the retry interval on the mismatch", got)
		}
		if pinned := pinnedAt(t, f.db, 2); pinned.IsZero() {
			t.Fatal("the mismatch roll pinned no successor")
		}

		// The sensitive key replaced with one the newest does not name: the
		// vote it alone can cast is the recovery, and its loss is the
		// redeploy — no roll, nothing pinned.
		terminal := newFounderRotationFixture(t)
		if err := trust.PersistCoreKeys(terminal.dir, trust.CoreKeys{
			Sensitive: stranger, Regular: terminal.keys.Regular,
			Root: terminal.keys.Root, CA: terminal.keys.CA,
		}); err != nil {
			t.Fatal(err)
		}
		if got := terminal.cfg.rotationPass(ctx); got != 7*time.Minute {
			t.Errorf("pass interval = %v, want the inspection interval on the terminal corner",
				got)
		}
		if pinned := pinnedAt(t, terminal.db, 2); !pinned.IsZero() {
			t.Error("the terminal corner rolled anyway")
		}
	})
}

// authoritativeRotationFixture is an onboarded authoritative core — the
// founder's decision beside it — with its persisted voting pair and the
// watch over it.
type authoritativeRotationFixture struct {
	db        trustdb.DB
	state     string
	cfg       RotationConfig
	issuer    *trust.Issuer
	founderDB trustdb.DB
}

// enroll issues the joiner a fresh chain on the founder, the gate the
// decision asks — the enrollment loop's renewal the test stands in for once
// the fake clock has outlived the chain it holds.
func (f *authoritativeRotationFixture) enroll(t *testing.T) {
	t.Helper()
	csr, _ := newCSR(t, joinerIATest)
	chain, err := f.issuer.IssueChain(csr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.founderDB.InsertChain(context.Background(), chain); err != nil {
		t.Fatal(err)
	}
}

func newAuthoritativeRotationFixture(t *testing.T) *authoritativeRotationFixture {
	t.Helper()
	f := newTrustFixture(t)
	decider := &TRCDecider{DB: f.db, IA: coreIATest, Sensitive: f.keys.Sensitive}
	// The joiner enrolled and onboarded: the founder's newest names it.
	key, cert := votingMaterial(t, joinerIATest)
	csr, _ := newCSR(t, joinerIATest)
	chain, err := f.issuer.IssueChain(csr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.InsertChain(context.Background(), chain); err != nil {
		t.Fatal(err)
	}
	onboarding, err := trust.AssembleOnboarding(f.trc, joinerIATest, cert)
	if err != nil {
		t.Fatal(err)
	}
	partial, err := trust.SignUpdate(onboarding, key, cert)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decider.DecideTRC(context.Background(), joinerIATest, partial); err != nil {
		t.Fatal(err)
	}
	db, err := bbolt.New(filepath.Join(t.TempDir(), "trust.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for _, trc := range []cppki.SignedTRC{f.trc, pinnedAt(t, f.db, 2)} {
		if _, err := db.InsertTRC(context.Background(), trc); err != nil {
			t.Fatal(err)
		}
	}
	state := t.TempDir()
	if err := trust.PersistVotingPair(state, key, cert); err != nil {
		t.Fatal(err)
	}
	cfg := RotationConfig{
		IA:              joinerIATest,
		DB:              db,
		State:           state,
		Remote:          trcRemote{db: f.db},
		Caster:          deciderCaster{decider: decider, presenter: joinerIATest},
		RetryInterval:   time.Millisecond,
		InspectInterval: 7 * time.Minute,
	}
	return &authoritativeRotationFixture{
		db: db, state: state, cfg: cfg,
		issuer: f.issuer, founderDB: f.db,
	}
}

// deciderCaster submits through a real decision, the presenter the channel
// would have verified.
type deciderCaster struct {
	decider   *TRCDecider
	presenter addr.IA
}

func (c deciderCaster) SubmitTRC(
	ctx context.Context, trc cppki.SignedTRC) (cppki.SignedTRC, error) {

	return c.decider.DecideTRC(ctx, c.presenter, trc)
}

// TestAuthoritativeRotationPasses checks the authoritative core's watch in a
// fake-time bubble: material beyond the threshold only inspects, material
// within it submits the roll through the channel its join used — both sides
// pinning, the staged pair persisting — and the mismatch trigger rolls at
// the next pass whatever the calendar says.
func TestAuthoritativeRotationPasses(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newAuthoritativeRotationFixture(t)
		ctx := context.Background()

		// Fresh material: no roll, calm inspection interval.
		if got := f.cfg.rotationPass(ctx); got != 7*time.Minute {
			t.Errorf("pass interval = %v, want the inspection interval", got)
		}
		if pinned := pinnedAt(t, f.db, 3); !pinned.IsZero() {
			t.Error("a pass above the threshold rolled anyway")
		}

		// Approaching expiry: the clock advances past the threshold — the
		// roll submits and pins on both sides.
		time.Sleep(trust.VotingValidity - trust.RotationThreshold + time.Minute)
		f.enroll(t)
		if got := f.cfg.rotationPass(ctx); got != time.Millisecond {
			t.Errorf("pass interval = %v, want the retry interval", got)
		}
		pinned := pinnedAt(t, f.db, 3)
		if pinned.IsZero() {
			t.Fatal("the roll pinned no successor")
		}
		key, err := trust.LoadOrCreateVotingKey(f.state)
		if err != nil {
			t.Fatal(err)
		}
		rolled := trust.CertsOf(pinned.TRC, joinerIATest)
		if len(rolled) != 1 || !trust.KeyMatchesCert(key, rolled[0]) {
			t.Error("the persisted pair does not cover the successor's certificate")
		}

		// The mismatch: a replaced pair rolls at the next pass.
		stranger, strangerCert := votingMaterial(t, joinerIATest)
		if err := trust.PersistVotingPair(f.state, stranger, strangerCert); err != nil {
			t.Fatal(err)
		}
		if got := f.cfg.rotationPass(ctx); got != time.Millisecond {
			t.Errorf("pass interval = %v, want the retry interval on the mismatch", got)
		}
		if pinned := pinnedAt(t, f.db, 4); pinned.IsZero() {
			t.Error("the mismatch roll pinned no successor")
		}
	})
}
