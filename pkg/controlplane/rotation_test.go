package controlplane

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/modules/enrollauth"
	"github.com/fancl20/cion/pkg/modules/trustdb"
	"github.com/fancl20/cion/pkg/statefile"
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

// founderRotationFixture is a founder with its decision, issuer, live keys,
// and the watch over them.
type founderRotationFixture struct {
	trustFixture
	decider *TRCDecider
	cfg     RotationConfig
}

func newFounderRotationFixture(t *testing.T) *founderRotationFixture {
	t.Helper()
	f := newTrustFixture(t)
	decider := &TRCDecider{DB: f.db, IA: coreIATest, Sensitive: f.keys.Sensitive}
	cfg := RotationConfig{
		IA:              coreIATest,
		DB:              f.db,
		State:           f.dir,
		Roll:            FounderRoll(decider, f.issuer),
		RetryInterval:   time.Millisecond,
		InspectInterval: 7 * time.Minute,
	}
	return &founderRotationFixture{trustFixture: *f, decider: decider, cfg: cfg}
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
// staged set promoted to the live files, the issuer rekeying under the fresh
// root, and the decision voting with the fresh sensitive key — and the
// threshold field overriding the default.
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
		if rolled := trust.CertsOf(pinned.TRC, coreIATest); len(rolled) != 3 {
			t.Fatalf("the successor names %d of the founder's certificates, want 3", len(rolled))
		}
		checkLiveCoreKeys(t, f.dir, pinned)
		// The issuer rekeyed: a chain it issues now verifies against the
		// successor, anchored in the fresh root.
		checkIssuesUnder(t, f.issuer, pinned)
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

// keyOfClass returns the key of the certificate's class.
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
// live key the newest TRC's certificate no longer covers — the operator who
// replaced the node's voting material — rolls at the next pass whatever the
// calendar says, while a live sensitive key the newest does not name is the
// terminal corner: no roll, nothing pinned.
func TestFounderRotationMismatch(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFounderRotationFixture(t)
		ctx := context.Background()

		// A stranger's key files, the replacement an operator copies in.
		stranger := t.TempDir()
		if _, err := trust.LoadOrCreateCoreKeys(stranger); err != nil {
			t.Fatal(err)
		}
		// The regular key replaced, the sensitive one still the named voter:
		// the roll fires on the mismatch alone.
		replaceKeyFiles(t, stranger, f.dir, trust.RegularKeyFile)
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
		replaceKeyFiles(t, stranger, terminal.dir, trust.SensitiveKeyFile)
		if got := terminal.cfg.rotationPass(ctx); got != 7*time.Minute {
			t.Errorf("pass interval = %v, want the inspection interval on the terminal corner",
				got)
		}
		if pinned := pinnedAt(t, terminal.db, 2); !pinned.IsZero() {
			t.Error("the terminal corner rolled anyway")
		}
	})
}

// TestFounderRotationPromotionFails checks the founder's roll whose
// promotion fails after its pin, a directory standing at the sensitive key
// file's temporary name: the decision votes with the fresh sensitive key and
// the issuer issues under the fresh root all the same, and once the
// directory is gone the next pass promotes and rolls nothing further.
func TestFounderRotationPromotionFails(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFounderRotationFixture(t)
		ctx := context.Background()
		blocker := filepath.Join(f.dir, "keys", trust.SensitiveKeyFile+".tmp")
		if err := os.Mkdir(blocker, 0o700); err != nil {
			t.Fatal(err)
		}

		time.Sleep(trust.VotingValidity - trust.RotationThreshold + time.Minute)
		if got := f.cfg.rotationPass(ctx); got != time.Millisecond {
			t.Errorf("pass interval = %v, want the retry interval", got)
		}
		pinned := pinnedAt(t, f.db, 2)
		if pinned.IsZero() {
			t.Fatal("the roll pinned no successor")
		}
		sensitive, err := trust.SignerCert(pinned.TRC, cppki.Sensitive)
		if err != nil {
			t.Fatal(err)
		}
		live, err := trust.LoadOrCreateCoreKeys(f.dir)
		if err != nil {
			t.Fatal(err)
		}
		if trust.KeyMatchesCert(live.Sensitive, sensitive) {
			t.Fatal("the promotion wrote the sensitive key past the blocker")
		}
		if !trust.KeyMatchesCert(f.decider.Sensitive, sensitive) {
			t.Error("the decision does not vote with the successor's sensitive key")
		}
		checkIssuesUnder(t, f.issuer, pinned)

		if err := os.Remove(blocker); err != nil {
			t.Fatal(err)
		}
		if got := f.cfg.rotationPass(ctx); got != 7*time.Minute {
			t.Errorf("pass interval = %v, want the inspection interval once promoted", got)
		}
		if third := pinnedAt(t, f.db, 3); !third.IsZero() {
			t.Error("the pass after the failed promotion rolled again")
		}
		checkLiveCoreKeys(t, f.dir, pinned)
	})
}

// checkLiveCoreKeys fails the test unless the founder's live keys cover the
// certificates the TRC names for it and no staged file remains.
func checkLiveCoreKeys(t *testing.T, state string, trc cppki.SignedTRC) {
	t.Helper()
	live, err := trust.LoadOrCreateCoreKeys(state)
	if err != nil {
		t.Fatal(err)
	}
	for _, cert := range trust.CertsOf(trc.TRC, coreIATest) {
		if !trust.KeyMatchesCert(keyOfClass(t, live, cert), cert) {
			t.Errorf("a live key does not cover %v's certificate %s", trc.TRC.ID, cert.Subject)
		}
	}
	checkNoStaged(t, state)
}

// checkIssuesUnder fails the test unless a chain the issuer issues verifies
// against the TRC alone.
func checkIssuesUnder(t *testing.T, issuer *trust.Issuer, trc cppki.SignedTRC) {
	t.Helper()
	csr, _ := newCSR(t, addr.MustIAFrom(coreIATest.ISD(), nodeIATest.AS()))
	chain, err := issuer.IssueChain(csr)
	if err != nil {
		t.Fatalf("the issuer issues no chain: %v", err)
	}
	if err := cppki.VerifyChain(chain, cppki.VerifyOptions{
		TRC: []*cppki.TRC{&trc.TRC}, CurrentTime: time.Now(),
	}); err != nil {
		t.Errorf("the issued chain does not verify against %v: %v", trc.TRC.ID, err)
	}
}

// checkNoStaged fails the test if the state directory holds a staged file.
func checkNoStaged(t *testing.T, state string) {
	t.Helper()
	_, err := os.Stat(filepath.Join(state, "keys", trust.StagedFile))
	if err == nil {
		t.Error("the staged file outlived its promotion")
	} else if !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
}

// replaceKeyFiles copies the named files of one state directory's keys
// folder over another's, the operator's replacement of the node's voting
// material.
func replaceKeyFiles(t *testing.T, from, to string, files ...string) {
	t.Helper()
	for _, file := range files {
		raw, err := os.ReadFile(filepath.Join(from, "keys", file))
		if err != nil {
			t.Fatal(err)
		}
		if err := statefile.Write(filepath.Join(to, "keys", file), raw); err != nil {
			t.Fatal(err)
		}
	}
}

// authoritativeRotationFixture is an onboarded authoritative core — the
// founder's decision beside it, its admission policy allowing — with its
// live voting pair and the watch over it.
type authoritativeRotationFixture struct {
	db        trustdb.DB
	state     string
	cfg       RotationConfig
	issuer    *trust.Issuer
	founderDB trustdb.DB
	decider   *TRCDecider
	// remote and caster are the roll's: the founder's TRCs, and the
	// submission through the founder's decision.
	remote trust.Remote
	caster trust.TRCCaster
	// auth records the founder's admission questions from the onboarding
	// on: the onboarding's own is cleared.
	auth *askAuthorizer
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
	auth := &askAuthorizer{verdict: enrollauth.AdmissionAllow}
	decider := &TRCDecider{
		DB:         f.db,
		IA:         coreIATest,
		Sensitive:  f.keys.Sensitive,
		Authorizer: auth,
	}
	// The joiner enrolled and onboarded: the founder's newest names it.
	state := t.TempDir()
	key, err := trust.LoadOrCreateVotingKey(state)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := trust.LoadOrCreateVotingCert(state, joinerIATest, key)
	if err != nil {
		t.Fatal(err)
	}
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
	auth.asked = nil
	db := openTrustDB(t, t.TempDir())
	for _, trc := range []cppki.SignedTRC{f.trc, pinnedAt(t, f.db, 2)} {
		if _, err := db.InsertTRC(context.Background(), trc); err != nil {
			t.Fatal(err)
		}
	}
	remote := trcRemote{db: f.db}
	caster := deciderCaster{decider: decider, presenter: joinerIATest}
	cfg := RotationConfig{
		IA:              joinerIATest,
		DB:              db,
		State:           state,
		Roll:            AuthoritativeRoll(remote, caster),
		RetryInterval:   time.Millisecond,
		InspectInterval: 7 * time.Minute,
	}
	return &authoritativeRotationFixture{
		db: db, state: state, cfg: cfg, remote: remote, caster: caster,
		issuer: f.issuer, founderDB: f.db, decider: decider, auth: auth,
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
// within it submits the roll through the channel its join used — a regular
// update the founder pins without asking its policy, both sides pinning, the
// staged pair promoted to the live files — and the mismatch trigger rolls at
// the next pass whatever the calendar says, by a sensitive update the policy
// is asked of once.
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
		checkLiveVotingPair(t, f.state, pinned)
		if got := updateType(t, pinned, pinnedAt(t, f.db, 2)); got != cppki.RegularUpdate {
			t.Errorf("the routine roll's update type = %v, want a regular update", got)
		}
		if len(f.auth.asked) != 0 {
			t.Errorf("the routine roll asked the founder's policy %d times, want none",
				len(f.auth.asked))
		}

		// The mismatch: a replaced pair rolls at the next pass.
		replaceVotingPair(t, f.state)
		if got := f.cfg.rotationPass(ctx); got != time.Millisecond {
			t.Errorf("pass interval = %v, want the retry interval on the mismatch", got)
		}
		mismatch := pinnedAt(t, f.db, 4)
		if mismatch.IsZero() {
			t.Fatal("the mismatch roll pinned no successor")
		}
		if got := updateType(t, mismatch, pinned); got != cppki.SensitiveUpdate {
			t.Errorf("the mismatch roll's update type = %v, want a sensitive update", got)
		}
		if len(f.auth.asked) != 1 {
			t.Errorf("the mismatch roll asked the founder's policy %d times, want 1",
				len(f.auth.asked))
		}
	})
}

// TestAuthoritativeRotationLostAnswer checks the authoritative core's roll
// whose answer is lost after the founder pinned it: the next pass finds the
// founder's newest naming the staged pair and completes the roll with no
// submission and no question to the founder's policy, and the pass after it
// finds nothing to roll.
func TestAuthoritativeRotationLostAnswer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newAuthoritativeRotationFixture(t)
		ctx := context.Background()
		caster := &losingCaster{TRCCaster: f.caster}
		f.cfg.Roll = AuthoritativeRoll(f.remote, caster)

		time.Sleep(trust.VotingValidity - trust.RotationThreshold + time.Minute)
		f.enroll(t)
		if got := f.cfg.rotationPass(ctx); got != time.Millisecond {
			t.Errorf("pass interval = %v, want the retry interval", got)
		}
		landed := pinnedAt(t, f.founderDB, 3)
		if landed.IsZero() {
			t.Fatal("the founder pinned no successor")
		}
		if pinned := pinnedAt(t, f.db, 3); !pinned.IsZero() {
			t.Fatal("the joiner pinned the successor whose answer was lost")
		}

		f.cfg.rotationPass(ctx)
		if caster.submissions != 1 {
			t.Errorf("the roll submitted %d times, want the lost one alone", caster.submissions)
		}
		if len(f.auth.asked) != 0 {
			t.Errorf("the roll asked the founder's policy %d times, want none", len(f.auth.asked))
		}
		pinned := pinnedAt(t, f.db, 3)
		if string(pinned.Raw) != string(landed.Raw) {
			t.Fatal("the joiner did not pin the founder's successor")
		}
		checkLiveVotingPair(t, f.state, pinned)
		if got := f.cfg.rotationPass(ctx); got != 7*time.Minute {
			t.Errorf("pass interval = %v, want the inspection interval once complete", got)
		}
	})
}

// TestAuthoritativeRotationPendingFallback checks the sensitive fallback
// under a policy that pends the first ask about a key and allows later ones,
// the operator's answer landing on the next ask: the retry submits the same
// staged key and lands, both asks naming it.
func TestAuthoritativeRotationPendingFallback(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newAuthoritativeRotationFixture(t)
		ctx := context.Background()
		auth := &pendingFirstAuthorizer{}
		f.decider.Authorizer = auth
		// A replaced pair the newest TRC does not name: the roll is the
		// sensitive fallback.
		replaceVotingPair(t, f.state)

		f.cfg.rotationPass(ctx)
		if pinned := pinnedAt(t, f.founderDB, 3); !pinned.IsZero() {
			t.Fatal("the founder pinned a submission its policy left pending")
		}
		f.cfg.rotationPass(ctx)
		pinned := pinnedAt(t, f.db, 3)
		if pinned.IsZero() {
			t.Fatal("the retry pinned no successor")
		}
		if got := updateType(t, pinned, pinnedAt(t, f.db, 2)); got != cppki.SensitiveUpdate {
			t.Errorf("the fallback's update type = %v, want a sensitive update", got)
		}
		if len(auth.asked) != 2 {
			t.Fatalf("the founder's policy was asked %d times, want 2", len(auth.asked))
		}
		if diff := cmp.Diff(auth.asked[0].Keys, auth.asked[1].Keys); diff != "" {
			t.Errorf("the retry asked about other keys (-first +retry):\n%s", diff)
		}
		checkLiveVotingPair(t, f.state, pinned)
	})
}

// losingCaster submits through the founder's decision and loses every answer
// after the decision, counting the submissions.
type losingCaster struct {
	trust.TRCCaster
	submissions int
}

func (c *losingCaster) SubmitTRC(
	ctx context.Context, trc cppki.SignedTRC) (cppki.SignedTRC, error) {

	c.submissions++
	if _, err := c.TRCCaster.SubmitTRC(ctx, trc); err != nil {
		return cppki.SignedTRC{}, err
	}
	return cppki.SignedTRC{}, serrors.New("the answer was lost")
}

// pendingFirstAuthorizer pends the first ask about a set of keys and allows
// the later ones, the operator's answer landing on the next ask; it records
// the facts asked with.
type pendingFirstAuthorizer struct {
	asked []enrollauth.AdmissionFacts
}

func (a *pendingFirstAuthorizer) Authorize(
	_ context.Context, f enrollauth.AdmissionFacts) enrollauth.AdmissionAnswer {

	seen := slices.ContainsFunc(a.asked, func(prior enrollauth.AdmissionFacts) bool {
		return slices.Equal(prior.Keys, f.Keys)
	})
	a.asked = append(a.asked, f)
	if seen {
		return enrollauth.AdmissionAnswer{Admission: enrollauth.AdmissionAllow}
	}
	return enrollauth.AdmissionAnswer{Admission: enrollauth.AdmissionPending}
}

// replaceVotingPair replaces the joiner's live pair with a stranger's, the
// operator's replacement of the node's voting material.
func replaceVotingPair(t *testing.T, state string) {
	t.Helper()
	stranger := t.TempDir()
	key, err := trust.LoadOrCreateVotingKey(stranger)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trust.LoadOrCreateVotingCert(stranger, joinerIATest, key); err != nil {
		t.Fatal(err)
	}
	replaceKeyFiles(t, stranger, state, trust.RegularKeyFile, trust.RegularVotingCertFile)
}

// checkLiveVotingPair fails the test unless the joiner's live key and
// certificate load as a pair, the certificate the one the TRC names for the
// joiner, and no staged file remains.
func checkLiveVotingPair(t *testing.T, state string, trc cppki.SignedTRC) {
	t.Helper()
	named := trust.CertsOf(trc.TRC, joinerIATest)
	if len(named) != 1 {
		t.Fatalf("%v names %d certificates of the joiner, want 1", trc.TRC.ID, len(named))
	}
	key, err := trust.LoadOrCreateVotingKey(state)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := trust.LoadOrCreateVotingCert(state, joinerIATest, key)
	if err != nil {
		t.Fatalf("the live pair does not load: %v", err)
	}
	if !cert.Equal(named[0]) {
		t.Errorf("the live certificate is not the one %v names", trc.TRC.ID)
	}
	checkNoStaged(t, state)
}

// updateType classifies the successor against its predecessor.
func updateType(t *testing.T, successor, pred cppki.SignedTRC) cppki.UpdateType {
	t.Helper()
	update, err := successor.TRC.ValidateUpdate(&pred.TRC)
	if err != nil {
		t.Fatal(err)
	}
	return update.Type
}
