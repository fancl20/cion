package controlplane

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/modules/trustdb"
	"github.com/fancl20/cion/pkg/modules/trustdb/impl/bbolt"
	"github.com/fancl20/cion/pkg/trust"
)

// fakeCore implements trust.Remote: it serves the TRC and issues chains
// through the issuer.
type fakeCore struct {
	issuer *trust.Issuer
	trc    cppki.SignedTRC

	mtx     sync.Mutex
	renewed int
}

var errFakeCoreUnavailable = errors.New("core unavailable")

func (c *fakeCore) TRC(ctx context.Context, id cppki.TRCID) (cppki.SignedTRC, error) {
	if c.trc.IsZero() {
		return cppki.SignedTRC{}, errFakeCoreUnavailable
	}
	return c.trc, nil
}

func (c *fakeCore) Chains(
	ctx context.Context, q trustdb.ChainQuery) ([][]*x509.Certificate, error) {

	return nil, errFakeCoreUnavailable
}

func (c *fakeCore) RenewChain(
	ctx context.Context, csr *x509.CertificateRequest,
	key crypto.Signer) ([]*x509.Certificate, error) {

	c.mtx.Lock()
	defer c.mtx.Unlock()
	if c.issuer == nil {
		return nil, errFakeCoreUnavailable
	}
	c.renewed++
	return c.issuer.IssueChain(csr)
}

func (c *fakeCore) renewals() int {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	return c.renewed
}

// lifecycleFixture is a node's enrollment state against a fake core.
type lifecycleFixture struct {
	db   trustdb.DB
	key  crypto.Signer
	core *fakeCore
	cfg  EnrollmentConfig
}

func newLifecycleFixture(t *testing.T, f *trustFixture) *lifecycleFixture {
	t.Helper()
	db, err := bbolt.New(filepath.Join(t.TempDir(), "trust.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	lf := &lifecycleFixture{
		db:   db,
		key:  key,
		core: &fakeCore{issuer: f.issuer, trc: f.trc},
	}
	lf.cfg = EnrollmentConfig{
		IA:            nodeIATest,
		DB:            db,
		Key:           key,
		Renewal:       NormalRenewal(lf.core),
		RetryInterval: time.Millisecond,
	}
	return lf
}

// enroll issues the node's first chain directly.
func (f *lifecycleFixture) enroll(t *testing.T) {
	t.Helper()
	csr, err := trust.CreateCSR(nodeIATest, f.key)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := f.core.issuer.IssueChain(csr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.InsertChain(context.Background(), chain); err != nil {
		t.Fatal(err)
	}
}

// enrollPassOf runs one non-core pass, failing the test on a terminal
// failure, and returns the wait it asks for.
func enrollPassOf(t *testing.T, ctx context.Context, cfg EnrollmentConfig) time.Duration {
	t.Helper()
	wait, err := cfg.enrollPass(ctx)
	if err != nil {
		t.Fatalf("enrollment pass: %v", err)
	}
	return wait
}

// absentVoting is the caster of a core that hosts no voting application.
type absentVoting struct{}

func (absentVoting) SubmitTRC(context.Context, cppki.SignedTRC) (cppki.SignedTRC, error) {
	return cppki.SignedTRC{}, trust.ErrNoVotingApp
}

// TestEnrollmentStopsWithoutVotingApp checks the onboarding's terminal
// failure in a fake-time bubble: an enrolled joining core whose cast finds
// no voting application makes RunEnrollment return it at that pass, with
// the context still live — which RunEnrollment does only once its chain
// sweep has returned.
func TestEnrollmentStopsWithoutVotingApp(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newTrustFixture(t)
		lf := newLifecycleFixture(t, f)
		lf.enroll(t)
		state := t.TempDir()
		key, err := trust.LoadOrCreateVotingKey(state)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := trust.LoadOrCreateVotingCert(state, nodeIATest, key)
		if err != nil {
			t.Fatal(err)
		}
		cfg := lf.cfg
		cfg.Renewal = AuthoritativeRenewal(lf.core, absentVoting{}, key, cert)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- RunEnrollment(ctx, cfg) }()
		synctest.Wait()
		select {
		case err := <-done:
			if !errors.Is(err, trust.ErrNoVotingApp) {
				t.Fatalf("RunEnrollment = %v, want the absent voting application", err)
			}
		default:
			t.Fatal("RunEnrollment still runs after the onboarding's terminal failure")
		}
	})
}

// TestEnrollmentPasses checks the lifecycle loop's decisions: a valid chain
// with enough remaining validity only inspects; below the renewal threshold
// it re-enrolls; past expiry it re-enrolls after logging an error. The
// chain's validity is walked through in a fake-time bubble.
func TestEnrollmentPasses(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newTrustFixture(t)
		lf := newLifecycleFixture(t, f)
		ctx := context.Background()
		lf.enroll(t)

		// Fresh chain: three days of validity, well above the one-day
		// threshold — no enrollment, calm inspection interval.
		lf.cfg.InspectInterval = 7 * time.Minute
		if got := enrollPassOf(t, ctx, lf.cfg); got != 7*time.Minute {
			t.Errorf("pass interval = %v, want the inspection interval", got)
		}
		if got := lf.core.renewals(); got != 0 {
			t.Errorf("renewals = %d, want 0 above the threshold", got)
		}

		// Approaching expiry: the clock advances past the threshold —
		// re-enroll, fast retry cadence.
		time.Sleep(trust.ASValidity - trust.ChainRenewalThreshold + time.Minute)
		if got := enrollPassOf(t, ctx, lf.cfg); got != time.Millisecond {
			t.Errorf("pass interval = %v, want the retry interval", got)
		}
		if got := lf.core.renewals(); got != 1 {
			t.Errorf("renewals = %d, want 1 below the threshold", got)
		}
		chain, err := trust.NewestChain(ctx, lf.db, nodeIATest, time.Now())
		if err != nil || chain == nil {
			t.Fatalf("no renewed chain: %v", err)
		}
		// The renewal is a second chain; the old one stays verifiable while it
		// overlaps.
		chains, err := lf.db.Chains(ctx, trustdb.ChainQuery{IA: nodeIATest})
		if err != nil {
			t.Fatal(err)
		}
		if len(chains) != 2 {
			t.Errorf("chains = %d, want 2 after renewal", len(chains))
		}

		// Past expiry: still re-enrolling, never settled.
		time.Sleep(3 * trust.ASValidity)
		if got := enrollPassOf(t, ctx, lf.cfg); got != time.Millisecond {
			t.Errorf("pass interval = %v, want the retry interval past expiry", got)
		}
		if got := lf.core.renewals(); got != 2 {
			t.Errorf("renewals = %d, want 2 after expiry", got)
		}
	})
}

// TestEnrollmentPassFailing checks a node whose enrollment fails near
// expiry: the pass keeps the fast cadence and keeps trying.
func TestEnrollmentPassFailing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newTrustFixture(t)
		lf := newLifecycleFixture(t, f)
		lf.enroll(t)
		lf.core.issuer = nil // the core goes dark
		time.Sleep(2 * trust.ASValidity)

		if got := enrollPassOf(t, context.Background(), lf.cfg); got != time.Millisecond {
			t.Errorf("pass interval = %v, want the retry interval while failing", got)
		}
		if got := lf.core.renewals(); got != 0 {
			t.Errorf("renewals = %d, want 0 against a dark core", got)
		}
	})
}

// unreadableChainsDB delegates to the wrapped database except for chain
// reads, which fail.
type unreadableChainsDB struct {
	trustdb.DB
}

func (unreadableChainsDB) Chains(
	context.Context, trustdb.ChainQuery) ([][]*x509.Certificate, error) {

	return nil, errors.New("the chains bucket is unreadable")
}

// TestEnrollmentPassUnreadableChains checks the pass on a chain read that
// fails, under the normal node's renewal and the founder's: the pass asks
// for the retry cadence with nothing enrolled or self-issued, so the loop
// reads again instead of ending.
func TestEnrollmentPassUnreadableChains(t *testing.T) {
	f := newTrustFixture(t)
	lf := newLifecycleFixture(t, f)
	ctx := context.Background()
	cfg := lf.cfg
	cfg.DB = unreadableChainsDB{DB: lf.db}

	if got := enrollPassOf(t, ctx, cfg); got != time.Millisecond {
		t.Errorf("pass interval = %v, want the retry interval", got)
	}
	if got := lf.core.renewals(); got != 0 {
		t.Errorf("renewals = %d, want none without a readable chain", got)
	}
	cfg.Renewal = FounderRenewal(f.issuer)
	if got := enrollPassOf(t, ctx, cfg); got != time.Millisecond {
		t.Errorf("founder's pass interval = %v, want the retry interval", got)
	}
	chains, err := lf.db.Chains(ctx, trustdb.ChainQuery{IA: nodeIATest})
	if err != nil {
		t.Fatal(err)
	}
	if len(chains) != 0 {
		t.Errorf("chains = %d, want none self-issued without a readable chain", len(chains))
	}
}

// TestChainSweepPass checks one sweep pass of the enrollment loop's trust
// database sweep in a fake-time bubble: a chain still within its validity is
// never deleted by however many sweeps pass; past expiry and the retention
// window it leaves, the store answers every valid query exactly as before, and
// the pinned TRC survives a sweep of a store whose chains are all expired.
func TestChainSweepPass(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newTrustFixture(t)
		lf := newLifecycleFixture(t, f)
		ctx := context.Background()
		// Pin the fixture's genesis TRC the way enrollment does.
		if _, err := lf.db.InsertTRC(ctx, f.trc); err != nil {
			t.Fatal(err)
		}
		lf.enroll(t)

		// The enrolled chain is valid for three days: however many sweeps
		// pass, it stays.
		for range 3 {
			lf.cfg.sweepOnce(ctx)
		}
		chains, err := lf.db.Chains(ctx, trustdb.ChainQuery{})
		if err != nil {
			t.Fatal(err)
		}
		if len(chains) != 1 {
			t.Fatalf("chains after sweeps of a valid chain = %d, want 1", len(chains))
		}

		// Past expiry the chain is already invisible to a query bounded by
		// the present; past the retention window one sweep pass removes it
		// for good — an unfiltered read is what changes, and nothing else.
		time.Sleep(trust.ASValidity + trust.ChainRetention + time.Minute)
		now := time.Now()
		chains, err = lf.db.Chains(ctx, trustdb.ChainQuery{
			Validity: cppki.Validity{NotBefore: now, NotAfter: now},
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(chains) != 0 {
			t.Fatalf("valid query past expiry = %d chains, want 0", len(chains))
		}
		lf.cfg.sweepOnce(ctx)
		chains, err = lf.db.Chains(ctx, trustdb.ChainQuery{})
		if err != nil {
			t.Fatal(err)
		}
		if len(chains) != 0 {
			t.Errorf("chains after the sweep = %d, want 0 (expired chain held)", len(chains))
		}

		// The pinned TRC survives the sweep of the emptied store.
		trc, err := lf.db.SignedTRC(ctx, cppki.TRCID{ISD: nodeIATest.ISD(), Base: 1, Serial: 1})
		if err != nil {
			t.Fatal(err)
		}
		if !cmp.Equal(trc, f.trc) {
			t.Error("the pinned TRC did not survive the sweep")
		}
	})
}

// TestChainSweepLoop checks the sweep's own loop: its hourly ticker fires
// under fake time and deletes the expired chain without any pass of the
// enrollment loop itself.
func TestChainSweepLoop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newTrustFixture(t)
		lf := newLifecycleFixture(t, f)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go lf.cfg.sweepChains(ctx)
		lf.enroll(t)

		// The chain expires and the retention window passes; the ticker's
		// next fire sweeps it.
		time.Sleep(trust.ASValidity + trust.ChainRetention + 2*ChainSweepInterval)
		synctest.Wait()
		chains, err := lf.db.Chains(ctx, trustdb.ChainQuery{})
		if err != nil {
			t.Fatal(err)
		}
		if len(chains) != 0 {
			t.Errorf("chains after the sweep's ticker fired = %d, want 0", len(chains))
		}
	})
}

// TestBeaconingRunReturnsOnCancel checks Run's own join: the loops step on
// their tickers, and Run returns once every loop has exited after the
// cancellation — on the bubble-and-cancel shape the sweep loop's episode
// set.
func TestBeaconingRunReturnsOnCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newBeaconFixture(t)
		var rounds atomic.Int32
		links := func() map[uint16]addr.IA {
			rounds.Add(1)
			return map[uint16]addr.IA{}
		}
		b, err := NewBeaconer(BeaconerConfig{
			IA:                   coreIATest,
			Engine:               f.engines[coreIATest],
			MACKey:               []byte(testMACKey),
			Store:                f.store,
			DB:                   f.pathDB,
			Links:                links,
			Sender:               f.sender,
			Core:                 true,
			PropagationInterval:  time.Millisecond,
			RegistrationInterval: 2 * time.Millisecond,
		})
		if err != nil {
			t.Fatal(err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan struct{})
		go func() {
			defer close(done)
			b.Run(ctx)
		}()
		time.Sleep(10 * time.Millisecond)
		if got := rounds.Load(); got < 3 {
			t.Fatalf("origination rounds = %d, want the loops stepping on their tickers", got)
		}

		cancel()
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Fatal("Run did not return once its loops had exited")
		}
	})
}

// TestCoreEnrollmentPass checks the pass on the founder's renewal: it
// self-issues on the same rule, keeping a valid chain for the node's
// lifetime.
func TestCoreEnrollmentPass(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newTrustFixture(t)
		lf := newLifecycleFixture(t, f)
		ctx := context.Background()
		cfg := EnrollmentConfig{
			IA:            nodeIATest,
			DB:            lf.db,
			Key:           lf.key,
			Renewal:       FounderRenewal(f.issuer),
			RetryInterval: time.Millisecond,
		}

		// No chain yet: self-issue immediately.
		if got := enrollPassOf(t, ctx, cfg); got != time.Millisecond {
			t.Errorf("pass interval = %v, want the retry interval without a chain", got)
		}
		chain, err := trust.NewestChain(context.Background(), lf.db, nodeIATest, time.Now())
		if err != nil || chain == nil {
			t.Fatalf("no self-issued chain: %v", err)
		}

		// Valid for three days: settle to the inspection interval.
		if got := enrollPassOf(t, ctx, cfg); got != cfg.interval(0, ChainInspectInterval) {
			t.Errorf("pass interval = %v, want the default inspection interval", got)
		}

		// Approaching expiry: self-issue again.
		time.Sleep(trust.ASValidity - trust.ChainRenewalThreshold + time.Minute)
		if got := enrollPassOf(t, ctx, cfg); got != time.Millisecond {
			t.Errorf("pass interval = %v, want the retry interval below the threshold", got)
		}
		chains, err := lf.db.Chains(context.Background(), trustdb.ChainQuery{IA: nodeIATest})
		if err != nil {
			t.Fatal(err)
		}
		if len(chains) != 2 {
			t.Fatalf("chains = %d, want 2 after self-renewal", len(chains))
		}
		fresh, err := trust.NewestChain(context.Background(), lf.db, nodeIATest, time.Now())
		if err != nil || fresh == nil {
			t.Fatalf("no renewed core chain: %v", err)
		}
		if !fresh[0].NotAfter.Equal(chain[0].NotAfter) && !fresh[0].NotAfter.After(chain[0].NotAfter) {
			t.Error("core chain was not renewed")
		}
	})
}
