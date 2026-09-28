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

	"github.com/fancl20/cion/pkg/modules/pathdb"
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
		Remote:        lf.core,
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
		if got := lf.cfg.enrollPass(ctx); got != 7*time.Minute {
			t.Errorf("pass interval = %v, want the inspection interval", got)
		}
		if got := lf.core.renewals(); got != 0 {
			t.Errorf("renewals = %d, want 0 above the threshold", got)
		}

		// Approaching expiry: the clock advances past the threshold —
		// re-enroll, fast retry cadence.
		time.Sleep(trust.ASValidity - trust.ChainRenewalThreshold + time.Minute)
		if got := lf.cfg.enrollPass(ctx); got != time.Millisecond {
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
		if got := lf.cfg.enrollPass(ctx); got != time.Millisecond {
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

		if got := lf.cfg.enrollPass(context.Background()); got != time.Millisecond {
			t.Errorf("pass interval = %v, want the retry interval while failing", got)
		}
		if got := lf.core.renewals(); got != 0 {
			t.Errorf("renewals = %d, want 0 against a dark core", got)
		}
	})
}

// TestChainSweepPass checks one sweep pass of the enrollment loops' trust
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

// panickingDB delegates to the wrapped database except on the first
// expired-segment sweep, which it panics instead — the seeded round.
type panickingDB struct {
	pathdb.DB
	swept atomic.Bool
}

func (d *panickingDB) DeleteExpired(ctx context.Context, now time.Time) (int, error) {
	if !d.swept.Swap(true) {
		panic("a round meets its panic")
	}
	return d.DB.DeleteExpired(ctx, now)
}

// TestBeaconingLoopAbsorbsPanics checks Run's own containment: a panicking
// round is absorbed and logged by the loop that ran it — the process
// intact, the sibling loops stepping on, and Run still returning once
// every loop has exited — on the bubble-and-cancel shape the sweep loop's
// episode set.
func TestBeaconingLoopAbsorbsPanics(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newBeaconFixture(t)
		db := &panickingDB{DB: f.pathDB}
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
			DB:                   db,
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

		// The sweep's first round panics and its loop dies on it — one sweep
		// ever — while the origination loop steps past it the whole while.
		time.Sleep(10 * time.Millisecond)
		if !db.swept.Load() {
			t.Fatal("the seeded round never ran")
		}
		if got := rounds.Load(); got < 3 {
			t.Fatalf("origination rounds = %d, want the loop stepping past the sibling's panicked round", got)
		}

		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("Run did not return after cancellation")
		}
	})
}

// TestCoreEnrollmentPass checks the core's loop: it self-issues on the same
// rule, keeping a valid chain for the node's lifetime.
func TestCoreEnrollmentPass(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newTrustFixture(t)
		lf := newLifecycleFixture(t, f)
		cfg := EnrollmentConfig{
			IA:            nodeIATest,
			DB:            lf.db,
			Key:           lf.key,
			Issuer:        f.issuer,
			RetryInterval: time.Millisecond,
		}

		// No chain yet: self-issue immediately.
		if got := cfg.corePass(context.Background()); got != time.Millisecond {
			t.Errorf("pass interval = %v, want the retry interval without a chain", got)
		}
		chain, err := trust.NewestChain(context.Background(), lf.db, nodeIATest, time.Now())
		if err != nil || chain == nil {
			t.Fatalf("no self-issued chain: %v", err)
		}

		// Valid for three days: settle to the inspection interval.
		if got := cfg.corePass(context.Background()); got != cfg.interval(0, ChainInspectInterval) {
			t.Errorf("pass interval = %v, want the default inspection interval", got)
		}

		// Approaching expiry: self-issue again.
		time.Sleep(trust.ASValidity - trust.ChainRenewalThreshold + time.Minute)
		if got := cfg.corePass(context.Background()); got != time.Millisecond {
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
