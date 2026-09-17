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
	"testing"
	"testing/synctest"
	"time"

	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/trust"
	"github.com/fancl20/cion/pkg/trust/impl/bbolt"
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
	ctx context.Context, q trust.ChainQuery) ([][]*x509.Certificate, error) {

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
	db   trust.DB
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
	t.Cleanup(func() { db.Close() }) //nolint:errcheck
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
		chains, err := lf.db.Chains(ctx, trust.ChainQuery{IA: nodeIATest})
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
		chains, err := lf.db.Chains(context.Background(), trust.ChainQuery{IA: nodeIATest})
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
