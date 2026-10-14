package trust

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/libs/loops"
	"github.com/fancl20/cion/pkg/modules/trustdb"
)

// Chain lifecycle intervals: while unenrolled the loop keeps a fast retry
// cadence; with a valid chain it settles to a calm inspection interval.
const (
	// EnrollmentRetryInterval is the pause between enrollment attempts.
	EnrollmentRetryInterval = 5 * time.Second
	// ChainInspectInterval is the pause between validity inspections of a
	// valid chain.
	ChainInspectInterval = time.Minute
	// EnrollmentTimeout bounds one enrollment attempt: a wedged connection
	// must not stall the loop renewing through it.
	EnrollmentTimeout = 10 * time.Second
	// ChainSweepInterval is the period of the trust database's expired-chain
	// sweep.
	ChainSweepInterval = time.Hour
)

// EnrollmentConfig configures the lifetime chain lifecycle of a node: every
// node keeps a valid chain — the founding core included — by re-enrolling
// before expiry, with warnings as expiry approaches and errors once it passes.
// The Renewal carries what the node's role adds to the loop.
type EnrollmentConfig struct {
	// IA is the node's ISD-AS.
	IA addr.IA
	// DB holds the node's chains and the pinned TRC.
	DB trustdb.DB
	// Key is the node's AS key.
	Key crypto.Signer
	// Renewal is the role's part of the lifecycle: FounderRenewal,
	// NormalRenewal, or AuthoritativeRenewal.
	Renewal Renewal
	// RetryInterval and InspectInterval override the defaults; zero keeps
	// them.
	RetryInterval   time.Duration
	InspectInterval time.Duration
}

func (cfg EnrollmentConfig) interval(v, def time.Duration) time.Duration {
	if v == 0 {
		return def
	}
	return v
}

// Renewal is a role's part of the chain lifecycle RunEnrollment runs: how
// the node obtains a fresh chain, and the work the role owes once its chain
// is valid. FounderRenewal, NormalRenewal, and AuthoritativeRenewal build the
// three.
type Renewal interface {
	// renew obtains a fresh chain for the node's key and stores it.
	renew(ctx context.Context, cfg EnrollmentConfig) error
	// owed runs at a pass whose chain needs no renewal: it does the work
	// the role still owes, reporting whether any was owed, or the work's
	// terminal failure.
	owed(ctx context.Context, cfg EnrollmentConfig) (bool, error)
}

// FounderRenewal is the founding core's renewal: its chain self-issued
// through the issuer that serves the enrollment requests, and nothing more
// owed.
func FounderRenewal(issuer *Issuer) Renewal {
	return founderRenewal{issuer: issuer}
}

type founderRenewal struct {
	issuer *Issuer
}

func (r founderRenewal) renew(ctx context.Context, cfg EnrollmentConfig) error {
	return SelfIssue(ctx, cfg.DB, r.issuer, cfg.IA, cfg.Key)
}

// SelfIssue issues ia's chain for key through the issuer that serves the
// enrollment requests and stores it in db: the founding core's renewal, and
// the chain its boot holds before the endpoint serves.
func SelfIssue(
	ctx context.Context,
	db trustdb.DB,
	issuer *Issuer,
	ia addr.IA,
	key crypto.Signer,
) error {

	csr, err := CreateCSR(ia, key)
	if err != nil {
		return err
	}
	chain, err := issuer.IssueChain(csr)
	if err != nil {
		return err
	}
	_, err = db.InsertChain(ctx, chain)
	return err
}

func (founderRenewal) owed(context.Context, EnrollmentConfig) (bool, error) {
	return false, nil
}

// NormalRenewal is the normal node's renewal: its chain renewed against the
// core's endpoint through the remote, and nothing more owed.
func NormalRenewal(remote Remote) Renewal {
	return normalRenewal{remote: remote}
}

type normalRenewal struct {
	remote Remote
}

func (r normalRenewal) renew(ctx context.Context, cfg EnrollmentConfig) error {
	_, err := RenewChain(ctx, cfg.DB, r.remote, cfg.IA, cfg.Key)
	return err
}

func (normalRenewal) owed(context.Context, EnrollmentConfig) (bool, error) {
	return false, nil
}

// AuthoritativeRenewal is the joining core's renewal: its chain renewed
// against the core's endpoint through the remote and, once the chain is
// valid, the sensitive update that onboards it, owed until the newest
// pinned TRC names the core — a successor carrying the voting certificate,
// signed with the voting key as its proof of possession, and submitted
// through the caster to the founder's voting application.
func AuthoritativeRenewal(
	remote Remote,
	caster TRCCaster,
	votingKey crypto.Signer,
	votingCert *x509.Certificate,
) Renewal {

	return authoritativeRenewal{
		remote:     remote,
		caster:     caster,
		votingKey:  votingKey,
		votingCert: votingCert,
	}
}

type authoritativeRenewal struct {
	remote     Remote
	caster     TRCCaster
	votingKey  crypto.Signer
	votingCert *x509.Certificate
}

func (r authoritativeRenewal) renew(ctx context.Context, cfg EnrollmentConfig) error {
	_, err := RenewChain(ctx, cfg.DB, r.remote, cfg.IA, cfg.Key)
	return err
}

// owed performs one onboarding attempt while the newest pinned TRC does
// not name the core: the submission's round trip, bounded like an
// enrollment attempt. A core that hosts no voting application is terminal,
// returned as ErrNoVotingApp: nothing the node does obtains voting
// power through the founder, and the network the node leaves behind keeps
// serving everything else, the application none of it depends on. Every
// other failure is logged for the next pass to retry.
func (r authoritativeRenewal) owed(ctx context.Context, cfg EnrollmentConfig) (bool, error) {
	if onboarded(ctx, cfg) {
		return false, nil
	}
	attemptCtx, cancel := context.WithTimeout(ctx, EnrollmentTimeout)
	defer cancel()
	err := JoinCore(attemptCtx, cfg.DB, r.remote, r.caster,
		cfg.IA, r.votingKey, r.votingCert)
	switch {
	case err == nil:
		slog.Info("Onboarded as an authoritative core", "isd_as", cfg.IA)
	case errors.Is(err, ErrNoVotingApp):
		return true, err
	default:
		slog.Warn("Submitting the onboarding update", "isd_as", cfg.IA, "err", err)
	}
	return true, nil
}

// onboarded reports whether the newest pinned TRC names the node a core of
// its ISD; a node that has pinned no TRC yet is not onboarded.
func onboarded(ctx context.Context, cfg EnrollmentConfig) bool {
	trc, err := cfg.DB.SignedTRC(ctx, NewestTRCID(cfg.IA.ISD()))
	if err != nil {
		slog.Error("Reading the newest pinned TRC", "isd_as", cfg.IA, "err", err)
		return false
	}
	return CoreNamed(trc.TRC, cfg.IA)
}

// RunEnrollment runs a node's chain lifecycle: each pass reads the newest
// chain's remaining validity and reports the newest pinned TRC's. It renews
// the Renewal's way when no valid chain exists, when the chain's validity
// drops below the renewal threshold, or when the chain does not verify
// against the newest pinned TRC alone — anchored in a root the TRC replaced
// — and with a valid chain does the work the role still owes. It also runs
// the trust database's expired-chain sweep on its own interval. The founding
// core's synchronous startup self-enrollment is its first pass. It returns
// nil once the context ends, and the owed work's terminal failure — a
// joining core's ErrNoVotingApp — with the sweep stopped.
func RunEnrollment(ctx context.Context, cfg EnrollmentConfig) error {
	sweepCtx, stopSweep := context.WithCancel(ctx)
	var sweep sync.WaitGroup
	sweep.Go(func() {
		cfg.sweepChains(sweepCtx)
	})
	defer sweep.Wait()
	defer stopSweep()
	for {
		wait, err := cfg.enrollPass(ctx)
		if err != nil {
			return err
		}
		if !loops.Sleep(ctx, wait) {
			return nil
		}
	}
}

// enrollPass runs one inspection: it returns how long to wait before the
// next one — the fast retry cadence while unenrolled, renewing, doing owed
// work, or failing to read the chain or the newest pinned TRC, the calm
// inspection interval with a valid chain and nothing owed — or the owed
// work's terminal failure.
func (cfg EnrollmentConfig) enrollPass(ctx context.Context) (time.Duration, error) {
	chain, remaining, err := newestChain(ctx, cfg)
	if err != nil {
		slog.Error("Inspecting the chain", "isd_as", cfg.IA, "err", err)
		return cfg.interval(cfg.RetryInterval, EnrollmentRetryInterval), nil
	}
	newest, err := cfg.DB.SignedTRC(ctx, NewestTRCID(cfg.IA.ISD()))
	if err != nil {
		slog.Error("Reading the newest pinned TRC", "isd_as", cfg.IA, "err", err)
		return cfg.interval(cfg.RetryInterval, EnrollmentRetryInterval), nil
	}
	logTRCValidity(cfg.IA, newest)
	switch {
	case chain == nil:
		slog.Warn("No valid chain; enrolling", "isd_as", cfg.IA)
		cfg.attemptRenewal(ctx)
	case remaining <= 0:
		slog.Error("Last chain expired; re-enrolling",
			"isd_as", cfg.IA, "expired_for", -remaining)
		cfg.attemptRenewal(ctx)
	case remaining < ChainRenewalThreshold:
		slog.Warn("Chain approaching expiry; re-enrolling",
			"isd_as", cfg.IA, "remaining", remaining)
		cfg.attemptRenewal(ctx)
	case !newest.IsZero() && !anchoredIn(chain, newest):
		slog.Warn("Chain does not anchor in the newest TRC; re-enrolling",
			"isd_as", cfg.IA, "trc", newest.TRC.ID)
		cfg.attemptRenewal(ctx)
	default:
		owed, err := cfg.Renewal.owed(ctx, cfg)
		if err != nil {
			return 0, err
		}
		if !owed {
			return cfg.interval(cfg.InspectInterval, ChainInspectInterval), nil
		}
	}
	return cfg.interval(cfg.RetryInterval, EnrollmentRetryInterval), nil
}

// anchoredIn reports whether the chain verifies against the TRC's roots
// alone.
func anchoredIn(chain []*x509.Certificate, trc cppki.SignedTRC) bool {
	return cppki.VerifyChain(chain, cppki.VerifyOptions{TRC: []*cppki.TRC{&trc.TRC}}) == nil
}

// attemptRenewal performs one renewal attempt the Renewal's way, bounded so
// a wedged connection does not stall the loop renewing through it.
func (cfg EnrollmentConfig) attemptRenewal(ctx context.Context) {
	attemptCtx, cancel := context.WithTimeout(ctx, EnrollmentTimeout)
	defer cancel()
	if err := cfg.Renewal.renew(attemptCtx, cfg); err != nil {
		slog.Warn("Renewing chain", "isd_as", cfg.IA, "err", err)
		return
	}
	slog.Info("Renewed chain", "isd_as", cfg.IA)
}

// newestChain returns the node's newest chain and its remaining validity; a
// nil chain means none is valid.
func newestChain(
	ctx context.Context,
	cfg EnrollmentConfig,
) ([]*x509.Certificate, time.Duration, error) {

	chain, err := NewestChain(ctx, cfg.DB, cfg.IA, time.Now())
	if err != nil {
		return nil, 0, fmt.Errorf("reading the newest chain: %w", err)
	}
	if chain == nil {
		return nil, 0, nil
	}
	return chain, time.Until(chain[0].NotAfter), nil
}

// logTRCValidity logs the newest pinned TRC's validity once it approaches
// expiry, log only: the holders' rotation watches cast the successors that
// extend it, and a certificate whose holder never rolls caps it for every
// role. The zero TRC, nothing pinned yet, reports nothing.
func logTRCValidity(ia addr.IA, trc cppki.SignedTRC) {
	if trc.IsZero() {
		return
	}
	remaining := time.Until(trc.TRC.Validity.NotAfter)
	switch {
	case remaining <= 0:
		slog.Error("Pinned TRC expired",
			"isd_as", ia, "expired_for", -remaining)
	case remaining < ChainRenewalThreshold:
		slog.Warn("Pinned TRC approaching expiry",
			"isd_as", ia, "remaining", remaining)
	}
}

// sweepChains runs the trust database's expired-chain sweep until the context
// is canceled, the beaconer's own loop shape: a ticker on ChainSweepInterval
// whose every pass deletes the chains expired past the retention window. The
// enrollment loop already owns the store's validity semantics; the sweep is
// the same reading done for the store's size instead of the node's chain.
func (cfg EnrollmentConfig) sweepChains(ctx context.Context) {
	ticker := time.NewTicker(ChainSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cfg.sweepOnce(ctx)
		}
	}
}

// sweepOnce deletes the trust database's chains expired past the retention
// window; errors log the beaconer's sweepOnce way, and a successful sweep is
// silent, for it is the common case.
func (cfg EnrollmentConfig) sweepOnce(ctx context.Context) {
	if _, err := cfg.DB.DeleteExpiredChains(ctx, time.Now().Add(-ChainRetention)); err != nil {
		slog.Error("Sweeping expired chains", "err", err)
	}
}
