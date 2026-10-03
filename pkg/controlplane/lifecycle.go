package controlplane

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
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/modules/trustdb"
	"github.com/fancl20/cion/pkg/trust"
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
// A joining core carries its voting material beside the chain: once enrolled,
// the loop casts the sensitive update that onboards it, and a joiner the
// newest pinned TRC already names casts nothing.
type EnrollmentConfig struct {
	// IA is the node's ISD-AS.
	IA addr.IA
	// DB holds the node's chains and the pinned TRC.
	DB trustdb.DB
	// Key is the node's AS key.
	Key crypto.Signer
	// Remote enrolls against the core's endpoint; nil on the founding
	// core, which self-issues through the Issuer.
	Remote trust.Remote
	// Issuer self-issues the core's chains.
	Issuer *trust.Issuer
	// VotingKey is the joining core's regular voting key; nil on the nodes
	// that hold none.
	VotingKey crypto.Signer
	// VotingCert is the certificate over VotingKey, carried by the
	// successor TRC the cast builds.
	VotingCert *x509.Certificate
	// Caster submits the onboarding update to the core's voting
	// application; the joining core's own client, nil on every other node.
	Caster trust.TRCCaster
	// Fatal is the loop's terminal failure: the reason recorded and the
	// node stopped, for an onboarding nothing the node does can advance.
	// Nil keeps the node serving, the failure logged.
	Fatal func(error)
	// RetryInterval and InspectInterval override the defaults; zero keeps
	// them.
	RetryInterval   time.Duration
	InspectInterval time.Duration
	// Timeout bounds one enrollment attempt; zero uses the default.
	Timeout time.Duration
}

func (cfg EnrollmentConfig) interval(v, def time.Duration) time.Duration {
	if v == 0 {
		return def
	}
	return v
}

func (cfg EnrollmentConfig) enroll(ctx context.Context) {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = EnrollmentTimeout
	}
	attemptCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if _, err := trust.RenewChain(attemptCtx, cfg.DB, cfg.Remote, cfg.IA,
		cfg.Key); err != nil {

		slog.Warn("Renewing chain", "isd_as", cfg.IA, "err", err)
		return
	}
	slog.Info("Renewed chain", "isd_as", cfg.IA)
}

// onboarded reports whether the newest pinned TRC names the node a core of
// its ISD; a node that has pinned no TRC yet is not onboarded.
func (cfg EnrollmentConfig) onboarded(ctx context.Context) bool {
	trc, err := cfg.DB.SignedTRC(ctx, cppki.TRCID{
		ISD:    cfg.IA.ISD(),
		Base:   scrypto.LatestVer,
		Serial: scrypto.LatestVer,
	})
	if err != nil {
		slog.Error("Reading the newest pinned TRC", "isd_as", cfg.IA, "err", err)
		return false
	}
	return trust.CoreNamed(trc.TRC, cfg.IA)
}

// cast performs one onboarding attempt: the submission's round trip,
// bounded like an enrollment attempt. A core that hosts no voting
// application is terminal: nothing the node does obtains voting power
// through the founder, so the node stops itself — the network it leaves
// behind keeps serving everything else, the application none of it depends
// on.
func (cfg EnrollmentConfig) cast(ctx context.Context) {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = EnrollmentTimeout
	}
	attemptCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	err := trust.JoinCore(attemptCtx, cfg.DB, cfg.Remote, cfg.Caster,
		cfg.IA, cfg.VotingKey, cfg.VotingCert)
	switch {
	case err == nil:
		slog.Info("Onboarded as an authoritative core", "isd_as", cfg.IA)
	case errors.Is(err, trust.ErrNoVotingApp):
		slog.Error("The core hosts no voting application; stopping the node",
			"isd_as", cfg.IA, "err", err)
		if cfg.Fatal != nil {
			cfg.Fatal(err)
		}
	default:
		slog.Warn("Submitting the onboarding update", "isd_as", cfg.IA, "err", err)
	}
}

// RunEnrollment runs the chain lifecycle of a non-core node: each pass reads
// the newest chain's remaining validity, re-enrolls when it drops below the
// renewal threshold or when no valid chain exists, casts the onboarding
// update a joining core still owes, and — on the nodes that roll nothing —
// watches the newest pinned TRC's validity the same way, log only, for the
// update that extends it is the founder's to cast. A core's rotation watch
// carries that report instead. It also runs the trust database's
// expired-chain sweep on its own interval.
func RunEnrollment(ctx context.Context, cfg EnrollmentConfig) {
	var sweep sync.WaitGroup
	sweep.Go(func() {
		cfg.sweepChains(ctx)
	})
	defer sweep.Wait()
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(cfg.enrollPass(ctx)):
		}
	}
}

// RunCoreEnrollment runs the founding core's chain lifecycle: the same loop
// with a local action — self-issuing through the core's issuer whenever the
// renewal threshold demands it, and the same expired-chain sweep. The
// founding core's rotation watch reports the trust material's validity
// beside this loop. The synchronous startup self-enrollment is the first
// pass; this loop keeps the chain valid for the node's lifetime.
func RunCoreEnrollment(ctx context.Context, cfg EnrollmentConfig) {
	var sweep sync.WaitGroup
	sweep.Go(func() {
		cfg.sweepChains(ctx)
	})
	defer sweep.Wait()
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(cfg.corePass(ctx)):
		}
	}
}

// enrollPass runs one non-core inspection: it returns how long to wait
// before the next one — the fast retry cadence while unenrolled, renewing,
// or onboarding, the calm inspection interval with a valid chain and, for a
// joining core, a pinned TRC that names it.
func (cfg EnrollmentConfig) enrollPass(ctx context.Context) time.Duration {
	chain, remaining := newestChain(ctx, cfg)
	if cfg.VotingKey == nil {
		// The normal node's report; a core's rotation watch carries it
		// instead, with the roll the report's escalation asks for.
		logTRCValidity(ctx, cfg)
	}
	switch {
	case chain == nil:
		slog.Warn("No valid chain; enrolling", "isd_as", cfg.IA)
		cfg.enroll(ctx)
	case remaining <= 0:
		slog.Error("Last chain expired; re-enrolling",
			"isd_as", cfg.IA, "expired_for", -remaining)
		cfg.enroll(ctx)
	case remaining < trust.ChainRenewalThreshold:
		slog.Warn("Chain approaching expiry; re-enrolling",
			"isd_as", cfg.IA, "remaining", remaining)
		cfg.enroll(ctx)
	case cfg.VotingKey != nil && cfg.Caster != nil && !cfg.onboarded(ctx):
		// The enrolled core's onboarding: the cast asks the founder, and a
		// joiner the newest TRC already names casts nothing.
		cfg.cast(ctx)
	default:
		return cfg.interval(cfg.InspectInterval, ChainInspectInterval)
	}
	return cfg.interval(cfg.RetryInterval, EnrollmentRetryInterval)
}

// corePass runs one core inspection: self-issuing whenever the renewal
// threshold demands it.
func (cfg EnrollmentConfig) corePass(ctx context.Context) time.Duration {
	chain, remaining := newestChain(ctx, cfg)
	switch {
	case chain == nil || remaining < trust.ChainRenewalThreshold:
		if chain != nil && remaining > 0 {
			slog.Warn("Core chain approaching expiry; self-issuing",
				"isd_as", cfg.IA, "remaining", remaining)
		}
		if err := selfIssue(ctx, cfg); err != nil {
			slog.Error("Core self-enrollment failed", "isd_as", cfg.IA, "err", err)
		}
	default:
		return cfg.interval(cfg.InspectInterval, ChainInspectInterval)
	}
	return cfg.interval(cfg.RetryInterval, EnrollmentRetryInterval)
}

// newestChain returns the node's newest chain and its remaining validity; a
// nil chain means none is valid.
func newestChain(ctx context.Context, cfg EnrollmentConfig) ([]*x509.Certificate, time.Duration) {
	chain, err := trust.NewestChain(ctx, cfg.DB, cfg.IA, time.Now())
	if err != nil {
		panic(fmt.Sprintf("reading the newest chain: %v", err))
	}
	if chain == nil {
		return nil, 0
	}
	return chain, time.Until(chain[0].NotAfter)
}

// selfIssue self-issues the core's chain through its issuer and stores it.
func selfIssue(ctx context.Context, cfg EnrollmentConfig) error {
	csr, err := trust.CreateCSR(cfg.IA, cfg.Key)
	if err != nil {
		return err
	}
	chain, err := cfg.Issuer.IssueChain(csr)
	if err != nil {
		return err
	}
	if _, err := cfg.DB.InsertChain(ctx, chain); err != nil {
		return err
	}
	slog.Info("Self-issued core chain", "isd_as", cfg.IA,
		"not_after", chain[0].NotAfter)
	return nil
}

// logTRCValidity logs the newest pinned TRC's validity once it approaches
// expiry; log only, for the cast that extends it is the founder's to make.
// The nodes that hold voting material run the rotation watch beside this
// report instead.
func logTRCValidity(ctx context.Context, cfg EnrollmentConfig) {
	now := time.Now()
	trc, err := cfg.DB.SignedTRC(ctx, cppki.TRCID{
		ISD:    cfg.IA.ISD(),
		Base:   scrypto.LatestVer,
		Serial: scrypto.LatestVer,
	})
	if err != nil || trc.IsZero() {
		return
	}
	remaining := trc.TRC.Validity.NotAfter.Sub(now)
	switch {
	case remaining <= 0:
		slog.Error("Pinned TRC expired",
			"isd_as", cfg.IA, "expired_for", -remaining)
	case remaining < trust.ChainRenewalThreshold:
		slog.Warn("Pinned TRC approaching expiry",
			"isd_as", cfg.IA, "remaining", remaining)
	}
}

// sweepChains runs the trust database's expired-chain sweep until the context
// is canceled, the beaconer's own loop shape: a ticker on ChainSweepInterval
// whose every pass deletes the chains expired past the retention window. The
// enrollment loops already own the store's validity semantics; the sweep is
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
	if _, err := cfg.DB.DeleteExpiredChains(ctx, time.Now().Add(-trust.ChainRetention)); err != nil {
		slog.Error("Sweeping expired chains", "err", err)
	}
}
