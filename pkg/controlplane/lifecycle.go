package controlplane

import (
	"context"
	"crypto"
	"crypto/x509"
	"log/slog"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/trust"
)

// Chain lifecycle intervals (proposal 0004): while unenrolled the loop keeps
// a fast retry cadence; with a valid chain it settles to a calm inspection
// interval.
const (
	// EnrollmentRetryInterval is the pause between enrollment attempts.
	EnrollmentRetryInterval = 5 * time.Second
	// ChainInspectInterval is the pause between validity inspections of a
	// valid chain.
	ChainInspectInterval = time.Minute
	// EnrollmentTimeout bounds one enrollment attempt: a wedged connection
	// must not stall the loop renewing through it.
	EnrollmentTimeout = 10 * time.Second
)

// EnrollmentConfig configures the lifetime chain lifecycle of a node
// (proposal 0004): every node keeps a valid chain — the founding core
// included — by re-enrolling before expiry, with warnings as expiry
// approaches and errors once it passes.
type EnrollmentConfig struct {
	// IA is the node's ISD-AS.
	IA addr.IA
	// DB holds the node's chains and the pinned TRC.
	DB trust.DB
	// Key is the node's AS key.
	Key crypto.Signer
	// Remote enrolls against the core's endpoint; nil on the founding
	// core, which self-issues through the Issuer.
	Remote trust.Remote
	// Issuer self-issues the core's chains.
	Issuer *trust.Issuer
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
	if _, err := trust.RenewChain(attemptCtx, cfg.DB, cfg.Remote, cfg.IA, cfg.Key); err != nil {
		slog.Warn("Renewing chain", "isd_as", cfg.IA, "err", err)
		return
	}
	slog.Info("Renewed chain", "isd_as", cfg.IA)
}

// RunEnrollment runs the chain lifecycle of a non-core node: each pass reads
// the newest chain's remaining validity, re-enrolls when it drops below the
// renewal threshold or when no valid chain exists, and watches the pinned
// TRC's validity the same way — log only, since a new base TRC means
// redeploying (ADR-0003).
func RunEnrollment(ctx context.Context, cfg EnrollmentConfig) {
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
// renewal threshold demands it. The synchronous startup self-enrollment is
// the first pass; this loop keeps the chain valid for the node's lifetime.
func RunCoreEnrollment(ctx context.Context, cfg EnrollmentConfig) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(cfg.corePass(ctx)):
		}
	}
}

// enrollPass runs one non-core inspection: it returns how long to wait
// before the next one — the fast retry cadence while unenrolled or renewing,
// the calm inspection interval with a valid chain.
func (cfg EnrollmentConfig) enrollPass(ctx context.Context) time.Duration {
	chain, remaining := newestChain(ctx, cfg)
	logTRCValidity(ctx, cfg)
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
	default:
		return cfg.interval(cfg.InspectInterval, ChainInspectInterval)
	}
	return cfg.interval(cfg.RetryInterval, EnrollmentRetryInterval)
}

// corePass runs one core inspection: self-issuing whenever the renewal
// threshold demands it.
func (cfg EnrollmentConfig) corePass(ctx context.Context) time.Duration {
	chain, remaining := newestChain(ctx, cfg)
	logTRCValidity(ctx, cfg)
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
		slog.Error("Reading newest chain", "isd_as", cfg.IA, "err", err)
		return nil, 0
	}
	if chain == nil {
		return nil, 0
	}
	return chain, chain[0].NotAfter.Sub(time.Now())
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

// logTRCValidity logs the pinned TRC's validity once it approaches expiry;
// log only, since a new base TRC means redeploying (ADR-0003).
func logTRCValidity(ctx context.Context, cfg EnrollmentConfig) {
	now := time.Now()
	trc, err := cfg.DB.SignedTRC(ctx, cppki.TRCID{ISD: cfg.IA.ISD(), Base: 1, Serial: 1})
	if err != nil || trc.IsZero() {
		return
	}
	remaining := trc.TRC.Validity.NotAfter.Sub(now)
	switch {
	case remaining <= 0:
		slog.Error("Pinned TRC expired; a new base TRC means redeploying",
			"isd_as", cfg.IA, "expired_for", -remaining)
	case remaining < trust.ChainRenewalThreshold:
		slog.Warn("Pinned TRC approaching expiry; a new base TRC means redeploying",
			"isd_as", cfg.IA, "remaining", remaining)
	}
}
