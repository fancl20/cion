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
// before expiry, with warnings as expiry approaches and once it passes.
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
	// RenewalThreshold overrides ChainRenewalThreshold; zero keeps it.
	RenewalThreshold time.Duration
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
	// renew obtains a fresh chain for the node's key and stores it. chain
	// is the node's valid chain that verifies against its anchor pool, the
	// authority a renewal rests on, and nil when it holds none.
	renew(ctx context.Context, cfg EnrollmentConfig, chain []*x509.Certificate) error
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

func (r founderRenewal) renew(ctx context.Context, cfg EnrollmentConfig, _ []*x509.Certificate) error {
	return SelfIssue(ctx, cfg.DB, r.issuer, cfg.IA, cfg.Key)
}

// SelfIssue issues ia's chain for key through the core's own issuer and
// stores it in db: a core's renewal, and the chain the founder's boot holds
// before the endpoint serves.
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

// NormalRenewal is the normal node's renewal: its chain renewed on its
// current one at any issuer through the issuers' remote, or enrolled at the
// founder through the founder's without one, and nothing more owed.
func NormalRenewal(founder, issuers Remote) Renewal {
	return normalRenewal{founder: founder, issuers: issuers}
}

type normalRenewal struct {
	founder, issuers Remote
}

func (r normalRenewal) renew(ctx context.Context, cfg EnrollmentConfig, chain []*x509.Certificate) error {
	return renewOrEnroll(ctx, cfg, r.founder, r.issuers, chain)
}

// renewOrEnroll renews the node's chain on its current one through the
// issuers' remote, or enrolls through the founder's when it holds none.
func renewOrEnroll(
	ctx context.Context,
	cfg EnrollmentConfig,
	founder, issuers Remote,
	chain []*x509.Certificate,
) error {

	remote := founder
	if chain != nil {
		remote = issuers
	}
	_, err := RenewChain(ctx, cfg.DB, remote, cfg.IA, cfg.Key, chain)
	return err
}

func (normalRenewal) owed(context.Context, EnrollmentConfig) (bool, error) {
	return false, nil
}

// AuthoritativeRenewal is the joining core's renewal: its chain self-issued
// through its own issuer while the issuer is anchored and the newest pinned
// TRC carries the core with its root, and renewed as a normal node's
// otherwise — before the onboarding lands, and once the founder removes the
// core. Once the chain is valid, the sensitive update that onboards the core
// is owed until the newest pinned TRC names it and carries its root — a
// successor carrying the voting and root certificates, signed with both keys
// as their proofs of possession, and submitted through the caster to the
// founder's voting application — and the issuer is anchored in the TRC that
// carries the root.
func AuthoritativeRenewal(
	founder, issuers Remote,
	caster TRCCaster,
	voting, root KeyCert,
	issuer *Issuer,
) Renewal {

	return authoritativeRenewal{
		founder: founder,
		issuers: issuers,
		caster:  caster,
		voting:  voting,
		root:    root,
		issuer:  issuer,
	}
}

type authoritativeRenewal struct {
	founder, issuers Remote
	caster           TRCCaster
	voting, root     KeyCert
	issuer           *Issuer
}

func (r authoritativeRenewal) renew(ctx context.Context, cfg EnrollmentConfig, chain []*x509.Certificate) error {
	newest, err := cfg.DB.SignedTRC(ctx, NewestTRCID(cfg.IA.ISD()))
	if err != nil {
		return fmt.Errorf("reading the newest pinned TRC: %w", err)
	}
	if r.issuer.Anchored() && Onboarded(newest.TRC, cfg.IA) {
		return SelfIssue(ctx, cfg.DB, r.issuer, cfg.IA, cfg.Key)
	}
	return renewOrEnroll(ctx, cfg, r.founder, r.issuers, chain)
}

// owed performs one onboarding attempt while the newest pinned TRC does not
// carry the core with its root: the submission's round trip, bounded like an
// enrollment attempt. A core that hosts no voting application is terminal,
// returned as ErrNoVotingApp: nothing the node does obtains voting power
// through the founder, and the network the node leaves behind keeps serving
// everything else, the application none of it depends on. Every other
// failure is logged for the next pass to retry. Once the newest pinned TRC
// carries the core, the issuer still unanchored is anchored in it.
func (r authoritativeRenewal) owed(ctx context.Context, cfg EnrollmentConfig) (bool, error) {
	newest, err := cfg.DB.SignedTRC(ctx, NewestTRCID(cfg.IA.ISD()))
	if err != nil {
		slog.Error("Reading the newest pinned TRC", "isd_as", cfg.IA, "err", err)
		return true, nil
	}
	if Onboarded(newest.TRC, cfg.IA) {
		if r.issuer.Anchored() {
			return false, nil
		}
		if err := r.issuer.Anchor(newest); err != nil {
			slog.Error("Anchoring the issuer", "isd_as", cfg.IA, "trc", newest.TRC.ID, "err", err)
			return true, nil
		}
		slog.Info("Issuing chains under the core's own root", "isd_as", cfg.IA,
			"trc", newest.TRC.ID)
		return false, nil
	}
	attemptCtx, cancel := context.WithTimeout(ctx, EnrollmentTimeout)
	defer cancel()
	err = JoinCore(attemptCtx, cfg.DB, r.founder, r.caster, cfg.IA, r.voting, r.root)
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

// RunEnrollment runs a node's chain lifecycle: each pass reads the remaining
// validity of the node's current chain — the newest of its valid chains the
// newest pinned TRC anchors alone — and reports the newest pinned TRC's. It
// renews the Renewal's way when no valid chain exists, when none the newest
// pinned TRC anchors does — each anchored in a root the TRC replaced or
// removed — or when the current chain's validity drops below the renewal
// threshold, and with a current chain does the work the role still owes. It
// also runs the trust database's expired-chain sweep on its own interval.
// The founding core's synchronous startup self-enrollment is its first pass.
// It returns nil once the context ends, and the owed work's terminal failure
// — a joining core's ErrNoVotingApp — with the sweep stopped.
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
// work, or failing to read the chains or the newest pinned TRC, the calm
// inspection interval with a current chain and nothing owed — or the owed
// work's terminal failure. A renewal rests on the node's anchored chain,
// which the anchor pool verifies.
func (cfg EnrollmentConfig) enrollPass(ctx context.Context) (time.Duration, error) {
	newest, err := cfg.DB.SignedTRC(ctx, NewestTRCID(cfg.IA.ISD()))
	if err != nil {
		slog.Error("Reading the newest pinned TRC", "isd_as", cfg.IA, "err", err)
		return cfg.interval(cfg.RetryInterval, EnrollmentRetryInterval), nil
	}
	logTRCValidity(cfg.IA, newest)
	now := time.Now()
	chains, err := cfg.DB.Chains(ctx, trustdb.ChainQuery{
		IA:       cfg.IA,
		Validity: cppki.Validity{NotBefore: now, NotAfter: now},
	})
	if err != nil {
		slog.Error("Inspecting the chain", "isd_as", cfg.IA, "err", err)
		return cfg.interval(cfg.RetryInterval, EnrollmentRetryInterval), nil
	}
	current := currentChain(chains, newest)
	switch {
	case len(chains) == 0:
		slog.Warn("No valid chain; enrolling", "isd_as", cfg.IA)
		cfg.attemptRenewal(ctx, nil)
	case current == nil:
		slog.Warn("No chain anchors in the newest TRC; renewing",
			"isd_as", cfg.IA, "trc", newest.TRC.ID)
		cfg.attemptRenewal(ctx, cfg.anchoredChain(ctx))
	case current[0].NotAfter.Sub(now) < cfg.interval(cfg.RenewalThreshold, ChainRenewalThreshold):
		slog.Warn("Chain approaching expiry; renewing",
			"isd_as", cfg.IA, "remaining", current[0].NotAfter.Sub(now))
		cfg.attemptRenewal(ctx, cfg.anchoredChain(ctx))
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

// currentChain returns the chain a pass inspects among the node's valid
// chains: the newest the TRC anchors alone, any while no TRC is pinned, and
// nil when none does. A chain a replaced or removed root anchors is passed
// over, however long it outlives the others.
func currentChain(chains [][]*x509.Certificate, trc cppki.SignedTRC) []*x509.Certificate {
	var current []*x509.Certificate
	for _, chain := range chains {
		if !trc.IsZero() && !anchoredIn(chain, trc) {
			continue
		}
		if current == nil || chain[0].NotAfter.After(current[0].NotAfter) {
			current = chain
		}
	}
	return current
}

// anchoredIn reports whether the chain verifies against the TRC's roots
// alone.
func anchoredIn(chain []*x509.Certificate, trc cppki.SignedTRC) bool {
	return cppki.VerifyChain(chain, cppki.VerifyOptions{TRC: []*cppki.TRC{&trc.TRC}}) == nil
}

// anchoredChain returns the chain a renewal rests on: the node's anchored
// chain, the newest of its valid chains that verifies against its anchor
// pool — the newest pinned TRC and its predecessor in its grace period — and
// nil when none does.
func (cfg EnrollmentConfig) anchoredChain(ctx context.Context) []*x509.Certificate {
	chain, err := AnchoredChain(ctx, cfg.DB, cfg.IA, time.Now())
	if err != nil {
		slog.Error("Reading the anchored chain", "isd_as", cfg.IA, "err", err)
		return nil
	}
	return chain
}

// attemptRenewal performs one renewal attempt the Renewal's way on the
// anchored chain, bounded so a wedged connection does not stall the loop
// renewing through it.
func (cfg EnrollmentConfig) attemptRenewal(ctx context.Context, chain []*x509.Certificate) {
	attemptCtx, cancel := context.WithTimeout(ctx, EnrollmentTimeout)
	defer cancel()
	if err := cfg.Renewal.renew(attemptCtx, cfg, chain); err != nil {
		slog.Warn("Renewing chain", "isd_as", cfg.IA, "err", err)
		return
	}
	slog.Info("Renewed chain", "isd_as", cfg.IA)
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
