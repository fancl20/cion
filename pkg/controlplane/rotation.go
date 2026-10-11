package controlplane

import (
	"context"
	"crypto"
	"crypto/x509"
	"log/slog"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/modules/trustdb"
	"github.com/fancl20/cion/pkg/trust"
)

// RotationConfig configures the rotation watch of a core: the loop beside
// the enrollment loop that rolls the trust material the node itself holds —
// the founder's sensitive and regular voting certificates and its root
// certificate, an authoritative core's regular one — before the earliest
// expiry among them crosses the threshold, or the moment the live keys and
// the newest TRC's certificates disagree, whatever the calendar says. The
// Roll carries what the holder adds to the watch.
type RotationConfig struct {
	// IA is the core's ISD-AS.
	IA addr.IA
	// DB holds the pinned TRCs.
	DB trustdb.DB
	// State is the state directory whose keys folder holds the voting
	// material: the live files the node signs with, and a roll's staged file
	// until a pinned TRC names it. Each pass promotes a staged file the
	// newest pinned TRC names and rereads the live files, so an operator's
	// replacement of the material, such as the eviction of a compromised
	// key, is seen at the next pass.
	State string
	// Roll is the holder's part of the watch: FounderRoll or
	// AuthoritativeRoll.
	Roll Roll

	// Threshold overrides trust.RotationThreshold; zero keeps it.
	Threshold time.Duration
	// RetryInterval and InspectInterval override the defaults; zero keeps
	// them.
	RetryInterval   time.Duration
	InspectInterval time.Duration
	// Timeout bounds one roll attempt; zero uses the default.
	Timeout time.Duration
}

func (cfg RotationConfig) interval(v, def time.Duration) time.Duration {
	if v == 0 {
		return def
	}
	return v
}

func (cfg RotationConfig) threshold() time.Duration {
	if cfg.Threshold == 0 {
		return trust.RotationThreshold
	}
	return cfg.Threshold
}

// Roll is a holder's part of the rotation watch RunRotation runs: whether
// the live material agrees with the certificates the newest TRC names for
// the node, and how the holder rolls it. FounderRoll and AuthoritativeRoll
// build the two.
type Roll interface {
	// check reads the live material: mismatch reports a live key the
	// newest TRC's certificate no longer covers, lost a live sensitive key
	// the newest TRC's sensitive certificate no longer covers.
	check(cfg RotationConfig, owned []*x509.Certificate) (mismatch, lost bool, err error)
	// roll performs one roll attempt.
	roll(ctx context.Context, cfg RotationConfig) error
}

// FounderRoll is the founding core's roll: its sensitive, regular, and root
// keys checked, and the roll of all three cast alone inside the decision's
// CastLocal, serialized with the submissions; once it pins, the decision
// votes with the fresh sensitive key and the issuer issues under the fresh
// root.
func FounderRoll(decider *TRCDecider, issuer *trust.Issuer) Roll {
	return founderRoll{decider: decider, issuer: issuer}
}

type founderRoll struct {
	decider *TRCDecider
	issuer  *trust.Issuer
}

func (founderRoll) check(cfg RotationConfig, owned []*x509.Certificate) (bool, bool, error) {
	keys, err := trust.LoadOrCreateCoreKeys(cfg.State)
	if err != nil {
		return false, false, err
	}
	var mismatch, lost bool
	for _, cert := range owned {
		ct, err := cppki.ValidateCert(cert)
		if err != nil {
			return false, false, err
		}
		var key crypto.Signer
		switch ct {
		case cppki.Sensitive:
			key = keys.Sensitive
		case cppki.Regular:
			key = keys.Regular
		case cppki.Root:
			key = keys.Root
		}
		if key != nil && !trust.KeyMatchesCert(key, cert) {
			if ct == cppki.Sensitive {
				lost = true
			} else {
				mismatch = true
			}
		}
	}
	return mismatch, lost, nil
}

func (r founderRoll) roll(ctx context.Context, cfg RotationConfig) error {
	return r.decider.CastLocal(ctx, func(newest cppki.SignedTRC) error {
		keys, completed, err := trust.RotateCoreKeys(ctx, cfg.DB, cfg.State,
			cfg.IA, newest)
		if err != nil {
			return err
		}
		// The node signs with the material the pin names before the disk
		// catches up: the decision votes with the fresh sensitive key, the
		// assignment made under the mutex the cast holds, and the issuer
		// issues under the fresh root. A promotion that fails here
		// completes at the next pass.
		r.decider.Sensitive = keys.Sensitive
		if err := r.issuer.Rekey(keys, completed); err != nil {
			return err
		}
		_, err = trust.PromoteStaged(cfg.State, cfg.IA, completed.TRC)
		return err
	})
}

// AuthoritativeRoll is the authoritative core's roll: its regular voting
// key checked, and the roll submitted through the caster to the founder's
// voting application, the channel its join used, the founder's newest TRC
// resolved through the remote.
func AuthoritativeRoll(remote trust.Remote, caster trust.TRCCaster) Roll {
	return authoritativeRoll{remote: remote, caster: caster}
}

type authoritativeRoll struct {
	remote trust.Remote
	caster trust.TRCCaster
}

func (authoritativeRoll) check(cfg RotationConfig, owned []*x509.Certificate) (bool, bool, error) {
	key, err := trust.LoadOrCreateVotingKey(cfg.State)
	if err != nil {
		return false, false, err
	}
	for _, cert := range owned {
		if ct, err := cppki.ValidateCert(cert); err == nil && ct == cppki.Regular &&
			!trust.KeyMatchesCert(key, cert) {

			return true, false, nil
		}
	}
	return false, false, nil
}

func (r authoritativeRoll) roll(ctx context.Context, cfg RotationConfig) error {
	return trust.RollVotingKey(ctx, cfg.DB, r.remote, r.caster, cfg.IA, cfg.State)
}

// RunRotation runs the rotation watch of a core: a calm inspection interval
// while nothing is due, the retry cadence while a cast is failing. Each pass
// reads the newest pinned TRC, promotes a staged file it names, reads the
// certificates in it the node itself holds, finds their earliest expiry, and
// rolls inside the threshold — or on the mismatch a live key and the newest
// TRC's certificates disagree on.
func RunRotation(ctx context.Context, cfg RotationConfig) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(cfg.rotationPass(ctx)):
		}
	}
}

// rotationPass runs one watch inspection: it returns how long to wait before
// the next one — the calm inspection interval while the node's material is
// beyond the threshold and agrees with the pin, the retry cadence while a
// roll is due or failing, or a promotion is. Within the threshold the holder
// rolls, its log escalating with the expiry while the casts fail.
func (cfg RotationConfig) rotationPass(ctx context.Context) time.Duration {
	newest, err := cfg.DB.SignedTRC(ctx, cppki.TRCID{
		ISD:    cfg.IA.ISD(),
		Base:   scrypto.LatestVer,
		Serial: scrypto.LatestVer,
	})
	if err != nil {
		slog.Error("Reading the newest pinned TRC", "isd_as", cfg.IA, "err", err)
		return cfg.interval(cfg.RetryInterval, EnrollmentRetryInterval)
	}
	if newest.IsZero() || !trust.CoreNamed(newest.TRC, cfg.IA) {
		// Nothing to roll yet: the founder always names itself, and a joining
		// core's onboarding cast is the enrollment loop's until it lands.
		return cfg.interval(cfg.InspectInterval, ChainInspectInterval)
	}
	// A roll that pinned and failed to promote its staged material completes
	// here, before the live files are read.
	if _, err := trust.PromoteStaged(cfg.State, cfg.IA, newest.TRC); err != nil {
		slog.Error("Promoting the staged voting material", "isd_as", cfg.IA, "err", err)
		return cfg.interval(cfg.RetryInterval, EnrollmentRetryInterval)
	}
	owned := trust.CertsOf(newest.TRC, cfg.IA)
	due, err := cfg.materialDue(owned)
	if err != nil {
		slog.Error("Reading the live voting material", "isd_as", cfg.IA, "err", err)
		return cfg.interval(cfg.RetryInterval, EnrollmentRetryInterval)
	}
	if due.lost {
		slog.Error("The live sensitive key is not the one the newest TRC names; "+
			"the vote it alone can cast is the recovery, and its loss is the redeploy",
			"isd_as", cfg.IA, "trc", newest.TRC.ID)
		return cfg.interval(cfg.InspectInterval, ChainInspectInterval)
	}
	if due.mismatch {
		slog.Warn("The live voting material disagrees with the newest TRC; rolling",
			"isd_as", cfg.IA, "trc", newest.TRC.ID)
	} else if due.remaining > cfg.threshold() {
		return cfg.interval(cfg.InspectInterval, ChainInspectInterval)
	} else if due.remaining <= 0 {
		slog.Error("Voting material expired; rolling",
			"isd_as", cfg.IA, "expired_for", -due.remaining)
	} else {
		slog.Warn("Voting material approaching expiry; rolling",
			"isd_as", cfg.IA, "remaining", due.remaining)
	}
	if err := cfg.attemptRoll(ctx); err != nil {
		slog.Warn("Rolling voting material", "isd_as", cfg.IA, "err", err)
	} else {
		slog.Info("Rolled voting material", "isd_as", cfg.IA)
	}
	return cfg.interval(cfg.RetryInterval, EnrollmentRetryInterval)
}

// materialState is one watch inspection's verdict on the material the node
// holds.
type materialState struct {
	// remaining is the earliest expiry among the certificates the newest TRC
	// names for the node.
	remaining time.Duration
	// mismatch reports a live key the newest TRC's certificate no longer
	// covers.
	mismatch bool
	// lost reports a live sensitive key the newest TRC's sensitive
	// certificate no longer covers: the vote it alone can cast is the
	// recovery, and its loss is the redeploy the quorum-one coupling
	// records — nothing the node does can advance it.
	lost bool
}

// materialDue reads the live voting material and reports its state against
// the certificates the newest TRC names for the node.
func (cfg RotationConfig) materialDue(owned []*x509.Certificate) (materialState, error) {
	mismatch, lost, err := cfg.Roll.check(cfg, owned)
	if err != nil {
		return materialState{}, err
	}
	state := materialState{
		remaining: time.Until(owned[0].NotAfter),
		mismatch:  mismatch,
		lost:      lost,
	}
	for _, cert := range owned[1:] {
		if remaining := time.Until(cert.NotAfter); remaining < state.remaining {
			state.remaining = remaining
		}
	}
	return state, nil
}

// attemptRoll performs one roll attempt the Roll's way, bounded like an
// enrollment attempt.
func (cfg RotationConfig) attemptRoll(ctx context.Context) error {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = trust.RollTimeout
	}
	attemptCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return cfg.Roll.roll(attemptCtx, cfg)
}
