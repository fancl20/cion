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
// the enrollment loops that rolls the trust material the node itself holds —
// the founder's sensitive and regular voting certificates and its root
// certificate, an authoritative core's regular one — before the earliest
// expiry among them crosses the threshold, or the moment the persisted keys
// and the newest TRC's certificates disagree, whatever the calendar says.
// The founder casts its roll alone, serialized on the decision; the
// authoritative submits through the channel its join used.
type RotationConfig struct {
	// IA is the core's ISD-AS.
	IA addr.IA
	// DB holds the pinned TRCs.
	DB trustdb.DB
	// State is the state directory whose keys folder holds the persisted
	// voting material. Each pass rereads it, so a replacement of the material
	// — the crash between a pin and its persist, or an operator evicting a
	// compromised key — is seen at the next pass.
	State string
	// Decider serializes the founder's own cast and holds the sensitive
	// signer the roll swaps; the founder's watch alone. Nil on the
	// authoritative core, whose roll rides the submission channel instead.
	Decider *TRCDecider
	// Issuer rekeys under the successor's fresh root; the founder's watch
	// alone.
	Issuer *trust.Issuer
	// Remote resolves the founder's newest TRC; the authoritative's watch
	// alone.
	Remote trust.Remote
	// Caster submits the roll to the founder's voting application; the
	// authoritative's watch alone.
	Caster trust.TRCCaster

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

// RunRotation runs the rotation watch of a core: a calm inspection interval
// while nothing is due, the retry cadence while a cast is failing. Each pass
// reads the newest pinned TRC and the certificates in it the node itself
// holds, finds their earliest expiry, and rolls inside the threshold — or on
// the mismatch a persisted key and the newest TRC's certificates disagree on.
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
// roll is due or failing. Beyond the threshold the pass reports what
// logTRCValidity reports; within it the holder rolls, the report escalating
// with the expiry while the casts fail.
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
	owned := trust.CertsOf(newest.TRC, cfg.IA)
	due, err := cfg.materialDue(owned)
	if err != nil {
		slog.Error("Reading the persisted voting material", "isd_as", cfg.IA, "err", err)
		return cfg.interval(cfg.RetryInterval, EnrollmentRetryInterval)
	}
	if due.lost {
		slog.Error("The persisted sensitive key is not the one the newest TRC names; "+
			"the vote it alone can cast is the recovery, and its loss is the redeploy",
			"isd_as", cfg.IA, "trc", newest.TRC.ID)
		return cfg.interval(cfg.InspectInterval, ChainInspectInterval)
	}
	if due.mismatch {
		slog.Warn("The persisted voting material disagrees with the newest TRC; rolling",
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
	if err := cfg.roll(ctx); err != nil {
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
	// mismatch reports a persisted key the newest TRC's certificate no
	// longer covers.
	mismatch bool
	// lost reports a persisted sensitive key the newest TRC's sensitive
	// certificate no longer covers: the vote it alone can cast is the
	// recovery, and its loss is the redeploy the quorum-one coupling
	// records — nothing the node does can advance it.
	lost bool
}

// materialDue reads the persisted voting material and reports its state
// against the certificates the newest TRC names for the node.
func (cfg RotationConfig) materialDue(owned []*x509.Certificate) (materialState, error) {
	state := materialState{remaining: time.Until(owned[0].NotAfter)}
	for _, cert := range owned[1:] {
		if remaining := time.Until(cert.NotAfter); remaining < state.remaining {
			state.remaining = remaining
		}
	}
	if cfg.Decider != nil {
		keys, err := trust.LoadOrCreateCoreKeys(cfg.State)
		if err != nil {
			return materialState{}, err
		}
		for _, cert := range owned {
			ct, err := cppki.ValidateCert(cert)
			if err != nil {
				return materialState{}, err
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
					state.lost = true
				} else {
					state.mismatch = true
				}
			}
		}
		return state, nil
	}
	key, err := trust.LoadOrCreateVotingKey(cfg.State)
	if err != nil {
		return materialState{}, err
	}
	for _, cert := range owned {
		if ct, err := cppki.ValidateCert(cert); err == nil && ct == cppki.Regular &&
			!trust.KeyMatchesCert(key, cert) {

			state.mismatch = true
		}
	}
	return state, nil
}

// roll performs one roll attempt, bounded like an enrollment attempt: the
// founder's cast serialized on the decision, the authoritative's submission
// through the channel its join used.
func (cfg RotationConfig) roll(ctx context.Context) error {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = trust.RollTimeout
	}
	attemptCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if cfg.Decider != nil {
		return cfg.Decider.CastLocal(attemptCtx, func(newest cppki.SignedTRC) error {
			keys, completed, err := trust.RotateCoreKeys(attemptCtx, cfg.DB, cfg.State,
				cfg.IA, newest)
			if err != nil {
				return err
			}
			if err := cfg.Issuer.Rekey(keys, completed); err != nil {
				return err
			}
			// The decision votes with the fresh sensitive key from the pin on,
			// the assignment made under the mutex the cast holds.
			cfg.Decider.Sensitive = keys.Sensitive
			return nil
		})
	}
	return trust.RollVotingKey(attemptCtx, cfg.DB, cfg.Remote, cfg.Caster, cfg.IA, cfg.State)
}
