package services

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/core/trust"
	"github.com/fancl20/cion/pkg/modules/membership"
)

// setupMembership builds the membership method Membership selects over the
// node's environment: the store, the trust database, and the renewal at the
// founder through the core client. The engine, the trust service, and the
// console take it, and start runs its loop.
func (n *node) setupMembership() {
	founding := n.cfg.role == trust.ASTypeCore
	env := membership.Env{
		IA:       n.ident.ia,
		Founding: founding,
		Store:    n.memberStore,
		DB:       n.trustDB,
		Pacing: membership.Pacing{
			Window:           n.cfg.Pacing.ChainValidity,
			RenewalThreshold: n.cfg.Pacing.RenewalThreshold,
			Inspect:          n.cfg.Pacing.EnrollmentInspect,
			Retry:            n.cfg.Pacing.Enrollment,
		},
	}
	if !founding {
		env.Renew = n.renewMembership
	}
	n.members = n.cfg.newMembership(env)
}

// renewMembership renews the node's chain at the founder through the core
// client, resting on the node's anchored chain — the newest it holds that
// verifies against its anchor pool — and returns the chain the founder
// issued.
func (n *node) renewMembership(ctx context.Context) ([]*x509.Certificate, error) {
	chain, err := trust.AnchoredChain(ctx, n.trustDB, n.ident.ia, time.Now())
	if err != nil {
		return nil, err
	}
	if chain == nil {
		return nil, errors.New("no chain the anchor pool verifies to rest the renewal on")
	}
	return trust.RenewChain(ctx, n.trustDB, n.coreClt, n.ident.ia, n.asKey, chain)
}

// nodeRemoval is the founding core's removal of a node: from the TRC at once
// where it names the node a core, with the grace period the membership
// method names, then its membership by the method's rule. Each step leaves
// what it already removed as it is, so a repeat finishes what a failure
// left.
func (n *node) nodeRemoval(decider *trust.TRCDecider) func(context.Context, addr.IA) error {
	return func(ctx context.Context, ia addr.IA) error {
		if err := decider.RemoveCore(ctx, ia, n.members.RemovalGrace()); err != nil {
			return fmt.Errorf("removing the core: %w", err)
		}
		if err := n.members.Remove(ctx, ia); err != nil {
			return fmt.Errorf("removing the membership: %w", err)
		}
		return nil
	}
}
