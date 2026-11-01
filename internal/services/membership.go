package services

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/scionproto/scion/pkg/scrypto/cppki"

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
// client, resting on the newest chain the node holds, which must verify
// against its anchor pool, and returns the chain the founder issued.
func (n *node) renewMembership(ctx context.Context) ([]*x509.Certificate, error) {
	chain, err := trust.NewestChain(ctx, n.trustDB, n.ident.ia, time.Now())
	if err != nil {
		return nil, err
	}
	if chain == nil {
		return nil, errors.New("no valid chain to rest the renewal on")
	}
	pool, err := trust.PinnedPool(ctx, n.trustDB, n.ident.ia.ISD())
	if err != nil {
		return nil, err
	}
	if err := cppki.VerifyChain(chain, cppki.VerifyOptions{TRC: pool}); err != nil {
		return nil, fmt.Errorf("the newest chain does not verify against the anchor pool: %w", err)
	}
	return trust.RenewChain(ctx, n.trustDB, n.coreClt, n.ident.ia, n.asKey, chain)
}
