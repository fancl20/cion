// Package none is the none method of the membership module: a network that
// goes without memberships. Every chain stands as its own membership,
// whichever core issued it, so the chains the TRC verifies are admitted as
// they are, and nothing is presented beside them. A membership never
// lapses, and the store keeps the newest chain of every ISD-AS the node
// admits, issues, or presents as its own: on the founding core, every node
// from its first chain on.
package none

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"

	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/modules/membership"
)

// Method is the none method.
type Method struct {
	store *membership.Store
}

var _ membership.Method = (*Method)(nil)

// New returns the none method over env.
func New(env membership.Env) *Method {
	return &Method{store: env.Store}
}

// Admit admits the chain, keeping it as its ISD-AS's membership.
func (m *Method) Admit(_ context.Context, f membership.Facts) error {
	m.keep(f.Chain)
	return nil
}

// Present keeps the node's own chain as its membership and presents nothing
// beside it.
func (m *Method) Present(_ context.Context, chain []*x509.Certificate) ([]*x509.Certificate, error) {
	m.keep(chain)
	return nil, nil
}

// Issued keeps the chain as its ISD-AS's membership.
func (m *Method) Issued(_ context.Context, chain []*x509.Certificate) error {
	_, err := m.store.Put(chain)
	return err
}

// List lists every membership the store holds, none with an expiry.
func (m *Method) List(context.Context) ([]membership.Membership, error) {
	all := m.store.All()
	list := make([]membership.Membership, 0, len(all))
	for _, c := range all {
		ia, err := cppki.ExtractIA(c[0].Subject)
		if err != nil {
			return nil, fmt.Errorf("reading a membership's ISD-AS: %w", err)
		}
		list = append(list, membership.Membership{IA: ia, Key: c[0].SubjectKeyId})
	}
	return list, nil
}

// Run renews nothing: the chain renews at the cores. It returns once ctx
// ends.
func (m *Method) Run(ctx context.Context) {
	<-ctx.Done()
}

// keep stores the chain as its ISD-AS's membership once it is the newest; a
// failed store is logged, for the decision it backed stands.
func (m *Method) keep(chain []*x509.Certificate) {
	if _, err := m.store.Put(chain); err != nil {
		slog.Warn("Keeping a membership", "err", err)
	}
}
