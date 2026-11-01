// Package founder is the founder method of the membership module: a node's
// membership is the newest chain the founder issued for its key under the
// founder's own CA. A membership counts at a node when it verifies through a
// founder root certificate in the node's anchor pool, judged at its own
// issuance, and the founder issued it no more than the membership window
// before the node's own membership. A peer's chain the TRC verified is
// admitted only where a counting membership binds its ISD-AS to its key: the
// chain itself when the founder issued it, else the membership the peer
// presented beside it, or the one the node holds. Each node renews its
// membership at the founder, and the founder renews a bound key on the
// binding alone. Removing a node frees its name, so the founder renews it no
// more and its membership lapses. Every node holds a membership that stands
// in for the chains a removed core issued, so a core's removal keeps no
// grace period.
package founder

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/core/trust"
	"github.com/fancl20/cion/pkg/libs/loops"
	"github.com/fancl20/cion/pkg/modules/membership"
	"github.com/fancl20/cion/pkg/modules/trustdb"
)

// RetryCap caps the waits of the membership renewal's retry schedule, so a
// node renews within a minute of the founder's return.
const RetryCap = time.Minute

// Method is the founder method.
type Method struct {
	env   membership.Env
	retry loops.Backoff
}

var _ membership.Method = (*Method)(nil)

// New returns the founder method over env.
func New(env membership.Env) *Method {
	return &Method{
		env:   env,
		retry: loops.Backoff{Base: or(env.Pacing.Retry, trust.EnrollmentRetryInterval), Max: RetryCap},
	}
}

// Admit admits the chain where a counting membership binds its ISD-AS to its
// key. At the founding core, a renewal rests on the name's binding instead:
// the founder renews a bound key whatever its membership's age, so a node
// renews after any outage.
func (m *Method) Admit(ctx context.Context, f membership.Facts) error {
	ia, err := cppki.ExtractIA(f.Chain[0].Subject)
	if err != nil {
		return fmt.Errorf("reading the chain's ISD-AS: %w", err)
	}
	if f.Boundary == membership.BoundaryRenewal && m.env.Founding {
		return m.bound(ctx, ia, f.Chain)
	}
	v, err := m.view(ctx)
	if err != nil {
		return err
	}
	candidates := [][]*x509.Certificate{f.Chain}
	if f.Boundary == membership.BoundaryHandshake && len(f.Presented) != 0 {
		candidates = append(candidates, f.Presented)
	}
	candidates = append(candidates, m.env.Store.Get(ia))
	for _, c := range candidates {
		if v.backs(c, ia, f.Chain) {
			m.keep(c)
			return nil
		}
	}
	return refuse(ia, f.Chain)
}

// Present returns the node's own membership where the founder did not issue
// chain, the node's newest; a chain the founder issued serves as its own
// membership.
func (m *Method) Present(ctx context.Context, chain []*x509.Certificate) ([]*x509.Certificate, error) {
	roots, err := m.roots(ctx)
	if err != nil {
		return nil, err
	}
	if issuedBy(chain, roots) {
		return nil, nil
	}
	own := m.own(ctx, roots)
	if own == nil || !sameKey(own, chain) {
		return nil, nil
	}
	return own, nil
}

// Issued keeps a chain the founding core issued as the membership of its
// ISD-AS; every other core's issuance makes no membership.
func (m *Method) Issued(_ context.Context, chain []*x509.Certificate) error {
	if !m.env.Founding {
		return nil
	}
	_, err := m.env.Store.Put(chain)
	return err
}

// List lists the memberships the store holds that count against the node's
// own, each with its expiry.
func (m *Method) List(ctx context.Context) ([]membership.Membership, error) {
	v, err := m.view(ctx)
	if err != nil {
		return nil, err
	}
	var list []membership.Membership
	for _, c := range m.env.Store.All() {
		if !v.counts(c) {
			continue
		}
		ia, err := cppki.ExtractIA(c[0].Subject)
		if err != nil {
			return nil, fmt.Errorf("reading a membership's ISD-AS: %w", err)
		}
		list = append(list, membership.Membership{
			IA:      ia,
			Key:     c[0].SubjectKeyId,
			Expires: c[0].NotAfter,
		})
	}
	return list, nil
}

// Remove frees the node's name at the founding core: a renewal finds the
// name bound to no key and is refused, and a re-enrollment is a first
// issuance the admission policy decides.
func (m *Method) Remove(ctx context.Context, ia addr.IA) error {
	return m.env.DB.Unbind(ctx, ia)
}

// RemovalGrace is zero: every node's membership stands in for the chains a
// removed core issued.
func (m *Method) RemovalGrace() time.Duration {
	return 0
}

// Run keeps the node's own membership current: each pass keeps a newer chain
// the founder issued the node, and renews at the founder below the renewal
// threshold or once the newest TRC alone does not anchor the membership,
// retrying on the retry schedule until it succeeds.
func (m *Method) Run(ctx context.Context) {
	for {
		for range m.retry.Tries(ctx) {
			if m.current(ctx) {
				break
			}
		}
		if !loops.Sleep(ctx, or(m.env.Pacing.Inspect, trust.ChainInspectInterval)) {
			return
		}
	}
}

// current brings the node's own membership current and reports whether it
// is: above the renewal threshold and verifying through a founder root of
// the newest TRC, so a removal that closes a roll's grace period strands
// none. The founding core's own chains are its memberships, kept as it
// self-issues them.
func (m *Method) current(ctx context.Context) bool {
	pool, err := trust.PinnedPool(ctx, m.env.DB, m.env.IA.ISD())
	if err != nil {
		slog.Error("Reading the pinned TRCs", "isd_as", m.env.IA, "err", err)
		return false
	}
	roots, err := founderRoots(pool)
	if err != nil {
		slog.Error("Reading the founder's roots", "isd_as", m.env.IA, "err", err)
		return false
	}
	own := m.capture(ctx, roots)
	if m.env.Founding {
		return true
	}
	newestRoots, err := founderRoots(pool[:1])
	if err != nil {
		slog.Error("Reading the founder's roots", "isd_as", m.env.IA, "err", err)
		return false
	}
	threshold := or(m.env.Pacing.RenewalThreshold, trust.ChainRenewalThreshold)
	if own != nil && time.Until(own[0].NotAfter) >= threshold && issuedBy(own, newestRoots) {
		return true
	}
	attemptCtx, cancel := context.WithTimeout(ctx, trust.EnrollmentTimeout)
	defer cancel()
	renewed, err := m.env.Renew(attemptCtx)
	if err != nil {
		slog.Warn("Renewing the membership at the founder", "isd_as", m.env.IA, "err", err)
		return false
	}
	m.keep(renewed)
	slog.Info("Renewed the membership", "isd_as", m.env.IA, "expires", renewed[0].NotAfter)
	return true
}

// bound admits a renewal at the founding core when the requester's key is
// the one its ISD-AS is bound to.
func (m *Method) bound(ctx context.Context, ia addr.IA, chain []*x509.Certificate) error {
	held, err := m.env.DB.BoundKey(ctx, ia)
	if err != nil {
		return fmt.Errorf("reading the binding of %s: %w", ia, err)
	}
	skid, err := cppki.SubjectKeyID(chain[0].PublicKey)
	if err != nil {
		return fmt.Errorf("computing the requester's key ID: %w", err)
	}
	if held == nil || !bytes.Equal(held, skid) {
		slog.Warn("Refusing a renewal its ISD-AS is not bound to",
			"isd_as", ia, "key", hex.EncodeToString(skid))
		return serrors.New("the requester's key is not the one its ISD-AS is bound to",
			"isd_as", ia)
	}
	return nil
}

// view is what one decision judges by: the founder's root certificates in
// the node's anchor pool, the issuance of the node's own membership — zero
// while it holds none — and the window.
type view struct {
	roots  *x509.CertPool
	own    time.Time
	window time.Duration
}

// view reads the decision's view.
func (m *Method) view(ctx context.Context) (view, error) {
	roots, err := m.roots(ctx)
	if err != nil {
		return view{}, err
	}
	v := view{roots: roots, window: or(m.env.Pacing.Window, membership.Window)}
	if own := m.own(ctx, roots); own != nil {
		v.own = own[0].NotBefore
	}
	return v, nil
}

// counts reports whether c counts as a membership: it verifies through a
// founder root at its own issuance, and the founder issued it no more than
// the window before the node's own membership. A node that holds none
// judges by the first alone.
func (v view) counts(c []*x509.Certificate) bool {
	return issuedBy(c, v.roots) && (v.own.IsZero() || v.own.Sub(c[0].NotBefore) <= v.window)
}

// backs reports whether c is a counting membership that binds ia to chain's
// key.
func (v view) backs(c []*x509.Certificate, ia addr.IA, chain []*x509.Certificate) bool {
	if len(c) != 2 || !sameKey(c, chain) {
		return false
	}
	certIA, err := cppki.ExtractIA(c[0].Subject)
	return err == nil && certIA.Equal(ia) && v.counts(c)
}

// roots returns the founder's root certificates in the node's anchor pool.
func (m *Method) roots(ctx context.Context) (*x509.CertPool, error) {
	pool, err := trust.PinnedPool(ctx, m.env.DB, m.env.IA.ISD())
	if err != nil {
		return nil, fmt.Errorf("reading the pinned TRCs: %w", err)
	}
	return founderRoots(pool)
}

// founderRoots returns the founder's root certificates in the TRCs: the root
// certificates whose subject names the founder, the AS the first TRC's
// sensitive voting certificate names. The pool is empty while the first TRC
// is the zero TRC, nothing pinned.
func founderRoots(trcs []*cppki.TRC) (*x509.CertPool, error) {
	roots := x509.NewCertPool()
	if trcs[0].IsZero() {
		return roots, nil
	}
	sensitive, err := trust.SignerCert(*trcs[0], cppki.Sensitive)
	if err != nil {
		return nil, fmt.Errorf("reading the founder from the TRC: %w", err)
	}
	founder, err := cppki.ExtractIA(sensitive.Subject)
	if err != nil {
		return nil, fmt.Errorf("reading the founder from the TRC: %w", err)
	}
	for _, trc := range trcs {
		certs, err := trc.RootCerts()
		if err != nil {
			return nil, fmt.Errorf("reading the TRC's root certificates: %w", err)
		}
		for _, root := range certs {
			if ia, err := cppki.ExtractIA(root.Subject); err == nil && ia.AS() == founder.AS() {
				roots.AddCert(root)
			}
		}
	}
	return roots, nil
}

// own returns the node's own membership: the store's, else the one capture
// finds.
func (m *Method) own(ctx context.Context, roots *x509.CertPool) []*x509.Certificate {
	if held := m.env.Store.Get(m.env.IA); held != nil {
		return held
	}
	return m.capture(ctx, roots)
}

// capture keeps the newest of the node's chains valid now that the founder
// issued — its first chain, and every later one the founder issued it — as
// the node's membership, and returns the membership the store then holds.
func (m *Method) capture(ctx context.Context, roots *x509.CertPool) []*x509.Certificate {
	now := time.Now()
	chains, err := m.env.DB.Chains(ctx, trustdb.ChainQuery{
		IA:       m.env.IA,
		Validity: cppki.Validity{NotBefore: now, NotAfter: now},
	})
	if err != nil {
		slog.Warn("Reading the node's chains", "isd_as", m.env.IA, "err", err)
		return m.env.Store.Get(m.env.IA)
	}
	var newest []*x509.Certificate
	for _, chain := range chains {
		if issuedBy(chain, roots) && (newest == nil || chain[0].NotBefore.After(newest[0].NotBefore)) {
			newest = chain
		}
	}
	if newest != nil {
		m.keep(newest)
	}
	return m.env.Store.Get(m.env.IA)
}

// keep stores c as its ISD-AS's membership once it is the newest; a failed
// store is logged, for the decision it backed stands.
func (m *Method) keep(c []*x509.Certificate) {
	if _, err := m.env.Store.Put(c); err != nil {
		slog.Warn("Keeping a membership", "err", err)
	}
}

// refuse logs a chain no counting membership backs, with the core whose CA
// certificate signed it — the evidence of the key that issued it — and
// returns the refusal.
func refuse(ia addr.IA, chain []*x509.Certificate) error {
	issuer, _ := cppki.ExtractIA(chain[1].Subject)
	slog.Warn("Refusing a chain no membership backs", "isd_as", ia, "issuer", issuer,
		"key", hex.EncodeToString(chain[0].SubjectKeyId))
	return serrors.New("no membership backs the chain", "isd_as", ia, "issuer", issuer)
}

// issuedBy reports whether c verifies through a root of the pool, judged at
// its AS certificate's issuance.
func issuedBy(c []*x509.Certificate, roots *x509.CertPool) bool {
	if cppki.ValidateChain(c) != nil {
		return false
	}
	intermediates := x509.NewCertPool()
	intermediates.AddCert(c[1])
	_, err := c[0].Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         roots,
		KeyUsages:     c[0].ExtKeyUsage,
		CurrentTime:   c[0].NotBefore,
	})
	return err == nil
}

// sameKey reports whether two chains' AS certificates certify one key.
func sameKey(a, b []*x509.Certificate) bool {
	return bytes.Equal(a[0].RawSubjectPublicKeyInfo, b[0].RawSubjectPublicKeyInfo)
}

// or returns v, or def when v is zero.
func or(v, def time.Duration) time.Duration {
	if v == 0 {
		return def
	}
	return v
}
