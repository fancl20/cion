// Package membership is the node's membership policy module: the seam that
// decides whether a peer's chain the TRC verified stands for its ISD-AS
// network-wide, what the node presents beside its own chain, and how the
// node keeps its own membership current. Its implementations are filed one
// package each beneath this root: the founder method, under which a node's
// membership is the newest chain the founder issued for its key, and none,
// under which every chain stands as its own membership. Both run the
// contract suite in impl/membershiptest. The root holds the store a method
// keeps its memberships in. The --trust.membership run argument selects
// exactly one method, so the core always calls one.
//
// Kind: policy — how a node's admission binds it network-wide; selected by
// the operator's --trust.membership argument, exactly one method, the same
// on every node of a network.
package membership

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/modules/trustdb"
)

// Window is the membership window: under the founder method, a membership
// counts at a node while the founder issued it no more than this before the
// node's own. It is the AS certificate validity, so the memberships of the
// nodes that renew on time lie within it of each other.
const Window = 3 * 24 * time.Hour

// Boundary names where a chain is decided.
type Boundary int

const (
	// BoundaryHandshake is the SCION-native channel's handshake: the peer
	// presented its chain and the certificates beside it.
	BoundaryHandshake Boundary = iota
	// BoundaryRenewal is a renewal request at an issuer: the chain the
	// request rests on.
	BoundaryRenewal
)

// Facts are what one decision reads.
type Facts struct {
	// Boundary is where the chain is decided.
	Boundary Boundary
	// Chain is the chain the TRC verified, its AS certificate first.
	Chain []*x509.Certificate
	// Presented is what the peer presented beside the chain in a handshake,
	// empty at a renewal.
	Presented []*x509.Certificate
}

// Method is a membership method: the contract every implementation keeps.
type Method interface {
	// Admit decides a chain the TRC verified: nil admits it, an error
	// refuses it.
	Admit(ctx context.Context, facts Facts) error
	// Present returns the certificates the node presents beside chain, its
	// own newest, empty when the chain stands alone.
	Present(ctx context.Context, chain []*x509.Certificate) ([]*x509.Certificate, error)
	// Issued takes a chain the node issued.
	Issued(ctx context.Context, chain []*x509.Certificate) error
	// List lists the memberships the method holds that have not lapsed, in
	// ISD-AS order.
	List(ctx context.Context) ([]Membership, error)
	// Run keeps the node's own membership current until ctx ends.
	Run(ctx context.Context)
	// Remove ends the node's membership at the founding core by the
	// method's rule: the founder renews it no more, and it lapses as any
	// unrenewed membership does.
	Remove(ctx context.Context, ia addr.IA) error
	// RemovalGrace is the grace period a core's removal leaves the removed
	// root: zero where every node holds a membership that stands in for
	// the chains the removed core issued.
	RemovalGrace() time.Duration
}

// Membership is one node's membership as a listing shows it.
type Membership struct {
	// IA is the node's ISD-AS.
	IA addr.IA
	// Key is the subject key ID the membership binds the ISD-AS to.
	Key []byte
	// Expires is the membership's AS certificate expiry, zero for a
	// membership that never lapses.
	Expires time.Time
}

// Env is what the node lends a method.
type Env struct {
	// IA is the node's ISD-AS.
	IA addr.IA
	// Founding marks the founding core.
	Founding bool
	// Store keeps the method's memberships.
	Store *Store
	// DB is the node's trust database: its pinned TRCs, its chains, and on
	// the founding core the bindings of names to keys.
	DB trustdb.DB
	// Renew renews the node's chain at the founder on its current chain,
	// keeps the issued chain as the node's, and returns it. Nil on the
	// founding core.
	Renew func(ctx context.Context) ([]*x509.Certificate, error)
	// Pacing shortens the method's waits; zero values keep the defaults.
	Pacing Pacing
}

// Pacing carries the test pacing of a method.
type Pacing struct {
	Window           time.Duration // the membership window
	RenewalThreshold time.Duration // remaining validity below which the node renews its membership
	Inspect          time.Duration // the pause between passes over a current membership
	Retry            time.Duration // the retry schedule's first wait
}
