// Package topology is the topology application (ADR 0009): the measured
// machinery of ADR-0008 and proposal 0008 — the rendezvous acceptor, the
// joiner's dials, the node directory, the in-band link service, and the
// selection loop — beside the file provider, the static alternative. A
// provider owns a node's topology policy; the node owns the mechanism that
// applies it: the link store, the generation swap, and the stable link
// addresses. The measured provider loads by default — loading it is what
// makes a node zero-conf — and the file provider loads when --link-set
// names a link-set; the two never combine, because two deciders writing
// the same entries is flapping by construction. The cross-node vocabulary
// it speaks is exchanges with distinct jobs alone — rendezvous for first
// contact and identity, the link service for in-band establishment, echo
// for measurement, BFD for liveness — and a future provider interoperates
// through the store and those exchanges alone.
package topology

import (
	"context"
	"log/slog"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/controlplane"
	"github.com/fancl20/cion/pkg/links"
	"github.com/fancl20/cion/pkg/scion"
	"github.com/fancl20/cion/pkg/trust"
)

// Provider is the seam between the node assembly and the topology machinery
// (ADR 0009). A provider owns three moments of a node's topology — it
// completes a first start's provisional identity before the phases
// assemble, it mounts the services it serves on the control endpoint, and
// it runs the loops that decide links under the node's supervision — with
// Wire delivering the pieces the phases build between the first and the
// rest, Seed landing the links it vouches for before the first data plane
// generation builds, and Close releasing its sockets.
type Provider interface {
	// CompleteIdentity completes a first start's provisional ISD draw — the
	// measured provider's from a bootstrap neighbor's rendezvous reply, the
	// file provider's from the link-set's first entry — returning the
	// completed ISD-AS. The founding core's draw is its network's name
	// already; it returns unchanged. The assembly persists what returns.
	CompleteIdentity(ctx context.Context, ia addr.IA) (addr.IA, error)
	// Wire delivers the pieces the node's phases built, after identity
	// completed and before Seed, Mounts, and Run.
	Wire(Pieces)
	// Seed lands the links the provider vouches for in the store — the
	// measured provider an entry per --neighbor, the file provider the
	// link-set's entries — before the first data plane generation builds.
	// Idempotent: an entry already recorded is left alone.
	Seed(ctx context.Context) error
	// Mounts returns the handlers the provider serves on the node's control
	// endpoint, mounted behind the peer-identity middleware; empty when the
	// provider serves none. A socket that fails to bind fails the node's
	// assembly here, as every phase's bind does.
	Mounts() ([]controlplane.Mount, error)
	// Run runs the provider's loops until the context is canceled, each in
	// its own goroutine with a panic absorbed and logged — one loop's bug
	// must not take the provider's down.
	Run(ctx context.Context)
	// Close releases the provider's sockets; Run returns.
	Close() error
}

// Pieces are the node's own components the phases build, delivered by Wire:
// the machinery consumes them, never the reverse — the application imports
// the core and the shared libraries, never the reverse.
type Pieces struct {
	// IA is the node's completed ISD-AS.
	IA addr.IA
	// Store is the neighbor table — the provider's decisions land in it, and
	// its snapshot is the identity its loops read: the neighbor an
	// establishment names is the one the link serves.
	Store links.DB
	// Peer is the channel's client; the in-band link requests ride its
	// mutually verified side.
	Peer *controlplane.PeerClient
	// Provider resolves the freshest path — the comparator's baseline.
	Provider *scion.PathProvider
	// Engine provides the node's chain as the directory client's
	// certificate.
	Engine *trust.Engine
	// Verdicts returns the health monitor's link verdicts by interface ID:
	// the selection loop's floor and demotions read them — established-but-
	// down entries satisfy no floor and a down neighbor counts as
	// infinitely slow.
	Verdicts func() map[uint16]bool
}

// runLoop runs one of the provider's long-lived loops in its own goroutine:
// a panic is logged and absorbed, and a return before the node's
// cancellation is logged with the loop's name — the node's own supervision,
// lent to the provider's loops.
func runLoop(ctx context.Context, name string, fn func(context.Context)) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("Panic in topology loop", "loop", name, "panic", r)
			}
		}()
		fn(ctx)
		if ctx.Err() == nil {
			slog.Error("Topology loop exited", "loop", name)
		}
	}()
}
