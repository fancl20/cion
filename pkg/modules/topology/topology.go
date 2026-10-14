// Package topology is the node's configuration source: what it provides is
// not a service the node offers but the node's own inputs — identity,
// links — granted from outside, for a node cannot author its own name in
// the namespace or its own edges in the graph. A provider owns a node's
// topology policy; the node owns the mechanism that applies it: the links
// module's store, the generation swap, and the stable link addresses.
// Beneath the contract, one package per implementation — the measured
// provider, whose rendezvous acceptor, joiner's dials, node directory,
// in-band link service, and selection loop load by default, loading them
// being what makes a node zero-conf, and the file provider beside it, the
// static alternative an operator vouches for. The two never combine,
// because two deciders writing the same entries is flapping by
// construction; the cross-node vocabulary either speaks is exchanges with
// distinct jobs alone — rendezvous for first contact and identity, the
// link service for in-band establishment, echo for measurement, BFD for
// liveness — and a future provider interoperates through the store and
// those exchanges alone.
//
// Kind: source — where topology decisions come from, selected by the run
// arguments of its own: the measured provider by default, the file
// provider when --topology.link-set names a link-set, the two refused together.
package topology

import (
	"context"
	"net/http"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/core/controlplane"
	"github.com/fancl20/cion/pkg/core/trust"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/modules/links"
)

// Provider is the seam between the node assembly and the topology
// machinery. A provider owns three moments of a node's topology
// — it completes a first start's provisional identity before the phases
// assemble, it mounts the services it serves on the control endpoint, and
// it runs the loops that decide links under the node's supervision — with
// Wire delivering the environment the phases build between the first and
// the rest, Seed landing the links it vouches for before the first data plane
// generation builds, and Close releasing its sockets.
type Provider interface {
	// CompleteIdentity completes a first start's provisional ISD draw — the
	// measured provider's from a bootstrap neighbor's rendezvous reply, the
	// file provider's from the link-set's first entry — returning the
	// completed ISD-AS. The founding core's draw is its network's name
	// already; it returns unchanged. The assembly persists what returns.
	CompleteIdentity(ctx context.Context, ia addr.IA) (addr.IA, error)
	// Wire delivers the environment the node's phases built, after identity
	// completed and before Seed, Mounts, and Run.
	Wire(Environment)
	// Seed lands the links the provider vouches for in the store — the
	// measured provider an entry per --topology.neighbor, the file provider the
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
	// must not take the provider's down — and returns once every loop it
	// started has returned.
	Run(ctx context.Context)
	// Close releases what assembly bound, once Run has returned.
	Close() error
}

// Environment is the node's own components the phases build, delivered by
// Wire: the machinery consumes them, never the reverse — the module imports
// the core and the libraries, never the reverse.
type Environment struct {
	// IA is the node's completed ISD-AS.
	IA addr.IA
	// Store is the neighbor table — the provider's decisions land in it, and
	// its snapshot is the identity its loops read: the neighbor an
	// establishment names is the one the link serves. A write is all it
	// takes to land a decision: the node's store signals every write, and
	// the node applies it as a data plane generation swap.
	Store links.DB
	// Peer is the node's channel to its peers; the in-band link requests ride
	// its mutually verified side.
	Peer PeerChannel
	// Paths resolves the node's paths: the freshest one is the comparator's
	// baseline, and the local one routes the directory's channel.
	Paths Paths
	// Engine provides the node's chain as the directory client's
	// certificate.
	Engine *trust.Engine
	// Verdicts returns the health monitor's link verdicts by interface ID:
	// the selection loop's floor and demotions read them — established-but-
	// down entries satisfy no floor and a down neighbor counts as
	// infinitely slow.
	Verdicts func() map[uint16]bool
	// Latencies receives the selection loop's per-link one-way delay
	// estimates; the beaconer's entries declare them.
	Latencies LatencyRecorder
}

// PeerChannel is the node's channel to its peers.
type PeerChannel interface {
	// VerifiedClient returns the client of the channel's mutually verified
	// side.
	VerifiedClient() *http.Client
}

// Paths resolves the node's paths to a destination ISD-AS.
type Paths interface {
	// Path returns a data-plane path from the local AS to dst.
	Path(ctx context.Context, dst addr.IA) (*spath.Decoded, error)
	// Enumerate returns every composed candidate path to dst with its
	// facts.
	Enumerate(ctx context.Context, dst addr.IA) ([]scion.Candidate, error)
	// LocalPath resolves a data-plane path from local state only, never a
	// fetch: the variant safe to call from inside a dial.
	LocalPath(dst addr.IA) (*spath.Decoded, error)
}

// LatencyRecorder receives per-link one-way delay estimates.
type LatencyRecorder interface {
	// Record records a link's one-way delay estimate by interface ID.
	Record(ifID uint16, oneWay time.Duration)
}
