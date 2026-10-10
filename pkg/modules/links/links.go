// Package links stores the neighbor table: one live entry per neighbor,
// holding the addresses, interface IDs, and state of the link. The store is
// the one source of truth — the control plane reads snapshots of it,
// and every data plane generation is built from its non-retired entries.
// Beneath the contract, one package per implementation — the bbolt store
// under the state directory, the memory store for tests and embeddings that
// prefer no state directory — and shared contract tests in impl/dbtest.
//
// Kind: storage — where the neighbor table persists, bound by the assembly;
// no run argument names a backend.
package links

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/slayers/path"
)

// State is the lifecycle state of a link entry.
type State int32

const (
	// StateCandidate is a link that exists but whose peer has not proven
	// itself yet: rendezvous-created entries start as candidates and retire
	// unless a verified beacon or enrollment arrives within the candidate
	// window.
	StateCandidate State = 1
	// StateEstablished is a link both endpoints stand behind: created by the
	// in-band link request, or promoted from a candidate by its evidence.
	StateEstablished State = 2
	// StateRetired is a withdrawn link. Its entry stays until the interface
	// ID's holdback passes, so no unexpired segment elsewhere names a link
	// that no longer exists.
	StateRetired State = 3
)

func (s State) String() string {
	switch s {
	case StateCandidate:
		return "candidate"
	case StateEstablished:
		return "established"
	case StateRetired:
		return "retired"
	default:
		return "unknown"
	}
}

// IfIDHoldback is how long a retired entry holds its interface ID back from
// reallocation: a constant exceeding the longest hop-field lifetime, so no
// unexpired segment elsewhere can name a link that no longer exists when the
// ID is reused.
var IfIDHoldback = path.ExpTimeToDuration(math.MaxUint8) + time.Hour

// Link is one neighbor table entry. The neighbor ISD-AS is learned from the
// peer's side of the establishment — its request, its reply, its certificate;
// the local link address is allocated once at establishment and rebound
// identically by every data plane generation, which is what makes a swap
// invisible to the peer.
type Link struct {
	// NeighborIA is the neighbor's ISD-AS; zero until learned.
	NeighborIA addr.IA
	// IfID is the local interface ID, allocated by the store on Insert.
	IfID uint16
	// RemoteIfID is the neighbor's interface ID of the link, learned from
	// its side of the establishment.
	RemoteIfID uint16
	// Local is the local link underlay address.
	Local netip.AddrPort
	// Remote is the neighbor's link underlay address.
	Remote netip.AddrPort
	// Rendezvous is the neighbor's rendezvous underlay address — the target
	// of first contact, retargeted to Remote once the reply arrives.
	Rendezvous netip.AddrPort
	// State is the entry's lifecycle state.
	State State
	// Created and Updated timestamp the entry.
	Created time.Time
	Updated time.Time
	// Retired is when the entry was retired; zero while live.
	Retired time.Time
}

// Live reports whether the entry is not retired.
func (l *Link) Live() bool { return l.State != StateRetired }

// Serving reports whether the data plane carries the link: a live entry with
// both link addresses. Seeded entries without addresses yet — a joiner's
// bootstrap neighbor whose rendezvous has not answered — wait for the reply.
func (l *Link) Serving() bool {
	return l.Live() && l.Local.IsValid() && l.Remote.IsValid()
}

// DB is the database of neighbor table entries. Lookup methods report
// absence as a nil entry with a nil error. A write that would leave two
// live entries naming one neighbor is refused with ErrDuplicateNeighbor,
// and one that would leave two serving entries with one remote address
// with ErrDuplicateRemote. The checks run inside the write: writers that
// each looked the neighbor up and found none cannot both record it, and the
// table never holds a link set the data plane refuses.
type DB interface {
	// Insert stores a new entry, stamping Created and Updated. An entry
	// carrying no interface ID is allocated one monotonically from a
	// persisted counter — the entry's IfID is set to it — and one carrying
	// an ID takes it, refused when the ID is held: live, or retired within
	// the holdback. The file provider's vouched entries are the carrier.
	Insert(ctx context.Context, l *Link) error
	// Update replaces the stored entry with the same interface ID, stamping
	// Updated.
	Update(ctx context.Context, l *Link) error
	// All returns every stored entry, retired ones included.
	All(ctx context.Context) ([]*Link, error)
	// ByRemote returns the live entry whose remote or rendezvous address
	// matches — the idempotence key of seeded neighbors.
	ByRemote(ctx context.Context, remote netip.AddrPort) (*Link, error)
	// ByNeighbor returns the live entry of the neighbor.
	ByNeighbor(ctx context.Context, ia addr.IA) (*Link, error)

	Close() error
}

var (
	// ErrDuplicateNeighbor refuses a write that would leave two live
	// entries naming one neighbor.
	ErrDuplicateNeighbor = errors.New("a live entry already names the neighbor")
	// ErrDuplicateRemote refuses a write that would leave two serving
	// entries with one remote address: the data plane carries one link per
	// remote address and builds no generation from two.
	ErrDuplicateRemote = errors.New("a serving entry already holds the remote address")
)

// Check returns the error a store refuses l with, given the stored entries
// other than l's own interface ID — the check each store runs inside the
// write it guards. ErrDuplicateNeighbor reports a live entry naming the live
// l's neighbor; unnamed entries name none. ErrDuplicateRemote reports a
// serving entry holding the serving l's remote address. The neighbor rule
// reports first: a writer that lost the race to record a neighbor retries
// on it.
func Check(entries []*Link, l *Link) error {
	if l.Live() && !l.NeighborIA.IsZero() {
		for _, e := range entries {
			if e.IfID != l.IfID && e.Live() && e.NeighborIA.Equal(l.NeighborIA) {
				return fmt.Errorf("neighbor %s: %w", l.NeighborIA, ErrDuplicateNeighbor)
			}
		}
	}
	if l.Serving() {
		for _, e := range entries {
			if e.IfID != l.IfID && e.Serving() && e.Remote == l.Remote {
				return fmt.Errorf("remote %s: %w", l.Remote, ErrDuplicateRemote)
			}
		}
	}
	return nil
}

// Links maps each live entry's interface ID to its neighbor ISD-AS — the
// snapshot every consumer of the link set reads: the beaconer's neighbor
// checks and propagation targets, the path library's one-hop egress
// resolution, and the core route's one-hop shortcut.
func Links(entries []*Link) map[uint16]addr.IA {
	out := make(map[uint16]addr.IA, len(entries))
	for _, l := range entries {
		if !l.Live() {
			continue
		}
		out[l.IfID] = l.NeighborIA
	}
	return out
}

// Serving returns the entries a data plane generation is built from: the live
// ones with both link addresses.
func Serving(entries []*Link) []*Link {
	var out []*Link
	for _, l := range entries {
		if l.Serving() {
			out = append(out, l)
		}
	}
	return out
}
