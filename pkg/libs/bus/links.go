package bus

import (
	"net/netip"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/modules/links"
)

// LinkState is the node's link state: the neighbor table's live entries,
// each with its link's verdict and the source the link last observed its
// peer at. A published LinkState, and every map its methods return, is never
// mutated. The zero LinkState, the topic's before the node's first publish,
// holds no table.
type LinkState struct {
	links  map[uint16]Link
	table  map[uint16]addr.IA
	usable map[uint16]addr.IA
}

// Link is one live entry's state.
type Link struct {
	// Entry is the neighbor table's entry.
	Entry links.Link
	// Down is the link's verdict: true while the link's BFD session holds it
	// down. A link the monitor runs no session for is up.
	Down bool
	// Observed is the source the link last observed its peer at; zero when
	// no data plane generation serves the link or none of its arrivals
	// recorded one.
	Observed netip.AddrPort
}

// NewLinkState returns the state of the given live entries' links.
func NewLinkState(ls ...Link) LinkState {
	s := LinkState{
		links:  make(map[uint16]Link, len(ls)),
		table:  make(map[uint16]addr.IA, len(ls)),
		usable: make(map[uint16]addr.IA, len(ls)),
	}
	for _, l := range ls {
		s.links[l.Entry.IfID] = l
		s.table[l.Entry.IfID] = l.Entry.NeighborIA
		if !l.Down {
			s.usable[l.Entry.IfID] = l.Entry.NeighborIA
		}
	}
	return s
}

// Table returns each live entry's neighbor by interface ID: the beaconer's
// neighbor checks and propagation targets, down links included, for a beacon
// arriving on a down link still names its neighbor. The zero LinkState
// returns nil.
func (s LinkState) Table() map[uint16]addr.IA {
	return s.table
}

// Usable returns the neighbors of the links whose verdict is up, by
// interface ID. The data plane refuses a down link's egress, and forwards a
// one-hop packet onto it without that check, so no signal tells the sender:
// every route out of the node — a composed path's first hop, the bootstrap
// route, a one-hop write, a one-hop route to a core — resolves over these
// links alone, and fails at once where none serves. The zero LinkState
// returns nil, which filters nothing.
func (s LinkState) Usable() map[uint16]addr.IA {
	return s.usable
}

// Up reports the interface's verdict; an interface no live entry holds is
// up, as the monitor counts one it runs no session for.
func (s LinkState) Up(ifID uint16) bool {
	return !s.links[ifID].Down
}

// Observed returns the source the interface's link last observed its peer
// at; zero when the state holds none.
func (s LinkState) Observed(ifID uint16) netip.AddrPort {
	return s.links[ifID].Observed
}
