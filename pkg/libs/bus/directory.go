package bus

import (
	"bytes"
	"encoding/hex"
	"net/netip"
	"slices"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/libs/segment"
)

// DirectoryID names one of the node's directories: a UUIDv7 an attachment
// minted, whose bytes order IDs by the moment they were minted. The zero ID
// names none.
type DirectoryID [16]byte

// Compare orders the ID against o by their bytes.
func (id DirectoryID) Compare(o DirectoryID) int {
	return bytes.Compare(id[:], o[:])
}

// IsZero reports whether the ID names no directory.
func (id DirectoryID) IsZero() bool {
	return id == DirectoryID{}
}

func (id DirectoryID) String() string {
	return hex.EncodeToString(id[:])
}

// Directory is the node's view of the directories it holds — each
// directory's entries by ISD-AS — and the directory each of its links
// joins. A published Directory is never mutated. The zero Directory, the
// topic's before the view's first publication, holds no directory.
type Directory struct {
	scopes []Scope
	byID   map[DirectoryID]Scope
	links  map[uint16]DirectoryID
}

// Scope is the view of one directory: each signer's entry by ISD-AS.
type Scope struct {
	id      DirectoryID
	entries []DirectoryEntry
	byIA    map[addr.IA]DirectoryEntry
}

// DirectoryEntry is one node's entry in a directory: the addresses the
// directory's peers reach it at, everything the selection loop needs to
// probe it as a candidate, each with the node's report of how its peers
// reach it there, and the round trips the node measured to them. The node
// signed it, and its ISD-AS is the one the signer's chain certifies.
type DirectoryEntry struct {
	// IA is the node's ISD-AS.
	IA addr.IA
	// Addresses are the node's addresses, one per host the directory's
	// peers see it at, ordered by host.
	Addresses []Address
	// Peers are the directory's peers the node measured, ordered by
	// ISD-AS.
	Peers []PeerReport
	// Published is the time the node signed the entry.
	Published time.Time
}

// PeerReport is one peer a node measured, as its entry reports it: the
// round trip, the link the node holds to the peer, and the changes it
// announced there.
type PeerReport struct {
	// IA is the peer's ISD-AS.
	IA addr.IA
	// RTT is the round trip the node measured to the peer.
	RTT time.Duration
	// IfID is the node's interface of its established link to the peer
	// whose verdict is up, zero for none.
	IfID uint16
	// Promoting reports that the node announced establishing a link to the
	// peer.
	Promoting bool
	// Retiring reports that the node announced retiring its link to the
	// peer, and Relies names the links the routes it judged that link by
	// cross.
	Retiring bool
	Relies   []segment.LinkID
}

// Equal reports whether two reports say the same.
func (r PeerReport) Equal(o PeerReport) bool {
	return r.IA == o.IA && r.RTT == o.RTT && r.IfID == o.IfID && r.Promoting == o.Promoting &&
		r.Retiring == o.Retiring && slices.Equal(r.Relies, o.Relies)
}

// Address is one host a directory's peers see a node at.
type Address struct {
	// ControlAddr is the underlay address of the node's control service,
	// the endpoint port on the host.
	ControlAddr netip.AddrPort
	// RendezvousAddr is the underlay address the node's rendezvous acceptor
	// listens on for first contact, the fixed rendezvous port on the host.
	RendezvousAddr netip.AddrPort
	// Reach is the node's report of how its peers reach it at the host.
	Reach Reach
}

// Reach is a node's report of how its peers reach it at one host. The zero
// value reports nothing observed.
type Reach struct {
	// BehindNAT reports that the host is not an address of the node's own:
	// a NAT stands between it and its peers.
	BehindNAT bool
	// RendezvousUnanswered reports that a linked peer that sees the node at
	// the host got no answer at its rendezvous address.
	RendezvousUnanswered bool
}

// NewScope returns the view of the directory the ID names, of the given
// entries, one per ISD-AS, ordered as given.
func NewScope(id DirectoryID, entries ...DirectoryEntry) Scope {
	s := Scope{id: id, entries: entries, byIA: make(map[addr.IA]DirectoryEntry, len(entries))}
	for _, e := range entries {
		s.byIA[e.IA] = e
	}
	return s
}

// ID returns the ID of the directory the scope views.
func (s Scope) ID() DirectoryID {
	return s.id
}

// Entries returns the scope's entries. The slice is never mutated.
func (s Scope) Entries() []DirectoryEntry {
	return s.entries
}

// Entry returns the node's entry, and whether the scope holds one.
func (s Scope) Entry(ia addr.IA) (DirectoryEntry, bool) {
	e, ok := s.byIA[ia]
	return e, ok
}

// NewDirectory returns the view of the given scopes, one per directory ID,
// ordered by ID, beside the directory each of the node's links joins.
func NewDirectory(links map[uint16]DirectoryID, scopes ...Scope) Directory {
	scopes = slices.Clone(scopes)
	slices.SortFunc(scopes, func(a, b Scope) int { return a.id.Compare(b.id) })
	d := Directory{scopes: scopes, byID: make(map[DirectoryID]Scope, len(scopes)), links: links}
	for _, s := range scopes {
		d.byID[s.id] = s
	}
	return d
}

// Scopes returns the views of the directories the node holds, ordered by
// ID, nil before the view's first publication. The slice is never mutated.
func (d Directory) Scopes() []Scope {
	return d.scopes
}

// Scope returns the view of the directory the ID names, and whether the
// node holds it.
func (d Directory) Scope(id DirectoryID) (Scope, bool) {
	s, ok := d.byID[id]
	return s, ok
}

// LinkScope returns the ID of the directory the link on the interface
// joins, and whether it joins one yet.
func (d Directory) LinkScope(ifID uint16) (DirectoryID, bool) {
	id, ok := d.links[ifID]
	return id, ok
}

// Latest returns the node's entry signed last among the scopes that hold
// one, and whether any does.
func (d Directory) Latest(ia addr.IA) (DirectoryEntry, bool) {
	var latest DirectoryEntry
	found := false
	for _, s := range d.scopes {
		if e, ok := s.byIA[ia]; ok && (!found || e.Published.After(latest.Published)) {
			latest, found = e, true
		}
	}
	return latest, found
}
