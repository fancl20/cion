package bus

import (
	"net/netip"
	"time"

	"github.com/scionproto/scion/pkg/addr"
)

// Directory is the node directory as the node last fetched it: each node's
// publication by ISD-AS. A published Directory is never mutated. The zero
// Directory, the topic's before the first fetch, holds no entry.
type Directory struct {
	entries []DirectoryEntry
	byIA    map[addr.IA]DirectoryEntry
}

// DirectoryEntry is one node's publication: everything the selection loop
// needs to probe the node as a candidate, and the node's report of how its
// peers reach it. The ISD-AS comes from the authenticated publisher's
// certificate chain, never from the claim.
type DirectoryEntry struct {
	// IA is the publisher's ISD-AS.
	IA addr.IA
	// ControlAddr is the underlay address of the publisher's control
	// service, the endpoint port on the published host.
	ControlAddr netip.AddrPort
	// RendezvousAddr is the underlay address the publisher's rendezvous
	// acceptor listens on for first contact, the fixed rendezvous port on
	// the published host.
	RendezvousAddr netip.AddrPort
	// Reach is the publisher's report of how its peers reach it.
	Reach Reach
	// Published is the publish time the core recorded.
	Published time.Time
}

// Reach is a node's report of how its peers reach it. The zero value
// reports nothing observed.
type Reach struct {
	// BehindNAT reports that the node's published host is not an address
	// of its own: a NAT stands between it and its peers.
	BehindNAT bool
	// RendezvousUnanswered reports that the acceptor of the node's latest
	// link request got no answer at its published rendezvous address.
	RendezvousUnanswered bool
}

// NewDirectory returns the directory of the given entries, one per ISD-AS.
func NewDirectory(entries ...DirectoryEntry) Directory {
	d := Directory{entries: entries, byIA: make(map[addr.IA]DirectoryEntry, len(entries))}
	for _, e := range entries {
		d.byIA[e.IA] = e
	}
	return d
}

// Entries returns the directory's entries, nil before the first fetch. The
// slice is never mutated.
func (d Directory) Entries() []DirectoryEntry {
	return d.entries
}

// Entry returns the node's entry, and whether the directory holds one.
func (d Directory) Entry(ia addr.IA) (DirectoryEntry, bool) {
	e, ok := d.byIA[ia]
	return e, ok
}
