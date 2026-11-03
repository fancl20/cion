package bus

import (
	"bytes"
	"cmp"
	"net/netip"
	"slices"

	"github.com/scionproto/scion/pkg/addr"
)

// TailnetState is the WireGuard application's view of the directory: the
// node's own slice, unset until the directory assigns it, and the node
// and host entries of the last directory it applied. A published
// TailnetState is never mutated. The zero TailnetState, the topic's before
// the application's first publication, holds no slice and no entry.
type TailnetState struct {
	// Slice is the node's own slice of the tailnet range; zero until the
	// directory assigns it.
	Slice netip.Prefix
	// Nodes are the directory's node entries, ordered by ISD-AS.
	Nodes []TailnetNode
	// Hosts are the directory's host entries, ordered by public key.
	Hosts []TailnetHost
}

// TailnetNode is one node's WireGuard entry.
type TailnetNode struct {
	// IA is the node's ISD-AS.
	IA addr.IA
	// PublicKey is the node's WireGuard public key.
	PublicKey [32]byte
	// Slice is the node's slice of the tailnet range.
	Slice netip.Prefix
	// HostEndpoint is the underlay address and shared port a host's client
	// dials the node at.
	HostEndpoint netip.AddrPort
}

// TailnetHost is one host's registry entry.
type TailnetHost struct {
	// PublicKey is the host's WireGuard public key.
	PublicKey [32]byte
	// Addr is the host's tailnet address.
	Addr netip.Addr
	// IA is the node that owns the host, whose slice the address came from.
	IA addr.IA
}

// NewTailnetState returns the view of the slice and the entries, copied
// and ordered — the nodes by ISD-AS, the hosts by public key, each the
// directory's key for its entries — so views of the same entries compare
// equal whatever order they arrived in.
func NewTailnetState(slice netip.Prefix, nodes []TailnetNode, hosts []TailnetHost) TailnetState {
	s := TailnetState{Slice: slice, Nodes: slices.Clone(nodes), Hosts: slices.Clone(hosts)}
	slices.SortFunc(s.Nodes, func(a, b TailnetNode) int { return cmp.Compare(a.IA, b.IA) })
	slices.SortFunc(s.Hosts, func(a, b TailnetHost) int {
		return bytes.Compare(a.PublicKey[:], b.PublicKey[:])
	})
	return s
}

// Equal reports whether the views carry the same slice and the same entries
// in the same order; views NewTailnetState built are equal exactly when they
// hold the same slice and entries. A nil list equals an empty one.
func (s TailnetState) Equal(o TailnetState) bool {
	return s.Slice == o.Slice && slices.Equal(s.Nodes, o.Nodes) && slices.Equal(s.Hosts, o.Hosts)
}
