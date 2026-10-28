package bus

import "net/netip"

// SelfState is the node's own state its publications carry: the host it is
// published at and the answer its published rendezvous address got. The zero
// SelfState names no host.
type SelfState struct {
	// Host is the host the node's publications carry; zero publishes
	// nothing.
	Host netip.Addr
	// RendezvousUnanswered reports that the acceptor of the node's latest
	// link request got no answer at the node's published rendezvous address.
	RendezvousUnanswered bool
}
