package bus

import "net/netip"

// SelfState is the node's own state its publications carry. The zero
// SelfState names no host.
type SelfState struct {
	// Host is the host the topology source names the node at: the WireGuard
	// entry's endpoint names it, and the wildcard bind routes toward it.
	// Zero names none yet.
	Host netip.Addr
}
