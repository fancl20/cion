// Package congestion is the node's congestion module: the seam that rules
// each link's egress queue — the rate the queue drains at, and the packets
// coming back over the link its fill marks — from the echoes the module sends
// the next hop across the link. The data plane holds the queues and calls the
// policy from its processors and senders; the method's own loop sends the
// echoes the policy calls for, on conns the assembly binds, and hands the
// policy their outcomes. The implementation is filed beneath this root: the
// brake method, which runs the contract suite in impl/congestiontest.
//
// Kind: policy — how each link's egress queue is paced and marked; one
// method, bound by the assembly, with no run argument selecting it.
package congestion

import "github.com/fancl20/cion/pkg/libs/evidence"

// Policy rules each link's egress queue: the contract every method keeps.
// The data plane calls it from its processors and senders, so its methods
// must not block, and it outlives the data plane's generations, so a link
// keeps its state across them.
type Policy interface {
	// Wrote counts what a link wrote: its packets and their bytes, data and
	// control alike, and whether its rate held data back as it wrote them:
	// its queue held more than half of what its bound lets it, or dropped
	// some past the bound.
	Wrote(ifID uint16, packets, bytes int, held bool)
	// Rate returns the rate, in bits per second, the link's egress queue
	// drains at: zero for a link the policy does not brake.
	Rate(ifID uint16) float64
	// Mark reports whether to mark a packet that came back over the link,
	// whose egress queue holds fill of what it can, from 0 to 1. A link
	// whose queue is empty marks nothing.
	Mark(ifID uint16, fill float64) bool
	// Sampled takes the outcome of one of the method's echoes across the
	// link to its next hop: its round trip, or its loss.
	Sampled(ifID uint16, s evidence.Sample)
}
