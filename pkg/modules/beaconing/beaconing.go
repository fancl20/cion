// Package beaconing is the node's beacon policy module: the seam that
// decides which of the routes the node holds its beacons carry to each
// receiver, and in what order — a neighbor the node propagates to, or the
// node itself, which terminates and registers its own set. The beaconer
// hands the policy only routes the receiver can take, their beacons still
// arriving over interfaces that lead to their senders, and keeps the first
// routes of its answer up to what a receiver's beacon store keeps per
// interface. The implementation is filed beneath this root: the coverage
// method, which runs the contract suite in impl/beaconingtest.
//
// Kind: policy — which routes the node's beacons carry; one method, bound
// by the assembly, with no run argument selecting it.
package beaconing

import (
	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/libs/segment"
)

// Candidate is a stored beacon with the interface it arrived on.
type Candidate struct {
	// Ingress is the interface the beacon arrived on: the node's parent
	// side of that link.
	Ingress uint16
	// PCB is the candidate beacon.
	PCB *segment.PCB
}

// Policy chooses the routes the node's beacons carry: the contract every
// method keeps. The propagation and registration loops ask it at once.
type Policy interface {
	// Select returns the candidates to send the receiver, in the order to
	// send them: each drawn from cands, the routes the receiver can take,
	// none twice, and one at least whenever cands holds any. The receiver
	// is a neighbor, or the node itself for the set it terminates and
	// registers. founder is the founding core the pinned TRC names, zero
	// while no TRC is pinned. The beacons stay as they are: the beacon store
	// holds them.
	Select(receiver, founder addr.IA, cands []Candidate) []Candidate
}
