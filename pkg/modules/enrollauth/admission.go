// Package enrollauth is the node's admission policy module: the seam
// gating a joiner node's first issuance, a joiner host's login, and the
// founder's sensitive vote on a core's TRC submission — with its
// implementations filed one package each beneath this root: the CIDR
// authorizer admitting nodes by addressing and no host at all, the
// Telegram one admitting nodes one by one from an operator's phone, and
// the portal one pending every new node for the operator's passkey
// console to decide through the Operator surface — and a shared contract
// suite in impl/authtest every implementation runs. A host is admitted on
// an auth key alone, one the Telegram or the portal method minted, which
// names the node the host lands on. The --trust.enroll-auth run argument
// selects exactly one method, the caller importing the implementation it
// names; unset is open enrollment, the zero-conf default, while every
// registration and the founder's vote are denied.
//
// Kind: policy — who is admitted, joiner node or host, and what the
// founder votes on; selected by the operator's --trust.enroll-auth spec,
// exactly one method.
package enrollauth

import (
	"context"
	"net/netip"

	"github.com/scionproto/scion/pkg/addr"
)

// Boundary names the boundary asking one admission question: enrollment at
// a joiner node's first issuance, registration at a joiner host's login,
// the voting submission at a core's TRC submission that needs the
// founder's sensitive vote. The same plugin answers all three,
// distinguished only by the context it is handed.
type Boundary int

const (
	// BoundaryEnrollment is a node's first chain issuance.
	BoundaryEnrollment Boundary = iota
	// BoundaryRegistration is a host's coordination login.
	BoundaryRegistration
	// BoundaryVoting is a core's TRC submission that needs the founder's
	// sensitive vote.
	BoundaryVoting
)

// AdmissionFacts are the verified facts of one admission exchange: the
// boundary asking, fingerprints of the keys the exchange presented, the
// return-routable source, the credential the joiner carried, and the
// exchange's claim — all of it in the clear, handed to the plugin, nothing
// else decided on. The source is bound by the completed handshake at every
// boundary, yet it remains the joiner's own claim otherwise: a node behind
// translation presents its private address, a host behind it the
// translated public one, so a private-range entry is what admits such
// joiners.
type AdmissionFacts struct {
	// Boundary is the boundary asking.
	Boundary Boundary
	// Keys holds fingerprints of the keys the exchange presented — the CSR's
	// subject key at enrollment, whose possession the CMS wrapper proved; the
	// machine and node keys at registration, the first authenticated by the
	// noise channel and the second offered for the data plane; the keys of
	// the certificates the submitted successor adds at the voting
	// submission, in the successor's order.
	Keys []string
	// Source is the return-routable source: the SCION underlay address at
	// enrollment, the internet address the completed TLS connection names at
	// registration, the peer channel's SCION underlay address at the voting
	// submission. The zero AddrPort when the context carries none, itself a
	// fact an implementation may fail closed on.
	Source netip.AddrPort
	// Credential is what the joiner carried: the registration's auth key,
	// empty at an enrollment exchange that carries none and at a bare
	// registration alike.
	Credential string
	// Claim is the ISD-AS the exchange is about: the enrollment's
	// self-assertion, the voting submission's channel-verified presenter;
	// zero at registration.
	Claim addr.IA
}

// AdmissionVerdict is an authorizer's decision. Deny is the zero value: an
// uninitialized verdict must not admit. Pending is not an error state but a
// first-class verdict the joiner's own retry loop consumes without change —
// the request returns as undecided and the next retry asks again.
type AdmissionVerdict int

const (
	// AdmissionDeny refuses the exchange.
	AdmissionDeny AdmissionVerdict = iota
	// AdmissionAllow admits it.
	AdmissionAllow
	// AdmissionPending holds the decision for an operator to make.
	AdmissionPending
)

// AdmissionAnswer is the verdict beside a note of the plugin's own words —
// what the registry records with the entry, the audit the operator reads
// beside the keys and addresses — and, for a registration, the node the
// host lands on.
type AdmissionAnswer struct {
	// Admission is the verdict.
	Admission AdmissionVerdict
	// Note carries the plugin's own account of its decision; the registry
	// records it with the entry.
	Note string
	// Node is the node a registration's host lands on: its address from
	// that node's slice, its one peer that node. The zero IA names the
	// founding core; the other boundaries ignore it.
	Node addr.IA
}

// AdmissionAuthorizer is the seam the boundaries ask: the caller invokes
// it exactly when the mechanical checks pass and nothing yet stands for the
// joiner — possession verified, the name free at enrollment, the key
// unseen at registration, a classifying update short of the founder's vote
// at the voting submission — and admits, refuses, or pends on its answer.
// The callers — the control plane's trust service, its TRC decision, the
// coordination application — import this root to pose the question; the
// implementations beneath it import the same root to answer it, and
// neither caller knows a type of them.
type AdmissionAuthorizer interface {
	// Authorize answers one admission exchange.
	Authorize(context.Context, AdmissionFacts) AdmissionAnswer
}
