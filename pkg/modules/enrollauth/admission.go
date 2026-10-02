// Package enrollauth is the node's admission policy module: the seam
// gating a joiner node's first issuance, a joiner host's login, and a
// core's seek for voting power — with its implementations filed one
// package each beneath this root: the CIDR
// authorizer admitting joiners by addressing, nodes and hosts alike, and
// the Telegram one admitting them one by one from an operator's phone —
// and a shared contract suite in impl/authtest every implementation
// runs. The --trust.enroll-auth run argument selects exactly one method, the
// caller importing the implementation it names; unset is open
// enrollment, the zero-conf default.
//
// Kind: policy — who is admitted, joiner node, host, or voting core;
// selected by the operator's --trust.enroll-auth spec, exactly one method.
package enrollauth

import (
	"context"
	"crypto/x509"
	"net/netip"

	"github.com/scionproto/scion/pkg/addr"
)

// Boundary names the boundary asking one admission question: enrollment at
// a joiner node's first issuance, registration at a joiner host's login,
// the voting submission at a core's seek for voting power. The same plugin
// answers all three, distinguished only by the context it is handed.
type Boundary int

const (
	// BoundaryEnrollment is a node's first chain issuance.
	BoundaryEnrollment Boundary = iota
	// BoundaryRegistration is a host's coordination login.
	BoundaryRegistration
	// BoundaryVoting is a core's submission of the TRC update that would
	// grant it voting power.
	BoundaryVoting
)

// AdmissionFacts are the verified facts of one admission exchange: the
// boundary asking, fingerprints of the keys the exchange presented, the
// return-routable source, the credential the joiner carried, and the
// exchange's claim — all of it in the clear, handed to the plugin,
// nothing else considered. The source is bound by the completed handshake
// at every boundary, yet it remains the joiner's own claim otherwise: a
// node behind translation presents its private address, a host behind it
// the translated public one, so a private-range entry is what admits such
// joiners.
type AdmissionFacts struct {
	// Boundary is the boundary asking.
	Boundary Boundary
	// Keys holds fingerprints of the keys the exchange presented — the CSR's
	// subject key at enrollment, whose possession the CMS wrapper proved; the
	// machine and node keys at registration, the first authenticated by the
	// noise channel and the second offered for the data plane; the voting
	// certificate's key at the voting submission, whose possession the
	// submitted TRC's signature proved.
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
	// VotingCert is the regular voting certificate the successor a core
	// submitted carries — what the submitter asks voting power with, on the
	// same seam the keys and the claim already answer. Nil at the other
	// boundaries.
	VotingCert *x509.Certificate
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
// beside the keys and addresses.
type AdmissionAnswer struct {
	// Admission is the verdict.
	Admission AdmissionVerdict
	// Note carries the plugin's own account of its decision; the registry
	// records it with the entry.
	Note string
}

// AdmissionAuthorizer is the seam the boundaries ask: the caller invokes
// it exactly when the mechanical checks pass and nothing yet stands for the
// joiner — possession verified, the name free at enrollment, the key
// unseen at registration, the update classifying at the voting submission —
// and admits, refuses, or pends on its answer. The callers — the control
// plane's trust service, its TRC decision, the coordination application —
// import this root to pose the question; the implementations beneath it
// import the same root to answer it, and neither caller knows a type of
// them.
type AdmissionAuthorizer interface {
	// Authorize answers one admission exchange.
	Authorize(context.Context, AdmissionFacts) AdmissionAnswer
}
