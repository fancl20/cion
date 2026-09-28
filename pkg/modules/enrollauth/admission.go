// Package enrollauth is the node's admission policy, the policy module of
// ADR-0013: the seam ADR-0010 places at a joiner node's first issuance and
// ADR-0011 generalizes to every boundary, with its implementations filed
// one package each beneath this root — the CIDR authorizer admitting
// joiners by addressing, nodes and hosts alike, and the Telegram one
// admitting them one by one from an operator's phone — and a shared
// contract suite in impl/authtest every implementation runs. The
// --enroll-auth run argument selects exactly one method, the caller
// importing the implementation it names; unset is open enrollment, the
// zero-conf default.
//
// Kind: policy — who is admitted, joiner node or host; selected by the
// operator's --enroll-auth spec, exactly one method.
package enrollauth

import (
	"context"
	"net/netip"

	"github.com/scionproto/scion/pkg/addr"
)

// Boundary names the boundary asking one admission question: ADR-0010's
// enrollment at a joiner node's first issuance, ADR-0011's registration at a
// joiner host's login. The same plugin answers both, distinguished only by
// the context it is handed.
type Boundary int

const (
	// BoundaryEnrollment is a node's first chain issuance.
	BoundaryEnrollment Boundary = iota
	// BoundaryRegistration is a host's coordination login.
	BoundaryRegistration
)

// AdmissionFacts are the verified facts of one admission exchange (ADR-0010's
// rule, generalized by ADR-0011): the boundary asking, fingerprints of the
// keys the exchange presented, the return-routable source, the credential
// the joiner carried, and the enrollment's claim — all of it in the clear,
// handed to the plugin, nothing else considered. The source is bound by the
// completed handshake at both boundaries, yet it remains the joiner's own
// claim otherwise: a node behind translation presents its private address, a
// host behind it the translated public one, so a private-range entry is what
// admits such joiners.
type AdmissionFacts struct {
	// Boundary is the boundary asking.
	Boundary Boundary
	// Keys holds fingerprints of the keys the exchange presented — the CSR's
	// subject key at enrollment, whose possession the CMS wrapper proved; the
	// machine and node keys at registration, the first authenticated by the
	// noise channel and the second offered for the data plane.
	Keys []string
	// Source is the return-routable source: the SCION underlay address at
	// enrollment, the internet address the completed TLS connection names at
	// registration. The zero AddrPort when the context carries none, itself a
	// fact an implementation may fail closed on.
	Source netip.AddrPort
	// Credential is what the joiner carried: the registration's auth key,
	// empty at an enrollment exchange that carries none and at a bare
	// registration alike.
	Credential string
	// Claim is enrollment's claimed ISD-AS; zero at registration.
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
// beside the keys and addresses.
type AdmissionAnswer struct {
	// Admission is the verdict.
	Admission AdmissionVerdict
	// Note carries the plugin's own account of its decision; the registry
	// records it with the entry.
	Note string
}

// AdmissionAuthorizer is the seam ADR-0010 places at first issuance and
// ADR-0011 generalizes to every boundary: the caller invokes it exactly when
// the mechanical checks pass and nothing yet stands for the joiner —
// possession verified, the name free at enrollment, the key unseen at
// registration — and admits, refuses, or pends on its answer. The callers —
// the control plane's trust service, the coordination application — import
// this root to pose the question; the implementations beneath it import the
// same root to answer it, and neither caller knows a type of them.
type AdmissionAuthorizer interface {
	// Authorize answers one admission exchange.
	Authorize(context.Context, AdmissionFacts) AdmissionAnswer
}
