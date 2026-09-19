package controlplane

import (
	"context"
	"crypto"
	"net/netip"

	"github.com/quic-go/quic-go/http3"
	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/scion"
)

// EnrollmentFacts are the three facts a first issuance established about the
// requester (ADR-0010): the ISD-AS the CSR claims, the subject key whose
// possession the CMS wrapper proved, and the SCION source address the
// completed handshake made return-routable. The address is the joiner's own
// claim in the SCION header — a node behind translation presents its private
// address — yet bound by the handshake, for a reply addressed to the claim
// travels the reversed arrival path and is delivered within the joiner's AS
// to the claimed host.
type EnrollmentFacts struct {
	// IA is the ISD-AS the CSR claims.
	IA addr.IA
	// Key is the CSR's subject key, possession of which the CMS wrapper
	// proved.
	Key crypto.PublicKey
	// Addr is the requester's SCION source address — the underlay address
	// the request context's connection names the peer by; the zero
	// AddrPort when the context carries none, itself a fact an
	// implementation may fail closed on.
	Addr netip.AddrPort
}

// EnrollmentVerdict is an authorizer's answer to a first issuance. Deny is
// the zero value: an uninitialized verdict must not admit. Pending is not an
// error state but a first-class verdict the joiner's enrollment retry loop
// consumes without change — the request returns unavailable and the next
// retry asks again.
type EnrollmentVerdict int

const (
	// EnrollmentDeny refuses the issuance.
	EnrollmentDeny EnrollmentVerdict = iota
	// EnrollmentAllow issues the chain.
	EnrollmentAllow
	// EnrollmentPending holds the decision for an operator to make.
	EnrollmentPending
)

// EnrollmentAuthorizer is the seam ADR-0010 places at first issuance: the
// trust service calls it exactly when the mechanical checks pass and no
// chain exists for the name — possession verified, the name free — and
// issues, refuses, or pends on its verdict. Implementations live beside the
// core as policy that imports it; the core learns no type of them.
type EnrollmentAuthorizer interface {
	// Authorize answers one first-issuance request with its verdict.
	Authorize(context.Context, EnrollmentFacts) EnrollmentVerdict
}

// remoteUnderlay returns the SCION source address the request context's
// connection carries — the *scion.Addr the QUIC transport named the peer by,
// the pattern arrivalInterface reads — and the zero AddrPort when the
// context carries none.
func remoteUnderlay(ctx context.Context) netip.AddrPort {
	remote, ok := ctx.Value(http3.RemoteAddrContextKey).(*scion.Addr)
	if !ok || remote == nil {
		return netip.AddrPort{}
	}
	return remote.Addr
}
