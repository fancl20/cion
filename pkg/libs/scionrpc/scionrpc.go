// Package scionrpc is the SCION-native channel: the drafts' RPC over HTTP/3
// (QUIC) riding SCION paths (control plane draft, Section 1.7), peers
// authenticated by their AS certificate chains against the TRC, and the
// drafts' service resolution answered beside it (control plane draft,
// Section 5). The control endpoint serves the drafts' services on it, and
// applications and modules serve and dial their own. A shared library: no
// loops of its own, no policy, and the node's credentials read through an
// interface the trust engine satisfies.
package scionrpc

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/netip"

	"github.com/quic-go/quic-go/http3"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/libs/scion"
)

// EndpointPort is the SCION UDP port of the control endpoint — the socket
// registered as the control service, so a peer addressing the service
// destination reaches the endpoint beside whose services the drafts'
// resolution exchange answers. It sits one step below the SCION endhost
// port in the underlay block's ladder, the slot every peer depends on: the
// drafts' own services, the node's most settled protocol.
const EndpointPort = 30042

// Mount is one handler a loaded application serves on the control endpoint:
// the pattern the HTTP mux mounts the handler at, the handler itself behind
// the peer-identity middleware. The core learns no type of the application
// that built it.
type Mount struct {
	// Pattern is the mux pattern the handler mounts at.
	Pattern string
	// Handler serves the pattern.
	Handler http.Handler
}

// Credentials are the node's side of the channel's mutual authentication:
// the chain it presents and the TRC anchors peers' chains verify against.
// A handshake asks for both, so they read local state only. The trust
// engine provides them, and the AS key behind the chain travels beside
// them.
type Credentials interface {
	// Chain returns the node's newest chain valid now, empty on a node not
	// enrolled yet.
	Chain(ctx context.Context) ([]*x509.Certificate, error)
	// AnchorPool returns the TRCs peers' chains verify against: the newest
	// pinned TRC and, inside its grace period, its predecessor. It is empty
	// on a node that has not pinned a TRC yet.
	AnchorPool() ([]*cppki.TRC, error)
}

// RemoteAddr returns the SCION address a request's connection carries — the
// *scion.Addr the QUIC transport named the peer by, which the HTTP/3 server
// puts in every request's context — or nil when the context carries none.
func RemoteAddr(ctx context.Context) *scion.Addr {
	remote, _ := ctx.Value(http3.RemoteAddrContextKey).(*scion.Addr)
	return remote
}

// RemoteUnderlay returns the underlay address of the request's remote SCION
// address, and the zero AddrPort when the context carries none.
func RemoteUnderlay(ctx context.Context) netip.AddrPort {
	remote := RemoteAddr(ctx)
	if remote == nil {
		return netip.AddrPort{}
	}
	return remote.Addr
}
