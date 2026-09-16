package controlplane

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
)

// authenticatedIAKey is the context key carrying the verified peer.
type authenticatedIAKey struct{}

// AuthenticatedIAContextKey returns the context key Authenticate peers the
// verified ISD-AS in by; tests of handlers inject the identity with it.
func AuthenticatedIAContextKey() any { return authenticatedIAKey{} }

// AuthenticatedIA returns the ISD-AS of the peer whose certificate chain the
// SCION-native channel verified, or the zero ISD-AS when the request carries
// none — requests without one never reach the handlers.
func AuthenticatedIA(ctx context.Context) addr.IA {
	ia, ok := ctx.Value(authenticatedIAKey{}).(addr.IA)
	if !ok {
		return addr.IA(0)
	}
	return ia
}

// Authenticate peers the verified chain's ISD-AS into the request context.
// The middleware shape serves every service the SCION-native channel serves:
// the handler reads what the transport authenticated. A chain that names no
// ISD-AS authenticates nothing — the request proceeds unidentified and the
// handlers that require an identity refuse it.
func Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			if ia, err := peerIA(r.TLS.PeerCertificates); err == nil {
				r = r.WithContext(context.WithValue(r.Context(), authenticatedIAKey{}, ia))
			}
		}
		next.ServeHTTP(w, r)
	})
}

// peerIA extracts the ISD-AS a verified chain's leaf names.
func peerIA(chain []*x509.Certificate) (addr.IA, error) {
	if len(chain) == 0 {
		return addr.IA(0), errors.New("no peer certificate")
	}
	return cppki.ExtractIA(chain[0].Subject)
}
