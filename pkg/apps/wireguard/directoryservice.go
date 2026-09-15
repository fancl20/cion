package wireguard

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"

	"connectrpc.com/connect"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	gatewayv1 "github.com/fancl20/cion/proto/gateway/v1"
)

// DirectoryService is the core node's gateway application's own service:
// Publish records the publisher's gateway entry on the application's
// authenticated channel, List serves the directory to every node. The
// channel is the SCION-native mTLS: the publisher identified by its verified
// certificate chain, so a node can only publish its own entry — the claimed
// entry's ISD-AS is ignored in favor of the authenticated one.
type DirectoryService struct {
	// Store persists the directory.
	Store DirectoryStore
	// Cnt counts accepted publications.
	Cnt *counters
}

// authenticatedIAKey is the context key carrying the verified publisher.
type authenticatedIAKey struct{}

// AuthenticatedIA returns the ISD-AS of the peer whose certificate chain the
// channel verified, or the zero ISD-AS when the request carries none —
// requests without one never reach the handlers.
func AuthenticatedIA(ctx context.Context) addr.IA {
	ia, ok := ctx.Value(authenticatedIAKey{}).(addr.IA)
	if !ok {
		return addr.IA(0)
	}
	return ia
}

// Authenticate peers the verified chain's ISD-AS into the request context.
// The middleware shape serves every service the application serves on the
// channel: the handler reads what the transport authenticated.
func Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			if ia, err := publisherIA(r.TLS.PeerCertificates); err == nil {
				r = r.WithContext(context.WithValue(r.Context(), authenticatedIAKey{}, ia))
			}
		}
		next.ServeHTTP(w, r)
	})
}

// publisherIA extracts the ISD-AS a verified chain's leaf names.
func publisherIA(chain []*x509.Certificate) (addr.IA, error) {
	if len(chain) == 0 {
		return addr.IA(0), errors.New("no peer certificate")
	}
	return cppki.ExtractIA(chain[0].Subject)
}

// Publish records the caller's entry. The entry's ISD-AS is the
// authenticated one; a claim of another ISD-AS is recorded under the
// authenticated one all the same.
func (s *DirectoryService) Publish(
	ctx context.Context,
	req *connect.Request[gatewayv1.PublishRequest],
) (*connect.Response[gatewayv1.PublishResponse], error) {

	publisher := AuthenticatedIA(ctx)
	if publisher.IsZero() {
		return nil, connect.NewError(connect.CodePermissionDenied,
			errors.New("no authenticated ISD-AS; the channel verified no chain"))
	}
	if req.Msg == nil || req.Msg.Entry == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("no entry"))
	}
	entry, err := entryFromPB(req.Msg.Entry)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("malformed entry: %w", err))
	}
	if !entry.IA.Equal(publisher) {
		slog.Warn("Directory publish claims another ISD-AS; recording the authenticated one",
			"authenticated", publisher, "claimed", entry.IA)
	}
	entry.IA = publisher
	if err := s.Store.Publish(ctx, entry); err != nil {
		return nil, connect.NewError(connect.CodeInternal,
			fmt.Errorf("storing the entry: %w", err))
	}
	if s.Cnt != nil {
		s.Cnt.published.Add(1)
	}
	return connect.NewResponse(&gatewayv1.PublishResponse{}), nil
}

// List returns every published entry.
func (s *DirectoryService) List(
	ctx context.Context,
	req *connect.Request[gatewayv1.ListRequest],
) (*connect.Response[gatewayv1.ListResponse], error) {

	entries, err := s.Store.List(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal,
			fmt.Errorf("reading the directory: %w", err))
	}
	resp := &gatewayv1.ListResponse{}
	for _, e := range entries {
		resp.Entries = append(resp.Entries, e.pb())
	}
	return connect.NewResponse(resp), nil
}

// entryFromPB decodes a wire entry.
func entryFromPB(pb *gatewayv1.Entry) (Entry, error) {
	var key PublicKey
	if len(pb.PublicKey) != len(key) {
		return Entry{}, fmt.Errorf("public key must be %d bytes", len(key))
	}
	copy(key[:], pb.PublicKey)
	overlay, err := netip.ParsePrefix(pb.OverlaySubnet)
	if err != nil {
		return Entry{}, fmt.Errorf("parsing overlay subnet: %w", err)
	}
	return Entry{
		IA:        addr.IA(pb.IsdAs),
		PublicKey: key,
		Overlay:   overlay,
	}, nil
}

// pb encodes the entry for the wire.
func (e Entry) pb() *gatewayv1.Entry {
	return &gatewayv1.Entry{
		IsdAs:         uint64(e.IA),
		PublicKey:     e.PublicKey[:],
		OverlaySubnet: e.Overlay.String(),
	}
}
