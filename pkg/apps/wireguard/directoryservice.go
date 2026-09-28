package wireguard

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"

	"connectrpc.com/connect"
	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/peeria"
	wireguardv1 "github.com/fancl20/cion/proto/wireguard/v1"
)

// DirectoryService is the core node's application's own service: Publish
// records the publisher's entry on the application's authenticated channel,
// List serves the directory to every node. The channel is the SCION-native
// mTLS: the publisher identified by its verified certificate chain, so a
// node can only publish its own entry — the claimed entry's ISD-AS is
// ignored in favor of the authenticated one.
type DirectoryService struct {
	// Store persists the directory.
	Store DirectoryStore
	// Cnt counts accepted publications.
	Cnt *counters
}

// AuthenticatedIA returns the ISD-AS of the peer whose certificate chain the
// channel verified, and Authenticate peers it into the request context — the
// peer-identity middleware of the SCION-native channel, consumed here for
// the publisher's identity.
var (
	AuthenticatedIA = peeria.AuthenticatedIA
	Authenticate    = peeria.Authenticate
)

// Publish records the caller's entry. The entry's ISD-AS is the
// authenticated one; a claim of another ISD-AS is recorded under the
// authenticated one all the same.
func (s *DirectoryService) Publish(
	ctx context.Context,
	req *connect.Request[wireguardv1.PublishRequest],
) (*connect.Response[wireguardv1.PublishResponse], error) {

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
	s.Cnt.published.Add(1)
	return connect.NewResponse(&wireguardv1.PublishResponse{}), nil
}

// List returns every published entry, nodes and hosts together.
func (s *DirectoryService) List(
	ctx context.Context,
	req *connect.Request[wireguardv1.ListRequest],
) (*connect.Response[wireguardv1.ListResponse], error) {

	directory, err := s.Store.List(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal,
			fmt.Errorf("reading the directory: %w", err))
	}
	resp := &wireguardv1.ListResponse{}
	for _, e := range directory.Nodes {
		resp.Entries = append(resp.Entries, e.pb())
	}
	for _, h := range directory.Hosts {
		resp.Hosts = append(resp.Hosts, h.pb())
	}
	return connect.NewResponse(resp), nil
}

// entryFromPB decodes a wire entry.
func entryFromPB(pb *wireguardv1.Entry) (Entry, error) {
	var key PublicKey
	if len(pb.PublicKey) != len(key) {
		return Entry{}, fmt.Errorf("public key must be %d bytes", len(key))
	}
	copy(key[:], pb.PublicKey)
	overlay, err := netip.ParsePrefix(pb.OverlaySubnet)
	if err != nil {
		return Entry{}, fmt.Errorf("parsing overlay subnet: %w", err)
	}
	entry := Entry{
		IA:        addr.IA(pb.IsdAs),
		PublicKey: key,
		Overlay:   overlay,
	}
	if pb.HostEndpoint != "" {
		endpoint, err := netip.ParseAddrPort(pb.HostEndpoint)
		if err != nil {
			return Entry{}, fmt.Errorf("parsing host endpoint: %w", err)
		}
		entry.HostEndpoint = endpoint
	}
	return entry, nil
}

// pb encodes the entry for the wire.
func (e Entry) pb() *wireguardv1.Entry {
	pb := &wireguardv1.Entry{
		IsdAs:         uint64(e.IA),
		PublicKey:     e.PublicKey[:],
		OverlaySubnet: e.Overlay.String(),
	}
	if e.HostEndpoint.IsValid() {
		pb.HostEndpoint = e.HostEndpoint.String()
	}
	return pb
}

// pb encodes the host entry for the wire.
func (h HostEntry) pb() *wireguardv1.HostEntry {
	return &wireguardv1.HostEntry{
		PublicKey: h.PublicKey[:],
		Address:   h.Addr.String(),
		IsdAs:     uint64(h.IA),
		Note:      h.Note,
	}
}

// hostEntryFromPB decodes a wire host entry.
func hostEntryFromPB(pb *wireguardv1.HostEntry) (HostEntry, error) {
	var key PublicKey
	if len(pb.PublicKey) != len(key) {
		return HostEntry{}, fmt.Errorf("public key must be %d bytes", len(key))
	}
	copy(key[:], pb.PublicKey)
	entry := HostEntry{
		PublicKey: key,
		IA:        addr.IA(pb.IsdAs),
		Note:      pb.Note,
	}
	addr, err := netip.ParseAddr(pb.Address)
	if err != nil {
		return HostEntry{}, fmt.Errorf("parsing address: %w", err)
	}
	entry.Addr = addr
	return entry, nil
}
