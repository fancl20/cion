package controlplane

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"sync"

	"connectrpc.com/connect"
	"github.com/quic-go/quic-go"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/pkg/core/trust"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/scionrpc"
	"github.com/fancl20/cion/pkg/modules/trustdb"
)

// PeerClient is the SCION-native channel's RPC client: ConnectRPC over HTTP/3
// (QUIC) riding SCION paths, peers authenticated by AS certificate chains
// verified against the pinned TRC. The peer address carries either a neighbor
// — sent over a one-hop path — or a SCION path supplied by the provider.
// Beacons ride a client-authenticated channel whose server certificate is
// not verified: their receivers may not be enrolled yet, and the PCB's
// signatures authenticate the path authoritatively anyway. Registrations and
// lookups verify the peer's chain against the pinned TRC.
type PeerClient struct {
	qclt *quic.Transport
	// beaconHCLT pools connections for beacon sends; verifiedHCLT for the
	// mutually verified RPCs; oneHopHCLT for the mutually verified RPCs that
	// dial one-hop paths alone — the confirm's channel, and the trust fetches
	// from a beacon's sender. All ride the same QUIC transport.
	beaconHCLT   *http.Client
	verifiedHCLT *http.Client
	oneHopHCLT   *http.Client

	mtx         sync.Mutex
	beaconClt   map[string]*Client
	verifiedClt map[string]*Client
	oneHopClt   map[string]*Client
}

// NewPeerClient creates the client for the SCION-native channel.
func NewPeerClient(cfg scionrpc.PeerClientConfig) *PeerClient {
	c := &PeerClient{
		qclt:        &quic.Transport{Conn: cfg.Conn},
		beaconClt:   make(map[string]*Client),
		verifiedClt: make(map[string]*Client),
		oneHopClt:   make(map[string]*Client),
	}
	// Beacons ride the client-authenticated channel; registrations and
	// lookups the mutually verified one. Both ride the same QUIC transport,
	// but the beacon channel dials one-hop alone: beacons terminate on each
	// neighbor's control service, whose handler reads the arrival interface
	// off the one-hop path — a provider path to the neighbor would leave it
	// unknown, and one exists whenever two cores beacon each other.
	beaconCfg := cfg
	beaconCfg.PathTo = nil
	c.beaconHCLT = scionrpc.NewSCIONClient(beaconCfg, c.qclt, false)
	c.verifiedHCLT = scionrpc.NewSCIONClient(cfg, c.qclt, true)
	// The one-hop channel keeps the beacon dial's discipline with the
	// verified channel's mutual authentication: a request it carries rides
	// the direct link of the entry it names, so the observation the peer's
	// link records is the sender's link socket.
	c.oneHopHCLT = scionrpc.NewSCIONClient(beaconCfg, c.qclt, true)
	return c
}

// Beacon propagates the extended PCB to the peer's beacon service (draft
// Section 2.3.5.1).
func (c *PeerClient) Beacon(ctx context.Context, peer *scion.Addr, pcb *cppb.PathSegment) error {
	clt := c.client(peer, c.beaconHCLT, c.beaconClt)
	_, err := clt.Beacon(ctx, connect.NewRequest(&cppb.BeaconRequest{Segment: pcb}))
	return err
}

// RegisterSegments registers down segments with the core's control service
// (Sections 3.1.3 and 3.3).
func (c *PeerClient) RegisterSegments(
	ctx context.Context,
	peer *scion.Addr,
	segments []*cppb.PathSegment,
) error {

	clt := c.client(peer, c.verifiedHCLT, c.verifiedClt)
	_, err := clt.SegmentsRegistration(ctx, connect.NewRequest(&cppb.SegmentsRegistrationRequest{
		Segments: map[int32]*cppb.SegmentsRegistrationRequest_Segments{
			int32(cppb.SegmentType_SEGMENT_TYPE_DOWN): {Segments: segments},
		},
	}))
	return err
}

// Segments requests path segments from the peer's control service (Section
// 5.2).
func (c *PeerClient) Segments(
	ctx context.Context,
	peer *scion.Addr,
	src, dst addr.IA,
) (*cppb.SegmentsResponse, error) {

	clt := c.client(peer, c.verifiedHCLT, c.verifiedClt)
	resp, err := clt.Segments(ctx, connect.NewRequest(&cppb.SegmentsRequest{
		SrcIsdAs: uint64(src),
		DstIsdAs: uint64(dst),
	}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// VerifiedClient returns the HTTP client of the mutually verified channel —
// the one registrations and lookups ride, peers authenticated by their
// chains against the pinned TRC — for an application's own services beside
// the drafts': the client machinery consumed as a library, sharing this
// client's transport and connection pool.
func (c *PeerClient) VerifiedClient() *http.Client {
	return c.verifiedHCLT
}

// Fetcher returns the trust fetcher that asks server — a neighbor's control
// service, named by its ISD-AS as a service destination — for TRCs and
// chains over the one-hop channel (Section 2.4): the source a received
// beacon's missing material comes from, reached over the link the beacon
// arrived on whatever routes the node holds beyond it.
func (c *PeerClient) Fetcher(server net.Addr) trust.Fetcher {
	return peerFetcher{client: c, server: server}
}

// peerFetcher asks one neighbor's control service for trust material.
type peerFetcher struct {
	client *PeerClient
	server net.Addr
}

func (f peerFetcher) TRC(ctx context.Context, id cppki.TRCID) (cppki.SignedTRC, error) {
	clt, err := f.trustClient()
	if err != nil {
		return cppki.SignedTRC{}, err
	}
	resp, err := clt.TRC(ctx, connect.NewRequest(trust.TRCRequest(id)))
	if err != nil {
		return cppki.SignedTRC{}, err
	}
	return cppki.DecodeSignedTRC(resp.Msg.Trc)
}

func (f peerFetcher) Chains(ctx context.Context, q trustdb.ChainQuery) ([][]*x509.Certificate, error) {
	clt, err := f.trustClient()
	if err != nil {
		return nil, err
	}
	resp, err := clt.Chains(ctx, connect.NewRequest(trust.ChainsRequest(q)))
	if err != nil {
		return nil, err
	}
	return trust.ParseChains(resp.Msg)
}

// trustClient returns the one-hop channel's client of the server, which the
// beaconer names by its SCION address.
func (f peerFetcher) trustClient() (*Client, error) {
	peer, ok := f.server.(*scion.Addr)
	if !ok {
		return nil, serrors.New("trust server is not a SCION address", "server", f.server)
	}
	return f.client.client(peer, f.client.oneHopHCLT, f.client.oneHopClt), nil
}

// OneHopClient returns the HTTP client of the mutually verified channel's
// one-hop side: the confirm's dial, whose requests ride the direct link of
// the entry they confirm.
func (c *PeerClient) OneHopClient() *http.Client {
	return c.oneHopHCLT
}

// Close releases the underlying QUIC transport.
func (c *PeerClient) Close() error {
	return c.qclt.Close()
}

// client returns the ConnectRPC client for the peer over the given channel,
// keyed by the peer's encoded authority so the HTTP/3 transport reuses the
// connection.
func (c *PeerClient) client(peer *scion.Addr, hclt *http.Client, clients map[string]*Client) *Client {
	authority := scionrpc.PeerAuthority(peer)
	c.mtx.Lock()
	defer c.mtx.Unlock()
	clt, ok := clients[authority]
	if !ok {
		clt = NewClient(hclt, "https://"+authority)
		clients[authority] = clt
	}
	return clt
}
