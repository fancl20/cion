package controlplane

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"sync"

	"connectrpc.com/connect"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/scionproto/scion/pkg/addr"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/trust"
)

// PeerClient is the SCION-native channel's RPC client: ConnectRPC over HTTP/3
// (QUIC) riding SCION paths, peers authenticated by AS certificate chains
// verified against the pinned TRC (proposal 0004). The peer address carries
// either a neighbor — sent over a one-hop path — or a SCION path supplied by
// the provider.
//
// Beacons ride a client-authenticated channel whose server certificate is
// not verified: their receivers may not be enrolled yet, and the PCB's
// signatures authenticate the path authoritatively anyway. Registrations and
// lookups verify the peer's chain against the pinned TRC.
type PeerClient struct {
	conn   *SCIONConn
	qclt   *quic.Transport
	engine *trust.Engine
	pathTo func(dst addr.IA) *scion.Decoded
	// beaconHCLT pools connections for beacon sends; verifiedHCLT for the
	// mutually verified RPCs. Both ride the same QUIC transport.
	beaconHCLT   *http.Client
	verifiedHCLT *http.Client

	mtx         sync.Mutex
	beaconClt   map[string]*Client
	verifiedClt map[string]*Client
}

// PeerClientConfig configures a PeerClient.
type PeerClientConfig struct {
	// Engine provides the node's AS chain as the client certificate.
	Engine *trust.Engine
	// Conn is the SCION connection QUIC rides.
	Conn *SCIONConn
	// PathTo resolves the data-plane path to a destination that is not a
	// direct neighbor; nil, or a nil result, sends over a one-hop path.
	PathTo func(dst addr.IA) *scion.Decoded
}

// NewPeerClient creates the client for the SCION-native channel.
func NewPeerClient(cfg PeerClientConfig) *PeerClient {
	c := &PeerClient{
		conn:        cfg.Conn,
		qclt:        &quic.Transport{Conn: cfg.Conn},
		engine:      cfg.Engine,
		pathTo:      cfg.PathTo,
		beaconClt:   make(map[string]*Client),
		verifiedClt: make(map[string]*Client),
	}
	// QUIC datagrams are capped so a datagram wrapped in a SCION header
	// still fits a standard 1500-byte MTU; idle connections die soon enough
	// that re-dials pick up fresh paths.
	quicConf := &quic.Config{InitialPacketSize: 1200}
	transport := func(verifyServer bool) *http3.Transport {
		return &http3.Transport{
			QUICConfig: quicConf,
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS13,
				InsecureSkipVerify: true, // per-dial verification against the TRC
			},
			Dial: func(ctx context.Context, authority string, tlsCfg *tls.Config,
				quicCfg *quic.Config) (*quic.Conn, error) {

				peer, err := peerFromAuthority(authority)
				if err != nil {
					return nil, err
				}
				if c.pathTo != nil {
					peer.Path = c.pathTo(peer.IA)
				}
				return c.qclt.Dial(ctx, peer, nativeClientTLS(peer.IA, c.engine, verifyServer), quicCfg)
			},
		}
	}
	c.beaconHCLT = &http.Client{Transport: transport(false)}
	c.verifiedHCLT = &http.Client{Transport: transport(true)}
	return c
}

// Beacon propagates the extended PCB to the peer's beacon service (draft
// Section 2.3.5.1).
func (c *PeerClient) Beacon(ctx context.Context, peer *Addr, pcb *cppb.PathSegment) error {
	clt := c.client(peer, c.beaconHCLT, c.beaconClt)
	_, err := clt.Beacon(ctx, connect.NewRequest(&cppb.BeaconRequest{Segment: pcb}))
	return err
}

// RegisterSegments registers down segments with the core's control service
// (Sections 3.1.3 and 3.3).
func (c *PeerClient) RegisterSegments(
	ctx context.Context,
	peer *Addr,
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
	peer *Addr,
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

// Close releases the underlying QUIC transport.
func (c *PeerClient) Close() error {
	return c.qclt.Close()
}

// client returns the ConnectRPC client for the peer over the given channel,
// keyed by the peer's encoded authority so the HTTP/3 transport reuses the
// connection.
func (c *PeerClient) client(peer *Addr, hclt *http.Client, clients map[string]*Client) *Client {
	authority := peerAuthority(peer)
	c.mtx.Lock()
	defer c.mtx.Unlock()
	clt, ok := clients[authority]
	if !ok {
		clt = NewClient(hclt, "https://"+authority)
		clients[authority] = clt
	}
	return clt
}

// peerAuthority encodes the peer address as a URL authority: hexadecimal, so
// it survives URL parsing unchanged and never collides with a real host.
func peerAuthority(peer *Addr) string {
	return hex.EncodeToString([]byte(peer.IA.String() + "," + peer.Addr.String()))
}

// peerFromAuthority decodes the URL authority back into a peer address. The
// HTTP/3 transport appends a default port to authorities without one; the
// separator is not a hexadecimal character, so it is cut unconditionally.
func peerFromAuthority(authority string) (*Addr, error) {
	if i := strings.IndexByte(authority, ':'); i >= 0 {
		authority = authority[:i]
	}
	raw, err := hex.DecodeString(authority)
	if err != nil {
		return nil, fmt.Errorf("decoding peer authority: %w", err)
	}
	parts := strings.Split(string(raw), ",")
	if len(parts) != 2 {
		return nil, fmt.Errorf("malformed peer authority %q", authority)
	}
	ia, err := addr.ParseIA(parts[0])
	if err != nil {
		return nil, fmt.Errorf("parsing peer ISD-AS: %w", err)
	}
	ap, err := netip.ParseAddrPort(parts[1])
	if err != nil {
		return nil, fmt.Errorf("parsing peer underlay address: %w", err)
	}
	return &Addr{IA: ia, Addr: ap}, nil
}
