package controlplane

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/scionproto/scion/pkg/addr"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/scion"
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
	conn   *scion.Conn
	qclt   *quic.Transport
	engine *trust.Engine
	pathTo func(dst addr.IA) *spath.Decoded
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
	Conn *scion.Conn
	// PathTo resolves the data-plane path to a destination that is not a
	// direct neighbor; nil, or a nil result, sends over a one-hop path.
	PathTo func(dst addr.IA) *spath.Decoded
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
	// Beacons ride the client-authenticated channel; registrations and
	// lookups the mutually verified one. Both ride the same QUIC transport.
	c.beaconHCLT = NewSCIONClient(cfg, c.qclt, false)
	c.verifiedHCLT = NewSCIONClient(cfg, c.qclt, true)
	return c
}

// NewSCIONClient returns an HTTP client over the SCION-native channel: HTTP/3
// (QUIC) riding the connection's SCION paths, presenting the node's chain as
// the client certificate and — with verifyServer set — verifying the peer's
// chain against the pinned TRC. The control endpoint's client machinery as a
// library, the form the WireGuard application's directory client consumes
// (proposal 0006).
// Closing qclt releases the connections the client dials.
func NewSCIONClient(
	cfg PeerClientConfig,
	qclt *quic.Transport,
	verifyServer bool,
) *http.Client {

	// QUIC datagrams are capped so a datagram wrapped in a SCION header
	// still fits a standard 1500-byte MTU. Idle connections die soon enough
	// that re-dials pick up fresh paths: the pool holds a connection by its
	// peer alone, and one whose route went dark is detectable only by its
	// silence — keep-alives sustain the healthy ones while an idle timeout
	// an order below QUIC's half-minute default retires a dark one, the next
	// request dialing the route the provider resolves now. (A request that
	// times out on a dark connection leaves it pooled: only the connection's
	// own silence closes it.)
	quicConf := &quic.Config{
		InitialPacketSize: 1200,
		MaxIdleTimeout:    5 * time.Second,
		KeepAlivePeriod:   2 * time.Second,
	}
	return &http.Client{Transport: &http3.Transport{
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
			if cfg.PathTo != nil {
				peer.Path = cfg.PathTo(peer.IA)
			}
			return qclt.Dial(ctx, peer, nativeClientTLS(peer.IA, cfg.Engine, verifyServer), quicCfg)
		},
	}}
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

// Close releases the underlying QUIC transport.
func (c *PeerClient) Close() error {
	return c.qclt.Close()
}

// client returns the ConnectRPC client for the peer over the given channel,
// keyed by the peer's encoded authority so the HTTP/3 transport reuses the
// connection.
func (c *PeerClient) client(peer *scion.Addr, hclt *http.Client, clients map[string]*Client) *Client {
	authority := PeerAuthority(peer)
	c.mtx.Lock()
	defer c.mtx.Unlock()
	clt, ok := clients[authority]
	if !ok {
		clt = NewClient(hclt, "https://"+authority)
		clients[authority] = clt
	}
	return clt
}

// PeerAuthority encodes the peer address as a URL authority: hexadecimal, so
// it survives URL parsing unchanged and never collides with a real host. The
// form every SCION-native client names its peer's endpoint by — an underlay
// or a service destination.
func PeerAuthority(peer *scion.Addr) string {
	return hex.EncodeToString([]byte(peer.String()))
}

// peerFromAuthority decodes the URL authority back into a peer address. The
// HTTP/3 transport appends a default port to authorities without one; the
// separator is not a hexadecimal character, so it is cut unconditionally.
func peerFromAuthority(authority string) (*scion.Addr, error) {
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
	if value, ok := strings.CutPrefix(parts[1], "svc:"); ok {
		svc, err := strconv.ParseUint(value, 16, 16)
		if err != nil {
			return nil, fmt.Errorf("parsing peer service: %w", err)
		}
		return &scion.Addr{IA: ia, Service: addr.SVC(svc)}, nil
	}
	ap, err := netip.ParseAddrPort(parts[1])
	if err != nil {
		return nil, fmt.Errorf("parsing peer underlay address: %w", err)
	}
	return &scion.Addr{IA: ia, Addr: ap}, nil
}
