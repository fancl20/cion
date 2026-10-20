package scionrpc

import (
	"context"
	"crypto"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/scionproto/scion/pkg/addr"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/libs/scion"
)

// PeerClientConfig configures a client of peers' endpoints over the channel.
type PeerClientConfig struct {
	// Credentials provide the node's AS chain as the client certificate and
	// the TRC anchors the peer's chain verifies against.
	Credentials Credentials
	// Key is the AS key behind the chain.
	Key crypto.Signer
	// Conn is the SCION connection QUIC rides.
	Conn *scion.Conn
	// PathTo resolves the data-plane path to a destination that is not a
	// direct neighbor; nil, or a nil result, sends over a one-hop path.
	PathTo func(dst addr.IA) *spath.Decoded
}

// NewSCIONClient returns an HTTP client over the SCION-native channel: HTTP/3
// (QUIC) riding the connection's SCION paths, presenting the node's chain as
// the client certificate and — with verifyServer set — verifying the peer's
// chain against the pinned TRC. Closing qclt releases the connections the
// client dials.
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
			return qclt.Dial(ctx, peer,
				nativeClientTLS(peer.IA, cfg.Credentials, cfg.Key, verifyServer), quicCfg)
		},
	}}
}

// PeerAuthority encodes the peer address as a URL authority: hexadecimal, so
// it survives URL parsing unchanged and never collides with a real host. The
// form every SCION-native client names its peer's endpoint by — an underlay
// or a service destination, the egress interface named beside them when the
// address carries one: the one-hop dial that rides a chosen link rather than
// resolving one, the confirm's own form.
func PeerAuthority(peer *scion.Addr) string {
	endpoint := peer.String()
	if peer.IfID != 0 {
		endpoint += fmt.Sprintf(",%d", peer.IfID)
	}
	return hex.EncodeToString([]byte(endpoint))
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
	if len(parts) != 2 && len(parts) != 3 {
		return nil, fmt.Errorf("malformed peer authority %q", authority)
	}
	ia, err := addr.ParseIA(parts[0])
	if err != nil {
		return nil, fmt.Errorf("parsing peer ISD-AS: %w", err)
	}
	peer := &scion.Addr{IA: ia}
	if value, ok := strings.CutPrefix(parts[1], "svc:"); ok {
		svc, err := strconv.ParseUint(value, 16, 16)
		if err != nil {
			return nil, fmt.Errorf("parsing peer service: %w", err)
		}
		peer.Service = addr.SVC(svc)
	} else {
		ap, err := netip.ParseAddrPort(parts[1])
		if err != nil {
			return nil, fmt.Errorf("parsing peer underlay address: %w", err)
		}
		peer.Addr = ap
	}
	if len(parts) == 3 {
		ifID, err := strconv.ParseUint(parts[2], 10, 16)
		if err != nil {
			return nil, fmt.Errorf("parsing peer egress interface: %w", err)
		}
		peer.IfID = uint16(ifID)
	}
	return peer, nil
}
