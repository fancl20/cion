package scionrpc

import (
	"context"
	"crypto"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
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

// maxConnAge caps how long a pooled connection over a resolved path serves.
// A connection rides its dial-time path for life — the far end reverses the
// first packet's — so the cap bounds how stale the path grows: a route the
// segments since improved on is taken within it, and the path's
// expiration, hours after its segment's origination, lies far beyond it.
const maxConnAge = 10 * time.Minute

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
	// still fits a standard 1500-byte MTU. The pool holds a connection by its
	// peer alone, riding the path its dial resolved. One whose route went
	// dark is detectable only by its silence: keep-alives sustain the healthy
	// ones while an idle timeout an order below QUIC's half-minute default
	// retires a dark one. Over resolved paths the age cap retires the healthy
	// ones too; a one-hop path needs none, created afresh for every packet.
	// Either way the next request dials the route the provider resolves
	// then. (A request that times out on a dark connection leaves it pooled:
	// only the connection's own silence closes it.) A connection dialed
	// before the node held a chain retires once it holds one.
	unchained := &unchainedConns{creds: cfg.Credentials}
	quicConf := &quic.Config{
		InitialPacketSize: 1200,
		MaxIdleTimeout:    5 * time.Second,
		KeepAlivePeriod:   2 * time.Second,
	}
	h3t := &http3.Transport{
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
			ephemeral := !holdsChain(ctx, cfg.Credentials)
			conn, err := qclt.Dial(ctx, peer,
				nativeClientTLS(peer.IA, cfg.Credentials, cfg.Key, verifyServer), quicCfg)
			if err == nil && ephemeral {
				unchained.track(conn)
			}
			return conn, err
		},
	}
	var pool connPool = h3t
	if cfg.PathTo != nil {
		pool = newAgedTransport(h3t, maxConnAge)
	}
	return &http.Client{Transport: &chainTransport{pool: pool, unchained: unchained}}
}

// unchainedConns holds the connections a client dialed while the node held
// no chain. Each presents the ephemeral certificate for its life, and a peer
// authenticates no request over it, however long keep-alives hold it open.
type unchainedConns struct {
	creds Credentials

	mtx   sync.Mutex
	conns []*quic.Conn
}

// track holds a connection dialed while the node held no chain, dropping
// the held ones already closed.
func (u *unchainedConns) track(conn *quic.Conn) {
	u.mtx.Lock()
	defer u.mtx.Unlock()
	u.conns = slices.DeleteFunc(u.conns, func(c *quic.Conn) bool {
		return c.Context().Err() != nil
	})
	u.conns = append(u.conns, conn)
}

// retire closes the held connections once the node holds a chain, reporting
// whether it closed any.
func (u *unchainedConns) retire(ctx context.Context) bool {
	u.mtx.Lock()
	defer u.mtx.Unlock()
	if len(u.conns) == 0 || !holdsChain(ctx, u.creds) {
		return false
	}
	for _, conn := range u.conns {
		_ = conn.CloseWithError(0, "the node holds a chain")
	}
	u.conns = nil
	return true
}

// holdsChain reports whether the node holds a chain, which a handshake then
// presents in place of the ephemeral certificate.
func holdsChain(ctx context.Context, creds Credentials) bool {
	chain, err := creds.Chain(ctx)
	return err == nil && len(chain) > 0
}

// chainTransport retires the unchained connections before a request once
// the node holds a chain, the pool dropping its idle ones beside them, so
// the request dials anew and presents the chain.
type chainTransport struct {
	pool      connPool
	unchained *unchainedConns
}

func (t *chainTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.unchained.retire(req.Context()) {
		t.pool.CloseIdleConnections()
	}
	return t.pool.RoundTrip(req)
}

// CloseIdleConnections closes the pool's connections no request rides.
func (t *chainTransport) CloseIdleConnections() {
	t.pool.CloseIdleConnections()
}

// connPool is a transport pooling connections: HTTP/3's, or a test's double.
type connPool interface {
	http.RoundTripper
	CloseIdleConnections()
}

// agedTransport retires its pool's connections by age: the first request an
// age past the last sweep sweeps again, the pool closing every connection no
// request rides — the request's own included, which then dials anew. The
// HTTP/3 pool counts a request as riding until its response's headers
// arrive, and a connection a request rode through a sweep serves until the
// next one.
type agedTransport struct {
	pool   connPool
	maxAge time.Duration

	mtx   sync.Mutex
	swept time.Time
}

// newAgedTransport returns the pool's aged transport, its first sweep an age
// away.
func newAgedTransport(pool connPool, maxAge time.Duration) *agedTransport {
	return &agedTransport{pool: pool, maxAge: maxAge, swept: time.Now()}
}

func (t *agedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mtx.Lock()
	if now := time.Now(); now.Sub(t.swept) >= t.maxAge {
		t.swept = now
		t.pool.CloseIdleConnections()
	}
	t.mtx.Unlock()
	return t.pool.RoundTrip(req)
}

// CloseIdleConnections closes the pool's connections no request rides.
func (t *agedTransport) CloseIdleConnections() {
	t.pool.CloseIdleConnections()
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
