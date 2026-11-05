package scionrpc

import (
	"context"
	"crypto"
	"crypto/tls"
	"encoding/hex"
	"errors"
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

	"github.com/fancl20/cion/pkg/libs/bus"
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
	// Lease returns the lease of a destination whose authority names no
	// path; nil, or a lease with nothing composed, sends over a one-hop
	// path.
	Lease func(dst addr.IA) *scion.Lease
	// Receivers, when set, records each peer's enrollment from the
	// certificate its handshake presented: the record of a client that
	// verifies no server, the beacon channel's.
	Receivers *Receivers
}

// Receivers records, per peer, whether the receiver of a client's latest
// handshake with it presented a chain the pinned TRC anchors, naming the
// peer: an enrolled node. A peer without a record has not enrolled. The zero
// value records nothing yet.
type Receivers struct {
	mtx      sync.Mutex
	enrolled map[addr.IA]bool
}

// Enrolled reports whether the peer's latest handshake presented a chain the
// pinned TRC anchors.
func (r *Receivers) Enrolled(peer addr.IA) bool {
	r.mtx.Lock()
	defer r.mtx.Unlock()
	return r.enrolled[peer]
}

// record records what the peer's latest handshake presented.
func (r *Receivers) record(peer addr.IA, enrolled bool) {
	r.mtx.Lock()
	defer r.mtx.Unlock()
	if r.enrolled == nil {
		r.enrolled = make(map[addr.IA]bool)
	}
	r.enrolled[peer] = enrolled
}

// NewSCIONClient returns an HTTP client over the SCION-native channel: HTTP/3
// (QUIC) riding the connection's SCION paths, presenting the node's chain as
// the client certificate and — with verifyServer set — verifying the peer's
// chain against the pinned TRC. A dial rides the path the peer's authority
// names, else the one its lease holds, and records what the peer presented
// in the configuration's Receivers when set. Closing qclt releases the
// connections the client dials.
func NewSCIONClient(
	cfg PeerClientConfig,
	qclt *quic.Transport,
	verifyServer bool,
) *http.Client {

	// QUIC datagrams are capped so a datagram wrapped in a SCION header
	// still fits a standard 1500-byte MTU. The pool holds a connection by its
	// authority, riding the path its dial took for life: the far end reverses
	// the first packet's. One whose route went dark is detectable only by its
	// silence: keep-alives sustain the healthy ones while an idle timeout an
	// order below QUIC's half-minute default retires a dark one. A connection
	// over a lease's path retires before the next request once the lease left
	// that path or its hop fields near their expiry, and the request dials the
	// path the lease holds then; a one-hop path, created afresh for every
	// packet, and a path the authority names, which keys the connection, need
	// neither. (A request that times out on a dark connection leaves it
	// pooled: only the connection's own silence closes it.) A connection
	// dialed before the node held a chain retires once it holds one.
	unchained := &unchainedConns{creds: cfg.Credentials}
	leased := &leasedConns{lease: cfg.Lease, conns: make(map[string]leasedConn)}
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
			var path scion.Leased
			overLease := peer.Path == nil && cfg.Lease != nil
			if overLease {
				if path, err = cfg.Lease(peer.IA).Path(); err != nil {
					overLease = false
				}
				peer.Path = path.Path
			}
			ephemeral := !holdsChain(ctx, cfg.Credentials)
			conn, err := qclt.Dial(ctx, peer,
				nativeClientTLS(peer.IA, cfg.Credentials, cfg.Key, verifyServer), quicCfg)
			if err == nil && ephemeral {
				unchained.track(conn)
			}
			if err == nil && cfg.Receivers != nil {
				cfg.Receivers.record(peer.IA, chainAnchored(cfg.Credentials, peer.IA,
					conn.ConnectionState().TLS.PeerCertificates))
			}
			if overLease {
				leased.dialed(authorityKey(authority), peer.IA, path, conn, err)
			}
			return conn, err
		},
	}
	return &http.Client{Transport: &chainTransport{pool: h3t, unchained: unchained, leased: leased}}
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
// the request dials anew and presents the chain. It retires the authority's
// connection over a lease's path first when that path no longer serves, and
// reports each response on the path its connection rides.
type chainTransport struct {
	pool      connPool
	unchained *unchainedConns
	leased    *leasedConns
}

func (t *chainTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.unchained.retire(req.Context()) {
		t.pool.CloseIdleConnections()
	}
	key := authorityKey(req.URL.Host)
	t.leased.retireStale(key)
	resp, err := t.pool.RoundTrip(req)
	if err == nil {
		t.leased.delivered(key)
	}
	return resp, err
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

// leasedConns holds the connections a client dialed over leases' paths, each
// by its authority's key, and reports their outcomes on those paths: a
// completed handshake and every response delivered, a refused handshake
// delivered too, an idle or a handshake timeout lost.
type leasedConns struct {
	// lease returns a destination's lease, read afresh at each use: the one
	// the provider holds then.
	lease func(dst addr.IA) *scion.Lease

	mtx   sync.Mutex
	conns map[string]leasedConn
}

// leasedConn is one connection over a lease's path: its destination, the
// path's identity, and its hop fields' expiry.
type leasedConn struct {
	conn   *quic.Conn
	dst    addr.IA
	id     bus.PathID
	expiry time.Time
}

// dialed reports a dial's outcome on the path dst's lease held, and holds
// the connection it dialed by the authority's key until the connection
// closes, its idle timeout then reported. A transport error the peer sent,
// or one its handshake messages raised, is a refused handshake.
func (l *leasedConns) dialed(key string, dst addr.IA, path scion.Leased, conn *quic.Conn, err error) {
	lease := l.lease(dst)
	var refused *quic.TransportError
	switch {
	case silent(err):
		lease.Lost(path.ID)
		return
	case errors.As(err, &refused) && (refused.Remote || refused.ErrorCode.IsCryptoError()):
		lease.Delivered(path.ID)
		return
	case err != nil:
		return
	}
	lease.Delivered(path.ID)
	l.mtx.Lock()
	l.conns[key] = leasedConn{conn: conn, dst: dst, id: path.ID, expiry: scion.PathExpiry(path.Path)}
	l.mtx.Unlock()
	context.AfterFunc(conn.Context(), func() {
		if silent(context.Cause(conn.Context())) {
			l.lease(dst).Lost(path.ID)
		}
		l.forget(key, conn)
	})
}

// retireStale closes the authority's connection when its destination's
// lease left the connection's path, or the path's hop fields lapse within
// the lease's margin: the pool then dials anew, and the requests in flight
// on it fail.
func (l *leasedConns) retireStale(key string) {
	l.mtx.Lock()
	lc, ok := l.conns[key]
	l.mtx.Unlock()
	if !ok {
		return
	}
	if path, err := l.lease(lc.dst).Path(); err == nil && path.ID == lc.id &&
		time.Until(lc.expiry) >= scion.LeaseExpiryMargin {
		return
	}
	_ = lc.conn.CloseWithError(0, "the path no longer serves its lease")
	l.forget(key, lc.conn)
}

// delivered reports a response on the path of the authority's connection.
func (l *leasedConns) delivered(key string) {
	l.mtx.Lock()
	lc, ok := l.conns[key]
	l.mtx.Unlock()
	if ok {
		l.lease(lc.dst).Delivered(lc.id)
	}
}

// forget drops the authority's connection when it is still conn.
func (l *leasedConns) forget(key string, conn *quic.Conn) {
	l.mtx.Lock()
	defer l.mtx.Unlock()
	if l.conns[key].conn == conn {
		delete(l.conns, key)
	}
}

// silent reports whether a connection's error is its path's silence: an idle
// or a handshake timeout.
func silent(err error) bool {
	var idle *quic.IdleTimeoutError
	var handshake *quic.HandshakeTimeoutError
	return errors.As(err, &idle) || errors.As(err, &handshake)
}

// authorityKey returns the authority without the port the HTTP/3 transport
// appends to it.
func authorityKey(authority string) string {
	key, _, _ := strings.Cut(authority, ":")
	return key
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

// RouteAuthority encodes the peer address as PeerAuthority does, and the
// path the address carries beside it: the authority of a dial that rides
// that path rather than one resolved at dial time, such as the reverse of a
// received request's. An address without a path encodes as PeerAuthority's.
func RouteAuthority(peer *scion.Addr) (string, error) {
	if peer.Path == nil {
		return PeerAuthority(peer), nil
	}
	raw := make([]byte, peer.Path.Len())
	if err := peer.Path.SerializeTo(raw); err != nil {
		return "", fmt.Errorf("encoding the peer's path: %w", err)
	}
	endpoint := fmt.Sprintf("%s,%d,%s", peer, peer.IfID, raw)
	return hex.EncodeToString([]byte(endpoint)), nil
}

// peerFromAuthority decodes the URL authority back into a peer address. The
// HTTP/3 transport appends a default port to authorities without one; the
// separator is not a hexadecimal character, so it is cut unconditionally.
// The path, the last field, is raw bytes and may hold the separator itself.
func peerFromAuthority(authority string) (*scion.Addr, error) {
	if i := strings.IndexByte(authority, ':'); i >= 0 {
		authority = authority[:i]
	}
	raw, err := hex.DecodeString(authority)
	if err != nil {
		return nil, fmt.Errorf("decoding peer authority: %w", err)
	}
	parts := strings.SplitN(string(raw), ",", 4)
	if len(parts) < 2 {
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
	if len(parts) >= 3 {
		ifID, err := strconv.ParseUint(parts[2], 10, 16)
		if err != nil {
			return nil, fmt.Errorf("parsing peer egress interface: %w", err)
		}
		peer.IfID = uint16(ifID)
	}
	if len(parts) == 4 {
		path := &spath.Decoded{}
		if err := path.DecodeFromBytes([]byte(parts[3])); err != nil {
			return nil, fmt.Errorf("parsing peer path: %w", err)
		}
		peer.Path = path
	}
	return peer, nil
}
