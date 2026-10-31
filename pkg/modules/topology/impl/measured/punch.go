package measured

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/quic-go/quic-go"
	"github.com/scionproto/scion/pkg/addr"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/core/trust"
	"github.com/fancl20/cion/pkg/libs/bus"
	"github.com/fancl20/cion/pkg/libs/loops"
	"github.com/fancl20/cion/pkg/libs/peeria"
	"github.com/fancl20/cion/pkg/libs/ratelimit"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/scionrpc"
	"github.com/fancl20/cion/pkg/libs/underlay"
	"github.com/fancl20/cion/pkg/modules/links"
	nodev1 "github.com/fancl20/cion/proto/node/v1"
	nodev1connect "github.com/fancl20/cion/proto/node/v1/nodev1connect"
)

// A punch reaches a node whose published rendezvous address answers
// nothing, a NAT or a filter in front of it: each side learns its socket's
// reflexive address from a reflector — the rendezvous acceptor of a
// dialable neighbor — and sends toward the other's, so each NAT admits the
// other side's packets.
const (
	// PunchPackets is how many packets each side sends toward the other's
	// reflexive address, PunchSpacing apart.
	PunchPackets = 5
	PunchSpacing = 50 * time.Millisecond
	// PunchMinInterval is the punch rate cap: the least pause between two
	// probes, or two link punches, one peer asks.
	PunchMinInterval = time.Second
	// punchHold bounds how long a probe's answering socket stays open: the
	// prober's runs and a second beside them.
	punchHold = ProbeRuns*ProbeWait + time.Second
)

const punchVersion = 1

// The kinds of punch packet.
const (
	// punchOpen opens the sender's NAT toward the receiver; a probe's
	// answering socket echoes it.
	punchOpen byte = 1
	// punchEcho answers a probe's punchOpen.
	punchEcho byte = 2
)

// punchPacket is one datagram of a punch: the exchange's nonce and its
// kind. A link socket's data plane drops it as malformed.
type punchPacket struct {
	nonce [16]byte
	kind  byte
}

func (p punchPacket) marshal() []byte {
	buf := make([]byte, 0, 19)
	buf = binary.BigEndian.AppendUint16(buf, punchVersion)
	buf = append(buf, p.nonce[:]...)
	return append(buf, p.kind)
}

func parsePunchPacket(b []byte) (punchPacket, bool) {
	if len(b) != 19 || binary.BigEndian.Uint16(b) != punchVersion {
		return punchPacket{}, false
	}
	var p punchPacket
	copy(p.nonce[:], b[2:18])
	p.kind = b[18]
	return p, true
}

// reflexiveAddr returns the socket's reflexive address: the source the
// reflector's reply to a binding request echoes.
func reflexiveAddr(ctx context.Context, conn underlay.UDPConn, reflector netip.AddrPort) (netip.AddrPort, error) {
	reply, _, _, err := echoOn(ctx, conn, reflector, RendezvousRequest{Binding: true})
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("learning the reflexive address from %s: %w", reflector, err)
	}
	if !reply.Reflexive.IsValid() {
		return netip.AddrPort{}, fmt.Errorf("the reflector %s echoes no reflexive address", reflector)
	}
	return reply.Reflexive, nil
}

// sendOpens sends the packets that open the socket's NAT toward the peer's
// reflexive address.
func sendOpens(ctx context.Context, conn underlay.UDPConn, to netip.AddrPort, nonce [16]byte) {
	raw := punchPacket{nonce: nonce, kind: punchOpen}.marshal()
	for i := range PunchPackets {
		if i > 0 && !loops.Sleep(ctx, PunchSpacing) {
			return
		}
		_, _ = conn.WriteToUDP(raw, udpAddr(to))
	}
}

// answerProbe opens the socket's NAT toward the prober while it echoes the
// prober's packets, until punchHold passes or the context ends, and
// releases the socket.
func answerProbe(ctx context.Context, conn underlay.UDPConn, theirs netip.AddrPort, nonce [16]byte) {
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithTimeout(ctx, punchHold)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Now()) })
	defer stop()
	var opens sync.WaitGroup
	defer opens.Wait()
	opens.Go(func() { sendOpens(ctx, conn, theirs, nonce) })
	echo := punchPacket{nonce: nonce, kind: punchEcho}.marshal()
	buf := make([]byte, 64)
	for ctx.Err() == nil {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if p, ok := parsePunchPacket(buf[:n]); ok && p.nonce == nonce && p.kind == punchOpen {
			_, _ = conn.WriteToUDP(echo, src)
		}
	}
}

// probeRTT sends ProbeRuns packets toward the peer's reflexive address,
// each awaiting its echo for ProbeWait, and returns the median of the
// answered round trips.
func probeRTT(
	ctx context.Context, conn underlay.UDPConn, theirs netip.AddrPort, nonce [16]byte,
) (time.Duration, error) {

	stop := context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Now()) })
	defer stop()
	open := punchPacket{nonce: nonce, kind: punchOpen}.marshal()
	buf := make([]byte, 64)
	var rtts []time.Duration
	for range ProbeRuns {
		if err := conn.SetReadDeadline(time.Now().Add(ProbeWait)); err != nil {
			return 0, err
		}
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		sent := time.Now()
		if _, err := conn.WriteToUDP(open, udpAddr(theirs)); err != nil {
			return 0, err
		}
		for {
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				break // the wait elapsed: lost
			}
			if p, ok := parsePunchPacket(buf[:n]); ok && p.nonce == nonce && p.kind == punchEcho {
				rtts = append(rtts, time.Since(sent))
				break
			}
		}
	}
	if len(rtts) == 0 {
		return 0, fmt.Errorf("no punch echo from %s", theirs)
	}
	return median(rtts), nil
}

// newNonce draws a punch's nonce.
func newNonce() ([16]byte, error) {
	var nonce [16]byte
	_, err := rand.Read(nonce[:])
	return nonce, err
}

// punchKey keys the punch rate cap: a peer's probes and its links' punches
// are each admitted at the cap's pace, so a promotion's punch need not wait
// out the probe that qualified it.
type punchKey struct {
	peer addr.IA
	link bool
}

// punchLimiter returns the punch rate limiter, built on first use so a
// struct literal configuration works.
func (s *LinkService) punchLimiter() *ratelimit.Keyed[punchKey] {
	s.punchOnce.Do(func() {
		interval := s.MinInterval
		if interval == 0 {
			interval = PunchMinInterval
		}
		s.punches = ratelimit.NewKeyed[punchKey](interval)
	})
	return s.punches
}

// punchCall is an admitted punch request: the authenticated caller, its
// reflexive address, the punch's nonce, and the reflector, in the directory
// the request names, the node learns its own reflexive address from.
type punchCall struct {
	peer      addr.IA
	theirs    netip.AddrPort
	nonce     [16]byte
	reflector netip.AddrPort
}

// admitPunch admits a punch request of the kind: an authenticated caller
// within the rate cap, its reflexive address and nonce, the directory it
// names, and a reflector the node holds there.
func (s *LinkService) admitPunch(
	ctx context.Context, link bool, reflexive string, nonce, directory []byte,
) (punchCall, error) {

	call := punchCall{peer: peeria.AuthenticatedIA(ctx)}
	if call.peer.IsZero() {
		return punchCall{}, connect.NewError(connect.CodePermissionDenied,
			"no authenticated ISD-AS; the channel verified no chain")
	}
	if !s.punchLimiter().Admit(punchKey{peer: call.peer, link: link}) {
		return punchCall{}, connect.Errorf(connect.CodeResourceExhausted,
			"peer %s exceeds the punch rate", call.peer)
	}
	theirs, err := netip.ParseAddrPort(reflexive)
	if err != nil {
		return punchCall{}, connect.NewError(connect.CodeInvalidArgument,
			"parsing the caller's reflexive address").WithCause(err)
	}
	call.theirs = theirs
	if len(nonce) != len(call.nonce) {
		return punchCall{}, connect.NewError(connect.CodeInvalidArgument, "a nonce of 16 bytes")
	}
	copy(call.nonce[:], nonce)
	id, err := parseDirectoryID(directory)
	if err != nil {
		return punchCall{}, connect.NewError(connect.CodeInvalidArgument, err.Error())
	}
	if id.IsZero() {
		return punchCall{}, connect.NewError(connect.CodeInvalidArgument, "the request names no directory")
	}
	if s.Reflector == nil {
		return punchCall{}, connect.NewError(connect.CodeUnimplemented, "the node punches nothing")
	}
	if call.reflector, err = s.Reflector(ctx, id); err != nil {
		return punchCall{}, connect.NewError(connect.CodeUnavailable,
			"no reflector answers the node").WithCause(err)
	}
	return call, nil
}

// PunchProbe answers a probe through both NATs, on a socket that lives as
// long as the request: punchProbe over the stream.
func (s *LinkService) PunchProbe(
	ctx context.Context,
	req *nodev1.PunchProbeRequest,
	stream nodev1connect.LinkServicePunchProbeServerStream,
) error {
	return s.punchProbe(ctx, req, stream.Send)
}

// punchProbe binds an ephemeral socket, learns its reflexive address, and
// sends it; the socket then opens the node's NAT toward the caller's and
// echoes the caller's packets until the request ends or punchHold passes.
func (s *LinkService) punchProbe(
	ctx context.Context,
	req *nodev1.PunchProbeRequest,
	send func(*nodev1.PunchProbeReply) error,
) error {

	call, err := s.admitPunch(ctx, false, req.ReflexiveAddr, req.Nonce, req.Directory)
	if err != nil {
		return err
	}
	conn, err := s.Sockets.NewUDP(net.UDPAddrFromAddrPort(netip.AddrPortFrom(s.LinkHost, 0)),
		netip.AddrPort{})
	if err != nil {
		return connect.NewError(connect.CodeInternal, "binding the probe socket").WithCause(err)
	}
	mine, err := reflexiveAddr(ctx, conn, call.reflector)
	if err != nil {
		_ = conn.Close()
		return connect.NewError(connect.CodeUnavailable,
			"learning the probe socket's reflexive address").WithCause(err)
	}
	if err := send(&nodev1.PunchProbeReply{ReflexiveAddr: mine.String()}); err != nil {
		_ = conn.Close()
		return err
	}
	answerProbe(ctx, conn, call.theirs, call.nonce)
	return nil
}

// Punch opens the node's NAT toward the authenticated caller for the link
// it establishes or punches again: the caller's entry — a candidate the
// punch records, the one an unfinished punch left, or a down one it moves to
// a fresh link address — binds its link address, sends toward the caller's
// reflexive address, and records it as the entry's locator.
func (s *LinkService) Punch(ctx context.Context, req *nodev1.PunchRequest) (*nodev1.PunchReply, error) {
	call, err := s.admitPunch(ctx, true, req.ReflexiveAddr, req.Nonce, req.Directory)
	if err != nil {
		return nil, err
	}
	if req.IfId == 0 || req.IfId > 0xffff {
		return nil, connect.NewError(connect.CodeInvalidArgument, "interface ID out of range")
	}
	if s.Punching != nil && s.Punching(call.peer) {
		return nil, connect.Errorf(connect.CodeAborted, "the node punches toward %s itself", call.peer)
	}
	s.mtx.Lock()
	entry, err := s.punchEntry(ctx, call.peer, uint16(req.IfId))
	s.mtx.Unlock()
	if err != nil {
		return nil, err
	}
	conn, err := s.Sockets.NewUDP(net.UDPAddrFromAddrPort(entry.Local), netip.AddrPort{})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, "binding the link address").WithCause(err)
	}
	mine, err := reflexiveAddr(ctx, conn, call.reflector)
	if err != nil {
		_ = conn.Close()
		return nil, connect.NewError(connect.CodeUnavailable,
			"learning the link socket's reflexive address").WithCause(err)
	}
	sendOpens(ctx, conn, call.theirs, call.nonce)
	_ = conn.Close()
	entry.Remote = call.theirs
	s.mtx.Lock()
	err = s.Store.Update(ctx, entry)
	s.mtx.Unlock()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, "recording the entry").WithCause(err)
	}
	slog.Info("Punched toward a peer", "neighbor", call.peer, "local", entry.Local,
		"remote", entry.Remote, "reflexive", mine, "interface", entry.IfID)
	return &nodev1.PunchReply{ReflexiveAddr: mine.String(), IfId: uint32(entry.IfID)}, nil
}

// punchEntry returns the caller's entry a link's punch binds: the live one
// an unfinished punch left, which names no locator yet; a standing one whose
// verdict is down and whose peer interface is the one the request names —
// the same link punched again — moved to a fresh link address, for the
// link's own socket stays bound until the punched locator lands, with its
// interface ID kept, so the routes through the link carry again once it
// does; or a candidate it records under the cap on a fresh link address. A
// caller whose standing entry is up, or pairs with another of its
// interfaces, is refused: that link stands until its own verdict retires it.
func (s *LinkService) punchEntry(ctx context.Context, peer addr.IA, remoteIfID uint16) (*links.Link, error) {
	entry, err := s.Store.ByNeighbor(ctx, peer)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, "reading the neighbor table").WithCause(err)
	}
	if entry != nil && !entry.Remote.IsValid() {
		entry.RemoteIfID = remoteIfID
		return entry, nil
	}
	if entry != nil && (entry.RemoteIfID != remoteIfID || s.Links.Latest().Up(entry.IfID)) {
		return nil, connect.Errorf(connect.CodeAlreadyExists, "a link to %s stands", peer)
	}
	entries, err := s.Store.All(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, "reading the link store").WithCause(err)
	}
	if entry == nil {
		if live := liveLinks(entries); live >= s.MaxLinks {
			return nil, connect.Errorf(connect.CodeResourceExhausted, "link cap reached (%d)", live)
		}
	}
	local, err := AllocateLinkAddr(s.Sockets, s.LinkHost, entries)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, "allocating the link address").WithCause(err)
	}
	if entry != nil {
		entry.Local = local
		entry.RemoteIfID = remoteIfID
		return entry, nil
	}
	entry = &links.Link{
		NeighborIA: peer,
		Local:      local,
		RemoteIfID: remoteIfID,
		State:      links.StateCandidate,
	}
	if err := s.Store.Insert(ctx, entry); err != nil {
		return nil, connect.NewError(connect.CodeInternal, "recording the entry").WithCause(err)
	}
	return entry, nil
}

// Puncher reaches the candidates whose published rendezvous address answers
// nothing; the measured provider's puncher satisfies it.
type Puncher interface {
	// Probe measures the round trip to the peer over a punched pair of
	// ephemeral sockets, each side's reflexive address as the peers of the
	// directory the ID names see it.
	Probe(ctx context.Context, peer addr.IA, id bus.DirectoryID) (time.Duration, error)
	// Establish punches from the entry's own link address, each side's
	// reflexive address as the peers of the directory the ID names see it,
	// and answers the peer's reflexive address and interface ID, the
	// entry's side to record.
	Establish(
		ctx context.Context, peer addr.IA, id bus.DirectoryID, entry *links.Link,
	) (netip.AddrPort, uint16, error)
}

// punchPaths resolves the route a punch request rides, segment lookups
// allowed: the puncher resolves it before the request, so the request's
// dial resolves nothing.
type punchPaths interface {
	Path(ctx context.Context, dst addr.IA) (*spath.Decoded, error)
}

// puncher sends the punches the selection loop asks for, over a channel of
// its own: a punch reaches a peer no link reaches yet, whose route takes
// the down segments a lookup fetches.
type puncher struct {
	// conn is the SCION connection the punch requests ride; engine
	// provides the node's chain as the client certificate and the TRC the
	// peer's chain verifies against.
	conn   *scion.Conn
	engine *trust.Engine
	paths  punchPaths
	// reflector returns the rendezvous address of a neighbor in the
	// directory the ID names, whose acceptor echoes a socket's reflexive
	// address.
	reflector func(ctx context.Context, id bus.DirectoryID) (netip.AddrPort, error)
	sockets   underlay.Sockets
	// host is the control host, which the probe socket binds.
	host netip.Addr

	mtx sync.Mutex
	// qclt is the QUIC transport over conn, built at the first request.
	qclt     *quic.Transport
	inflight map[addr.IA]bool
}

var _ Puncher = (*puncher)(nil)

// client returns a link service client of the peer for one request, and
// the release that closes its connection: its own HTTP client, whose dial
// rides the route resolved here.
func (p *puncher) client(ctx context.Context, peer addr.IA) (nodev1connect.LinkServiceClient, func(), error) {
	route, err := p.paths.Path(ctx, peer)
	if err != nil {
		return nil, nil, fmt.Errorf("resolving the route to %s: %w", peer, err)
	}
	p.mtx.Lock()
	if p.qclt == nil {
		p.qclt = &quic.Transport{Conn: p.conn}
	}
	qclt := p.qclt
	p.mtx.Unlock()
	hclt := scionrpc.NewSCIONClient(scionrpc.PeerClientConfig{
		Credentials: p.engine,
		Key:         p.engine.Key,
		Conn:        p.conn,
		PathTo:      func(addr.IA) *spath.Decoded { return route },
	}, qclt, true)
	authority := scionrpc.PeerAuthority(&scion.Addr{IA: peer, Service: addr.SvcCS})
	clt := nodev1connect.NewLinkServiceClient(connect.NewClient(
		connecthttp.NewTransport(hclt, "https://"+authority)))
	return clt, hclt.CloseIdleConnections, nil
}

// Close releases the punch requests' QUIC transport.
func (p *puncher) Close() error {
	p.mtx.Lock()
	defer p.mtx.Unlock()
	if p.qclt == nil {
		return nil
	}
	return p.qclt.Close()
}

// learn returns the socket's reflexive address as the directory's peers see
// it, from a reflector the node holds in the directory.
func (p *puncher) learn(
	ctx context.Context, conn underlay.UDPConn, id bus.DirectoryID,
) (netip.AddrPort, error) {

	reflector, err := p.reflector(ctx, id)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return reflexiveAddr(ctx, conn, reflector)
}

// Probe measures the round trip to the peer over a punched pair of
// ephemeral sockets, the peer's answering for as long as the probe's
// stream stays open, each side's reflexive address as the directory's peers
// see it.
func (p *puncher) Probe(ctx context.Context, peer addr.IA, id bus.DirectoryID) (time.Duration, error) {
	clt, release, err := p.client(ctx, peer)
	if err != nil {
		return 0, err
	}
	defer release()
	conn, err := p.sockets.NewUDP(net.UDPAddrFromAddrPort(netip.AddrPortFrom(p.host, 0)),
		netip.AddrPort{})
	if err != nil {
		return 0, fmt.Errorf("binding the probe socket: %w", err)
	}
	defer func() { _ = conn.Close() }()
	mine, err := p.learn(ctx, conn, id)
	if err != nil {
		return 0, err
	}
	nonce, err := newNonce()
	if err != nil {
		return 0, err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := clt.PunchProbe(ctx, &nodev1.PunchProbeRequest{
		ReflexiveAddr: mine.String(),
		Nonce:         nonce[:],
		Directory:     id[:],
	})
	if err != nil {
		return 0, err
	}
	defer func() { _ = stream.Close() }()
	reply, err := stream.Receive()
	if err != nil {
		return 0, err
	}
	theirs, err := netip.ParseAddrPort(reply.ReflexiveAddr)
	if err != nil {
		return 0, fmt.Errorf("parsing the peer's reflexive address: %w", err)
	}
	return probeRTT(ctx, conn, theirs, nonce)
}

// Establish punches from the entry's own link address, released before it
// returns, each side's reflexive address as the directory's peers see it,
// and answers the peer's reflexive address and interface ID. Its bind fails
// while the peer's own punch toward the node holds the address.
func (p *puncher) Establish(
	ctx context.Context, peer addr.IA, id bus.DirectoryID, entry *links.Link,
) (netip.AddrPort, uint16, error) {

	p.mtx.Lock()
	if p.inflight == nil {
		p.inflight = make(map[addr.IA]bool)
	}
	p.inflight[peer] = true
	p.mtx.Unlock()
	defer func() {
		p.mtx.Lock()
		delete(p.inflight, peer)
		p.mtx.Unlock()
	}()
	clt, release, err := p.client(ctx, peer)
	if err != nil {
		return netip.AddrPort{}, 0, err
	}
	defer release()
	conn, err := p.sockets.NewUDP(net.UDPAddrFromAddrPort(entry.Local), netip.AddrPort{})
	if err != nil {
		return netip.AddrPort{}, 0, fmt.Errorf("binding the link address: %w", err)
	}
	defer func() { _ = conn.Close() }()
	mine, err := p.learn(ctx, conn, id)
	if err != nil {
		return netip.AddrPort{}, 0, err
	}
	nonce, err := newNonce()
	if err != nil {
		return netip.AddrPort{}, 0, err
	}
	reply, err := clt.Punch(ctx, &nodev1.PunchRequest{
		ReflexiveAddr: mine.String(),
		Nonce:         nonce[:],
		IfId:          uint32(entry.IfID),
		Directory:     id[:],
	})
	if err != nil {
		return netip.AddrPort{}, 0, err
	}
	theirs, err := netip.ParseAddrPort(reply.ReflexiveAddr)
	if err != nil {
		return netip.AddrPort{}, 0, fmt.Errorf("parsing the peer's reflexive address: %w", err)
	}
	sendOpens(ctx, conn, theirs, nonce)
	return theirs, uint16(reply.IfId), nil
}

// punching reports whether a link's punch toward the peer is in flight.
func (p *puncher) punching(peer addr.IA) bool {
	p.mtx.Lock()
	defer p.mtx.Unlock()
	return p.inflight[peer]
}
