package wireguard

import (
	"encoding/binary"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"golang.zx2c4.com/wireguard/device"

	"github.com/fancl20/cion/pkg/libs/scion"
)

// Relay admission policy: a host's initiation holds a pending session until
// the node's response answers it, the pending sessions bounded in total and
// per source address.
const (
	// pendingLifetime is how long a pending session lives from its
	// initiation: the initiator's own retry time, after which it begins a
	// new handshake under a new sender index, so a response to the old one
	// meets nothing.
	pendingLifetime = device.RekeyTimeout + device.RekeyTimeoutJitterMaxMs*time.Millisecond
	// maxPendingSessions bounds the pending sessions the relay holds.
	maxPendingSessions = 1024
	// maxPendingPerSource bounds the pending sessions of one source — an
	// IPv4 address, an IPv6 /64 — which several instances of one client
	// share: mihomo runs one tailnet instance per exit.
	maxPendingPerSource = 64
)

// relayVerdict is what the relay does with a datagram it classified.
type relayVerdict int

const (
	// relayToDevice hands the datagram to the host device.
	relayToDevice relayVerdict = iota
	// relayOnward carries the datagram, unchanged, to its session's other
	// end: a host's to the node's relay service, a node's to the host's
	// endpoint.
	relayOnward
	// relayDrop drops and counts the datagram.
	relayDrop
	// relayCookie drops a host's initiation and answers its source, from the
	// shared port, with the cookie reply the relay created on the node's
	// behalf.
	relayCookie
)

// hostRelay is the node's relay for its hosts' sessions with other nodes. A
// host reaches every node at its own node's host-facing port, and the relay
// carries the WireGuard datagrams of each session a host holds with another
// node — unchanged, nothing added — between the host's endpoint and that
// node's relay service over the SCION underlay. It tells a session's
// datagrams apart by WireGuard's own message format: a handshake initiation
// by the mac1 its initiator keyed to the responder's public key, every later
// message by the index its receiver chose. The relay socket also carries the
// host device's own sessions with the hosts other nodes relay to it.
//
// The relay cannot authenticate a host: mac1 is keyed to the responder's
// public key alone, which every host's netmap holds, and the handshake
// encrypts the initiator's key to the responder. The responder authenticates
// instead — its host device holds exactly the hosts the directory registers
// and answers no other — so a host's initiation begins a pending session,
// bounded in total and per source address, that lives pendingLifetime
// unless the responder's response answers it first; an answered session
// lives until it falls silent. Under load the relay, as a WireGuard device
// does, admits an initiation only with a mac2 proving the host receives at
// its source address, and answers one without with a cookie reply: the
// reply is keyed to the responder's public key, which the relay holds, so
// the host's standard cookie handling accepts it as the responder's.
type hostRelay struct {
	// ia is the node's ISD-AS; its own directory entry gets no checker.
	ia addr.IA
	// conn is the relay socket, registered under SvcHostRelay.
	conn *scion.Conn
	// paths is the mesh socket, whose path cache the relay's sends resolve
	// through.
	paths *meshSocket
	cnt   *counters
	// now is the clock sessions expire and load passes by.
	now func() time.Time
	// own verifies initiations keyed to the node's own public key.
	own device.CookieChecker
	// maxPending bounds the pending sessions, an eighth of it putting the
	// relay under load: maxPendingSessions, which tests lower.
	maxPending int

	mtx sync.Mutex
	// nodes verifies initiations keyed to each other directory node's key.
	nodes []nodeChecker
	// byHost holds the sessions by their node and the host's sender index,
	// the receiver index the node's datagrams name; byNode holds the
	// answered ones by the node's sender index, the receiver index the
	// host's datagrams name.
	byHost map[sessionKey]*relaySession
	byNode map[uint32]*relaySession
	// pending counts the pending sessions, and perSource counts them by
	// their endpoint's source, as sourceOf names it. queue holds them in
	// the order they began, among the sessions answered or forgotten since,
	// which leave it as they reach its front.
	pending   int
	perSource map[netip.Prefix]int
	queue     []*relaySession
	// loadedUntil is when the relay's load passes, unless its pending
	// sessions reach an eighth of their bound again first.
	loadedUntil time.Time
	// swept is when the last sweep of expired sessions ran.
	swept time.Time
}

// nodeChecker verifies initiations keyed to one directory node's key and
// creates cookie replies on the node's behalf.
type nodeChecker struct {
	ia  addr.IA
	key PublicKey
	mac *device.CookieChecker
}

// sessionKey names a relayed session by its node and the host's sender
// index.
type sessionKey struct {
	node  addr.IA
	index uint32
}

// relaySession is one session the relay carries between a host and a node:
// pending from the host's initiation until the node's response answers it.
type relaySession struct {
	node addr.IA
	// host is the endpoint the host's initiation arrived from, which the
	// node's datagrams leave for.
	host netip.AddrPort
	// hostIndex is the host's sender index; nodeIndex is the node's, set
	// once its response passed.
	hostIndex uint32
	nodeIndex uint32
	answered  bool
	// began is when the host's initiation arrived, which a pending session
	// lives pendingLifetime from.
	began time.Time
	// seen is when the session's last datagram passed, which an answered
	// session falls silent from.
	seen time.Time
}

// newHostRelay builds the relay of the node ia whose public key is own, on
// the relay socket conn, resolving paths through the mesh socket.
func newHostRelay(ia addr.IA, own PublicKey, conn *scion.Conn, paths *meshSocket, cnt *counters) *hostRelay {
	r := &hostRelay{
		ia:         ia,
		conn:       conn,
		paths:      paths,
		cnt:        cnt,
		now:        time.Now,
		maxPending: maxPendingSessions,
		byHost:     make(map[sessionKey]*relaySession),
		byNode:     make(map[uint32]*relaySession),
		perSource:  make(map[netip.Prefix]int),
	}
	r.own.Init(device.NoisePublicKey(own))
	return r
}

// setNodes keys the relay's checkers to the directory's node entries: one
// per node other than this one. A node whose ISD-AS and key are unchanged
// keeps its checker, and with it the secret the cookies it issued are bound
// by, which a fresh checker would void.
func (r *hostRelay) setNodes(entries []Entry) {
	type identity struct {
		ia  addr.IA
		key PublicKey
	}
	r.mtx.Lock()
	defer r.mtx.Unlock()
	held := make(map[identity]*device.CookieChecker, len(r.nodes))
	for _, n := range r.nodes {
		held[identity{ia: n.ia, key: n.key}] = n.mac
	}
	nodes := make([]nodeChecker, 0, len(entries))
	for _, e := range entries {
		if e.IA.Equal(r.ia) {
			continue
		}
		mac, ok := held[identity{ia: e.IA, key: e.PublicKey}]
		if !ok {
			mac = &device.CookieChecker{}
			mac.Init(device.NoisePublicKey(e.PublicKey))
		}
		nodes = append(nodes, nodeChecker{ia: e.IA, key: e.PublicKey, mac: mac})
	}
	r.nodes = nodes
}

// fromHost classifies a datagram a host sent to the shared port, returning
// the node an onward datagram leaves for, the cookie reply a relayCookie
// verdict answers with, and the verdict. An initiation keyed to the node's
// own key goes to the host device, and one keyed to another directory
// node's meets the relay's admission toward that node; one keyed to no
// node's drops. A response, a cookie reply, or a transport message goes
// onward to the node whose recorded sender index it names as its receiver,
// and to the host device otherwise.
func (r *hostRelay) fromHost(pkt []byte, from netip.AddrPort) (addr.IA, []byte, relayVerdict) {
	switch typ := messageType(pkt); typ {
	case device.MessageInitiationType:
		if r.own.CheckMAC1(pkt) {
			return 0, nil, relayToDevice
		}
		return r.admit(pkt, from)
	case device.MessageResponseType, device.MessageCookieReplyType, device.MessageTransportType:
		now := r.now()
		r.mtx.Lock()
		defer r.mtx.Unlock()
		if s := r.liveLocked(r.byNode[receiverIndex(pkt, typ)], now); s != nil {
			s.seen = now
			return s.node, nil, relayOnward
		}
	}
	return 0, nil, relayToDevice
}

// admit classifies a host's initiation not keyed to the node's own key. One
// keyed to no directory node's key drops. For one keyed to another node's,
// the queue's expired front pops first; then, under load, one without a
// mac2 valid for its source drops, answered with the cookie reply that lets
// the host's next initiation carry one. A copy of an initiation the relay
// holds goes onward, for the node's own replay protection to judge, leaving
// its session as it stands; any other records a pending session and goes
// onward, or drops where the pending sessions stand at their bound in total
// or for the source address.
func (r *hostRelay) admit(pkt []byte, from netip.AddrPort) (addr.IA, []byte, relayVerdict) {
	now := r.now()
	r.mtx.Lock()
	defer r.mtx.Unlock()
	i := slices.IndexFunc(r.nodes, func(n nodeChecker) bool { return n.mac.CheckMAC1(pkt) })
	if i < 0 {
		return 0, nil, relayDrop
	}
	node := r.nodes[i]
	r.expireLocked(now)
	src := sourceBytes(from)
	if r.underLoadLocked(now) && !node.mac.CheckMAC2(pkt, src) {
		return 0, cookieReply(node.mac, pkt, src), relayCookie
	}
	key := sessionKey{node: node.ia, index: senderIndex(pkt)}
	if r.liveLocked(r.byHost[key], now) != nil {
		return node.ia, nil, relayOnward
	}
	if r.pending >= r.maxPending || r.perSource[sourceOf(from.Addr())] >= maxPendingPerSource {
		return 0, nil, relayDrop
	}
	r.recordLocked(key, from, now)
	return node.ia, nil, relayOnward
}

// fromNode classifies a datagram a node sent to the relay socket. A
// response, a cookie reply, or a transport message whose receiver index is
// the host's sender index of a session the relay recorded with that node
// goes onward to the host's endpoint, a response answering the session and
// recording the node's sender index; every other goes to the host device,
// for it belongs to the device's own session with a host the node relays.
// An initiation keyed to the node's own key begins such a session and goes
// to the host device too; one keyed to any other key is the node's own
// toward a host, and drops: relayed sessions begin at the host.
func (r *hostRelay) fromNode(pkt []byte, node addr.IA) (netip.AddrPort, relayVerdict) {
	switch typ := messageType(pkt); typ {
	case device.MessageInitiationType:
		if r.own.CheckMAC1(pkt) {
			return netip.AddrPort{}, relayToDevice
		}
		return netip.AddrPort{}, relayDrop
	case device.MessageResponseType, device.MessageCookieReplyType, device.MessageTransportType:
		now := r.now()
		r.mtx.Lock()
		defer r.mtx.Unlock()
		s := r.liveLocked(r.byHost[sessionKey{node: node, index: receiverIndex(pkt, typ)}], now)
		if s == nil {
			break
		}
		s.seen = now
		if typ == device.MessageResponseType {
			r.answerLocked(s, senderIndex(pkt))
		}
		return s.host, relayOnward
	}
	return netip.AddrPort{}, relayToDevice
}

// underLoadLocked reports whether the relay is under load: its pending
// sessions reach an eighth of their bound, or did within the last
// UnderLoadAfterTime — the rule a WireGuard device applies to its queue of
// handshakes.
func (r *hostRelay) underLoadLocked(now time.Time) bool {
	if r.pending >= r.maxPending/8 {
		r.loadedUntil = now.Add(device.UnderLoadAfterTime)
		return true
	}
	return now.Before(r.loadedUntil)
}

// recordLocked records the pending session a host's initiation toward a
// node begins, from the endpoint the initiation arrived from, counting it
// and queueing it. Every initiation carries a fresh sender index, so a
// host's later handshake records its endpoint anew.
func (r *hostRelay) recordLocked(key sessionKey, host netip.AddrPort, now time.Time) {
	s := &relaySession{node: key.node, host: host, hostIndex: key.index, began: now, seen: now}
	r.byHost[key] = s
	r.pending++
	r.perSource[sourceOf(host.Addr())]++
	r.queue = append(r.queue, s)
}

// answerLocked records the sender index the node's response named, the
// receiver index the host's later datagrams of the session name; the first
// response answers a pending session, taking it out of the pending counts.
func (r *hostRelay) answerLocked(s *relaySession, index uint32) {
	if !s.answered {
		r.unpendLocked(s)
	} else if r.byNode[s.nodeIndex] == s {
		delete(r.byNode, s.nodeIndex)
	}
	s.nodeIndex, s.answered = index, true
	r.byNode[index] = s
}

// liveLocked returns the session unless it is nil or expired, in which case
// the relay forgets it. A pending session expires pendingLifetime after its
// initiation; an answered one once silent past WireGuard's rejection time —
// its keys are older still, so neither end accepts another datagram of it.
func (r *hostRelay) liveLocked(s *relaySession, now time.Time) *relaySession {
	if s == nil {
		return nil
	}
	if s.expired(now) {
		r.forgetLocked(s)
		return nil
	}
	return s
}

// expired reports whether the session's lifetime has passed at now.
func (s *relaySession) expired(now time.Time) bool {
	if s.answered {
		return now.Sub(s.seen) > device.RejectAfterTime
	}
	return now.Sub(s.began) >= pendingLifetime
}

// forgetLocked drops the session from the indices that still name it, and
// a pending one from the pending counts.
func (r *hostRelay) forgetLocked(s *relaySession) {
	key := sessionKey{node: s.node, index: s.hostIndex}
	if r.byHost[key] == s {
		delete(r.byHost, key)
		if !s.answered {
			r.unpendLocked(s)
		}
	}
	if s.answered && r.byNode[s.nodeIndex] == s {
		delete(r.byNode, s.nodeIndex)
	}
}

// unpendLocked takes a pending session out of the pending counts.
func (r *hostRelay) unpendLocked(s *relaySession) {
	r.pending--
	src := sourceOf(s.host.Addr())
	r.perSource[src]--
	if r.perSource[src] == 0 {
		delete(r.perSource, src)
	}
}

// sourceOf names the source a pending session counts against: an IPv4
// address alone, and an IPv6 address by its /64, the block one subscriber
// commonly holds whole.
func sourceOf(addr netip.Addr) netip.Prefix {
	addr = addr.Unmap()
	if addr.Is4() {
		return netip.PrefixFrom(addr, 32)
	}
	return netip.PrefixFrom(addr, 64).Masked()
}

// expireLocked pops the queue's front up to its first live pending session,
// forgetting the expired pending sessions and dropping the sessions
// answered or forgotten since they began; the queue holds the pending
// sessions in the order they began, so none behind a live one has expired.
// The sweep follows when due.
func (r *hostRelay) expireLocked(now time.Time) {
	for len(r.queue) > 0 {
		s := r.queue[0]
		if !s.answered && r.byHost[sessionKey{node: s.node, index: s.hostIndex}] == s {
			if !s.expired(now) {
				break
			}
			r.forgetLocked(s)
		}
		// The popped slot leaves the backing array holding no session.
		r.queue[0] = nil
		r.queue = r.queue[1:]
	}
	r.sweepLocked(now)
}

// sweepLocked forgets the expired sessions, at most once per rejection time.
// The queue expires the pending sessions as initiations arrive; the sweep
// reaches the answered ones no datagram looks up, and as initiations alone
// add sessions and each runs it, no answered session silent for two
// rejection times outlives the next one added.
func (r *hostRelay) sweepLocked(now time.Time) {
	if now.Sub(r.swept) < device.RejectAfterTime {
		return
	}
	r.swept = now
	for _, s := range r.byHost {
		r.liveLocked(s, now)
	}
}

// cookieReply creates the cookie reply the node's checker answers the
// initiation with, bound to the source, in WireGuard's wire layout: the
// type and the receiver index, little-endian, the nonce, and the sealed
// cookie.
func cookieReply(mac *device.CookieChecker, pkt, src []byte) []byte {
	// CreateReply fails only where crypto/rand's Read does, which never
	// returns an error: the runtime crashes the program instead.
	reply, _ := mac.CreateReply(pkt, senderIndex(pkt), src)
	b := make([]byte, 0, device.MessageCookieReplySize)
	b = binary.LittleEndian.AppendUint32(b, reply.Type)
	b = binary.LittleEndian.AppendUint32(b, reply.Receiver)
	b = append(b, reply.Nonce[:]...)
	return append(b, reply.Cookie[:]...)
}

// sourceBytes encodes a host's source endpoint for the cookies bound to it:
// the address's bytes, then the port, big-endian.
func sourceBytes(from netip.AddrPort) []byte {
	return binary.BigEndian.AppendUint16(from.Addr().AsSlice(), from.Port())
}

// forward carries a host's datagram, unchanged, to the node's relay
// service, on the path the mesh socket holds for the node.
func (r *hostRelay) forward(node addr.IA, pkt []byte) {
	err := r.paths.sendOn(r.conn, scion.Addr{IA: node, Service: SvcHostRelay}, [][]byte{pkt},
		&r.cnt.relayedDatagrams, &r.cnt.relayDrops)
	if err != nil {
		slog.Debug("WireGuard relay forward", "node", node, "err", err)
	}
}

// send carries the host device's datagrams to the relay service of the node
// that relays the host: on the path the mesh socket holds for the node, the
// reversed path of the node's latest arrival seeding the cache when it holds
// none.
func (r *hostRelay) send(via scion.Addr, bufs [][]byte) error {
	return r.paths.sendOn(r.conn, scion.Addr{IA: via.IA, Service: SvcHostRelay, Path: via.Path}, bufs,
		&r.cnt.sentDatagrams, &r.cnt.sendFailures)
}

// Close closes the relay socket, failing a read loop still blocked on it.
func (r *hostRelay) Close() {
	_ = r.conn.Close()
}

// messageType returns the WireGuard message type a datagram carries by the
// format the protocol fixes — the type byte, three reserved zero bytes, and
// the type's own size, a transport message's at least an empty one's — and
// zero for a datagram of no message format.
func messageType(pkt []byte) byte {
	if len(pkt) < 4 || pkt[1] != 0 || pkt[2] != 0 || pkt[3] != 0 {
		return 0
	}
	switch typ, size := pkt[0], len(pkt); {
	case typ == device.MessageInitiationType && size == device.MessageInitiationSize,
		typ == device.MessageResponseType && size == device.MessageResponseSize,
		typ == device.MessageCookieReplyType && size == device.MessageCookieReplySize,
		typ == device.MessageTransportType && size >= device.MessageTransportSize:
		return typ
	}
	return 0
}

// senderIndex returns the sender index an initiation or a response names.
func senderIndex(pkt []byte) uint32 {
	return binary.LittleEndian.Uint32(pkt[4:8])
}

// receiverIndex returns the receiver index a response, a cookie reply, or a
// transport message names: a response's follows its sender index, the
// others' follows the type.
func receiverIndex(pkt []byte, typ byte) uint32 {
	if typ == device.MessageResponseType {
		return binary.LittleEndian.Uint32(pkt[8:12])
	}
	return binary.LittleEndian.Uint32(pkt[4:8])
}
