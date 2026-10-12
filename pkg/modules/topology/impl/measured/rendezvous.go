package measured

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/modules/links"
)

// RendezvousPort is the UDP port every node's rendezvous acceptor listens on
// for first contact, beside the endpoint on the control address's host: one
// step further down the underlay block's ladder, the port that binds
// joiners only, and only before identity.
const RendezvousPort = 30043

const rendezvousVersion = 1

// Rendezvous cadence and limits. The exchange is underlay-level and carries no
// cryptography, because the joiner has nothing to show yet: the nonce echo is
// the return-routability check, and the rate cap and the link-count cap bound
// admission.
const (
	// RendezvousAttempts bounds one dial's request runs and
	// RendezvousAttemptWait each reply wait.
	RendezvousAttempts    = 3
	RendezvousAttemptWait = 500 * time.Millisecond
	// RendezvousMinInterval is the acceptor's rate cap: the least pause
	// between admissions of one source.
	RendezvousMinInterval = time.Second
)

// RendezvousRequest is the joiner's first contact: a nonce, its ISD-AS, and
// the link address it will receive on. The nonce is random per dial; the
// reply echoing it proves it reached the acceptor and came back — a spoofed
// source never receives its reply.
type RendezvousRequest struct {
	Nonce    [16]byte
	IA       addr.IA
	LinkAddr netip.AddrPort
}

func (r RendezvousRequest) Marshal() []byte {
	a := r.LinkAddr.String()
	buf := make([]byte, 0, 30+len(a))
	buf = binary.BigEndian.AppendUint16(buf, rendezvousVersion)
	buf = append(buf, r.Nonce[:]...)
	buf = binary.BigEndian.AppendUint64(buf, uint64(r.IA))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(a)))
	return append(buf, a...)
}

func ParseRendezvousRequest(b []byte) (RendezvousRequest, error) {
	rd := &binReader{b: b}
	if rd.uint16() != rendezvousVersion {
		return RendezvousRequest{}, fmt.Errorf("unsupported rendezvous version")
	}
	var req RendezvousRequest
	rd.read(&req.Nonce)
	req.IA = addr.IA(rd.uint64())
	n := int(rd.uint16())
	a := rd.bytes(n)
	if rd.err != nil {
		return RendezvousRequest{}, fmt.Errorf("reading rendezvous request: %w", rd.err)
	}
	linkAddr, err := netip.ParseAddrPort(string(a))
	if err != nil {
		return RendezvousRequest{}, fmt.Errorf("parsing rendezvous link address: %w", err)
	}
	req.LinkAddr = linkAddr
	return req, nil
}

// RendezvousReply echoes the nonce and carries the acceptor's link address,
// interface ID, and ISD-AS — its ISD is the network's, what a joiner's
// identity completes with — beside the request's observed source address,
// the one fact address translation cannot hide: the dialer keeps its host
// as its learned external host.
type RendezvousReply struct {
	Nonce    [16]byte
	LinkAddr netip.AddrPort
	IfID     uint16
	IA       addr.IA
	// Observed is the source address the acceptor observed the request
	// arrive from — the address it already replies to. Zero when the reply
	// does not echo one.
	Observed netip.AddrPort
}

func (r RendezvousReply) Marshal() []byte {
	a := r.LinkAddr.String()
	buf := make([]byte, 0, 32+len(a))
	buf = binary.BigEndian.AppendUint16(buf, rendezvousVersion)
	buf = append(buf, r.Nonce[:]...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(a)))
	buf = append(buf, a...)
	buf = binary.BigEndian.AppendUint16(buf, r.IfID)
	buf = binary.BigEndian.AppendUint64(buf, uint64(r.IA))
	if !r.Observed.IsValid() {
		// An absent echo: the appended field is the reply's last, so the
		// form without it is the reply a predecessor writes.
		return buf
	}
	o := r.Observed.String()
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(o)))
	return append(buf, o...)
}

func ParseRendezvousReply(b []byte) (RendezvousReply, error) {
	rd := &binReader{b: b}
	if rd.uint16() != rendezvousVersion {
		return RendezvousReply{}, fmt.Errorf("unsupported rendezvous version")
	}
	var reply RendezvousReply
	rd.read(&reply.Nonce)
	n := int(rd.uint16())
	a := rd.bytes(n)
	reply.IfID = rd.uint16()
	reply.IA = addr.IA(rd.uint64())
	if rd.err != nil {
		return RendezvousReply{}, fmt.Errorf("reading rendezvous reply: %w", rd.err)
	}
	linkAddr, err := netip.ParseAddrPort(string(a))
	if err != nil {
		return RendezvousReply{}, fmt.Errorf("parsing rendezvous link address: %w", err)
	}
	reply.LinkAddr = linkAddr
	// The observed source is appended after the form every version shares:
	// a reply that carries no such field is one that does not echo it.
	if len(rd.b) > 0 {
		n := int(rd.uint16())
		o := rd.bytes(n)
		if rd.err != nil {
			return RendezvousReply{}, fmt.Errorf("reading rendezvous reply: %w", rd.err)
		}
		observed, err := netip.ParseAddrPort(string(o))
		if err != nil {
			return RendezvousReply{}, fmt.Errorf("parsing rendezvous observed source: %w", err)
		}
		reply.Observed = observed
	}
	return reply, nil
}

// binReader is the rendezvous wire's cursor: every read consumes from the
// front and records truncation, so one error check serves a whole parse.
type binReader struct {
	b   []byte
	err error
}

func (r *binReader) uint16() uint16 {
	if len(r.b) < 2 {
		r.err = errors.New("truncated")
		return 0
	}
	v := binary.BigEndian.Uint16(r.b)
	r.b = r.b[2:]
	return v
}

func (r *binReader) uint64() uint64 {
	if len(r.b) < 8 {
		r.err = errors.New("truncated")
		return 0
	}
	v := binary.BigEndian.Uint64(r.b)
	r.b = r.b[8:]
	return v
}

func (r *binReader) bytes(n int) []byte {
	if n < 0 || len(r.b) < n {
		r.err = errors.New("truncated")
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

// read consumes len(dst) bytes into dst.
func (r *binReader) read(dst *[16]byte) {
	b := r.bytes(len(dst))
	if r.err == nil {
		copy(dst[:], b)
	}
}

// Rendezvous is the acceptor every node runs on its advertised rendezvous
// address: one unconnected UDP socket answering first-contact requests. The
// entries it creates start as candidates — a peer that produces no verified
// beacon or enrollment within the candidate window retires. Identity adoption
// is the exchange's own act: the acceptor names its entry from the request's
// ISD-AS and the joiner names its own from the reply, so every establishment
// names both sides before the link serves.
type Rendezvous struct {
	conn *net.UDPConn
	cfg  RendezvousConfig

	// mtx serializes the handlers' lookup-and-mutate runs over the store.
	mtx sync.Mutex

	// byAddr rate-caps unnamed claims by the address claimed, byIA named
	// ones by the ISD-AS: a node's dials share one key however many
	// ephemeral sockets they use.
	byAddr sourceLimiter[netip.AddrPort]
	byIA   sourceLimiter[addr.IA]
}

// RendezvousConfig configures a Rendezvous acceptor.
type RendezvousConfig struct {
	// Bind is the advertised rendezvous address, "host:port".
	Bind string
	// IA is the local ISD-AS, carried by the replies for a joiner's
	// identity to complete with.
	IA addr.IA
	// MinInterval is the least pause between admissions of one source; zero
	// uses the default.
	MinInterval time.Duration
	// Store is the neighbor table.
	Store links.DB
	// MaxLinks caps the live link count.
	MaxLinks int
	// LinkHost is the host link addresses are allocated on.
	LinkHost netip.Addr
}

// NewRendezvous binds the rendezvous address.
func NewRendezvous(cfg RendezvousConfig) (*Rendezvous, error) {
	bind, err := net.ResolveUDPAddr("udp", cfg.Bind)
	if err != nil {
		return nil, fmt.Errorf("parsing rendezvous address: %w", err)
	}
	conn, err := net.ListenUDP("udp", bind)
	if err != nil {
		return nil, fmt.Errorf("binding rendezvous address: %w", err)
	}
	interval := cfg.MinInterval
	if interval == 0 {
		interval = RendezvousMinInterval
	}
	return &Rendezvous{
		conn:   conn,
		cfg:    cfg,
		byAddr: newSourceLimiter[netip.AddrPort](interval),
		byIA:   newSourceLimiter[addr.IA](interval),
	}, nil
}

// Close releases the socket; Run returns.
func (r *Rendezvous) Close() error {
	return r.conn.Close()
}

// Run answers requests until the context is canceled or the socket fails.
// The context's end closes the socket, failing the read; Run returns with
// the socket closed and released either way, waiting on a close already
// under way, for a second Close returns before the first's release
// finishes.
func (r *Rendezvous) Run(ctx context.Context) {
	release := sync.OnceValue(r.conn.Close)
	stop := context.AfterFunc(ctx, func() { _ = release() })
	defer func() {
		stop()
		_ = release()
	}()
	buf := make([]byte, 128)
	for {
		n, src, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				slog.Error("Reading rendezvous request", "err", err)
			}
			return
		}
		reply, err := r.handle(ctx, buf[:n], src)
		if err != nil {
			slog.Debug("Rendezvous request refused", "src", src, "err", err)
			continue
		}
		if _, err := r.conn.WriteToUDP(reply, src); err != nil {
			slog.Debug("Writing rendezvous reply", "src", src, "err", err)
		}
	}
}

// handle applies the admission policy and records the entry, returning the
// reply to send to the source. The echo is the return-routability check: the
// reply only ever reaches the socket the request came from. The exchange
// carries no cryptography — the claim names no identity the acceptor can
// check — so a claim only ever mints, names, or retargets a candidate: an
// established entry answers with its recorded side untouched, and a claim
// at an address another serving link holds is turned away, the store
// refusing the second. The store calls run under ctx, the loop's.
func (r *Rendezvous) handle(ctx context.Context, raw []byte, src *net.UDPAddr) ([]byte, error) {
	req, err := ParseRendezvousRequest(raw)
	if err != nil {
		return nil, err
	}
	if req.IA.IsZero() {
		if !r.byAddr.admit(req.LinkAddr) {
			return nil, fmt.Errorf("claim %s exceeds the admission rate", req.LinkAddr)
		}
		unnamed, err := r.unnamedLinks(ctx)
		if err != nil {
			return nil, err
		}
		if unnamed >= r.cfg.MaxLinks {
			return nil, fmt.Errorf("unnamed candidate cap reached (%d)", r.cfg.MaxLinks)
		}
	} else if !r.byIA.admit(req.IA) {
		return nil, fmt.Errorf("ISD-AS %s exceeds the admission rate", req.IA)
	}
	// The lookup and the write run under the handler's lock: concurrent
	// requests for one peer re-answer the first's entry instead of racing
	// a second into the table. The in-band link service and the selection's
	// establishment record entries too; the store refuses a neighbor's
	// second live entry and a second live entry on one local address, and a
	// claim that loses either race looks again: it answers with the winner's
	// entry, or mints its own on a fresh address.
	r.mtx.Lock()
	defer r.mtx.Unlock()
	entry, err := r.admit(ctx, req)
	if errors.Is(err, links.ErrDuplicateNeighbor) || errors.Is(err, links.ErrDuplicateLocal) {
		entry, err = r.admit(ctx, req)
	}
	if err != nil {
		return nil, err
	}
	reply := RendezvousReply{
		Nonce:    req.Nonce,
		LinkAddr: entry.Local,
		IfID:     entry.IfID,
		IA:       r.cfg.IA,
		Observed: src.AddrPort(),
	}
	return reply.Marshal(), nil
}

// admit returns the claim's entry: the one the table holds for it, an
// unnamed one a named claim adopts, or a candidate it mints under the cap.
func (r *Rendezvous) admit(ctx context.Context, req RendezvousRequest) (*links.Link, error) {
	var entry *links.Link
	var err error
	if req.IA.IsZero() {
		// An unnamed claim — a probe, or a bootstrap joiner whose identity
		// is not final — deduplicates by the address it claims.
		entry, err = r.cfg.Store.ByRemote(ctx, req.LinkAddr)
		if err != nil {
			return nil, err
		}
	} else {
		entry, err = r.cfg.Store.ByNeighbor(ctx, req.IA)
		if err != nil {
			return nil, err
		}
		if entry == nil {
			// A named claim the table holds only by the address claimed —
			// the bootstrap joiner's second dial, its identity completed —
			// names that entry instead of minting a second one: adoption is
			// the request's own act.
			byRemote, err := r.cfg.Store.ByRemote(ctx, req.LinkAddr)
			if err != nil {
				return nil, err
			}
			if byRemote != nil && byRemote.NeighborIA.IsZero() {
				byRemote.NeighborIA = req.IA
				if err := r.cfg.Store.Update(ctx, byRemote); err != nil {
					return nil, err
				}
				slog.Info("Rendezvous named a candidate", "neighbor", req.IA,
					"remote", byRemote.Remote, "interface", byRemote.IfID)
				entry = byRemote
			}
		}
	}
	if entry == nil {
		entries, err := r.cfg.Store.All(ctx)
		if err != nil {
			return nil, fmt.Errorf("reading the link store: %w", err)
		}
		if live := namedLive(entries); live >= r.cfg.MaxLinks {
			return nil, fmt.Errorf("link cap reached (%d)", live)
		}
		local, err := AllocateLinkAddr(r.cfg.LinkHost, entries)
		if err != nil {
			return nil, err
		}
		entry = &links.Link{
			NeighborIA: req.IA,
			Local:      local,
			Remote:     req.LinkAddr,
			State:      links.StateCandidate,
		}
		if err := r.cfg.Store.Insert(ctx, entry); err != nil {
			return nil, err
		}
		slog.Info("Rendezvous admitted a candidate", "neighbor", req.IA,
			"local", entry.Local, "remote", entry.Remote, "interface", entry.IfID)
	} else if entry.State == links.StateCandidate && entry.Remote != req.LinkAddr {
		// The claim retargets an unnamed or unproven entry only; an
		// established link keeps the address its peer's request recorded.
		entry.Remote = req.LinkAddr
		if err := r.cfg.Store.Update(ctx, entry); err != nil {
			return nil, err
		}
	}
	return entry, nil
}

// unnamedLinks counts the live entries without a neighbor name — probes and
// bootstrap claims, bounded by the same cap until the candidate window
// retires them.
func (r *Rendezvous) unnamedLinks(ctx context.Context) (int, error) {
	return r.countLinks(ctx, func(l *links.Link) bool {
		return l.Live() && l.NeighborIA.IsZero()
	})
}

// countLinks counts the entries a predicate keeps.
func (r *Rendezvous) countLinks(ctx context.Context, keep func(*links.Link) bool) (int, error) {
	entries, err := r.cfg.Store.All(ctx)
	if err != nil {
		return 0, fmt.Errorf("reading the link store: %w", err)
	}
	live := 0
	for _, l := range entries {
		if keep(l) {
			live++
		}
	}
	return live, nil
}

// RendezvousEcho sends one request run to the target and returns the reply
// with the round trip, the measurement the selection loop probes candidates
// with. The requester claims the given address; a probe claims its control
// address, a promotion its link address. The context's end moves the read
// deadline to the past, ending a wait in flight; each attempt reads the
// context after setting its own deadline, so no attempt overrides the move
// unseen.
func RendezvousEcho(
	ctx context.Context,
	bindHost netip.Addr,
	target netip.AddrPort,
	ia addr.IA,
	linkAddr netip.AddrPort,
) (RendezvousReply, time.Duration, error) {

	conn, err := net.ListenUDP("udp",
		net.UDPAddrFromAddrPort(netip.AddrPortFrom(bindHost, 0)))
	if err != nil {
		return RendezvousReply{}, 0, fmt.Errorf("binding the rendezvous client: %w", err)
	}
	defer func() { _ = conn.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Now()) })
	defer stop()
	var req RendezvousRequest
	if _, err := rand.Read(req.Nonce[:]); err != nil {
		return RendezvousReply{}, 0, err
	}
	req.IA = ia
	req.LinkAddr = linkAddr
	raw := req.Marshal()

	// The reply carries two addresses beside the fixed fields; the buffer
	// holds the longest form an IPv6 reply takes.
	buf := make([]byte, 192)
	for range RendezvousAttempts {
		if err := conn.SetReadDeadline(time.Now().Add(RendezvousAttemptWait)); err != nil {
			return RendezvousReply{}, 0, err
		}
		if err := ctx.Err(); err != nil {
			return RendezvousReply{}, 0, err
		}
		sent := time.Now()
		if _, err := conn.WriteToUDP(raw, udpAddr(target)); err != nil {
			return RendezvousReply{}, 0, err
		}
		for {
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				break // the wait elapsed or the context ended: lost, retry
			}
			reply, err := ParseRendezvousReply(buf[:n])
			if err != nil || reply.Nonce != req.Nonce {
				continue
			}
			return reply, time.Since(sent), nil
		}
	}
	return RendezvousReply{}, 0, fmt.Errorf("no rendezvous reply from %s", target)
}

func udpAddr(ap netip.AddrPort) *net.UDPAddr {
	return net.UDPAddrFromAddrPort(ap)
}

// sourceLimiterCap bounds the keys a sourceLimiter tracks.
const sourceLimiterCap = 1024

// sourceLimiter rate-caps admissions per key: one admission per interval,
// refills over time, and stops tracking keys once silent. It tracks at most
// sourceLimiterCap keys and sweeps the silent ones at most once per
// interval, so a flood of fresh keys costs bounded memory and amortized
// time; a fresh key arriving while the table is full is refused.
type sourceLimiter[K comparable] struct {
	interval time.Duration

	mtx   sync.Mutex
	last  map[K]time.Time
	swept time.Time
}

func newSourceLimiter[K comparable](interval time.Duration) sourceLimiter[K] {
	return sourceLimiter[K]{interval: interval, last: make(map[K]time.Time)}
}

// admit reports whether the key may be admitted now.
func (l *sourceLimiter[K]) admit(key K) bool {
	now := time.Now()
	l.mtx.Lock()
	defer l.mtx.Unlock()
	at, held := l.last[key]
	if held && now.Sub(at) < l.interval {
		return false
	}
	if !held && len(l.last) >= sourceLimiterCap && !l.sweep(now) {
		return false
	}
	l.last[key] = now
	return true
}

// sweep forgets the keys silent for an interval — each would be admitted
// again, so forgetting it changes no answer — at most once per interval,
// and reports whether the table has room for a fresh key.
func (l *sourceLimiter[K]) sweep(now time.Time) bool {
	if now.Sub(l.swept) >= l.interval {
		l.swept = now
		for k, at := range l.last {
			if now.Sub(at) >= l.interval {
				delete(l.last, k)
			}
		}
	}
	return len(l.last) < sourceLimiterCap
}
