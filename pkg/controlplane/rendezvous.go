package controlplane

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

	"github.com/fancl20/cion/pkg/links"
)

// RendezvousPort is the UDP port every node's rendezvous acceptor listens on
// for first contact, beside the discovery port on the control address's host.
const RendezvousPort = 30045

const rendezvousVersion = 1

// Rendezvous cadence and limits. The exchange is underlay-level and carries
// no cryptography, because the joiner has nothing to show yet: the nonce echo
// is the return-routability check, and the rate cap and the link-count cap
// bound admission (ADR-0006).
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
// identity completes with.
type RendezvousReply struct {
	Nonce    [16]byte
	LinkAddr netip.AddrPort
	IfID     uint16
	IA       addr.IA
}

func (r RendezvousReply) Marshal() []byte {
	a := r.LinkAddr.String()
	buf := make([]byte, 0, 30+len(a))
	buf = binary.BigEndian.AppendUint16(buf, rendezvousVersion)
	buf = append(buf, r.Nonce[:]...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(a)))
	buf = append(buf, a...)
	buf = binary.BigEndian.AppendUint16(buf, r.IfID)
	return binary.BigEndian.AppendUint64(buf, uint64(r.IA))
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
	return reply, nil
}

// read consumes len(dst) bytes into dst.
func (r *binReader) read(dst *[16]byte) {
	b := r.bytes(len(dst))
	if r.err == nil {
		copy(dst[:], b)
	}
}

// AllocateLinkAddr allocates a link's local underlay address: an ephemeral
// port on the given host, bound once to reserve it and released for the data
// plane generation to rebind. Every generation rebinds the recorded address
// identically, which is what makes a swap invisible to the peer.
func AllocateLinkAddr(host netip.Addr) (netip.AddrPort, error) {
	c, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(host, 0)))
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("allocating a link address: %w", err)
	}
	addr := c.LocalAddr().(*net.UDPAddr).AddrPort()
	if err := c.Close(); err != nil {
		return netip.AddrPort{}, err
	}
	return addr, nil
}

// Rendezvous is the acceptor every node runs on its advertised rendezvous
// address: one unconnected UDP socket answering first-contact requests. The
// entries it creates start as candidates — a peer that produces no verified
// beacon or enrollment within the candidate window retires (ADR-0006).
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
	// AllowAS optionally restricts admission to the listed ISD-ASes; nil
	// means open admission.
	AllowAS map[addr.IA]bool
	// MaxLinks caps the live link count.
	MaxLinks int
	// LinkHost is the host link addresses are allocated on.
	LinkHost netip.Addr
	// Changed is called after each store mutation.
	Changed func()
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
func (r *Rendezvous) Run(ctx context.Context) {
	go func() {
		<-ctx.Done()
		r.conn.Close() //nolint:errcheck
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
		reply, err := r.handle(buf[:n], src)
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
// check — so a claim only ever mints or retargets a candidate: an
// established entry answers with its recorded side untouched.
func (r *Rendezvous) handle(raw []byte, src *net.UDPAddr) ([]byte, error) {
	req, err := ParseRendezvousRequest(raw)
	if err != nil {
		return nil, err
	}
	if r.cfg.AllowAS != nil && !r.cfg.AllowAS[req.IA] {
		return nil, fmt.Errorf("ISD-AS %s is not allowlisted", req.IA)
	}
	if req.IA.IsZero() {
		if !r.byAddr.admit(req.LinkAddr) {
			return nil, fmt.Errorf("claim %s exceeds the admission rate", req.LinkAddr)
		}
		if r.unnamedLinks() >= r.cfg.MaxLinks {
			return nil, fmt.Errorf("unnamed candidate cap reached (%d)", r.cfg.MaxLinks)
		}
	} else if !r.byIA.admit(req.IA) {
		return nil, fmt.Errorf("ISD-AS %s exceeds the admission rate", req.IA)
	}
	// The lookup and the insert run under the handler's lock: concurrent
	// requests for one peer re-answer the first's entry instead of racing
	// a second into the table.
	r.mtx.Lock()
	defer r.mtx.Unlock()
	var entry *links.Link
	if !req.IA.IsZero() {
		entry, err = r.cfg.Store.ByNeighbor(context.Background(), req.IA)
	} else {
		// An unnamed claim — a probe, or a bootstrap joiner whose identity
		// is not final — deduplicates by the address it claims.
		entry, err = r.cfg.Store.ByRemote(context.Background(), req.LinkAddr)
	}
	if err != nil {
		return nil, err
	}
	if entry == nil {
		if live := r.namedLinks(); live >= r.cfg.MaxLinks {
			return nil, fmt.Errorf("link cap reached (%d)", live)
		}
		local, err := AllocateLinkAddr(r.cfg.LinkHost)
		if err != nil {
			return nil, err
		}
		entry = &links.Link{
			NeighborIA: req.IA,
			Local:      local,
			Remote:     req.LinkAddr,
			State:      links.StateCandidate,
		}
		if err := r.cfg.Store.Insert(context.Background(), entry); err != nil {
			return nil, err
		}
		r.changed()
		slog.Info("Rendezvous admitted a candidate", "neighbor", req.IA,
			"local", entry.Local, "remote", entry.Remote, "interface", entry.IfID)
	} else if entry.State == links.StateCandidate && entry.Remote != req.LinkAddr {
		// The claim retargets an unnamed or unproven entry only; an
		// established link keeps the address its peer's request or greeting
		// recorded.
		entry.Remote = req.LinkAddr
		if err := r.cfg.Store.Update(context.Background(), entry); err != nil {
			return nil, err
		}
		r.changed()
	}
	reply := RendezvousReply{
		Nonce:    req.Nonce,
		LinkAddr: entry.Local,
		IfID:     entry.IfID,
		IA:       r.cfg.IA,
	}
	return reply.Marshal(), nil
}

// unnamedLinks counts the live entries without a neighbor name — probes and
// bootstrap claims, bounded by the same cap until the candidate window
// retires them.
func (r *Rendezvous) unnamedLinks() int {
	return r.countLinks(func(l *links.Link) bool {
		return l.Live() && l.NeighborIA.IsZero()
	})
}

// namedLinks counts the live entries that name a neighbor — the ones the
// link cap bounds, since only they carry beacons. Unnamed candidates —
// probes and bootstrap claims — retire with the candidate window.
func (r *Rendezvous) namedLinks() int {
	return r.countLinks(func(l *links.Link) bool {
		return l.Live() && !l.NeighborIA.IsZero()
	})
}

// countLinks counts the entries a predicate keeps.
func (r *Rendezvous) countLinks(keep func(*links.Link) bool) int {
	entries, err := r.cfg.Store.All(context.Background())
	if err != nil {
		slog.Error("Reading the link store", "err", err)
		return r.cfg.MaxLinks // refuse on a store that cannot be read
	}
	live := 0
	for _, l := range entries {
		if keep(l) {
			live++
		}
	}
	return live
}

func (r *Rendezvous) changed() {
	if r.cfg.Changed != nil {
		r.cfg.Changed()
	}
}

// RendezvousEcho sends one request run to the target and returns the reply
// with the round trip, the measurement the selection loop probes candidates
// with. The requester claims the given address; a probe claims its control
// address, a promotion its link address.
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
	defer conn.Close() //nolint:errcheck
	var req RendezvousRequest
	if _, err := rand.Read(req.Nonce[:]); err != nil {
		return RendezvousReply{}, 0, err
	}
	req.IA = ia
	req.LinkAddr = linkAddr
	raw := req.Marshal()

	buf := make([]byte, 128)
	for attempt := 0; attempt < RendezvousAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return RendezvousReply{}, 0, err
		}
		sent := time.Now()
		if _, err := conn.WriteToUDP(raw, udpAddr(target)); err != nil {
			return RendezvousReply{}, 0, err
		}
		if err := conn.SetReadDeadline(sent.Add(RendezvousAttemptWait)); err != nil {
			return RendezvousReply{}, 0, err
		}
		for {
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				break // the wait elapsed: lost, retry
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

// sourceLimiter rate-caps admissions per key: one admission per interval,
// refills over time, and stops tracking keys once silent.
type sourceLimiter[K comparable] struct {
	interval time.Duration

	mtx  sync.Mutex
	last map[K]time.Time
}

func newSourceLimiter[K comparable](interval time.Duration) sourceLimiter[K] {
	return sourceLimiter[K]{interval: interval, last: make(map[K]time.Time)}
}

// admit reports whether the key may be admitted now.
func (l *sourceLimiter[K]) admit(key K) bool {
	now := time.Now()
	l.mtx.Lock()
	defer l.mtx.Unlock()
	if len(l.last) > 1024 {
		for k, at := range l.last {
			if now.Sub(at) > 10*l.interval {
				delete(l.last, k)
			}
		}
	}
	if at, ok := l.last[key]; ok && now.Sub(at) < l.interval {
		return false
	}
	l.last[key] = now
	return true
}
