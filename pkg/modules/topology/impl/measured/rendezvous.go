package measured

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"google.golang.org/protobuf/proto"

	"github.com/fancl20/cion/pkg/libs/ratelimit"
	"github.com/fancl20/cion/pkg/libs/scionrpc"
	"github.com/fancl20/cion/pkg/libs/underlay"
	"github.com/fancl20/cion/pkg/modules/links"
	nodev1 "github.com/fancl20/cion/proto/node/v1"
)

// RendezvousPort is the UDP port every node's rendezvous acceptor listens on
// for first contact, beside the endpoint on the control address's host: one
// step further down the underlay block's ladder, the port that binds
// joiners only, and only before identity.
const RendezvousPort = 30043

// ParseRendezvousAddr parses a rendezvous address as the neighbor argument
// spells it: "host:port" as spelled, a bare host naming the fixed rendezvous
// port — the one address a joiner dials before it holds anything else.
func ParseRendezvousAddr(s string) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap, nil
	}
	host, err := netip.ParseAddr(s)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("parsing rendezvous address %q: %w", s, err)
	}
	return netip.AddrPortFrom(host, RendezvousPort), nil
}

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
// the link address it will receive on. The nonce is random per attempt; the
// reply echoing it proves it reached the acceptor and came back — a spoofed
// source never receives its reply. A binding request claims no link
// address and names no ISD-AS: the acceptor answers it with the
// requester's reflexive address alone and records nothing.
type RendezvousRequest struct {
	Nonce    [16]byte
	IA       addr.IA
	LinkAddr netip.AddrPort
	Binding  bool
}

// bindingPadding is the padding a binding request carries: past the longest
// binding reply — the nonce, the ISD-AS, and an IPv6 reflexive address at its
// longest, 78 bytes — so the reply a request buys is never larger than
// itself.
const bindingPadding = 64

// Marshal writes the request's datagram.
func (r RendezvousRequest) Marshal() ([]byte, error) {
	pb := &nodev1.RendezvousRequest{Nonce: r.Nonce[:], IsdAs: uint64(r.IA)}
	if r.Binding {
		pb.Binding = true
		pb.Padding = make([]byte, bindingPadding)
	} else {
		pb.LinkAddr = r.LinkAddr.String()
	}
	return proto.Marshal(pb)
}

// ParseRendezvousRequest reads a request's datagram.
func ParseRendezvousRequest(b []byte) (RendezvousRequest, error) {
	var pb nodev1.RendezvousRequest
	if err := proto.Unmarshal(b, &pb); err != nil {
		return RendezvousRequest{}, fmt.Errorf("reading rendezvous request: %w", err)
	}
	req := RendezvousRequest{IA: addr.IA(pb.IsdAs), Binding: pb.Binding}
	if err := readNonce(&req.Nonce, pb.Nonce); err != nil {
		return RendezvousRequest{}, err
	}
	if req.Binding {
		if pb.LinkAddr != "" {
			return RendezvousRequest{}, errors.New("a binding request claims a link address")
		}
		return req, nil
	}
	linkAddr, err := netip.ParseAddrPort(pb.LinkAddr)
	if err != nil {
		return RendezvousRequest{}, fmt.Errorf("parsing rendezvous link address: %w", err)
	}
	req.LinkAddr = linkAddr
	return req, nil
}

// RendezvousReply echoes the nonce and carries the acceptor's link address,
// interface ID, and ISD-AS — its ISD is the network's, what a joiner's
// identity completes with. A binding reply carries the requester's
// reflexive address, the one fact a NAT cannot hide, in place of the link
// address and the interface.
type RendezvousReply struct {
	Nonce    [16]byte
	LinkAddr netip.AddrPort
	IfID     uint16
	IA       addr.IA
	// Reflexive is a binding reply's requester's reflexive address: the
	// source the acceptor observed the request arrive from, the address it
	// already replies to. Zero in a link reply.
	Reflexive netip.AddrPort
}

// Marshal writes the reply's datagram.
func (r RendezvousReply) Marshal() ([]byte, error) {
	pb := &nodev1.RendezvousReply{
		Nonce: r.Nonce[:],
		IfId:  uint32(r.IfID),
		IsdAs: uint64(r.IA),
	}
	if r.LinkAddr.IsValid() {
		pb.LinkAddr = r.LinkAddr.String()
	}
	if r.Reflexive.IsValid() {
		pb.ReflexiveAddr = r.Reflexive.String()
	}
	return proto.Marshal(pb)
}

// ParseRendezvousReply reads a reply's datagram.
func ParseRendezvousReply(b []byte) (RendezvousReply, error) {
	var pb nodev1.RendezvousReply
	if err := proto.Unmarshal(b, &pb); err != nil {
		return RendezvousReply{}, fmt.Errorf("reading rendezvous reply: %w", err)
	}
	if pb.IfId > 0xffff {
		return RendezvousReply{}, fmt.Errorf("rendezvous interface ID %d out of range", pb.IfId)
	}
	reply := RendezvousReply{IfID: uint16(pb.IfId), IA: addr.IA(pb.IsdAs)}
	if err := readNonce(&reply.Nonce, pb.Nonce); err != nil {
		return RendezvousReply{}, err
	}
	if pb.LinkAddr != "" {
		linkAddr, err := netip.ParseAddrPort(pb.LinkAddr)
		if err != nil {
			return RendezvousReply{}, fmt.Errorf("parsing rendezvous link address: %w", err)
		}
		reply.LinkAddr = linkAddr
	}
	if pb.ReflexiveAddr != "" {
		reflexive, err := netip.ParseAddrPort(pb.ReflexiveAddr)
		if err != nil {
			return RendezvousReply{}, fmt.Errorf("parsing rendezvous reflexive address: %w", err)
		}
		reply.Reflexive = reflexive
	}
	return reply, nil
}

// readNonce copies a message's nonce, refusing one of another length.
func readNonce(dst *[16]byte, nonce []byte) error {
	if len(nonce) != len(dst) {
		return fmt.Errorf("rendezvous nonce of %d bytes, want %d", len(nonce), len(dst))
	}
	copy(dst[:], nonce)
	return nil
}

// Rendezvous is the acceptor every node runs on its advertised rendezvous
// address: one unconnected UDP socket answering first-contact requests and
// binding requests. The entries it creates start as candidates — a peer that
// produces no verified beacon or enrollment within the candidate window
// retires. Identity adoption is the exchange's own act: the acceptor names
// its entry from the request's ISD-AS and the joiner names its own from the
// reply, so every establishment names both sides before the link serves.
type Rendezvous struct {
	conn underlay.UDPConn
	cfg  RendezvousConfig

	// mtx serializes the handlers' lookup-and-mutate runs over the store.
	mtx sync.Mutex

	// byAddr rate-caps unnamed claims by the source observed, byIA named
	// ones by the ISD-AS: a node's named dials share one key however many
	// sockets they leave from. bySource rate-caps binding requests by the
	// source observed: each socket its own key.
	byAddr   *ratelimit.Keyed[netip.AddrPort]
	byIA     *ratelimit.Keyed[addr.IA]
	bySource *ratelimit.Keyed[netip.AddrPort]
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
	// Sockets is the socket source the acceptor's bind and the dials
	// construct through; the zero value is the kernel's.
	Sockets underlay.Sockets
}

// NewRendezvous binds the rendezvous address.
func NewRendezvous(cfg RendezvousConfig) (*Rendezvous, error) {
	bind, err := net.ResolveUDPAddr("udp", cfg.Bind)
	if err != nil {
		return nil, fmt.Errorf("parsing rendezvous address: %w", err)
	}
	conn, err := cfg.Sockets.NewUDP(bind, netip.AddrPort{})
	if err != nil {
		return nil, fmt.Errorf("binding rendezvous address: %w", err)
	}
	interval := cfg.MinInterval
	if interval == 0 {
		interval = RendezvousMinInterval
	}
	return &Rendezvous{
		conn:     conn,
		cfg:      cfg,
		byAddr:   ratelimit.NewKeyed[netip.AddrPort](interval),
		byIA:     ratelimit.NewKeyed[addr.IA](interval),
		bySource: ratelimit.NewKeyed[netip.AddrPort](interval),
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

// recordedLinkAddr applies the claim rule the dialer's records keep: the
// claim's host when it names one, the observed host when it does not — the
// address the exchange's own round trip proved answers — the claim's port
// always, for it names the socket that will receive. A wildcard-bound peer
// claims the wildcard; what it cannot name, the exchange observes. The
// acceptor's own record of a claim takes the observation whole, host and
// port both — see handle.
func recordedLinkAddr(claim, observed netip.AddrPort) netip.AddrPort {
	if !claim.Addr().IsUnspecified() {
		return claim
	}
	return netip.AddrPortFrom(observed.Addr().Unmap(), claim.Port())
}

// observedAddr returns a datagram's source as the exchange records it: the
// kernel's v4-mapped form of a wildcard socket's arrival normalized to the
// plain address.
func observedAddr(src *net.UDPAddr) netip.AddrPort {
	ap := src.AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// handle applies the admission policy and records the entry, returning the
// reply to send to the source. The echo is the return-routability check: the
// reply only ever reaches the socket the request came from. The exchange
// carries no cryptography — the claim names no identity the acceptor can
// check — so a claim only ever mints, names, or retargets a candidate: an
// established entry answers with its recorded side untouched, and a claim
// at an address another serving link holds is turned away, the store
// refusing the second. A claim — a joiner's dial from the socket that will
// serve, unnamed before its identity completes — records the request's
// observed source whole, host and port both: the observation names the
// dialing socket's mapping, whatever the middle made of it. A binding
// request claims nothing and records nothing. The store calls run under
// ctx, the loop's.
func (r *Rendezvous) handle(ctx context.Context, raw []byte, src *net.UDPAddr) ([]byte, error) {
	req, err := ParseRendezvousRequest(raw)
	if err != nil {
		return nil, err
	}
	if req.Binding {
		return r.answerBinding(req, len(raw), src)
	}
	req.LinkAddr = observedAddr(src)
	if req.IA.IsZero() {
		if !r.byAddr.Admit(req.LinkAddr) {
			return nil, fmt.Errorf("claim %s exceeds the admission rate", req.LinkAddr)
		}
		unnamed, err := r.unnamedLinks(ctx)
		if err != nil {
			return nil, err
		}
		if unnamed >= r.cfg.MaxLinks {
			return nil, fmt.Errorf("unnamed candidate cap reached (%d)", r.cfg.MaxLinks)
		}
	} else if !r.byIA.Admit(req.IA) {
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
	}
	return reply.Marshal()
}

// answerBinding answers a binding request with the requester's reflexive
// address, recording nothing. A request naming an ISD-AS is refused, and so
// is one shorter than its reply: the acceptor amplifies nothing.
func (r *Rendezvous) answerBinding(req RendezvousRequest, size int, src *net.UDPAddr) ([]byte, error) {
	if !req.IA.IsZero() {
		return nil, fmt.Errorf("a binding request names the ISD-AS %s", req.IA)
	}
	observed := observedAddr(src)
	reply, err := RendezvousReply{Nonce: req.Nonce, IA: r.cfg.IA, Reflexive: observed}.Marshal()
	if err != nil {
		return nil, err
	}
	if len(reply) > size {
		return nil, fmt.Errorf("a binding request of %d bytes is shorter than its reply's %d",
			size, len(reply))
	}
	if !r.bySource.Admit(observed) {
		return nil, fmt.Errorf("source %s exceeds the admission rate", observed)
	}
	return reply, nil
}

// admit returns the claim's entry: the one the table holds for it, an
// unnamed one a named claim adopts, or a candidate it mints under the cap.
func (r *Rendezvous) admit(ctx context.Context, req RendezvousRequest) (*links.Link, error) {
	var entry *links.Link
	var err error
	if req.IA.IsZero() {
		// An unnamed claim — a joiner whose identity is not final —
		// deduplicates by its observed source.
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
			// A named claim the table holds only by its observed source —
			// the bootstrap joiner's second dial, its identity completed,
			// from the socket its first left from — names that entry
			// instead of minting a second one: adoption is the request's
			// own act.
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
		local, err := AllocateLinkAddr(r.cfg.Sockets, r.cfg.LinkHost, entries)
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

// unnamedLinks counts the live entries without a neighbor name — the
// joiners' first claims, bounded by the same cap until their named dials
// name them or the candidate window retires them.
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

// rendezvousSilenceHint names the confusion an unanswered dial to the control
// endpoint's port carries — the address an operator copies from the control
// argument: the endpoint serves SCION and drops rendezvous packets, and the
// acceptor answers a port further down the underlay block's ladder. Empty
// for every other target, the probes' derived ones among them.
func rendezvousSilenceHint(target netip.AddrPort) string {
	if target.Port() != scionrpc.EndpointPort {
		return ""
	}
	return fmt.Sprintf("; that port is the SCION control endpoint's (%d), which drops "+
		"rendezvous packets — the acceptor binds %d", scionrpc.EndpointPort, RendezvousPort)
}

// RendezvousEcho sends one request run to the target from a link's own socket
// and returns the reply with the round trip and the address the reply
// arrived from — the acceptor's routable host on the path the dial proved,
// the observation an unspecified answer records under the answer's port. The
// dial binds the given address, the entry's own link address, so the mapping
// the acceptor observes is the socket that will serve — the socket held for
// the round trip alone and released before the store write lands and the
// generation binds, the same probe-and-release the band allocation performs.
// An answered exchange sends one empty datagram from the held socket to the
// acceptor's link address — the answer's, under the claim rule — before the
// release, so a NAT maps the link's own flow before the acceptor's link can
// claim it. The requester claims the given link address. The context's end
// moves the read deadline to the past, ending a wait in flight; each attempt
// reads the context after setting its own deadline, so no attempt overrides
// the move unseen.
func RendezvousEcho(
	ctx context.Context,
	sockets underlay.Sockets,
	bind netip.AddrPort,
	target netip.AddrPort,
	ia addr.IA,
	linkAddr netip.AddrPort,
) (RendezvousReply, netip.AddrPort, time.Duration, error) {

	conn, err := sockets.NewUDP(net.UDPAddrFromAddrPort(bind), netip.AddrPort{})
	if err != nil {
		return RendezvousReply{}, netip.AddrPort{}, 0,
			fmt.Errorf("binding the rendezvous client: %w", err)
	}
	defer func() { _ = conn.Close() }()
	reply, observed, rtt, err := echoOn(ctx, conn, target, RendezvousRequest{IA: ia, LinkAddr: linkAddr})
	if err != nil {
		return RendezvousReply{}, netip.AddrPort{}, 0, err
	}
	if !reply.LinkAddr.IsValid() {
		return RendezvousReply{}, netip.AddrPort{}, 0,
			fmt.Errorf("the acceptor %s names no link address", target)
	}
	// The link's flow speaks before the acceptor's link can: a NAT keeps the
	// dial's port for the flow toward the acceptor's link socket only while
	// no packet of that socket has reached the mapping first, and the
	// acceptor's link sends to the recorded mapping from the moment its
	// entry lands. The acceptor's data plane drops the empty datagram as
	// malformed; a lost one costs only the race it would have won.
	_, _ = conn.WriteToUDP(nil, udpAddr(recordedLinkAddr(reply.LinkAddr, observed)))
	return reply, observed, rtt, nil
}

// bindingEcho sends one binding request run from an ephemeral socket on the
// host to the target and returns the reply — the acceptor's ISD-AS and the
// requester's reflexive address — with the round trip. The acceptor records
// nothing.
func bindingEcho(
	ctx context.Context, sockets underlay.Sockets, host netip.Addr, target netip.AddrPort,
) (RendezvousReply, time.Duration, error) {
	conn, err := sockets.NewUDP(net.UDPAddrFromAddrPort(netip.AddrPortFrom(host, 0)), netip.AddrPort{})
	if err != nil {
		return RendezvousReply{}, 0, fmt.Errorf("binding the rendezvous client: %w", err)
	}
	defer func() { _ = conn.Close() }()
	reply, _, rtt, err := echoOn(ctx, conn, target, RendezvousRequest{Binding: true})
	return reply, rtt, err
}

// echoOn sends one request run from a socket the caller holds — the request
// given, each attempt under a fresh nonce — and returns the first reply to
// any attempt with the round trip from that attempt's send, and the address
// the reply arrived from: a late reply to one attempt answers the run, timed
// from its own request rather than the next one. The context's end moves the
// read deadline to the past, ending a wait in flight; each attempt reads the
// context after setting its own deadline, so no attempt overrides the move
// unseen.
func echoOn(
	ctx context.Context,
	conn underlay.UDPConn,
	target netip.AddrPort,
	req RendezvousRequest,
) (RendezvousReply, netip.AddrPort, time.Duration, error) {

	stop := context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Now()) })
	defer stop()

	// The reply carries two addresses beside the fixed fields; the buffer
	// holds the longest form an IPv6 reply takes.
	buf := make([]byte, 192)
	sent := make(map[[16]byte]time.Time, RendezvousAttempts)
	for range RendezvousAttempts {
		if _, err := rand.Read(req.Nonce[:]); err != nil {
			return RendezvousReply{}, netip.AddrPort{}, 0, err
		}
		raw, err := req.Marshal()
		if err != nil {
			return RendezvousReply{}, netip.AddrPort{}, 0, err
		}
		if err := conn.SetReadDeadline(time.Now().Add(RendezvousAttemptWait)); err != nil {
			return RendezvousReply{}, netip.AddrPort{}, 0, err
		}
		if err := ctx.Err(); err != nil {
			return RendezvousReply{}, netip.AddrPort{}, 0, err
		}
		sent[req.Nonce] = time.Now()
		if _, err := conn.WriteToUDP(raw, udpAddr(target)); err != nil {
			return RendezvousReply{}, netip.AddrPort{}, 0, err
		}
		for {
			n, src, err := conn.ReadFromUDP(buf)
			if err != nil {
				break // the wait elapsed or the context ended: lost, retry
			}
			reply, err := ParseRendezvousReply(buf[:n])
			if err != nil {
				continue
			}
			if at, ok := sent[reply.Nonce]; ok {
				return reply, observedAddr(src), time.Since(at), nil
			}
		}
	}
	return RendezvousReply{}, netip.AddrPort{}, 0,
		fmt.Errorf("no rendezvous reply from %s%s", target, rendezvousSilenceHint(target))
}

func udpAddr(ap netip.AddrPort) *net.UDPAddr {
	return net.UDPAddrFromAddrPort(ap)
}
