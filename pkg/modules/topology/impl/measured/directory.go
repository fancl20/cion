package measured

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/google/uuid"
	"github.com/scionproto/scion/pkg/addr"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	cryptopb "github.com/scionproto/scion/pkg/proto/crypto"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/pkg/scrypto/signed"
	"github.com/scionproto/scion/pkg/slayers/path"
	"google.golang.org/protobuf/proto"

	"github.com/fancl20/cion/pkg/core/trust"
	"github.com/fancl20/cion/pkg/libs/bus"
	"github.com/fancl20/cion/pkg/libs/loops"
	"github.com/fancl20/cion/pkg/libs/peeria"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/scionrpc"
	"github.com/fancl20/cion/pkg/libs/segment"
	"github.com/fancl20/cion/pkg/modules/topology"
	nodev1 "github.com/fancl20/cion/proto/node/v1"
	nodev1connect "github.com/fancl20/cion/proto/node/v1/nodev1connect"
)

// The node directory's pacing: a node signs its entries every refresh
// interval and at each change of its own state, a view shows an entry for a
// lifetime past its signing, each end of a serving link sends the other its
// summary every summary period, and a node forwards each signer's entries
// at most once per forwarding bound.
const (
	// EntryRefreshInterval is how often a node signs its entries with no
	// change of its own state.
	EntryRefreshInterval = 5 * time.Minute
	// EntryLifetime is how long past its signing a view shows an entry.
	EntryLifetime = 15 * time.Minute
	// EntrySummaryPeriod is how often each end of a serving link sends the
	// other its summary.
	EntrySummaryPeriod = 5 * time.Minute
	// EntryForwardBound is the least time between two forwards of one
	// signer's entries in one directory.
	EntryForwardBound = 5 * time.Second
	// EntryRetry is how long the signing waits while the node holds no
	// chain to sign with, and the first wait after a failed catch-up, the
	// later ones doubling up to the summary period.
	EntryRetry = 5 * time.Second
)

// entryFutureBound is how far past the node's clock an entry's signing time
// may lie for a view to show it: the allowance the node grants a beacon's
// timestamp.
var entryFutureBound = path.ExpTimeToDuration(0)

const (
	// entryCallTimeout bounds each push and sync, and each entry's
	// verification.
	entryCallTimeout = 5 * time.Second
	// maxEntriesPerCall bounds the entries and the summaries one push or
	// sync carries.
	maxEntriesPerCall = 4096
)

// errNotReady marks a signing waiting on the node's chain.
var errNotReady = errors.New("the node's entries are not ready")

// errWithdrawn marks a signing after the node withdrew its entries.
var errWithdrawn = errors.New("the node withdrew its entries")

// errUnattached marks a link whose directory is not known yet: the link's
// peer has not reported the host it sees the node at.
var errUnattached = errors.New("the link joins no directory yet")

// DirectoryTrust is the trust the directory's entries rest on: the node's
// signer and the verification of an entry at its signing time. The trust
// engine provides it.
type DirectoryTrust interface {
	Signer(ctx context.Context) (trust.Signer, error)
	VerifyBoundAt(ctx context.Context, ia addr.IA, server net.Addr,
		signedMsg *cryptopb.SignedMessage, at time.Time,
		associatedData ...[]byte) (*signed.Message, error)
}

var _ DirectoryTrust = (*trust.Engine)(nil)

// NodeDirectoryConfig configures a NodeDirectory.
type NodeDirectoryConfig struct {
	// IA is the node's ISD-AS.
	IA addr.IA
	// Addresses returns, at each signing, the node's addresses at the hosts
	// a directory's peers see it at, in the hosts' order, each with the
	// node's report of how its peers reach it there; an error fails the
	// signing.
	Addresses func(hosts []netip.Addr) ([]*nodev1.Address, error)
	// Peers returns, at each signing, the peers the node reports in the
	// directory the ID names, ordered by ISD-AS; nil reports none. Each
	// publication of Links signs again where a reported peer's link or
	// announcements changed.
	Peers func(id bus.DirectoryID) []*nodev1.Peer
	// Cluster returns, at each signing, the ISD-AS naming the cluster the
	// node joined, zero for none; nil names none. A changed cluster signs
	// again at once.
	Cluster func() addr.IA
	// Trust signs the node's entries and verifies its neighbors'; nil signs
	// and accepts none.
	Trust DirectoryTrust
	// Links is the link state topic: each link's observed source names the
	// neighbor as the node sees it, and entries travel to the neighbors the
	// usable links reach. Nil observes and reaches none.
	Links *bus.Topic[bus.LinkState]
	// Peer is the node's channel to its peers, whose one-hop side the pushes
	// and the syncs ride; nil reaches no neighbor.
	Peer topology.PeerChannel
	// Directory is the node directory topic the views are published on; nil
	// publishes none.
	Directory *bus.Topic[bus.Directory]
	// Retry, ForwardBound, and SummaryPeriod override the defaults; zero
	// keeps them.
	Retry         time.Duration
	ForwardBound  time.Duration
	SummaryPeriod time.Duration
}

// NodeDirectory is the node's copy of the directories it holds. It groups
// the node's links into attachments by the host each link's peer reports
// seeing the node at; each attachment names a directory ID, and the two
// ends of every link keep the lesser of their IDs, which each sync carries.
// Each directory holds each signer's greatest signed entry, merged by the
// order alone. The node signs its entry in each directory, merges the
// greater entries its neighbors push into the directory of the link they
// arrived over once they verify, floods them along that directory's links,
// catches each link's two ends up with a sync of summaries, and publishes
// its views on the node bus. The measured provider runs it on every node,
// reports each link's host to it, and serves its DirectoryService.
type NodeDirectory struct {
	cfg NodeDirectoryConfig

	// mtx guards the attachments, the links, and the directories.
	mtx sync.Mutex
	// attachments holds the node's attachments by host, and links the host
	// each link's peer last reported seeing the node at, by interface.
	attachments map[netip.Addr]*attachment
	links       map[uint16]netip.Addr
	// scopes holds each directory the node holds, by ID.
	scopes map[bus.DirectoryID]*scope
	// mint mints the directory ID of a new attachment.
	mint func() bus.DirectoryID

	// viewWake, forwardWake, signWake, and catchUp wake the loops: an entry
	// merged or a link attached, an entry due, an attachment or the node's
	// addresses changed, and every link due to sync anew — at the node's
	// first chain, before which no neighbor's channel admitted it, at a
	// link's first attachment, and at a merge, which changed the ID the
	// node's end of its links names.
	viewWake    chan struct{}
	forwardWake chan struct{}
	signWake    chan struct{}
	catchUp     chan struct{}

	// signMtx serializes the node's signings; chained records that the node
	// held its chain, signed that one of its signings landed, and withdrawn
	// that it withdrew its entries, after which it signs no other.
	signMtx   sync.Mutex
	chained   bool
	signed    bool
	withdrawn bool

	// clients holds the one-hop client of each neighbor's directory
	// service, by encoded authority.
	clientsMtx sync.Mutex
	clients    map[string]nodev1connect.DirectoryServiceClient
}

var _ nodev1connect.DirectoryServiceHandler = (*NodeDirectory)(nil)

// attachment is a group of the node's links whose peers see the node at
// one host.
type attachment struct {
	host netip.Addr
	// id is the directory the attachment names.
	id bus.DirectoryID
}

// scope is one directory: each signer's greatest entry, and its forwarding
// state.
type scope struct {
	entries map[addr.IA]*signedEntry
	// due marks the signers whose greatest entry waits to be forwarded, and
	// lastForward holds when each signer's entry was forwarded last.
	due         map[addr.IA]bool
	lastForward map[addr.IA]time.Time
}

func newScope() *scope {
	return &scope{
		entries:     make(map[addr.IA]*signedEntry),
		due:         make(map[addr.IA]bool),
		lastForward: make(map[addr.IA]time.Time),
	}
}

// merge keeps the entry when it is greater than the one held of its signer,
// schedules its forward, and reports whether it kept it.
func (s *scope) merge(e *signedEntry) bool {
	held, ok := s.entries[e.signer]
	if ok && e.key.compare(held.key) <= 0 {
		return false
	}
	s.entries[e.signer] = e
	s.due[e.signer] = true
	return true
}

// NewNodeDirectory returns the node's directories, holding none.
func NewNodeDirectory(cfg NodeDirectoryConfig) *NodeDirectory {
	return &NodeDirectory{
		cfg:         cfg,
		attachments: make(map[netip.Addr]*attachment),
		links:       make(map[uint16]netip.Addr),
		scopes:      make(map[bus.DirectoryID]*scope),
		mint:        newDirectoryID,
		viewWake:    make(chan struct{}, 1),
		forwardWake: make(chan struct{}, 1),
		signWake:    make(chan struct{}, 1),
		catchUp:     make(chan struct{}, 1),
		clients:     make(map[string]nodev1connect.DirectoryServiceClient),
	}
}

// newDirectoryID mints a directory ID: a UUIDv7 from the node's clock.
func newDirectoryID() bus.DirectoryID {
	return bus.DirectoryID(uuid.Must(uuid.NewV7()))
}

// parseDirectoryID reads a directory ID off the wire: 16 bytes, or none.
func parseDirectoryID(b []byte) (bus.DirectoryID, error) {
	var id bus.DirectoryID
	switch len(b) {
	case 0:
		return id, nil
	case len(id):
		copy(id[:], b)
		return id, nil
	default:
		return id, fmt.Errorf("a directory ID of %d bytes, want %d", len(b), len(id))
	}
}

// signedEntry is one signer's signed entry as a directory holds it.
type signedEntry struct {
	msg *cryptopb.SignedMessage
	// signer and key are read from the header before verification; digest
	// is the SHA-256 of the signed bytes.
	signer addr.IA
	key    entryKey
	digest [sha256.Size]byte
	// withdrawn and entry are the verified body: a withdrawal, naming no
	// address, or the bus form of the addresses and the reports it carries.
	withdrawn bool
	entry     bus.DirectoryEntry
	// from is the neighbor that sent the entry, zero for the node's own.
	from addr.IA
}

// entryKey is what orders a signer's entries: the TRC the signer named,
// base then serial, then the signing time, then the signed bytes.
type entryKey struct {
	trc      cppki.TRCID
	signedAt time.Time
	signed   []byte
}

// compare orders k against o.
func (k entryKey) compare(o entryKey) int {
	if c := compareTRC(k.trc, o.trc); c != 0 {
		return c
	}
	if c := k.signedAt.Compare(o.signedAt); c != 0 {
		return c
	}
	return bytes.Compare(k.signed, o.signed)
}

// compareSummary orders k against the entry a summary names by what the
// summary carries: the TRC and the signing time.
func (k entryKey) compareSummary(s *nodev1.Summary) int {
	if c := compareTRC(k.trc, summaryTRC(s)); c != 0 {
		return c
	}
	return cmp.Compare(k.signedAt.UnixNano(), s.SignedAt)
}

// compareTRC orders two TRCs of one ISD: base, then serial.
func compareTRC(a, b cppki.TRCID) int {
	if c := cmp.Compare(a.Base, b.Base); c != 0 {
		return c
	}
	return cmp.Compare(a.Serial, b.Serial)
}

// summaryTRC returns the TRC a summary names.
func summaryTRC(s *nodev1.Summary) cppki.TRCID {
	return cppki.TRCID{
		ISD:    addr.IA(s.IsdAs).ISD(),
		Base:   scrypto.Version(s.TrcBase),
		Serial: scrypto.Version(s.TrcSerial),
	}
}

// parseEntry reads a signed entry's header, unverified: its signer, the TRC
// it names, and its signing time. A header naming no signer or no signing
// time fails.
func parseEntry(msg *cryptopb.SignedMessage) (*signedEntry, error) {
	hdr, err := signed.ExtractUnverifiedHeader(msg)
	if err != nil {
		return nil, fmt.Errorf("reading the header: %w", err)
	}
	var keyID cppb.VerificationKeyID
	if err := proto.Unmarshal(hdr.VerificationKeyID, &keyID); err != nil {
		return nil, fmt.Errorf("reading the verification key ID: %w", err)
	}
	signer := addr.IA(keyID.IsdAs)
	if signer.IsZero() || signer.IsWildcard() {
		return nil, fmt.Errorf("the header names no signer: %v", signer)
	}
	if hdr.Timestamp.IsZero() {
		return nil, errors.New("the header names no signing time")
	}
	return &signedEntry{
		msg:    msg,
		signer: signer,
		key: entryKey{
			trc: cppki.TRCID{
				ISD:    signer.ISD(),
				Base:   scrypto.Version(keyID.TrcBase),
				Serial: scrypto.Version(keyID.TrcSerial),
			},
			signedAt: hdr.Timestamp,
			signed:   msg.HeaderAndBody,
		},
		digest: sha256.Sum256(msg.HeaderAndBody),
	}, nil
}

// read records the verified body: a withdrawal when it names no address. A
// body naming another ISD-AS than its signer, or a malformed address, fails.
func (e *signedEntry) read(body *nodev1.Entry) error {
	if ia := addr.IA(body.IsdAs); !ia.Equal(e.signer) {
		return fmt.Errorf("the body names %v, signed by %v", ia, e.signer)
	}
	e.withdrawn = len(body.Addresses) == 0
	e.entry = bus.DirectoryEntry{IA: e.signer, Cluster: addr.IA(body.Cluster), Published: e.key.signedAt}
	for _, a := range body.Addresses {
		control, err := netip.ParseAddrPort(a.ControlAddr)
		if err != nil {
			return fmt.Errorf("parsing a control address: %w", err)
		}
		rendezvous, err := netip.ParseAddrPort(a.RendezvousAddr)
		if err != nil {
			return fmt.Errorf("parsing a rendezvous address: %w", err)
		}
		e.entry.Addresses = append(e.entry.Addresses, bus.Address{
			ControlAddr:    control,
			RendezvousAddr: rendezvous,
			Reach: bus.Reach{
				BehindNAT:            a.BehindNat,
				RendezvousUnanswered: a.RendezvousUnanswered,
			},
		})
	}
	for _, p := range body.Peers {
		report, err := readPeer(p)
		if err != nil {
			return err
		}
		e.entry.Peers = append(e.entry.Peers, report)
	}
	return nil
}

// readPeer reads one reported peer: an interface ID no hop field could carry
// fails.
func readPeer(p *nodev1.Peer) (bus.PeerReport, error) {
	ifID, err := interfaceID(p.IfId)
	if err != nil {
		return bus.PeerReport{}, err
	}
	report := bus.PeerReport{
		IA:        addr.IA(p.IsdAs),
		RTT:       time.Duration(p.RttUs) * time.Microsecond,
		Low:       time.Duration(p.RttLowUs) * time.Microsecond,
		High:      time.Duration(p.RttHighUs) * time.Microsecond,
		IfID:      ifID,
		Promoting: p.Promoting,
		Retiring:  p.Retiring,
	}
	for _, l := range p.Relies {
		ifID, err := interfaceID(l.IfId)
		if err != nil {
			return bus.PeerReport{}, err
		}
		report.Relies = append(report.Relies, segment.LinkID{IA: addr.IA(l.IsdAs), IfID: ifID})
	}
	return report, nil
}

// interfaceID reads a reported interface ID.
func interfaceID(id uint32) (uint16, error) {
	if id > math.MaxUint16 {
		return 0, fmt.Errorf("an interface ID of %d", id)
	}
	return uint16(id), nil
}

// summary returns the summary naming the entry.
func (e *signedEntry) summary() *nodev1.Summary {
	return &nodev1.Summary{
		IsdAs:     uint64(e.signer),
		TrcBase:   uint64(e.key.trc.Base),
		TrcSerial: uint64(e.key.trc.Serial),
		SignedAt:  e.key.signedAt.UnixNano(),
		Digest:    e.digest[:],
	}
}

// Run signs the node's entries, keeps the views, forwards the merged
// entries, and catches each link's two ends up until the context is
// canceled, returning once every loop has returned.
func (d *NodeDirectory) Run(ctx context.Context) {
	var wg sync.WaitGroup
	loops.Go(ctx, &wg, "node directory signing", d.runSign)
	loops.Go(ctx, &wg, "node directory view", d.runView)
	loops.Go(ctx, &wg, "node directory forwarding", d.runForward)
	loops.Go(ctx, &wg, "node directory catch-up", d.runCatchUp)
	wg.Wait()
}

// attach records that the link's peer sees the node at the host: the link
// joins the host's attachment, minted with a fresh directory ID when the
// node holds none. It returns the attachment's ID. A link that joins
// another attachment wakes the catch-up, whose sync over the link carries
// the attachment's ID to the peer.
func (d *NodeDirectory) attach(ifID uint16, host netip.Addr) bus.DirectoryID {
	d.mtx.Lock()
	prev, had := d.links[ifID]
	d.links[ifID] = host
	a, ok := d.attachments[host]
	if !ok {
		a = &attachment{host: host, id: d.mint()}
		d.attachments[host] = a
		d.scopes[a.id] = newScope()
	}
	id := a.id
	d.mtx.Unlock()
	if !had || prev != host {
		wake(d.signWake)
		wake(d.viewWake)
		wake(d.catchUp)
	}
	return id
}

// adopt gives the link's attachment the peer's directory ID when it is the
// lesser, and returns the attachment's ID; false while the link has no
// attachment.
func (d *NodeDirectory) adopt(ifID uint16, peer bus.DirectoryID) (bus.DirectoryID, bool) {
	d.mtx.Lock()
	host, ok := d.links[ifID]
	if !ok {
		d.mtx.Unlock()
		return bus.DirectoryID{}, false
	}
	a := d.attachments[host]
	merged := !peer.IsZero() && peer.Compare(a.id) < 0
	if merged {
		d.mergeLocked(a.id, peer)
	}
	id := a.id
	d.mtx.Unlock()
	if merged {
		wake(d.signWake)
		wake(d.viewWake)
		wake(d.forwardWake)
		wake(d.catchUp)
	}
	return id, true
}

// resign wakes the signing: the node's addresses changed.
func (d *NodeDirectory) resign() {
	wake(d.signWake)
}

// mergeLocked gives the lesser ID every attachment naming the greater, and
// joins the greater's directory into the lesser's, signer by signer, or
// names it by the lesser when the node holds no directory under it. The
// links that named either ID lack the other's entries; the catch-up the
// merge wakes syncs each of them. The caller holds the directory's lock.
func (d *NodeDirectory) mergeLocked(greater, lesser bus.DirectoryID) {
	for _, a := range d.attachments {
		if a.id == greater {
			a.id = lesser
		}
	}
	src := d.scopes[greater]
	delete(d.scopes, greater)
	dst, ok := d.scopes[lesser]
	if !ok {
		d.scopes[lesser] = src
		return
	}
	for _, e := range src.entries {
		if held, ok := dst.entries[e.signer]; !ok || e.key.compare(held.key) > 0 {
			dst.entries[e.signer] = e
		}
	}
}

// linkScopeLocked returns the directory the link's attachment names, nil
// while the link has none. The caller holds the directory's lock.
func (d *NodeDirectory) linkScopeLocked(ifID uint16) (bus.DirectoryID, *scope) {
	host, ok := d.links[ifID]
	if !ok {
		return bus.DirectoryID{}, nil
	}
	id := d.attachments[host].id
	return id, d.scopes[id]
}

// linkID returns the ID of the directory the link's attachment names, and
// whether the link has one.
func (d *NodeDirectory) linkID(ifID uint16) (bus.DirectoryID, bool) {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	id, s := d.linkScopeLocked(ifID)
	return id, s != nil
}

// Withdraw signs the node's withdrawal, an entry naming no address, in each
// directory that holds an entry of the node's own, and pushes each to every
// neighbor a usable link of its directory reaches, returning once each push
// answered or ctx ended; the node signs no entry after it.
func (d *NodeDirectory) Withdraw(ctx context.Context) {
	withdrawals, err := d.withdrawals(ctx)
	if err != nil {
		slog.Warn("Withdrawing the node's directory entries", "err", err)
	}
	if len(withdrawals) == 0 {
		return
	}
	d.push(ctx, withdrawals)
	slog.Info("Withdrew the node's directory entries", "directories", len(withdrawals))
}

// withdrawals signs and merges the node's withdrawal in each directory that
// holds an entry of the node's own that is no withdrawal, and returns them
// by directory.
func (d *NodeDirectory) withdrawals(ctx context.Context) (map[bus.DirectoryID][]*signedEntry, error) {
	if d.cfg.Trust == nil {
		return nil, nil
	}
	d.signMtx.Lock()
	defer d.signMtx.Unlock()
	if d.withdrawn {
		return nil, nil
	}
	d.mtx.Lock()
	var ids []bus.DirectoryID
	for id, s := range d.scopes {
		if e, ok := s.entries[d.cfg.IA]; ok && !e.withdrawn {
			ids = append(ids, id)
		}
	}
	d.mtx.Unlock()
	if len(ids) == 0 {
		return nil, nil
	}
	signer, err := d.cfg.Trust.Signer(ctx)
	if err != nil {
		return nil, err
	}
	d.withdrawn = true
	out := make(map[bus.DirectoryID][]*signedEntry, len(ids))
	for _, id := range ids {
		e, err := d.signIn(ctx, signer, id, &nodev1.Entry{IsdAs: uint64(d.cfg.IA)})
		if err != nil {
			return out, err
		}
		if e != nil {
			out[id] = []*signedEntry{e}
		}
	}
	return out, nil
}

// runSign signs the node's entry in each directory it holds once it holds
// a chain, again in each directory whose attachments, their reach, or the
// links and announcements of the node's peer reports changed — at each
// publication of the link state, which the reports' links follow, among
// others — and in each directory a refresh interval past the node's entry
// held there; each signing names the newest TRC the node pins. A signing
// that waits on the chain, or fails, retries at the retry interval.
func (d *NodeDirectory) runSign(ctx context.Context) {
	retry := intervalOr(d.cfg.Retry, EntryRetry)
	timer := time.NewTimer(0)
	defer timer.Stop()
	var linkStates <-chan bus.LinkState
	if d.cfg.Links != nil && d.cfg.Peers != nil {
		linkStates = d.cfg.Links.Subscribe(ctx)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-d.signWake:
		case <-linkStates:
		case <-timer.C:
		}
		next, err := d.signScopes(ctx)
		switch {
		case errors.Is(err, errWithdrawn):
			<-ctx.Done()
			return
		case err != nil:
			slog.Debug("Signing the node's directory entries", "err", err)
			timer.Reset(retry)
		case next.IsZero():
			timer.Stop()
		default:
			timer.Reset(time.Until(next))
		}
	}
}

// signScopes signs the node's entry in each directory its links attach to
// whose addresses, or whose peers' links and announcements, differ from the
// node's entry held there, or whose held entry is a refresh interval old,
// and returns when the next signing is
// due — a refresh, or the retry of one that lost to an entry of the node's
// own signed later by its clock — the zero time when no directory waits on
// one. The first signing that finds the node's chain wakes the catch-up.
func (d *NodeDirectory) signScopes(ctx context.Context) (time.Time, error) {
	if d.cfg.Trust == nil {
		return time.Time{}, fmt.Errorf("%w: no trust to sign with", errNotReady)
	}
	d.signMtx.Lock()
	defer d.signMtx.Unlock()
	if d.withdrawn {
		return time.Time{}, errWithdrawn
	}
	signer, err := d.cfg.Trust.Signer(ctx)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %w", errNotReady, err)
	}
	if !d.chained {
		d.chained = true
		wake(d.catchUp)
	}
	bodies, err := d.ownBodies()
	if err != nil {
		return time.Time{}, err
	}
	var next time.Time
	for _, id := range slices.SortedFunc(maps.Keys(bodies), bus.DirectoryID.Compare) {
		signedAt, current := d.ownHeld(id, bodies[id])
		refreshAt := signedAt.Add(EntryRefreshInterval)
		if !current || !time.Now().Before(refreshAt) {
			e, err := d.signIn(ctx, signer, id, bodies[id])
			if err != nil {
				return time.Time{}, err
			}
			if e != nil {
				refreshAt = e.key.signedAt.Add(EntryRefreshInterval)
			} else {
				// The directory went away, or holds an entry of the node's
				// own signed later by its clock: the signing there retries
				// once the clock passes that entry.
				refreshAt, _ = d.ownHeld(id, bodies[id])
			}
		}
		next = earliest(next, refreshAt)
	}
	return next, nil
}

// ownBodies returns the node's entry in each directory one of its links
// attaches to: its addresses at the hosts of the attachments naming the
// directory that hold a link, ordered by host.
func (d *NodeDirectory) ownBodies() (map[bus.DirectoryID]*nodev1.Entry, error) {
	d.mtx.Lock()
	attached := make(map[netip.Addr]bool, len(d.links))
	for _, host := range d.links {
		attached[host] = true
	}
	hosts := make(map[bus.DirectoryID][]netip.Addr)
	for host, a := range d.attachments {
		if attached[host] {
			hosts[a.id] = append(hosts[a.id], host)
		}
	}
	d.mtx.Unlock()
	bodies := make(map[bus.DirectoryID]*nodev1.Entry, len(hosts))
	for id, hs := range hosts {
		slices.SortFunc(hs, netip.Addr.Compare)
		addresses, err := d.cfg.Addresses(hs)
		if err != nil {
			return nil, fmt.Errorf("reading the addresses at %v: %w", hs, err)
		}
		bodies[id] = &nodev1.Entry{IsdAs: uint64(d.cfg.IA), Addresses: addresses}
		if d.cfg.Peers != nil {
			bodies[id].Peers = d.cfg.Peers(id)
		}
		if d.cfg.Cluster != nil {
			bodies[id].Cluster = uint64(d.cfg.Cluster())
		}
	}
	return bodies, nil
}

// ownHeld returns the signing time of the node's entry the directory
// holds, and whether that entry is no withdrawal and names the body's
// addresses, its peers' links and announcements, and its cluster.
func (d *NodeDirectory) ownHeld(id bus.DirectoryID, body *nodev1.Entry) (time.Time, bool) {
	want := signedEntry{signer: d.cfg.IA}
	if want.read(body) != nil {
		return time.Time{}, false
	}
	d.mtx.Lock()
	defer d.mtx.Unlock()
	s, ok := d.scopes[id]
	if !ok {
		return time.Time{}, false
	}
	held, ok := s.entries[d.cfg.IA]
	if !ok {
		return time.Time{}, false
	}
	return held.key.signedAt, !held.withdrawn &&
		slices.Equal(held.entry.Addresses, want.entry.Addresses) &&
		sameChanges(held.entry.Peers, want.entry.Peers) &&
		held.entry.Cluster == want.entry.Cluster
}

// sameChanges reports whether two peer reports name the same links and
// announcements: each peer's interface, promotion, retirement, and
// reliance, a peer one report omits naming none. Round trips and their
// bounds, and peers that name neither, may differ: every signing carries
// the whole report, so they wait for the entry's next signing, at the
// latest its refresh.
func sameChanges(a, b []bus.PeerReport) bool {
	changes := func(reports []bus.PeerReport) map[addr.IA]bus.PeerReport {
		out := make(map[addr.IA]bus.PeerReport, len(reports))
		for _, r := range reports {
			if r.IfID != 0 || r.Promoting || r.Retiring {
				r.RTT, r.Low, r.High = 0, 0, 0
				out[r.IA] = r
			}
		}
		return out
	}
	return maps.EqualFunc(changes(a), changes(b), bus.PeerReport.Equal)
}

// signIn signs the body as the node's entry in the directory the ID names,
// once the node's clock passed the signing time of its entry held there,
// and merges it. It returns nil when the directory went away meanwhile —
// joined into another, where the node signs anew — or the entry lost to one
// of the node's own signed later by its clock. The caller holds signMtx.
func (d *NodeDirectory) signIn(
	ctx context.Context, signer trust.Signer, id bus.DirectoryID, body *nodev1.Entry,
) (*signedEntry, error) {

	if wait := d.ownSigningWait(id, time.Now()); wait > 0 && !loops.Sleep(ctx, wait) {
		return nil, ctx.Err()
	}
	raw, err := proto.Marshal(body)
	if err != nil {
		return nil, err
	}
	msg, err := signer.Sign(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("signing the entry: %w", err)
	}
	e, err := parseEntry(msg)
	if err != nil {
		return nil, err
	}
	if err := e.read(body); err != nil {
		return nil, err
	}
	d.mtx.Lock()
	s, ok := d.scopes[id]
	merged := ok && s.merge(e)
	d.mtx.Unlock()
	if !ok {
		return nil, nil
	}
	if !merged {
		slog.Warn("The node's new directory entry lost to one of its own signed "+
			"later by its clock; the clock may have stepped back",
			"directory", id, "signed_at", e.key.signedAt)
		return nil, nil
	}
	d.signed = true
	wake(d.viewWake)
	wake(d.forwardWake)
	return e, nil
}

// ownClockSlack is how far the node's clock may stand behind the signing
// time of the node's entry held in a directory for a signing there to wait
// it out.
const ownClockSlack = time.Second

// ownSigningWait returns how long a signing at now in the directory waits
// for the node's clock to pass the signing time of the node's entry held
// there, so the node's entries grow by their signing time: none when the
// clock passed it, or when the clock stands ownClockSlack or more behind
// it.
func (d *NodeDirectory) ownSigningWait(id bus.DirectoryID, now time.Time) time.Duration {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	s, ok := d.scopes[id]
	if !ok {
		return 0
	}
	held, ok := s.entries[d.cfg.IA]
	if !ok || now.After(held.key.signedAt) {
		return 0
	}
	if wait := held.key.signedAt.Sub(now) + time.Nanosecond; wait < ownClockSlack {
		return wait
	}
	return 0
}

// hasSigned reports whether one of the node's signings landed since it
// started.
func (d *NodeDirectory) hasSigned() bool {
	d.signMtx.Lock()
	defer d.signMtx.Unlock()
	return d.signed
}

// wins reports whether the entry is greater than the one held of its signer
// in the directory of the link's attachment, false while the link has
// none.
func (d *NodeDirectory) wins(ifID uint16, e *signedEntry) bool {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	_, s := d.linkScopeLocked(ifID)
	if s == nil {
		return false
	}
	held, ok := s.entries[e.signer]
	return !ok || e.key.compare(held.key) > 0
}

// mergeOver keeps the entry in the directory of the link's attachment when
// it is greater than the one held of its signer, schedules its forward,
// wakes the view, and reports whether it kept it.
func (d *NodeDirectory) mergeOver(ifID uint16, e *signedEntry) bool {
	d.mtx.Lock()
	_, s := d.linkScopeLocked(ifID)
	merged := s != nil && s.merge(e)
	d.mtx.Unlock()
	if merged {
		wake(d.viewWake)
		wake(d.forwardWake)
	}
	return merged
}

// wake sends on a wake channel without blocking: a wake already pending
// carries this one.
func wake(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// accept merges the entries the neighbor sent over the link into the
// directory of the link's attachment, each once it is greater than the one
// held and verifies against a chain of its signer valid at its signing
// time, missing trust material asked of the neighbor over the link, and
// returns how many it merged. An entry the views would never show again is
// discarded on arrival, as a directory discards it once held, and one that
// cannot win is never verified.
func (d *NodeDirectory) accept(
	ctx context.Context, msgs []*cryptopb.SignedMessage, from addr.IA, ifID uint16,
) int {

	if d.cfg.Trust == nil {
		return 0
	}
	server := &scion.Addr{IA: from, Service: addr.SvcCS, IfID: ifID}
	now := time.Now()
	merged := 0
	for _, msg := range msgs {
		e, err := parseEntry(msg)
		if err != nil {
			slog.Debug("Refusing a malformed directory entry", "from", from, "err", err)
			continue
		}
		if stale(e.key.signedAt, now) || !d.wins(ifID, e) {
			continue
		}
		if err := d.verify(ctx, e, server); err != nil {
			slog.Debug("Refusing a directory entry", "signer", e.signer, "from", from,
				"err", err)
			continue
		}
		e.from = from
		if !d.mergeOver(ifID, e) {
			continue
		}
		merged++
		if e.signer.Equal(d.cfg.IA) && d.hasSigned() {
			slog.Warn("A directory holds an entry of the node's own signed later "+
				"than its latest; the clock may have stepped back",
				"signed_at", e.key.signedAt)
		}
	}
	return merged
}

// verify verifies the entry against a chain of its signer valid at its
// signing time, missing trust material asked of server, and reads its body.
func (d *NodeDirectory) verify(ctx context.Context, e *signedEntry, server net.Addr) error {
	ctx, cancel := context.WithTimeout(ctx, entryCallTimeout)
	defer cancel()
	m, err := d.cfg.Trust.VerifyBoundAt(ctx, e.signer, server, e.msg, e.key.signedAt)
	if err != nil {
		return err
	}
	var body nodev1.Entry
	if err := proto.Unmarshal(m.Body, &body); err != nil {
		return fmt.Errorf("reading the body: %w", err)
	}
	return e.read(&body)
}

// stale reports whether a view, at now, never shows again an entry signed
// at signedAt: one signed two lifetimes back or more, a lifetime past its
// leaving the window.
func stale(signedAt, now time.Time) bool {
	return !signedAt.After(now.Add(-2 * EntryLifetime))
}

// view is the node's view of its directories: the entries each shows by
// signer, by directory ID, and the directory each attached link joins.
type view struct {
	scopes map[bus.DirectoryID]map[addr.IA]*signedEntry
	links  map[uint16]bus.DirectoryID
}

// runView publishes the views on the directory topic whenever they change:
// at each merged entry or attached link, and when an entry enters or
// leaves the window. Each pass discards what the views never show again.
func (d *NodeDirectory) runView(ctx context.Context) {
	var shown view
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-d.viewWake:
		case <-timer.C:
		}
		v, next := d.pass(time.Now())
		if !sameView(shown, v) {
			d.publish(v)
			shown = v
		}
		if next.IsZero() {
			timer.Stop()
		} else {
			timer.Reset(time.Until(next))
		}
	}
}

// pass forgets the links no live entry holds any more, discards the entries
// the views never show again at now, the attachments that hold no link and
// whose directory holds no entry, and the directories no attachment names,
// and returns the view at now and when the clock alone changes it next. The
// link state is read under the directory's lock: a link is live before it
// is attached, so the read sees every attached link that is still live.
func (d *NodeDirectory) pass(now time.Time) (view, time.Time) {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	if d.cfg.Links != nil {
		live := d.cfg.Links.Latest().Table()
		for ifID := range d.links {
			if _, ok := live[ifID]; !ok {
				delete(d.links, ifID)
			}
		}
	}
	for _, s := range d.scopes {
		for signer, e := range s.entries {
			if stale(e.key.signedAt, now) {
				delete(s.entries, signer)
				delete(s.due, signer)
			}
		}
	}
	attached := make(map[netip.Addr]bool, len(d.links))
	for _, host := range d.links {
		attached[host] = true
	}
	named := make(map[bus.DirectoryID]bool, len(d.attachments))
	for host, a := range d.attachments {
		if !attached[host] && len(d.scopes[a.id].entries) == 0 {
			delete(d.attachments, host)
			continue
		}
		named[a.id] = true
	}
	for id := range d.scopes {
		if !named[id] {
			delete(d.scopes, id)
		}
	}
	return d.viewLocked(now)
}

// viewLocked returns the view at now and when the clock alone changes it
// next — the earliest shown entry leaving the window, or held one entering
// it — the zero time when it never does. Each directory's view shows each
// signer's entry that is no withdrawal and was signed less than a lifetime
// before now and no later than the future bound after it, whatever TRC it
// names. The caller holds the directory's lock.
func (d *NodeDirectory) viewLocked(now time.Time) (view, time.Time) {
	v := view{
		scopes: make(map[bus.DirectoryID]map[addr.IA]*signedEntry, len(d.scopes)),
		links:  make(map[uint16]bus.DirectoryID, len(d.links)),
	}
	var next time.Time
	for id, s := range d.scopes {
		shown := make(map[addr.IA]*signedEntry)
		for signer, e := range s.entries {
			if e.withdrawn {
				continue
			}
			enters := e.key.signedAt.Add(-entryFutureBound)
			leaves := e.key.signedAt.Add(EntryLifetime)
			switch {
			case now.Before(enters):
				next = earliest(next, enters)
			case now.Before(leaves):
				shown[signer] = e
				next = earliest(next, leaves)
			}
		}
		v.scopes[id] = shown
	}
	for ifID, host := range d.links {
		v.links[ifID] = d.attachments[host].id
	}
	return v, next
}

// sameView reports whether two views show the same entries in the same
// directories and attach the same links to them.
func sameView(a, b view) bool {
	if !maps.Equal(a.links, b.links) || len(a.scopes) != len(b.scopes) {
		return false
	}
	for id, shown := range a.scopes {
		other, ok := b.scopes[id]
		if !ok || !maps.Equal(shown, other) {
			return false
		}
	}
	return true
}

// publish publishes the view on the directory topic, each directory's
// entries ordered by ISD-AS.
func (d *NodeDirectory) publish(v view) {
	if d.cfg.Directory == nil {
		return
	}
	scopes := make([]bus.Scope, 0, len(v.scopes))
	for id, shown := range v.scopes {
		entries := make([]bus.DirectoryEntry, 0, len(shown))
		for _, e := range shown {
			entries = append(entries, e.entry)
		}
		slices.SortFunc(entries, func(a, b bus.DirectoryEntry) int { return cmp.Compare(a.IA, b.IA) })
		scopes = append(scopes, bus.NewScope(id, entries...))
	}
	d.cfg.Directory.Publish(bus.NewDirectory(v.links, scopes...))
}

// runForward forwards each signer's greatest entry of each directory once
// it is due: at once when the signer's last forward there lies a bound
// back, else at the bound's end, the entry then greatest travelling. Each
// pass pushes the due entries of each directory to every neighbor a usable
// link of that directory reaches but the one each came from.
func (d *NodeDirectory) runForward(ctx context.Context) {
	bound := intervalOr(d.cfg.ForwardBound, EntryForwardBound)
	timer := time.NewTimer(0)
	timer.Stop()
	defer timer.Stop()
	for {
		batches, next := d.dueEntries(time.Now(), bound)
		if len(batches) != 0 {
			d.push(ctx, batches)
		}
		var wait <-chan time.Time
		if !next.IsZero() {
			timer.Reset(time.Until(next))
			wait = timer.C
		}
		select {
		case <-ctx.Done():
			return
		case <-d.forwardWake:
		case <-wait:
		}
	}
}

// dueEntries returns, by directory, the greatest entry of each signer due
// at now, marking it forwarded, and when the next signer waiting on its
// bound is due.
func (d *NodeDirectory) dueEntries(
	now time.Time, bound time.Duration,
) (map[bus.DirectoryID][]*signedEntry, time.Time) {

	d.mtx.Lock()
	defer d.mtx.Unlock()
	batches := make(map[bus.DirectoryID][]*signedEntry)
	var next time.Time
	for id, s := range d.scopes {
		for signer := range s.due {
			if at := s.lastForward[signer].Add(bound); now.Before(at) {
				next = earliest(next, at)
				continue
			}
			delete(s.due, signer)
			if e, ok := s.entries[signer]; ok {
				batches[id] = append(batches[id], e)
				s.lastForward[signer] = now
			}
		}
		for signer, at := range s.lastForward {
			if !s.due[signer] && !now.Before(at.Add(bound)) {
				delete(s.lastForward, signer)
			}
		}
	}
	return batches, next
}

// neighbor is a neighbor a usable link reaches, and the directory the
// link's attachment names.
type neighbor struct {
	ia addr.IA
	id bus.DirectoryID
}

// attachedNeighbors returns the neighbor each usable attached link
// reaches, by interface ID; none without the link state or the peer
// channel.
func (d *NodeDirectory) attachedNeighbors() map[uint16]neighbor {
	if d.cfg.Links == nil || d.cfg.Peer == nil {
		return nil
	}
	usable := usableNeighbors(d.cfg.Links.Latest())
	d.mtx.Lock()
	defer d.mtx.Unlock()
	out := make(map[uint16]neighbor, len(usable))
	for ifID, ia := range usable {
		if id, s := d.linkScopeLocked(ifID); s != nil {
			out[ifID] = neighbor{ia: ia, id: id}
		}
	}
	return out
}

// usableNeighbors returns the named neighbor each usable link reaches, by
// interface ID.
func usableNeighbors(state bus.LinkState) map[uint16]addr.IA {
	out := make(map[uint16]addr.IA)
	for ifID, ia := range state.Usable() {
		if !ia.IsZero() {
			out[ifID] = ia
		}
	}
	return out
}

// push hands each directory's entries to every neighbor a usable link of
// that directory reaches but the one each came from, and returns once
// every push answered or failed.
func (d *NodeDirectory) push(ctx context.Context, batches map[bus.DirectoryID][]*signedEntry) {
	var wg sync.WaitGroup
	for ifID, n := range d.attachedNeighbors() {
		var out []*cryptopb.SignedMessage
		for _, e := range batches[n.id] {
			if !e.from.Equal(n.ia) {
				out = append(out, e.msg)
			}
		}
		if len(out) == 0 {
			continue
		}
		wg.Go(func() {
			if err := d.pushTo(ctx, ifID, n.ia, out); err != nil {
				slog.Debug("Pushing directory entries", "neighbor", n.ia, "err", err)
			}
		})
	}
	wg.Wait()
}

// pushTo hands the entries to the neighbor over the link's one-hop
// channel, as many calls as the per-call bound asks.
func (d *NodeDirectory) pushTo(
	ctx context.Context, ifID uint16, ia addr.IA, entries []*cryptopb.SignedMessage,
) error {

	clt := d.client(ifID, ia)
	for chunk := range slices.Chunk(entries, maxEntriesPerCall) {
		callCtx, cancel := context.WithTimeout(ctx, entryCallTimeout)
		_, err := clt.Push(callCtx, &nodev1.PushRequest{Entries: chunk})
		cancel()
		if err != nil {
			return err
		}
	}
	return nil
}

// client returns the client of the neighbor's directory service over the
// link's one-hop channel, keyed by its encoded authority so the transport
// reuses the connection.
func (d *NodeDirectory) client(ifID uint16, ia addr.IA) nodev1connect.DirectoryServiceClient {
	authority := scionrpc.PeerAuthority(&scion.Addr{IA: ia, Service: addr.SvcCS, IfID: ifID})
	d.clientsMtx.Lock()
	defer d.clientsMtx.Unlock()
	clt, ok := d.clients[authority]
	if !ok {
		clt = nodev1connect.NewDirectoryServiceClient(connect.NewClient(
			connecthttp.NewTransport(d.cfg.Peer.OneHopClient(), "https://"+authority)))
		d.clients[authority] = clt
	}
	return clt
}

// caughtUp is one catch-up's outcome.
type caughtUp struct {
	ifID uint16
	ia   addr.IA
	err  error
}

// runCatchUp syncs summaries with each neighbor a usable link reaches: once
// the link appears, every summary period while it serves, and with every
// neighbor when the catch-up wakes — once the node first holds its chain,
// before which no neighbor's channel admitted the node, when a link joins
// another attachment, and at a merge. A failed catch-up retries from the
// retry interval, doubling up to the summary period. The catch-ups run off
// the loop, one per link at a time; the loop returns once every catch-up
// has.
func (d *NodeDirectory) runCatchUp(ctx context.Context) {
	if d.cfg.Links == nil || d.cfg.Peer == nil {
		<-ctx.Done()
		return
	}
	period := intervalOr(d.cfg.SummaryPeriod, EntrySummaryPeriod)
	retries := loops.Attempts[uint16]{
		Backoff: loops.Backoff{Base: intervalOr(d.cfg.Retry, EntryRetry), Max: period},
	}
	states := d.cfg.Links.Subscribe(ctx)
	// neighbors holds the neighbor each usable link reaches, next when each
	// link's catch-up is due — at once while it holds none — busy the links
	// whose catch-up runs, and again those whose catch-up is due at once
	// when it ends.
	neighbors := make(map[uint16]addr.IA)
	next := make(map[uint16]time.Time)
	busy := make(map[uint16]bool)
	again := make(map[uint16]bool)
	done := make(chan caughtUp)
	var wg sync.WaitGroup
	defer wg.Wait()
	timer := time.NewTimer(0)
	timer.Stop()
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case state, ok := <-states:
			if !ok {
				return
			}
			current := usableNeighbors(state)
			for ifID, ia := range neighbors {
				if current[ifID] != ia {
					delete(next, ifID)
					delete(again, ifID)
					retries.Forget(ifID)
				}
			}
			neighbors = current
		case <-d.catchUp:
			for ifID := range neighbors {
				delete(next, ifID)
				if busy[ifID] {
					again[ifID] = true
				}
			}
		case r := <-done:
			delete(busy, r.ifID)
			now := time.Now()
			switch {
			case neighbors[r.ifID] != r.ia:
			case again[r.ifID]:
				delete(again, r.ifID)
			case r.err != nil:
				slog.Debug("Catching the directory up", "neighbor", r.ia, "err", r.err)
				retries.Tried(r.ifID, now)
				next[r.ifID], _ = retries.Next(r.ifID)
			default:
				retries.Forget(r.ifID)
				next[r.ifID] = now.Add(period)
			}
		case <-timer.C:
		}
		now := time.Now()
		var wakeAt time.Time
		for ifID, ia := range neighbors {
			if busy[ifID] {
				continue
			}
			if at := next[ifID]; now.Before(at) {
				wakeAt = earliest(wakeAt, at)
				continue
			}
			busy[ifID] = true
			wg.Go(func() {
				err := d.syncWith(ctx, ifID, ia)
				select {
				case done <- caughtUp{ifID: ifID, ia: ia, err: err}:
				case <-ctx.Done():
				}
			})
		}
		if wakeAt.IsZero() {
			timer.Stop()
		} else {
			timer.Reset(time.Until(wakeAt))
		}
	}
}

// syncWith sends the neighbor the ID and the summary of the link's
// directory over the link's one-hop channel, keeps the lesser of the two
// ends' IDs, merges the entries it answers with, and pushes it the entries
// of the signers it names.
func (d *NodeDirectory) syncWith(ctx context.Context, ifID uint16, ia addr.IA) error {
	id, summaries, ok := d.summaries(ifID)
	if !ok {
		return errUnattached
	}
	callCtx, cancel := context.WithTimeout(ctx, entryCallTimeout)
	resp, err := d.client(ifID, ia).Sync(callCtx, &nodev1.SyncRequest{
		Directory: id[:],
		Summaries: summaries,
	})
	cancel()
	if err != nil {
		return err
	}
	peer, err := parseDirectoryID(resp.Directory)
	if err != nil {
		return err
	}
	if peer.IsZero() {
		return errors.New("the neighbor's answer names no directory")
	}
	if _, ok := d.adopt(ifID, peer); !ok {
		return errUnattached
	}
	entries := resp.Entries
	if len(entries) > maxEntriesPerCall {
		entries = entries[:maxEntriesPerCall]
	}
	d.accept(ctx, entries, ia, ifID)
	if wanted := d.held(ifID, resp.Wanted); len(wanted) != 0 {
		return d.pushTo(ctx, ifID, ia, wanted)
	}
	return nil
}

// summaries returns the ID of the directory of the link's attachment and
// the summary of every entry it holds, ordered by signer, at most as many
// as one call carries, and whether the link has an attachment.
func (d *NodeDirectory) summaries(ifID uint16) (bus.DirectoryID, []*nodev1.Summary, bool) {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	id, s := d.linkScopeLocked(ifID)
	if s == nil {
		return bus.DirectoryID{}, nil, false
	}
	out := make([]*nodev1.Summary, 0, len(s.entries))
	for _, signer := range slices.Sorted(maps.Keys(s.entries)) {
		out = append(out, s.entries[signer].summary())
	}
	if len(out) > maxEntriesPerCall {
		out = out[:maxEntriesPerCall]
	}
	return id, out, true
}

// held returns the entries the directory of the link's attachment holds of
// the signers named.
func (d *NodeDirectory) held(ifID uint16, signers []uint64) []*cryptopb.SignedMessage {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	_, s := d.linkScopeLocked(ifID)
	if s == nil {
		return nil
	}
	var out []*cryptopb.SignedMessage
	for _, signer := range signers {
		if e, ok := s.entries[addr.IA(signer)]; ok {
			out = append(out, e.msg)
		}
	}
	return out
}

// Push merges the pushed entries greater than the ones held into the
// directory of the link they arrived over, missing trust material asked of
// the neighbor that sent them over that link.
func (d *NodeDirectory) Push(
	ctx context.Context, req *nodev1.PushRequest,
) (*nodev1.PushResponse, error) {

	from, ifID, err := d.sender(ctx)
	if err != nil {
		return nil, err
	}
	if len(req.Entries) > maxEntriesPerCall {
		return nil, connect.NewError(connect.CodeResourceExhausted, fmt.Sprintf(
			"%d entries, past the %d one call carries", len(req.Entries), maxEntriesPerCall))
	}
	d.accept(ctx, req.Entries, from, ifID)
	return &nodev1.PushResponse{}, nil
}

// Sync keeps the lesser of the neighbor's directory ID for the link and
// the ID of the link's attachment, and answers the neighbor's summary of the
// link's directory with that ID, the entries the neighbor lacks or holds a
// lesser one of, and the signers whose entries the node lacks or holds a
// lesser one of.
func (d *NodeDirectory) Sync(
	ctx context.Context, req *nodev1.SyncRequest,
) (*nodev1.SyncResponse, error) {

	_, ifID, err := d.sender(ctx)
	if err != nil {
		return nil, err
	}
	if len(req.Summaries) > maxEntriesPerCall {
		return nil, connect.NewError(connect.CodeResourceExhausted, fmt.Sprintf(
			"%d summaries, past the %d one call carries", len(req.Summaries), maxEntriesPerCall))
	}
	peer, err := parseDirectoryID(req.Directory)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err.Error())
	}
	if peer.IsZero() {
		return nil, connect.NewError(connect.CodeInvalidArgument, "the request names no directory")
	}
	id, ok := d.adopt(ifID, peer)
	if !ok {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errUnattached.Error())
	}
	entries, wanted, ok := d.reconcile(ifID, req.Summaries, time.Now())
	if !ok {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errUnattached.Error())
	}
	return &nodev1.SyncResponse{Directory: id[:], Entries: entries, Wanted: wanted}, nil
}

// sender returns the authenticated neighbor a request came from and the
// interface of the link it arrived over: every call rides a link's one-hop
// channel.
func (d *NodeDirectory) sender(ctx context.Context) (addr.IA, uint16, error) {
	from := peeria.AuthenticatedIA(ctx)
	if from.IsZero() {
		return 0, 0, connect.NewError(connect.CodePermissionDenied,
			"no authenticated ISD-AS; the channel verified no chain")
	}
	if d.cfg.Trust == nil {
		return 0, 0, connect.NewError(connect.CodeUnavailable,
			"the node holds no trust to verify entries with")
	}
	remote := scionrpc.RemoteAddr(ctx)
	if remote == nil || remote.IfID == 0 {
		return 0, 0, connect.NewError(connect.CodePermissionDenied,
			"the call arrived over no link; the directory's calls ride a link's one-hop channel")
	}
	return from, remote.IfID, nil
}

// reconcile answers a summary of the link's directory: the entries of the
// signers whose entry the summary lacks or names a lesser one of, and the
// signers whose entry the directory lacks or holds a lesser one of, each
// ordered by signer; ok is false while the link has no attachment. The
// summary carries no signed bytes, so on a tie of TRC and signing time with
// a different digest each side sends its own and the join picks. A summary
// naming an entry the views, at now, never show again wants nothing.
func (d *NodeDirectory) reconcile(
	ifID uint16, theirs []*nodev1.Summary, now time.Time,
) ([]*cryptopb.SignedMessage, []uint64, bool) {

	named := make(map[addr.IA]*nodev1.Summary, len(theirs))
	for _, s := range theirs {
		named[addr.IA(s.IsdAs)] = s
	}
	d.mtx.Lock()
	defer d.mtx.Unlock()
	_, sc := d.linkScopeLocked(ifID)
	if sc == nil {
		return nil, nil, false
	}
	var entries []*cryptopb.SignedMessage
	for _, signer := range slices.Sorted(maps.Keys(sc.entries)) {
		e := sc.entries[signer]
		s, ok := named[signer]
		if !ok || e.key.compareSummary(s) > 0 || ties(e, s) {
			entries = append(entries, e.msg)
		}
	}
	if len(entries) > maxEntriesPerCall {
		entries = entries[:maxEntriesPerCall]
	}
	var wanted []uint64
	for _, signer := range slices.Sorted(maps.Keys(named)) {
		s := named[signer]
		if stale(time.Unix(0, s.SignedAt), now) {
			continue
		}
		e, ok := sc.entries[signer]
		if !ok || e.key.compareSummary(s) < 0 || ties(e, s) {
			wanted = append(wanted, uint64(signer))
		}
	}
	return entries, wanted, true
}

// ties reports whether the summary names an entry of the same TRC and
// signing time as the held one, with other signed bytes.
func ties(e *signedEntry, s *nodev1.Summary) bool {
	return e.key.compareSummary(s) == 0 && !bytes.Equal(e.digest[:], s.Digest)
}

func intervalOr(v, def time.Duration) time.Duration {
	if v == 0 {
		return def
	}
	return v
}
