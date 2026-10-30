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
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
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
	"github.com/fancl20/cion/pkg/modules/topology"
	nodev1 "github.com/fancl20/cion/proto/node/v1"
	nodev1connect "github.com/fancl20/cion/proto/node/v1/nodev1connect"
)

// The node directory's pacing: a node signs its entry every refresh interval
// and at each change of its own state, the view shows an entry for a
// lifetime past its signing, each end of a serving link sends the other its
// summary every summary period, and a node forwards each signer's entries at
// most once per forwarding bound.
const (
	// EntryRefreshInterval is how often a node signs its entry with no
	// change of its own state.
	EntryRefreshInterval = 5 * time.Minute
	// EntryLifetime is how long past its signing the view shows an entry.
	EntryLifetime = 15 * time.Minute
	// EntrySummaryPeriod is how often each end of a serving link sends the
	// other its summary.
	EntrySummaryPeriod = 5 * time.Minute
	// EntryForwardBound is the least time between two forwards of one
	// signer's entries.
	EntryForwardBound = 5 * time.Second
	// EntryRetry is how long the signing waits while the node's own state
	// is not ready — a chain the enrollment loop has not produced yet, a
	// host not resolved — and the first wait after a failed sync, the later
	// ones doubling up to the summary period.
	EntryRetry = 5 * time.Second
)

// entryFutureBound is how far past the node's clock an entry's signing time
// may lie for the view to show it: the allowance the node grants a beacon's
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

// errNotReady marks a signing waiting on the node's own state.
var errNotReady = errors.New("the node's entry is not ready")

// errWithdrawn marks a signing after the node withdrew its entry.
var errWithdrawn = errors.New("the node withdrew its entry")

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
	// Self is the topic of the node's own state: the host the entry names —
	// every socket keeps binding the control host whatever it names, and a
	// zero host signs nothing — and the rendezvous answer its report
	// carries. The node signs its entry at each event.
	Self *bus.Topic[bus.SelfState]
	// BehindNAT reports, at each signing, whether a NAT stands between the
	// node and its peers at the entry's host; an error fails the signing.
	// Nil reports none.
	BehindNAT func(host netip.Addr) (bool, error)
	// Trust signs the node's entries and verifies its neighbors'; nil signs
	// and accepts none.
	Trust DirectoryTrust
	// Links is the link state topic: entries travel to the neighbors its
	// usable links reach. Nil reaches none.
	Links *bus.Topic[bus.LinkState]
	// Peer is the node's channel to its peers, whose one-hop side the pushes
	// and the syncs ride; nil reaches no neighbor.
	Peer topology.PeerChannel
	// Directory is the node directory topic the view is published on; nil
	// publishes none.
	Directory *bus.Topic[bus.Directory]
	// Retry, ForwardBound, and SummaryPeriod override the defaults; zero
	// keeps them.
	Retry         time.Duration
	ForwardBound  time.Duration
	SummaryPeriod time.Duration
}

// NodeDirectory is the node's copy of the node directory: each signer's
// greatest signed entry, merged by the order alone. It signs the node's own
// entry, merges the greater entries its neighbors push once they verify,
// floods them along the links, catches each link's two ends up with a sync
// of summaries, and publishes its view on the node bus. The measured
// provider runs it on every node and serves its DirectoryService.
type NodeDirectory struct {
	cfg NodeDirectoryConfig

	// mtx guards the entries and the forwarding state.
	mtx sync.Mutex
	// entries holds each signer's greatest entry.
	entries map[addr.IA]*signedEntry
	// due marks the signers whose greatest entry waits to be forwarded, and
	// lastForward holds when each signer's entry was forwarded last.
	due         map[addr.IA]bool
	lastForward map[addr.IA]time.Time

	// viewWake, forwardWake, and catchUp wake the loops: an entry merged, an
	// entry due, and the node's first signing, before which no neighbor's
	// channel admitted it.
	viewWake    chan struct{}
	forwardWake chan struct{}
	catchUp     chan struct{}

	// signMtx serializes the node's signings; signed records that one
	// landed, and withdrawn that the node withdrew its entry, after which it
	// signs no other.
	signMtx   sync.Mutex
	signed    bool
	withdrawn bool

	// clients holds the one-hop client of each neighbor's directory
	// service, by encoded authority.
	clientsMtx sync.Mutex
	clients    map[string]nodev1connect.DirectoryServiceClient
}

var _ nodev1connect.DirectoryServiceHandler = (*NodeDirectory)(nil)

// NewNodeDirectory returns the node's directory, holding no entry.
func NewNodeDirectory(cfg NodeDirectoryConfig) *NodeDirectory {
	return &NodeDirectory{
		cfg:         cfg,
		entries:     make(map[addr.IA]*signedEntry),
		due:         make(map[addr.IA]bool),
		lastForward: make(map[addr.IA]time.Time),
		viewWake:    make(chan struct{}, 1),
		forwardWake: make(chan struct{}, 1),
		catchUp:     make(chan struct{}, 1),
		clients:     make(map[string]nodev1connect.DirectoryServiceClient),
	}
}

// signedEntry is one signer's signed entry as the directory holds it.
type signedEntry struct {
	msg *cryptopb.SignedMessage
	// signer and key are read from the header before verification; digest
	// is the SHA-256 of the signed bytes.
	signer addr.IA
	key    entryKey
	digest [sha256.Size]byte
	// withdrawn and entry are the verified body: a withdrawal, naming no
	// address, or the bus form of the addresses and the report it carries.
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

// read records the verified body: a withdrawal when it names no address.
// A body naming another ISD-AS than its signer, one address alone, or a
// malformed address fails.
func (e *signedEntry) read(body *nodev1.Entry) error {
	if ia := addr.IA(body.IsdAs); !ia.Equal(e.signer) {
		return fmt.Errorf("the body names %v, signed by %v", ia, e.signer)
	}
	e.withdrawn = body.ControlAddr == "" && body.RendezvousAddr == ""
	if e.withdrawn {
		return nil
	}
	control, err := netip.ParseAddrPort(body.ControlAddr)
	if err != nil {
		return fmt.Errorf("parsing the control address: %w", err)
	}
	rendezvous, err := netip.ParseAddrPort(body.RendezvousAddr)
	if err != nil {
		return fmt.Errorf("parsing the rendezvous address: %w", err)
	}
	e.entry = bus.DirectoryEntry{
		IA:             e.signer,
		ControlAddr:    control,
		RendezvousAddr: rendezvous,
		Reach: bus.Reach{
			BehindNAT:            body.BehindNat,
			RendezvousUnanswered: body.RendezvousUnanswered,
		},
		Published: e.key.signedAt,
	}
	return nil
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

// Run signs the node's entry, keeps the view, forwards the merged entries,
// and catches each link's two ends up until the context is canceled,
// returning once every loop has returned.
func (d *NodeDirectory) Run(ctx context.Context) {
	var wg sync.WaitGroup
	loops.Go(ctx, &wg, "node directory signing", d.runSign)
	loops.Go(ctx, &wg, "node directory view", d.runView)
	loops.Go(ctx, &wg, "node directory forwarding", d.runForward)
	loops.Go(ctx, &wg, "node directory catch-up", d.runCatchUp)
	wg.Wait()
}

// Withdraw signs the node's withdrawal, an entry naming no address, and
// pushes it to every neighbor a usable link reaches, returning once each
// push answered or ctx ended; the node signs no entry after it. A node that
// never signed its entry withdraws nothing.
func (d *NodeDirectory) Withdraw(ctx context.Context) {
	if !d.hasSigned() {
		return
	}
	e, err := d.sign(ctx, func() (*nodev1.Entry, error) {
		return &nodev1.Entry{IsdAs: uint64(d.cfg.IA)}, nil
	})
	if err != nil {
		slog.Warn("Withdrawing the node's directory entry", "err", err)
		return
	}
	if e == nil {
		return
	}
	d.push(ctx, []*signedEntry{e})
	slog.Info("Withdrew the node's directory entry")
}

// runSign signs the node's entry once its own state is ready, again at each
// event of that state, and every refresh interval; each signing names the
// newest TRC the node pins. A signing that waits on the node's own state, or
// fails, retries at the retry interval.
func (d *NodeDirectory) runSign(ctx context.Context) {
	retry := intervalOr(d.cfg.Retry, EntryRetry)
	var self <-chan bus.SelfState
	if d.cfg.Self != nil {
		self = d.cfg.Self.Subscribe(ctx)
		// The subscription delivers the state as it stands, which the first
		// signing reads anyway.
		select {
		case <-self:
		default:
		}
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-self:
			if !ok {
				return
			}
		case <-timer.C:
		}
		wait := EntryRefreshInterval
		err := d.signOwn(ctx)
		switch {
		case errors.Is(err, errWithdrawn):
			<-ctx.Done()
			return
		case err != nil:
			slog.Debug("Signing the node's directory entry", "err", err)
			wait = retry
		}
		timer.Reset(wait)
	}
}

// signOwn signs the node's entry as its own state reads now: a host that
// did not resolve signs nothing.
func (d *NodeDirectory) signOwn(ctx context.Context) error {
	self := d.cfg.Self.Latest()
	if !self.Host.IsValid() {
		return fmt.Errorf("%w: the entry's host did not resolve", errNotReady)
	}
	_, err := d.sign(ctx, func() (*nodev1.Entry, error) { return d.ownBody(self) })
	return err
}

// ownBody returns the node's entry as the state names it: the endpoint and
// rendezvous ports on its host, and its report of whether a NAT stands in
// front of that host and whether its rendezvous answered.
func (d *NodeDirectory) ownBody(self bus.SelfState) (*nodev1.Entry, error) {
	behindNAT := false
	if d.cfg.BehindNAT != nil {
		var err error
		if behindNAT, err = d.cfg.BehindNAT(self.Host); err != nil {
			return nil, fmt.Errorf("reporting the entry's reach: %w", err)
		}
	}
	return &nodev1.Entry{
		IsdAs:                uint64(d.cfg.IA),
		ControlAddr:          netip.AddrPortFrom(self.Host, scionrpc.EndpointPort).String(),
		RendezvousAddr:       netip.AddrPortFrom(self.Host, RendezvousPort).String(),
		BehindNat:            behindNAT,
		RendezvousUnanswered: self.RendezvousUnanswered,
	}, nil
}

// sign signs the body build returns as the node's entry, once the node holds
// a chain to sign with and its clock passed the held entry's signing time,
// merges it, and returns it: nil when it lost to an entry of the node's own
// signed later by its clock. After a withdrawal the node signs nothing.
func (d *NodeDirectory) sign(
	ctx context.Context, build func() (*nodev1.Entry, error),
) (*signedEntry, error) {

	if d.cfg.Trust == nil {
		return nil, fmt.Errorf("%w: no trust to sign with", errNotReady)
	}
	d.signMtx.Lock()
	defer d.signMtx.Unlock()
	if d.withdrawn {
		return nil, errWithdrawn
	}
	signer, err := d.cfg.Trust.Signer(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errNotReady, err)
	}
	if wait := d.ownSigningWait(time.Now()); wait > 0 && !loops.Sleep(ctx, wait) {
		return nil, ctx.Err()
	}
	body, err := build()
	if err != nil {
		return nil, err
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
	if !d.merge(e) {
		slog.Warn("The node's new directory entry lost to one of its own signed "+
			"later by its clock; the clock may have stepped back",
			"signed_at", e.key.signedAt)
		return nil, nil
	}
	if !d.signed {
		d.signed = true
		wake(d.catchUp)
	}
	d.withdrawn = e.withdrawn
	return e, nil
}

// ownClockSlack is how far the node's clock may stand behind the signing
// time of the node's held entry for a signing to wait it out.
const ownClockSlack = time.Second

// ownSigningWait returns how long a signing at now waits for the node's
// clock to pass the signing time of the node's held entry, so the node's
// entries grow by their signing time: none when the clock passed it, or
// when the clock stands ownClockSlack or more behind it.
func (d *NodeDirectory) ownSigningWait(now time.Time) time.Duration {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	held, ok := d.entries[d.cfg.IA]
	if !ok || now.After(held.key.signedAt) {
		return 0
	}
	if wait := held.key.signedAt.Sub(now) + time.Nanosecond; wait < ownClockSlack {
		return wait
	}
	return 0
}

// hasSigned reports whether the node signed its entry since it started.
func (d *NodeDirectory) hasSigned() bool {
	d.signMtx.Lock()
	defer d.signMtx.Unlock()
	return d.signed
}

// wins reports whether the entry is greater than the one held of its
// signer.
func (d *NodeDirectory) wins(e *signedEntry) bool {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	held, ok := d.entries[e.signer]
	return !ok || e.key.compare(held.key) > 0
}

// merge keeps the entry when it is greater than the one held of its signer,
// schedules its forward, wakes the view, and reports whether it kept it.
func (d *NodeDirectory) merge(e *signedEntry) bool {
	d.mtx.Lock()
	held, ok := d.entries[e.signer]
	if ok && e.key.compare(held.key) <= 0 {
		d.mtx.Unlock()
		return false
	}
	d.entries[e.signer] = e
	d.due[e.signer] = true
	d.mtx.Unlock()
	wake(d.viewWake)
	wake(d.forwardWake)
	return true
}

// wake sends on a wake channel without blocking: a wake already pending
// carries this one.
func wake(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// accept merges the pushed entries greater than the ones held, each once
// it verifies against a chain of its signer valid at its signing time,
// missing trust material asked of server, and returns how many it merged.
// An entry the view would never show again is discarded on arrival, as the
// directory discards it once held, and one that cannot win is never
// verified.
func (d *NodeDirectory) accept(
	ctx context.Context, msgs []*cryptopb.SignedMessage, from addr.IA, server net.Addr,
) int {

	if d.cfg.Trust == nil {
		return 0
	}
	now := time.Now()
	merged := 0
	for _, msg := range msgs {
		e, err := parseEntry(msg)
		if err != nil {
			slog.Debug("Refusing a malformed directory entry", "from", from, "err", err)
			continue
		}
		if stale(e.key.signedAt, now) || !d.wins(e) {
			continue
		}
		if err := d.verify(ctx, e, server); err != nil {
			slog.Debug("Refusing a directory entry", "signer", e.signer, "from", from,
				"err", err)
			continue
		}
		e.from = from
		if !d.merge(e) {
			continue
		}
		merged++
		if e.signer.Equal(d.cfg.IA) && d.hasSigned() {
			slog.Warn("The directory holds an entry of the node's own signed later "+
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

// stale reports whether the view, at now, never shows again an entry signed
// at signedAt: one signed two lifetimes back or more, a lifetime past its
// leaving the window.
func stale(signedAt, now time.Time) bool {
	return !signedAt.After(now.Add(-2 * EntryLifetime))
}

// runView publishes the view on the directory topic whenever it changes: at
// each merged entry, and when an entry enters or leaves the window. Each
// pass discards the entries the view never shows again.
func (d *NodeDirectory) runView(ctx context.Context) {
	var shown map[addr.IA]*signedEntry
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-d.viewWake:
		case <-timer.C:
		}
		view, next := d.pass(time.Now())
		if !sameView(shown, view) {
			d.publish(view)
			shown = view
		}
		if next.IsZero() {
			timer.Stop()
		} else {
			timer.Reset(time.Until(next))
		}
	}
}

// pass discards the entries the view never shows again at now, and returns
// the view at now and when the clock alone changes it next.
func (d *NodeDirectory) pass(now time.Time) (map[addr.IA]*signedEntry, time.Time) {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	for signer, e := range d.entries {
		if stale(e.key.signedAt, now) {
			delete(d.entries, signer)
			delete(d.due, signer)
		}
	}
	return d.viewLocked(now)
}

// viewLocked returns the entries the view shows at now, by signer, and when
// the clock alone changes the view next — the earliest shown entry leaving
// the window, or held one entering it — the zero time when it never does.
// The view shows each signer's entry that is no withdrawal and was signed
// less than a lifetime before now and no later than the future bound after
// it, whatever TRC it names. The caller holds the directory's lock.
func (d *NodeDirectory) viewLocked(now time.Time) (map[addr.IA]*signedEntry, time.Time) {
	view := make(map[addr.IA]*signedEntry)
	var next time.Time
	for signer, e := range d.entries {
		if e.withdrawn {
			continue
		}
		enters := e.key.signedAt.Add(-entryFutureBound)
		leaves := e.key.signedAt.Add(EntryLifetime)
		switch {
		case now.Before(enters):
			next = earliest(next, enters)
		case now.Before(leaves):
			view[signer] = e
			next = earliest(next, leaves)
		}
	}
	return view, next
}

// sameView reports whether two views show the same entries.
func sameView(a, b map[addr.IA]*signedEntry) bool {
	if len(a) != len(b) {
		return false
	}
	for signer, e := range a {
		if b[signer] != e {
			return false
		}
	}
	return true
}

// publish publishes the view on the directory topic, its entries ordered by
// ISD-AS.
func (d *NodeDirectory) publish(view map[addr.IA]*signedEntry) {
	if d.cfg.Directory == nil {
		return
	}
	entries := make([]bus.DirectoryEntry, 0, len(view))
	for _, e := range view {
		entries = append(entries, e.entry)
	}
	slices.SortFunc(entries, func(a, b bus.DirectoryEntry) int { return cmp.Compare(a.IA, b.IA) })
	d.cfg.Directory.Publish(bus.NewDirectory(entries...))
}

// runForward forwards each signer's greatest entry once it is due: at once
// when the signer's last forward lies a bound back, else at the bound's end,
// the entry then greatest travelling. Each pass pushes the due entries to
// every neighbor a usable link reaches but the one each came from.
func (d *NodeDirectory) runForward(ctx context.Context) {
	bound := intervalOr(d.cfg.ForwardBound, EntryForwardBound)
	timer := time.NewTimer(0)
	timer.Stop()
	defer timer.Stop()
	for {
		batch, next := d.dueEntries(time.Now(), bound)
		if len(batch) != 0 {
			d.push(ctx, batch)
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

// dueEntries returns the greatest entry of each signer due at now, marking
// it forwarded, and when the next signer waiting on its bound is due.
func (d *NodeDirectory) dueEntries(
	now time.Time, bound time.Duration,
) ([]*signedEntry, time.Time) {

	d.mtx.Lock()
	defer d.mtx.Unlock()
	var batch []*signedEntry
	var next time.Time
	for signer := range d.due {
		if at := d.lastForward[signer].Add(bound); now.Before(at) {
			next = earliest(next, at)
			continue
		}
		delete(d.due, signer)
		if e, ok := d.entries[signer]; ok {
			batch = append(batch, e)
			d.lastForward[signer] = now
		}
	}
	for signer, at := range d.lastForward {
		if !d.due[signer] && !now.Before(at.Add(bound)) {
			delete(d.lastForward, signer)
		}
	}
	return batch, next
}

// neighbors returns the neighbor each usable link reaches, by interface ID;
// none without the link state or the peer channel.
func (d *NodeDirectory) neighbors() map[uint16]addr.IA {
	if d.cfg.Links == nil || d.cfg.Peer == nil {
		return nil
	}
	return usableNeighbors(d.cfg.Links.Latest())
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

// push hands the entries to every neighbor a usable link reaches but the
// one each came from, and returns once every push answered or failed.
func (d *NodeDirectory) push(ctx context.Context, entries []*signedEntry) {
	var wg sync.WaitGroup
	for ifID, ia := range d.neighbors() {
		var out []*cryptopb.SignedMessage
		for _, e := range entries {
			if !e.from.Equal(ia) {
				out = append(out, e.msg)
			}
		}
		if len(out) == 0 {
			continue
		}
		wg.Go(func() {
			if err := d.pushTo(ctx, ifID, ia, out); err != nil {
				slog.Debug("Pushing directory entries", "neighbor", ia, "err", err)
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

// synced is one sync's outcome.
type synced struct {
	ifID uint16
	ia   addr.IA
	err  error
}

// runCatchUp syncs summaries with each neighbor a usable link reaches: once
// the link appears, every summary period while it serves, and with every
// neighbor at the node's first signing, before which no neighbor's channel
// admitted the node. A failed sync retries from the retry interval,
// doubling up to the summary period. The syncs run off the loop, one per
// link at a time; the loop returns once every sync has.
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
	// link's sync is due — at once while it holds none — busy the links whose
	// sync runs, and again those whose sync is due at once when it ends.
	neighbors := make(map[uint16]addr.IA)
	next := make(map[uint16]time.Time)
	busy := make(map[uint16]bool)
	again := make(map[uint16]bool)
	done := make(chan synced)
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
				slog.Debug("Syncing the directory", "neighbor", r.ia, "err", r.err)
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
				case done <- synced{ifID: ifID, ia: ia, err: err}:
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

// syncWith sends the neighbor the node's summary over the link's one-hop
// channel, merges the entries it answers with, and pushes it the entries of
// the signers it names.
func (d *NodeDirectory) syncWith(ctx context.Context, ifID uint16, ia addr.IA) error {
	callCtx, cancel := context.WithTimeout(ctx, entryCallTimeout)
	resp, err := d.client(ifID, ia).Sync(callCtx, &nodev1.SyncRequest{
		Summaries: d.summaries(),
	})
	cancel()
	if err != nil {
		return err
	}
	entries := resp.Entries
	if len(entries) > maxEntriesPerCall {
		entries = entries[:maxEntriesPerCall]
	}
	d.accept(ctx, entries, ia, &scion.Addr{IA: ia, Service: addr.SvcCS, IfID: ifID})
	if wanted := d.held(resp.Wanted); len(wanted) != 0 {
		return d.pushTo(ctx, ifID, ia, wanted)
	}
	return nil
}

// summaries returns the summary of every entry the directory holds, ordered
// by signer, at most as many as one call carries.
func (d *NodeDirectory) summaries() []*nodev1.Summary {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	out := make([]*nodev1.Summary, 0, len(d.entries))
	for _, signer := range slices.Sorted(maps.Keys(d.entries)) {
		out = append(out, d.entries[signer].summary())
	}
	if len(out) > maxEntriesPerCall {
		out = out[:maxEntriesPerCall]
	}
	return out
}

// held returns the entries the directory holds of the signers named.
func (d *NodeDirectory) held(signers []uint64) []*cryptopb.SignedMessage {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	var out []*cryptopb.SignedMessage
	for _, s := range signers {
		if e, ok := d.entries[addr.IA(s)]; ok {
			out = append(out, e.msg)
		}
	}
	return out
}

// Push merges the pushed entries greater than the ones held, missing trust
// material asked of the neighbor that sent them, over the link they arrived
// on.
func (d *NodeDirectory) Push(
	ctx context.Context, req *nodev1.PushRequest,
) (*nodev1.PushResponse, error) {

	from, server, err := d.sender(ctx)
	if err != nil {
		return nil, err
	}
	if len(req.Entries) > maxEntriesPerCall {
		return nil, connect.NewError(connect.CodeResourceExhausted, fmt.Sprintf(
			"%d entries, past the %d one call carries", len(req.Entries), maxEntriesPerCall))
	}
	d.accept(ctx, req.Entries, from, server)
	return &nodev1.PushResponse{}, nil
}

// Sync answers the neighbor's summary with the entries the neighbor lacks
// or holds a lesser one of, and names the signers whose entries the node
// lacks or holds a lesser one of.
func (d *NodeDirectory) Sync(
	ctx context.Context, req *nodev1.SyncRequest,
) (*nodev1.SyncResponse, error) {

	if _, _, err := d.sender(ctx); err != nil {
		return nil, err
	}
	if len(req.Summaries) > maxEntriesPerCall {
		return nil, connect.NewError(connect.CodeResourceExhausted, fmt.Sprintf(
			"%d summaries, past the %d one call carries", len(req.Summaries), maxEntriesPerCall))
	}
	entries, wanted := d.reconcile(req.Summaries, time.Now())
	return &nodev1.SyncResponse{Entries: entries, Wanted: wanted}, nil
}

// sender returns the authenticated neighbor a request came from and the
// control service that holds the trust material its entries rest on: the
// neighbor's, over the link the request arrived on.
func (d *NodeDirectory) sender(ctx context.Context) (addr.IA, net.Addr, error) {
	from := peeria.AuthenticatedIA(ctx)
	if from.IsZero() {
		return 0, nil, connect.NewError(connect.CodePermissionDenied,
			"no authenticated ISD-AS; the channel verified no chain")
	}
	if d.cfg.Trust == nil {
		return 0, nil, connect.NewError(connect.CodeUnavailable,
			"the node holds no trust to verify entries with")
	}
	server := &scion.Addr{IA: from, Service: addr.SvcCS}
	if remote := scionrpc.RemoteAddr(ctx); remote != nil {
		server.IfID, server.Path = remote.IfID, remote.Path
	}
	return from, server, nil
}

// reconcile answers a summary: the entries of the signers whose entry the
// summary lacks or names a lesser one of, and the signers whose entry the
// directory lacks or holds a lesser one of, each ordered by signer. The
// summary carries no signed bytes, so on a tie of TRC and signing time with
// a different digest each side sends its own and the join picks. A summary
// naming an entry the view, at now, never shows again wants nothing.
func (d *NodeDirectory) reconcile(
	theirs []*nodev1.Summary, now time.Time,
) ([]*cryptopb.SignedMessage, []uint64) {

	named := make(map[addr.IA]*nodev1.Summary, len(theirs))
	for _, s := range theirs {
		named[addr.IA(s.IsdAs)] = s
	}
	d.mtx.Lock()
	defer d.mtx.Unlock()
	var entries []*cryptopb.SignedMessage
	for _, signer := range slices.Sorted(maps.Keys(d.entries)) {
		e := d.entries[signer]
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
		e, ok := d.entries[signer]
		if !ok || e.key.compareSummary(s) < 0 || ties(e, s) {
			wanted = append(wanted, uint64(signer))
		}
	}
	return entries, wanted
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
