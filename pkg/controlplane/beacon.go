package controlplane

import (
	"context"
	"hash"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/pathdb"
	"github.com/fancl20/cion/pkg/segment"
	"github.com/fancl20/cion/pkg/trust"
)

const (
	// PropagationInterval is the beaconing period: the draft's intra-ISD
	// floor of five seconds (Section 2.3.4).
	PropagationInterval = 5 * time.Second

	// RegistrationInterval is the registration period (Section 3.1), on the
	// order of a minute.
	RegistrationInterval = time.Minute

	// BestSetSize is the fixed bounded set of PCBs selected for forwarding
	// and termination (ADR-0004: no policy engine, no per-policy
	// configuration).
	BestSetSize = 5

	// SendTimeout bounds each beacon and registration RPC: a wedged
	// connection must not stall the loop that sends it.
	SendTimeout = 5 * time.Second
)

// clockSkewAllowance is how far in the future a PCB timestamp may lie; the
// draft recommends the hop-field expiration time as the allowance (Section
// 2.2.4).
var clockSkewAllowance = path.ExpTimeToDuration(0)

// SegmentSender sends beacon and registration RPCs over the SCION-native
// channel; PeerClient satisfies it.
type SegmentSender interface {
	// Beacon propagates the extended PCB to the peer's beacon service.
	Beacon(ctx context.Context, peer *Addr, pcb *control_plane.PathSegment) error
	// RegisterSegments registers down segments with the core's control
	// service.
	RegisterSegments(ctx context.Context, peer *Addr,
		segments []*control_plane.PathSegment) error
}

// Beaconer runs ADR-0004's exploration: the founding core originates signed
// path-segment beacons on its links, every node verifies the accumulated
// signatures against the TRC before storing or propagating them, propagation
// floods outward with the TRC naming the cores whose interfaces are pruned,
// and non-cores terminate accepted beacons into registered segments. Link
// roles are not configured: the interface a beacon arrives on is the node's
// parent side, the interfaces beacons are propagated to are child sides, and
// a link whose neighbor the TRC names as a core is a core link.
type Beaconer struct {
	ia           addr.IA
	engine       *trust.Engine
	macFactory   func() hash.Hash
	store        *BeaconStore
	db           pathdb.DB
	links        map[uint16]addr.IA
	neighbors    func() map[uint16]Neighbor
	sender       SegmentSender
	coreRoute    func() *Addr
	core         bool
	propagation  time.Duration
	registration time.Duration
	sendTimeout  time.Duration
	now          func() time.Time

	// bootstrap keeps the freshest unverified beacon and the interface it
	// arrived on: a fresh node receives beacons before it has pinned the TRC
	// and may use their reversed path — extended with its own hop — as the
	// route for its enrollment fetch; never for storing, propagating, or
	// registering (proposal 0004).
	bootstrapMtx     sync.Mutex
	bootstrap        *segment.PCB
	bootstrapIngress uint16
}

// BeaconerConfig configures a Beaconer.
type BeaconerConfig struct {
	// IA is the local ISD-AS.
	IA addr.IA
	// Engine signs AS entries and verifies received ones.
	Engine *trust.Engine
	// MACKey is the data-plane forwarding key, MACing created hop fields
	// with the same algorithm the processor verifies.
	MACKey []byte
	// Store is the in-memory beacon store for candidates.
	Store *BeaconStore
	// DB is the persistent path database for registered segments.
	DB pathdb.DB
	// Links maps each external interface ID to the IA of the neighbor.
	Links map[uint16]addr.IA
	// Neighbors returns the currently discovered neighbors; nil disables
	// sending beacons (reception still works).
	Neighbors func() map[uint16]Neighbor
	// Sender sends beacon and registration RPCs over the SCION-native
	// channel.
	Sender SegmentSender
	// CoreRoute resolves the core's endpoint — the one-hop path when the
	// core is a neighbor, else the provider's route.
	CoreRoute func() *Addr
	// Core marks the founding core, which originates beacons.
	Core bool
	// PropagationInterval and RegistrationInterval override the defaults;
	// zero keeps them.
	PropagationInterval  time.Duration
	RegistrationInterval time.Duration
	// Now is the clock; nil uses time.Now.
	Now func() time.Time
	// SendTimeout bounds each RPC; zero uses the default.
	SendTimeout time.Duration
}

// NewBeaconer returns a beaconer with the defaults filled in.
func NewBeaconer(cfg BeaconerConfig) (*Beaconer, error) {
	if _, err := scrypto.InitMac(cfg.MACKey); err != nil {
		return nil, serrors.Wrap("initializing MAC", err)
	}
	macFactory := func() hash.Hash {
		mac, _ := scrypto.InitMac(cfg.MACKey)
		return mac
	}
	propagation := cfg.PropagationInterval
	if propagation == 0 {
		propagation = PropagationInterval
	}
	registration := cfg.RegistrationInterval
	if registration == 0 {
		registration = RegistrationInterval
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	sendTimeout := cfg.SendTimeout
	if sendTimeout == 0 {
		sendTimeout = SendTimeout
	}
	return &Beaconer{
		ia:           cfg.IA,
		engine:       cfg.Engine,
		macFactory:   macFactory,
		store:        cfg.Store,
		db:           cfg.DB,
		links:        cfg.Links,
		neighbors:    cfg.Neighbors,
		sender:       cfg.Sender,
		coreRoute:    cfg.CoreRoute,
		core:         cfg.Core,
		propagation:  propagation,
		registration: registration,
		sendTimeout:  sendTimeout,
		now:          now,
	}, nil
}

// Run executes the beaconing loops until the context is canceled: origination
// on the core or propagation elsewhere, registration, and the expired-
// segment sweep of the path database.
func (b *Beaconer) Run(ctx context.Context) {
	if b.core {
		go b.loop(ctx, b.propagation, b.originateOnce)
		go b.loop(ctx, b.registration, b.registerCoreOnce)
	} else {
		go b.loop(ctx, b.propagation, b.propagateOnce)
		go b.loop(ctx, b.registration, b.registerOnce)
	}
	go b.loop(ctx, b.registration, b.sweepOnce)
	<-ctx.Done()
}

func (b *Beaconer) loop(ctx context.Context, interval time.Duration, f func(context.Context)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			f(ctx)
		}
	}
}

// HandleBeacon applies the reception checks of Section 2.3.1 to the received
// PCB and stores it as a candidate. A node that has not pinned the TRC
// cannot verify beacons; it records the freshest one as its bootstrap route
// for the enrollment fetch instead.
func (b *Beaconer) HandleBeacon(
	ctx context.Context,
	pcb *segment.PCB,
	ingress uint16,
) error {

	if err := b.checkBeacon(pcb, ingress); err != nil {
		return err
	}
	if !b.trcPinned() {
		b.recordBootstrap(ingress, pcb)
		return nil
	}
	if err := b.verifySignatures(ctx, pcb); err != nil {
		return err
	}
	b.store.Insert(ingress, pcb)
	return nil
}

// HandleRegistration verifies a down segment registered with this core and
// stores it in the path database (Sections 3.1.3 and 3.3).
func (b *Beaconer) HandleRegistration(
	ctx context.Context,
	pb *control_plane.PathSegment,
) error {

	pcb, err := segment.ParsePCB(pb)
	if err != nil {
		return serrors.Wrap("parsing registered segment", err)
	}
	if err := b.checkRegistered(pcb); err != nil {
		return err
	}
	if err := b.verifySignatures(ctx, pcb); err != nil {
		return err
	}
	seg, err := pathdb.NewSegment(pathdb.SegmentTypeDown, pb)
	if err != nil {
		return err
	}
	if _, err := b.db.Insert(ctx, seg); err != nil {
		return serrors.Wrap("storing down segment", err)
	}
	return nil
}

// BootstrapRoute returns the reversed data-plane path of the freshest
// unverified beacon originating at dst, extended with the node's own
// unsigned hop — the route of a node that has not yet verified any up
// segment to that core: its enrollment fetch and the trust fetches around
// it ride it, all protected by the WebPKI-authenticated channel. It is
// never stored, propagated, or registered, serves only its originating
// core, and verified up segments take over the moment one exists.
func (b *Beaconer) BootstrapRoute(dst addr.IA) *scion.Decoded {
	b.bootstrapMtx.Lock()
	defer b.bootstrapMtx.Unlock()
	if b.bootstrap == nil || !b.bootstrap.Expiration().After(b.now()) {
		return nil
	}
	if !b.bootstrap.FirstIA().Equal(dst) {
		return nil
	}
	route, err := b.bootstrap.Clone()
	if err != nil {
		return nil
	}
	if _, err := route.AppendRouteHop(b.ia, segment.EntryOptions{
		IngressIfID: b.bootstrapIngress,
	}, b.macFactory); err != nil {
		return nil
	}
	return route.ReversePath()
}

func (b *Beaconer) recordBootstrap(ingress uint16, pcb *segment.PCB) {
	b.bootstrapMtx.Lock()
	defer b.bootstrapMtx.Unlock()
	if b.bootstrap == nil || pcb.Timestamp().After(b.bootstrap.Timestamp()) {
		b.bootstrap = pcb
		b.bootstrapIngress = ingress
	}
}

// checkBeacon applies the structural reception checks of Section 2.3.1: PCB
// validity in time, loop prevention, the identity-to-link binding of the
// arrival interface (the check ADR-0003 deferred to the first signed
// control-plane message), and entry continuity. Under emergent link roles
// the arrival interface is by definition the parent side, so no link-type
// check exists to apply.
func (b *Beaconer) checkBeacon(pcb *segment.PCB, ingress uint16) error {
	if len(pcb.Entries) == 0 {
		return serrors.New("beacon without AS entries")
	}
	// Loop prevention: the general case of the draft's core check — a
	// segment already containing the local ISD-AS is discarded, so the core
	// drops any beacon containing itself.
	if pcb.ContainsIA(b.ia) {
		return serrors.New("beacon already contains this ISD-AS", "isd_as", b.ia)
	}
	neighbor, ok := b.links[ingress]
	if !ok {
		return serrors.New("beacon arrived on unknown interface", "interface", ingress)
	}
	if last := pcb.LastIA(); !last.Equal(neighbor) {
		return serrors.New("last AS entry does not match the neighbor of the arrival interface",
			"interface", ingress, "expected", neighbor, "actual", last)
	}
	if err := checkContinuity(pcb); err != nil {
		return err
	}
	return checkTimeWindow(pcb, b.now())
}

// checkRegistered applies the receiving core's checks to a registered down
// segment (Section 3.1.3): verification as on beacon reception, plus the
// first AS entry naming this core. The loop check does not apply — the
// segment is addressed to this core.
func (b *Beaconer) checkRegistered(pcb *segment.PCB) error {
	if len(pcb.Entries) == 0 {
		return serrors.New("registered segment without AS entries")
	}
	if first := pcb.FirstIA(); !first.Equal(b.ia) {
		return serrors.New("registered segment does not originate at this core",
			"expected", b.ia, "actual", first)
	}
	if err := checkContinuity(pcb); err != nil {
		return err
	}
	return checkTimeWindow(pcb, b.now())
}

// checkContinuity checks that consecutive AS entries chain (Section 2.3.1,
// check 4).
func checkContinuity(pcb *segment.PCB) error {
	for i := 0; i < len(pcb.Entries)-1; i++ {
		if next := pcb.Entries[i].Next; !next.Equal(pcb.Entries[i+1].IA) {
			return serrors.New("consecutive AS entries do not chain",
				"index", i, "next", next, "actual", pcb.Entries[i+1].IA)
		}
	}
	return nil
}

// checkTimeWindow checks the PCB validity of Section 2.2.4: the timestamp
// must not lie in the future beyond the clock-skew allowance, and no hop may
// be expired.
func checkTimeWindow(pcb *segment.PCB, now time.Time) error {
	if pcb.Timestamp().After(now.Add(clockSkewAllowance)) {
		return serrors.New("beacon timestamp is in the future",
			"timestamp", pcb.Timestamp(), "now", now)
	}
	if !pcb.Expiration().After(now) {
		return serrors.New("beacon has an expired hop", "expiration", pcb.Expiration())
	}
	return nil
}

// verifySignatures verifies every AS entry's signature against the
// TRC-anchored chain the entry references, fetching missing chains through
// the provider (Section 2.3.1, check 1).
func (b *Beaconer) verifySignatures(ctx context.Context, pcb *segment.PCB) error {
	for i := range pcb.Entries {
		entry := pcb.Entries[i]
		if _, err := b.engine.Verify(ctx, entry.Signed, pcb.AssociatedData(i)...); err != nil {
			return serrors.Wrap("verifying AS entry signature", err,
				"index", i, "isd_as", entry.IA)
		}
	}
	return nil
}

// trcPinned reports whether the ISD's base TRC is pinned locally.
func (b *Beaconer) trcPinned() bool {
	trc, err := b.engine.BaseTRC()
	return err == nil && !trc.IsZero()
}

// coreASes returns the ISD's core ASes named by the pinned TRC; empty when
// the TRC is not pinned yet, in which case propagation floods upward too —
// harmless, since every beacon already contains the core and the core drops
// any beacon containing itself.
func (b *Beaconer) coreASes() map[addr.IA]bool {
	ias, err := b.engine.CoreASes(b.ia.ISD())
	if err != nil || len(ias) == 0 {
		return nil
	}
	set := make(map[addr.IA]bool, len(ias))
	for _, ia := range ias {
		set[ia] = true
	}
	return set
}

// originateOnce originates a fresh PCB on each of the core's links (draft
// Sections 2.3.4 and 2.3.5.1): new segment information and the core's own
// signed AS entry, delivered to the neighbor's beacon service.
func (b *Beaconer) originateOnce(ctx context.Context) {
	neighbors := b.neighbors()
	for ifID, neighborIA := range b.links {
		pcb, err := segment.NewPCB(b.now())
		if err != nil {
			slog.Error("Creating beacon", "err", err)
			continue
		}
		if err := pcb.AppendEntry(ctx, b.ia, segment.EntryOptions{
			Next:       neighborIA,
			EgressIfID: ifID,
		}, b.macFactory, b.engine); err != nil {
			slog.Error("Signing origin beacon", "interface", ifID, "err", err)
			continue
		}
		peer, ok := b.neighborEndpoint(neighbors, ifID, neighborIA)
		if !ok {
			continue
		}
		if err := b.sendBeacon(ctx, peer, pcb.PB); err != nil {
			slog.Warn("Propagating origin beacon", "interface", ifID, "err", err)
		}
	}
}

// propagateOnce selects the fixed bounded set of freshest candidates, appends
// this AS's signed entry, and propagates each on every external interface
// except the one the beacon arrived on and except interfaces whose neighbor
// the TRC names as a core — beacons never travel toward a core (Section
// 2.3.5).
func (b *Beaconer) propagateOnce(ctx context.Context) {
	neighbors := b.neighbors()
	cores := b.coreASes()
	for _, cand := range b.store.BestSet(BestSetSize) {
		for egress, neighborIA := range b.links {
			if egress == cand.Ingress {
				continue
			}
			if cores[neighborIA] {
				continue
			}
			peer, ok := b.neighborEndpoint(neighbors, egress, neighborIA)
			if !ok {
				continue
			}
			extended, err := cand.PCB.Clone()
			if err != nil {
				slog.Error("Copying candidate beacon", "err", err)
				continue
			}
			if err := extended.AppendEntry(ctx, b.ia, segment.EntryOptions{
				Next:        neighborIA,
				IngressIfID: cand.Ingress,
				EgressIfID:  egress,
			}, b.macFactory, b.engine); err != nil {
				slog.Error("Extending beacon", "interface", egress, "err", err)
				continue
			}
			if err := b.sendBeacon(ctx, peer, extended.PB); err != nil {
				slog.Warn("Propagating beacon", "interface", egress, "err", err)
			}
		}
	}
}

// registerOnce terminates the freshest candidates per Section 3.1.1 — a
// final AS entry with unset next AS and egress interface, signed — storing
// the resulting up segments in the local path database and registering the
// down segments with the control service of the core that originated the
// PCB, riding the reversed up segment (Sections 3.1.2, 3.1.3, and 3.3).
func (b *Beaconer) registerOnce(ctx context.Context) {
	peers := make(map[addr.IA][]*control_plane.PathSegment)
	for _, cand := range b.store.BestSet(BestSetSize) {
		terminated, err := b.terminate(cand)
		if err != nil {
			slog.Error("Terminating beacon", "err", err)
			continue
		}
		up, err := pathdb.NewSegment(pathdb.SegmentTypeUp, terminated.PB)
		if err != nil {
			slog.Error("Building up segment", "err", err)
			continue
		}
		if _, err := b.db.Insert(ctx, up); err != nil {
			slog.Error("Storing up segment", "err", err)
		}
		peers[terminated.FirstIA()] = append(peers[terminated.FirstIA()], terminated.PB)
	}
	if len(peers) == 0 {
		return
	}
	route := b.coreRoute()
	if route == nil {
		slog.Debug("No route to a core yet; down segments not registered")
		return
	}
	for origin, segments := range peers {
		if !origin.Equal(route.IA) {
			slog.Warn("No route to the originating core; segment not registered",
				"origin", origin, "route", route.IA)
			continue
		}
		if err := b.sendRegistration(ctx, route, segments); err != nil {
			slog.Warn("Registering down segments", "core", origin, "err", err)
		}
	}
}

// registerCoreOnce terminates core beacons — those received over core links
// — into core segments in the core's own path database (Section 3.2). No
// core beacons exist while the ISD has a single core; the path is exercised
// by the same termination code.
func (b *Beaconer) registerCoreOnce(ctx context.Context) {
	cores := b.coreASes()
	for _, cand := range b.store.BestSet(BestSetSize) {
		if !cores[b.links[cand.Ingress]] {
			continue
		}
		terminated, err := b.terminate(cand)
		if err != nil {
			slog.Error("Terminating core beacon", "err", err)
			continue
		}
		coreSeg, err := pathdb.NewSegment(pathdb.SegmentTypeCore, terminated.PB)
		if err != nil {
			slog.Error("Building core segment", "err", err)
			continue
		}
		if _, err := b.db.Insert(ctx, coreSeg); err != nil {
			slog.Error("Storing core segment", "err", err)
		}
	}
}

// terminate appends the terminating AS entry to a candidate: ingress the
// receiving interface, egress and next AS unset, signed (Section 3.1.1).
func (b *Beaconer) terminate(cand Candidate) (*segment.PCB, error) {
	terminated, err := cand.PCB.Clone()
	if err != nil {
		return nil, err
	}
	if err := terminated.AppendEntry(context.Background(), b.ia, segment.EntryOptions{
		IngressIfID: cand.Ingress,
	}, b.macFactory, b.engine); err != nil {
		return nil, err
	}
	return terminated, nil
}

func (b *Beaconer) sweepOnce(ctx context.Context) {
	if _, err := b.db.DeleteExpired(ctx, b.now()); err != nil {
		slog.Error("Sweeping expired segments", "err", err)
	}
}

// sendBeacon sends one beacon RPC, bounded so a wedged connection cannot
// stall the loop sending it.
func (b *Beaconer) sendBeacon(
	ctx context.Context, peer *Addr, pb *control_plane.PathSegment) error {

	ctx, cancel := context.WithTimeout(ctx, b.sendTimeout)
	defer cancel()
	return b.sender.Beacon(ctx, peer, pb)
}

// sendRegistration sends one registration RPC, bounded like sendBeacon.
func (b *Beaconer) sendRegistration(
	ctx context.Context, peer *Addr, segments []*control_plane.PathSegment) error {

	ctx, cancel := context.WithTimeout(ctx, b.sendTimeout)
	defer cancel()
	return b.sender.RegisterSegments(ctx, peer, segments)
}

// neighborEndpoint resolves a neighbor's control endpoint address: the
// discovery greeting's control address with the endpoint port.
func (b *Beaconer) neighborEndpoint(
	neighbors map[uint16]Neighbor,
	ifID uint16,
	neighborIA addr.IA,
) (*Addr, bool) {

	n, ok := neighbors[ifID]
	if !ok {
		return nil, false
	}
	return &Addr{
		IA:   neighborIA,
		Addr: netip.AddrPortFrom(n.ControlAddr.Addr(), EndpointPort),
	}, true
}
