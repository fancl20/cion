package controlplane

import (
	"context"
	"fmt"
	"hash"
	"log/slog"
	"net"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/slayers/path"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/pkg/core/trust"
	"github.com/fancl20/cion/pkg/libs/bus"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/segment"
	"github.com/fancl20/cion/pkg/modules/pathdb"
)

const (
	// PropagationInterval is the beaconing period: the draft's intra-ISD
	// floor of five seconds (Section 2.3.4).
	PropagationInterval = 5 * time.Second

	// RegistrationInterval is the registration period (Section 3.1), on the
	// order of a minute.
	RegistrationInterval = time.Minute

	// SendTimeout bounds each beacon and registration RPC, and with it how
	// long a peer that went dark holds its slot.
	SendTimeout = 5 * time.Second

	// qualifyingIntervals is how many propagation intervals a route
	// qualifies for after its latest origination arrived: a route whose
	// beacons stop, through a link that died, leaves every set that much
	// later, while its candidate stays unexpired for hours.
	qualifyingIntervals = 3
)

// clockSkewAllowance is how far in the future a PCB timestamp may lie; the
// draft recommends the hop-field expiration time as the allowance (Section
// 2.2.4).
var clockSkewAllowance = path.ExpTimeToDuration(0)

// SegmentSender sends beacon and registration RPCs over the SCION-native
// channel; PeerClient satisfies it.
type SegmentSender interface {
	// Beacon propagates the extended PCB to the peer's beacon service.
	Beacon(ctx context.Context, peer *scion.Addr, pcb *control_plane.PathSegment) error
	// RegisterSegments registers down segments with the core's control
	// service.
	RegisterSegments(ctx context.Context, peer *scion.Addr,
		segments []*control_plane.PathSegment) error
	// Enrolled reports whether the peer's latest handshake on the beacon
	// channel presented a chain the pinned TRC anchors.
	Enrolled(peer addr.IA) bool
	// Probe reaches the peer's control service over the beacon channel,
	// so that the peer's enrollment is recorded whether or not a beacon
	// goes to it.
	Probe(ctx context.Context, peer *scion.Addr) error
}

// Beaconer runs beacon exploration: the core tiers — founding and
// authoritative alike — originate signed path-segment beacons on their links
// and terminate core beacons into core segments, every node verifies the
// accumulated signatures against the TRC before storing or propagating them,
// propagation floods outward — pruning the interfaces toward the cores the
// TRC names and toward the neighbors a beacon already crosses — and
// non-cores terminate accepted beacons into registered segments. Link roles
// are not configured: the interface a beacon arrives on is the node's parent
// side, the interfaces beacons are propagated to are child sides, and a link
// whose neighbor the TRC names as a core is a core link.
type Beaconer struct {
	ia           addr.IA
	engine       *trust.Engine
	macFactory   func() hash.Hash
	store        *BeaconStore
	db           pathdb.DB
	links        *bus.Topic[bus.LinkState]
	latencies    *bus.Topic[bus.LinkLatencies]
	cluster      *bus.Topic[bus.Cluster]
	sender       SegmentSender
	core         bool
	propagation  time.Duration
	registration time.Duration

	// bootstrap keeps the freshest beacon of each origin the node heard
	// before it pinned the TRC, and the interface it arrived on — unverified
	// until the pin, verified after: a fresh node receives beacons before it
	// has pinned the TRC and may use their reversed path — extended with its
	// own hop — as the route for its enrollment fetch, and a core tier,
	// which stores no up segments, keeps riding it to its neighboring cores;
	// never for storing, propagating, or registering. BootstrapCore names the
	// freshest origin: a node not enrolled receives the founder's beacons
	// alone.
	bootstrapMtx     sync.Mutex
	bootstraps       map[addr.IA]*segment.PCB
	bootstrapIngress map[addr.IA]uint16

	// sends joins the RPCs the passes run off their loops, and busy holds
	// the slots whose RPCs are outstanding. A pass skips a busy slot, so a
	// peer that went dark holds only its own, for up to SendTimeout, while
	// every loop keeps its cadence for the other peers.
	sends   sync.WaitGroup
	busyMtx sync.Mutex
	busy    map[sendTarget]bool
}

// sendKind names the pass an RPC belongs to. Each pass holds its own slot
// per peer, so origination, propagation, registration, and the enrollment
// probe never wait on one another.
type sendKind uint8

const (
	originating sendKind = iota
	propagating
	registering
	probing
)

// sendTarget is one pass's slot for one peer.
type sendTarget struct {
	kind sendKind
	peer addr.IA
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
	// Links is the node's link state topic, read fresh each pass, so a node
	// may start with zero links. Its table alone names each neighbor's
	// identity and the destination its beacons are addressed with; a down
	// interface originates and propagates nothing, resuming with the
	// verdict's up edge. A nil topic serves no links.
	Links *bus.Topic[bus.LinkState]
	// Latencies is the node's link latency topic, whose last event's
	// estimates the entries the beaconer signs declare. A nil topic declares
	// nothing.
	Latencies *bus.Topic[bus.LinkLatencies]
	// Cluster is the node's cluster topic, whose last event names the
	// members of the cluster the node joined. A nil topic names none.
	Cluster *bus.Topic[bus.Cluster]
	// Sender sends beacon and registration RPCs over the SCION-native
	// channel.
	Sender SegmentSender
	// Core marks the core tiers — the founding and the authoritative —
	// which originate beacons beside propagating them and terminate core
	// beacons into core segments.
	Core bool
	// PropagationInterval and RegistrationInterval override the defaults;
	// zero keeps them.
	PropagationInterval  time.Duration
	RegistrationInterval time.Duration
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
	return &Beaconer{
		ia:               cfg.IA,
		engine:           cfg.Engine,
		macFactory:       macFactory,
		store:            cfg.Store,
		db:               cfg.DB,
		links:            cfg.Links,
		latencies:        cfg.Latencies,
		cluster:          cfg.Cluster,
		sender:           cfg.Sender,
		core:             cfg.Core,
		propagation:      propagation,
		registration:     registration,
		bootstraps:       make(map[addr.IA]*segment.PCB),
		bootstrapIngress: make(map[addr.IA]uint16),
		busy:             make(map[sendTarget]bool),
	}, nil
}

// egressLatency returns the egress link's latest one-way delay estimate —
// the declaration the entry carries; a nil topic and a link the last event
// lacks declare nothing.
func (b *Beaconer) egressLatency(ifID uint16) time.Duration {
	return b.latencies.Latest().Of(ifID)
}

// Run executes the beaconing loops until the context is canceled:
// propagation on every tier, origination and core-beacon termination on the
// core tiers, down-segment registration on the others, and the expired-
// segment sweep of the path database. It returns once every loop has exited
// and every RPC a pass started has returned, so a caller that waits for Run
// closes no store beneath an in-flight pass.
func (b *Beaconer) Run(ctx context.Context) {
	var wg sync.WaitGroup
	loop := func(interval time.Duration, f func(context.Context)) {
		wg.Go(func() {
			b.loop(ctx, interval, f)
		})
	}
	loop(b.propagation, b.propagateOnce)
	if b.core {
		loop(b.propagation, b.originateOnce)
		loop(b.registration, b.registerCoreOnce)
	} else {
		loop(b.registration, b.registerOnce)
	}
	loop(b.registration, b.sweepOnce)
	<-ctx.Done()
	wg.Wait()
	b.sends.Wait()
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

// pending reports whether the slot's previous RPCs are still outstanding;
// the pass skips the slot this round.
func (b *Beaconer) pending(t sendTarget) bool {
	b.busyMtx.Lock()
	defer b.busyMtx.Unlock()
	return b.busy[t]
}

// goSend runs the slot's RPCs off the loop, the slot busy until they
// return. Only the slot's own pass sends for it, and that pass checked
// pending first, so the slot is free here.
func (b *Beaconer) goSend(t sendTarget, rpcs func()) {
	b.busyMtx.Lock()
	b.busy[t] = true
	b.busyMtx.Unlock()
	b.sends.Go(func() {
		defer func() {
			b.busyMtx.Lock()
			delete(b.busy, t)
			b.busyMtx.Unlock()
		}()
		rpcs()
	})
}

// HandleBeacon applies the reception checks of Section 2.3.1 to the received
// PCB and stores it as a candidate. A node that has not pinned the TRC
// cannot verify beacons; it records the freshest one as its bootstrap route
// for the enrollment fetch instead. A pinned node verifies with material its
// sender holds — the neighbor at the arrival interface, which verified the
// same entries before it propagated them — whatever routes the node holds to
// the core. It refreshes the slots it holds with each verified beacon, so
// their routes name the interfaces the link's two ends use now. A core opens
// a slot for every core it hears, whatever its pin: the slot is its only
// route to a core it links to. A non-core opens none after its pin: its
// slots stay the origins it heard before, the founder's alone when its
// neighbors sent it the founder's beacons alone.
func (b *Beaconer) HandleBeacon(
	ctx context.Context,
	pcb *segment.PCB,
	ingress uint16,
) error {

	if err := b.checkBeacon(pcb, ingress); err != nil {
		return err
	}
	pinned, err := b.trcPinned()
	if err != nil {
		return err
	}
	if !pinned {
		b.recordBootstrap(ingress, pcb, true)
		return nil
	}
	sender := &scion.Addr{IA: pcb.LastIA(), Service: addr.SvcCS}
	if err := b.verifySignatures(ctx, pcb, sender); err != nil {
		return err
	}
	b.store.Insert(ingress, pcb)
	b.recordBootstrap(ingress, pcb, b.core)
	return nil
}

// HandleRegistration verifies a down segment registered with this core and
// stores it in the path database (Sections 3.1.3 and 3.3). Missing trust
// material is asked of server, the registrant's control service, before the
// provider's own source: the registrant holds every chain its segment
// references, whichever core issued them.
func (b *Beaconer) HandleRegistration(
	ctx context.Context,
	pb *control_plane.PathSegment,
	server net.Addr,
) error {

	pcb, err := segment.ParsePCB(pb)
	if err != nil {
		return serrors.Wrap("parsing registered segment", err)
	}
	if err := b.checkRegistered(pcb); err != nil {
		return err
	}
	if err := b.verifySignatures(ctx, pcb, server); err != nil {
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

// BootstrapRoute returns the reversed data-plane path of the freshest beacon
// originating at dst, extended with the node's own unsigned hop — the route
// of a node that has not verified any up segment to that core: a fresh
// node's enrollment fetch and the trust fetches around it ride it, all
// protected by the WebPKI-authenticated channel, and a core tier, which
// stores no up segments, keeps riding it to its neighboring cores. It is
// never stored, propagated, or registered, serves only its originating
// core, and verified up segments take over the moment one exists. A beacon
// whose arrival interface the link table no longer holds serves none: the
// data plane carries no such interface, and a beacon over the link's new
// interface takes over once one arrives.
func (b *Beaconer) BootstrapRoute(dst addr.IA) *spath.Decoded {
	b.bootstrapMtx.Lock()
	defer b.bootstrapMtx.Unlock()
	pcb, ok := b.bootstraps[dst]
	if !ok || !pcb.Expiration().After(time.Now()) {
		return nil
	}
	ingress := b.bootstrapIngress[dst]
	if _, live := b.links.Latest().Table()[ingress]; !live {
		return nil
	}
	route, err := pcb.Clone()
	if err != nil {
		panic(fmt.Sprintf("cloning the bootstrap beacon: %v", err))
	}
	if _, err := route.AppendRouteHop(b.ia, segment.EntryOptions{
		IngressIfID: ingress,
	}, b.macFactory); err != nil {
		panic(fmt.Sprintf("extending the bootstrap beacon: %v", err))
	}
	return route.ReversePath()
}

// recordBootstrap keeps the beacon in its origin's slot when it is fresher
// than the one the slot holds; an origin without a slot gains one only when
// add is set.
func (b *Beaconer) recordBootstrap(ingress uint16, pcb *segment.PCB, add bool) {
	b.bootstrapMtx.Lock()
	defer b.bootstrapMtx.Unlock()
	origin := pcb.FirstIA()
	existing, ok := b.bootstraps[origin]
	if !ok && !add {
		return
	}
	if ok && !pcb.Timestamp().After(existing.Timestamp()) {
		return
	}
	b.bootstraps[origin] = pcb
	b.bootstrapIngress[origin] = ingress
}

// BootstrapCore returns the origin of the freshest bootstrap beacon, the core
// a node that has not pinned the TRC aims its founder route at: a node not
// enrolled receives the founder's beacons alone, so the origin is the
// founder unless a neighbor broke that rule, which the founder's WebPKI
// identity then exposes. Zero when the node holds none. Beacons originate
// only at cores.
func (b *Beaconer) BootstrapCore() addr.IA {
	b.bootstrapMtx.Lock()
	defer b.bootstrapMtx.Unlock()
	var core addr.IA
	var freshest time.Time
	for origin, pcb := range b.bootstraps {
		at := pcb.Timestamp()
		if core.IsZero() || at.After(freshest) || at.Equal(freshest) && origin < core {
			core, freshest = origin, at
		}
	}
	return core
}

// BootstrapNeighbor returns the neighbor that sent the freshest bootstrap
// beacon of the origin — the beacon's last AS entry — and zero when the node
// holds none of it.
func (b *Beaconer) BootstrapNeighbor(origin addr.IA) addr.IA {
	b.bootstrapMtx.Lock()
	defer b.bootstrapMtx.Unlock()
	pcb, ok := b.bootstraps[origin]
	if !ok {
		return 0
	}
	return pcb.LastIA()
}

// checkBeacon applies the structural reception checks of Section 2.3.1: PCB
// validity in time, loop prevention, the identity-to-link binding of the
// arrival interface, and entry continuity. Under emergent link roles
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
	// The draft's core check itself, applied at reception: a beacon's origin —
	// its first entry — names a core the pinned TRC lists, so a non-core's
	// beacons never become up segments. The empty set of the not-yet-pinned
	// bootstrap state waives the check, the tolerance the propagation pruning
	// already carries; the drop lands here, before signature verification spends
	// work on the beacon.
	cores, err := b.coreASes()
	if err != nil {
		return err
	}
	if cores != nil && !cores[pcb.FirstIA()] {
		return serrors.New("beacon does not originate at a core the TRC names",
			"origin", pcb.FirstIA())
	}
	neighbor, ok := b.links.Latest().Table()[ingress]
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
	return checkTimeWindow(pcb, time.Now())
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
	return checkTimeWindow(pcb, time.Now())
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
// TRC-anchored chain the entry references, bound to the identity the entry
// claims: the signer's key must name the entry's own ISD-AS, so an enrolled AS
// cannot sign entries in another's name. Missing TRCs and chains are asked of
// server — the sending AS's control service for a beacon (Section 2.3.1,
// check 1), the registrant's for a registration — before the provider's own
// source.
func (b *Beaconer) verifySignatures(ctx context.Context, pcb *segment.PCB, server net.Addr) error {
	for i := range pcb.Entries {
		entry := pcb.Entries[i]
		if _, err := b.engine.VerifyBound(ctx, entry.IA, server, entry.Signed,
			pcb.AssociatedData(i)...); err != nil {
			return serrors.Wrap("verifying AS entry signature", err,
				"index", i, "isd_as", entry.IA)
		}
	}
	return nil
}

// trcPinned reports whether the ISD's base TRC is pinned locally.
func (b *Beaconer) trcPinned() (bool, error) {
	trc, err := b.engine.BaseTRC()
	if err != nil {
		return false, serrors.Wrap("reading the pinned TRC", err)
	}
	return !trc.IsZero(), nil
}

// coreASes returns the ISD's core ASes named by the pinned TRC; empty when
// the TRC is not pinned yet, in which case propagation floods upward too —
// harmless, since every beacon already crosses its originating core, a
// neighbor propagation never sends it to.
func (b *Beaconer) coreASes() (map[addr.IA]bool, error) {
	ias, err := b.engine.CoreASes(b.ia.ISD())
	if err != nil {
		return nil, serrors.Wrap("enumerating the core ASes", err)
	}
	if len(ias) == 0 {
		return nil, nil
	}
	set := make(map[addr.IA]bool, len(ias))
	for _, ia := range ias {
		set[ia] = true
	}
	return set, nil
}

// originateOnce originates a fresh PCB on each of the core's links (draft
// Sections 2.3.4 and 2.3.5.1): new segment information and the core's own
// signed AS entry, delivered to the neighbor's beacon service — the
// neighbor's control service as a service destination on the one-hop path,
// the drafts' own control-traffic pattern, the neighbor's ISD-AS read from
// the store's snapshot. A core other than the founder originates nothing
// toward a peer that has not enrolled, which receives the founder's beacons
// alone. Each neighbor's send runs off the loop; a neighbor whose previous
// beacon is still in flight gets none this round.
func (b *Beaconer) originateOnce(ctx context.Context) {
	founder, err := b.engine.FounderAS(b.ia.ISD())
	if err != nil {
		slog.Error("Originating beacons", "err", err)
		return
	}
	cores, err := b.coreASes()
	if err != nil {
		slog.Error("Originating beacons", "err", err)
		return
	}
	state := b.links.Latest()
	for ifID, neighborIA := range state.Table() {
		if neighborIA.IsZero() {
			continue // a link whose neighbor establishment has not named
		}
		if !state.Up(ifID) {
			continue // a down interface originates nothing
		}
		if !b.ia.Equal(founder) && !cores[neighborIA] && !b.sender.Enrolled(neighborIA) {
			continue
		}
		target := sendTarget{originating, neighborIA}
		if b.pending(target) {
			continue
		}
		pcb, err := segment.NewPCB(time.Now())
		if err != nil {
			slog.Error("Creating beacon", "err", err)
			continue
		}
		if err := pcb.AppendEntry(ctx, b.ia, segment.EntryOptions{
			Next:          neighborIA,
			EgressIfID:    ifID,
			EgressLatency: b.egressLatency(ifID),
		}, b.macFactory, b.engine); err != nil {
			slog.Error("Signing origin beacon", "interface", ifID, "err", err)
			continue
		}
		peer := &scion.Addr{IA: neighborIA, Service: addr.SvcCS}
		b.goSend(target, func() {
			if err := b.sendBeacon(ctx, peer, pcb.PB); err != nil {
				slog.Warn("Propagating origin beacon", "interface", ifID, "err", err)
			}
		})
	}
}

// propagateOnce sends each neighbor a set of its own, each route extended
// with this AS's signed entry, on every external interface except
// interfaces whose neighbor the TRC names as a core — beacons never travel
// toward a core (Section 2.3.5). A neighbor's set is picked among the
// qualifying routes that do not cross it, which it would discard as a loop
// (Section 2.3.1): the neighbor a route arrived from, and on links between
// non-cores, which carry beacons both ways, any neighbor it passed on its way
// here. A neighbor that has not enrolled receives a set picked among the
// founder's routes alone, and a probe that records its enrollment once it
// has. A neighbor in the node's cluster also receives the routes into the
// cluster; a neighbor outside it receives none of them. The propagation
// targets are the neighbors' control services as service destinations on
// the one-hop paths. Each neighbor's beacons go out off the loop in pick
// order, until a call fails short of the neighbor's answer — a refused or
// failed dial, which every further call would repeat — while a beacon the
// neighbor rejects as invalid leaves the rest to go; the next round retries.
// A neighbor whose previous beacons are still in flight gets none this
// round.
func (b *Beaconer) propagateOnce(ctx context.Context) {
	cores, err := b.coreASes()
	if err != nil {
		slog.Error("Propagating beacons", "err", err)
		return
	}
	founder, err := b.engine.FounderAS(b.ia.ISD())
	if err != nil {
		slog.Error("Propagating beacons", "err", err)
		return
	}
	state := b.links.Latest()
	ranked := rankRoutes(b.qualifying(state))
	cluster := b.joined()
	for egress, neighborIA := range state.Table() {
		if neighborIA.IsZero() {
			continue // a link whose neighbor establishment has not named
		}
		if cores[neighborIA] {
			continue
		}
		if !state.Up(egress) {
			continue // a down interface propagates nothing
		}
		origin := addr.IA(0)
		if !b.sender.Enrolled(neighborIA) {
			b.probe(ctx, neighborIA)
			if founder.IsZero() {
				continue
			}
			origin = founder
		}
		target := sendTarget{propagating, neighborIA}
		if b.pending(target) {
			continue
		}
		var takeable []route
		for _, r := range ranked {
			if (origin.IsZero() || r.PCB.FirstIA().Equal(origin)) && !r.PCB.ContainsIA(neighborIA) {
				takeable = append(takeable, r)
			}
		}
		var into bus.Cluster
		if cluster.Has(neighborIA) {
			into = cluster
		}
		var beacons []*control_plane.PathSegment
		for _, cand := range pickSet(takeable, founder, into) {
			extended, err := cand.PCB.Clone()
			if err != nil {
				slog.Error("Copying candidate beacon", "err", err)
				continue
			}
			if err := extended.AppendEntry(ctx, b.ia, segment.EntryOptions{
				Next:          neighborIA,
				IngressIfID:   cand.Ingress,
				EgressIfID:    egress,
				EgressLatency: b.egressLatency(egress),
			}, b.macFactory, b.engine); err != nil {
				slog.Error("Extending beacon", "interface", egress, "err", err)
				continue
			}
			beacons = append(beacons, extended.PB)
		}
		if len(beacons) == 0 {
			continue
		}
		peer := &scion.Addr{IA: neighborIA, Service: addr.SvcCS}
		b.goSend(target, func() {
			for _, pb := range beacons {
				err := b.sendBeacon(ctx, peer, pb)
				if err == nil {
					continue
				}
				slog.Warn("Propagating beacon", "interface", egress, "err", err)
				if connect.CodeOf(err) != connect.CodeInvalidArgument {
					return
				}
			}
		})
	}
}

// registerOnce terminates the node's own set, picked among every qualifying
// route, per Section 3.1.1 — a final AS entry with unset next AS and egress
// interface, signed — storing the resulting up segments in the local path
// database and registering each origin's down segments with the control
// service of the core that originated the PCBs (Sections 3.1.2, 3.1.3, and
// 3.3). The peer is named by ISD-AS and service alone: the peer client's
// dial resolves the route per destination — one hop over the link to a
// neighboring core, else the freshest up segment's reversal, stored by this
// same pass. Each origin's registration runs off the loop, so the next pass
// stores newly arrived up segments on time whatever a registration waits
// on; an origin whose previous registration is still in flight is skipped
// this round, and a dial that fails logs and a later pass retries.
func (b *Beaconer) registerOnce(ctx context.Context) {
	set, err := b.ownSet()
	if err != nil {
		slog.Error("Registering segments", "err", err)
		return
	}
	peers := make(map[addr.IA][]*control_plane.PathSegment)
	for _, cand := range set {
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
	for origin, segments := range peers {
		target := sendTarget{registering, origin}
		if b.pending(target) {
			continue
		}
		peer := &scion.Addr{IA: origin, Service: addr.SvcCS}
		b.goSend(target, func() {
			if err := b.sendRegistration(ctx, peer, segments); err != nil {
				slog.Warn("Registering down segments", "core", origin, "err", err)
			}
		})
	}
}

// registerCoreOnce terminates the core beacons of the core's own set — those
// received over core links — into core segments in the core's own path
// database (Section 3.2): each core terminates what it receives, and core
// segments stay local, none registered with another core.
func (b *Beaconer) registerCoreOnce(ctx context.Context) {
	cores, err := b.coreASes()
	if err != nil {
		slog.Error("Terminating core beacons", "err", err)
		return
	}
	set, err := b.ownSet()
	if err != nil {
		slog.Error("Terminating core beacons", "err", err)
		return
	}
	for _, cand := range set {
		if !cores[cand.PCB.LastIA()] {
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

// qualifying returns the candidates whose latest origination arrived within
// qualifyingIntervals propagation intervals, among those whose arrival
// interface the link table still binds to the neighbor that sent them — the
// beacon's last entry, the binding reception checked. A beacon that arrived
// over a link since retired, or since re-established under a new interface
// ID, names an ingress interface that no longer leads to its sender, and a
// hop extended or terminated through it would publish a route the data
// plane cannot carry: the beaconer neither propagates nor terminates it.
func (b *Beaconer) qualifying(state bus.LinkState) []Candidate {
	table := state.Table()
	return b.store.Qualifying(qualifyingIntervals*b.propagation, func(c Candidate) bool {
		return table[c.Ingress].Equal(c.PCB.LastIA())
	})
}

// ownSet returns the set the node terminates: picked among every qualifying
// route, the founder's cheapest first, the routes into the node's cluster
// included.
func (b *Beaconer) ownSet() ([]Candidate, error) {
	founder, err := b.engine.FounderAS(b.ia.ISD())
	if err != nil {
		return nil, err
	}
	return pickSet(rankRoutes(b.qualifying(b.links.Latest())), founder, b.joined()), nil
}

// joined returns the cluster the node joined, as its cluster topic names it
// last; none without a topic.
func (b *Beaconer) joined() bus.Cluster {
	if b.cluster == nil {
		return bus.Cluster{}
	}
	return b.cluster.Latest()
}

// probe sends the peer the sender's probe off the loop, unless the previous
// one is still in flight: a dial that records whether the peer has enrolled,
// whatever beacons go to it.
func (b *Beaconer) probe(ctx context.Context, peerIA addr.IA) {
	target := sendTarget{probing, peerIA}
	if b.pending(target) {
		return
	}
	peer := &scion.Addr{IA: peerIA, Service: addr.SvcCS}
	b.goSend(target, func() {
		ctx, cancel := context.WithTimeout(ctx, SendTimeout)
		defer cancel()
		if err := b.sender.Probe(ctx, peer); err != nil {
			slog.Debug("Probing the peer's enrollment", "peer", peerIA, "err", err)
		}
	})
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
	if _, err := b.db.DeleteExpired(ctx, time.Now()); err != nil {
		slog.Error("Sweeping expired segments", "err", err)
	}
}

// sendBeacon sends one beacon RPC, bounded so a wedged connection cannot
// stall the loop sending it.
func (b *Beaconer) sendBeacon(
	ctx context.Context, peer *scion.Addr, pb *control_plane.PathSegment) error {

	ctx, cancel := context.WithTimeout(ctx, SendTimeout)
	defer cancel()
	return b.sender.Beacon(ctx, peer, pb)
}

// sendRegistration sends one registration RPC, bounded like sendBeacon.
func (b *Beaconer) sendRegistration(
	ctx context.Context, peer *scion.Addr, segments []*control_plane.PathSegment) error {

	ctx, cancel := context.WithTimeout(ctx, SendTimeout)
	defer cancel()
	return b.sender.RegisterSegments(ctx, peer, segments)
}
