package controlplane

import (
	"context"
	"fmt"
	"hash"
	"log/slog"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/dataplane"
	"github.com/fancl20/cion/pkg/links"
)

// HealthMonitor owns a BFD session per serving link and reduces the
// arrivals to one verdict per interface — ADR-0008's ninth point made code:
// liveness is a service the node owes its neighbors, run for every serving
// link whatever the loaded provider is doing, because a neighbor's detection
// of the node depends on the node answering its BFD. The monitor reads the
// store, not the provider, so the file provider's links carry sessions like
// any other's. Sessions are keyed by interface ID and survive generation
// swaps — a swap rebinds the link's stable local address and re-attaches the
// writer, the session's state and timers untouched, so a peer sees the
// session continue across the milliseconds a swap costs.
type HealthMonitor struct {
	ia         addr.IA
	store      links.DB
	now        func() time.Time
	tick       time.Duration
	detectMult uint8
	macFactory func() hash.Hash

	mtx      sync.Mutex
	sessions map[uint16]*BFDSession
}

// HealthMonitorConfig configures a HealthMonitor.
type HealthMonitorConfig struct {
	// IA is the local ISD-AS.
	IA addr.IA
	// MACKey is the forwarding key, shared with the data plane, used to MAC
	// the one-hop paths of outgoing control packets.
	MACKey []byte
	// Store is the neighbor table, read live: the monitor starts a session
	// for every serving entry and stops the departed ones'.
	Store links.DB
	// Interval is the transmission interval; zero uses
	// BFDTransmissionInterval.
	Interval time.Duration
	// DetectMultiplier is the count of intervals without an arrival that
	// marks a link down; zero uses BFDDetectMultiplier.
	DetectMultiplier uint8
	// Now is the clock; nil uses time.Now.
	Now func() time.Time
}

func (cfg HealthMonitorConfig) interval() time.Duration {
	if cfg.Interval == 0 {
		return BFDTransmissionInterval
	}
	return cfg.Interval
}

func (cfg HealthMonitorConfig) detectMultiplier() uint8 {
	if cfg.DetectMultiplier == 0 {
		return BFDDetectMultiplier
	}
	return cfg.DetectMultiplier
}

// NewHealthMonitor returns a monitor over the link store. The node
// assembles it before the first data plane generation, so every generation
// finds a session per serving link.
func NewHealthMonitor(cfg HealthMonitorConfig) (*HealthMonitor, error) {
	if cfg.Store == nil {
		return nil, fmt.Errorf("no link store configured")
	}
	macFactory, err := initMac(cfg.MACKey)
	if err != nil {
		return nil, fmt.Errorf("initializing MAC: %w", err)
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &HealthMonitor{
		ia:         cfg.IA,
		store:      cfg.Store,
		now:        now,
		tick:       cfg.interval(),
		detectMult: cfg.detectMultiplier(),
		macFactory: macFactory,
		sessions:   make(map[uint16]*BFDSession),
	}, nil
}

// Session returns the serving entry's session, starting one for a link the
// monitor has not seen — the assembly asks as it builds each generation, so
// the session exists before the link that carries it.
func (m *HealthMonitor) Session(l *links.Link) *BFDSession {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	return m.session(l)
}

// session returns or starts the entry's session; the mutex must be held.
func (m *HealthMonitor) session(l *links.Link) *BFDSession {
	if s, ok := m.sessions[l.IfID]; ok {
		s.update(l.NeighborIA, l.Local.Addr(), l.Remote.Addr())
		return s
	}
	s := newBFDSession(m.ia, m.macFactory, m.tick, m.detectMult, m.now,
		l.IfID, l.NeighborIA, l.Local.Addr(), l.Remote.Addr())
	m.sessions[l.IfID] = s
	return s
}

// Up returns the interface's verdict; an interface with no session — one
// the monitor has not seen — is up, as a node restarts with every link up.
func (m *HealthMonitor) Up(ifID uint16) bool {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	s, ok := m.sessions[ifID]
	if !ok {
		return true
	}
	return s.IsUp()
}

// Verdicts returns the per-interface verdicts the node's consumers read: a
// down interface originates and propagates nothing, the core route's
// one-hop shortcut falls through to the composed route, and the selection
// loop's floor and demotions count up links only.
func (m *HealthMonitor) Verdicts() map[uint16]bool {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	out := make(map[uint16]bool, len(m.sessions))
	for ifID, s := range m.sessions {
		out[ifID] = s.IsUp()
	}
	return out
}

// Run maintains the sessions until the context is canceled: a session for
// every serving entry, none for the departed ones, and every session's
// interval — expiring silent links and transmitting control packets, down
// verdicts included, which is how recovery is seen.
func (m *HealthMonitor) Run(ctx context.Context) {
	m.reconcile()
	ticker := time.NewTicker(m.tick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.reconcile()
			m.tickAll()
		}
	}
}

// reconcile starts sessions for the serving entries and stops the departed
// ones' — a link that left the serving set, retired or demoted, transmits
// no more.
func (m *HealthMonitor) reconcile() {
	entries, err := m.store.All(context.Background())
	if err != nil {
		slog.Error("Health monitor reading the link store", "err", err)
		return
	}
	serving := make(map[uint16]bool, len(entries))
	m.mtx.Lock()
	defer m.mtx.Unlock()
	for _, l := range entries {
		if !l.Serving() {
			continue
		}
		serving[l.IfID] = true
		m.session(l).tick() // a new session transmits at once
	}
	for ifID, s := range m.sessions {
		if !serving[ifID] {
			s.stop()
			delete(m.sessions, ifID)
		}
	}
}

// tickAll runs every session's interval.
func (m *HealthMonitor) tickAll() {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	for _, s := range m.sessions {
		s.tick()
	}
}

// The session the data plane's link carries is the monitor's — the verdict
// crosses the seam inside it, needing no channel of its own.
var _ dataplane.Session = (*BFDSession)(nil)
