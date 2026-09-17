package controlplane

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/pkg/links"
	"github.com/fancl20/cion/pkg/links/impl/memory"
)

// newTestMonitor returns a monitor over a memory store at the production
// timers' cadence.
func newTestMonitor(t *testing.T) (*HealthMonitor, *memory.DB) {
	t.Helper()
	store := memory.New()
	m, err := NewHealthMonitor(HealthMonitorConfig{
		IA:     bfdIA,
		MACKey: []byte("0123456789abcdef"),
		Store:  store,
	})
	if err != nil {
		t.Fatal(err)
	}
	return m, store
}

// servingEntry is a serving store entry: both link addresses, established.
func servingEntry(neighbor addr.IA) *links.Link {
	return &links.Link{
		NeighborIA: neighbor,
		Local:      netip.MustParseAddrPort("127.0.0.1:40001"),
		Remote:     netip.MustParseAddrPort("127.0.0.1:40002"),
		State:      links.StateEstablished,
	}
}

// TestMonitorSessionsFollowTheStore checks the reconcile: a session for
// every serving entry — the file provider's links included, the monitor
// reading the store, not the provider — and none for the departed ones.
func TestMonitorSessionsFollowTheStore(t *testing.T) {
	m, store := newTestMonitor(t)
	ctx := context.Background()

	entry := servingEntry(bfdPeer)
	if err := store.Insert(ctx, entry); err != nil {
		t.Fatal(err)
	}
	m.reconcile()
	if s := m.Session(entry); s == nil {
		t.Fatal("no session for the serving entry")
	}
	if !m.Up(entry.IfID) {
		t.Error("a fresh session's verdict is down")
	}
	got := false
	for ifID, up := range m.Verdicts() {
		if ifID == entry.IfID && up {
			got = true
		}
	}
	if !got {
		t.Error("the verdicts map omits the serving link")
	}

	// A retired entry departs the serving set: its session stops.
	entry.State = links.StateRetired
	entry.Retired = time.Now()
	if err := store.Update(ctx, entry); err != nil {
		t.Fatal(err)
	}
	m.reconcile()
	if m.sessionsOf() != 0 {
		t.Error("the departed link kept a session")
	}
	// An interface the monitor has not seen is up: a node restarts with
	// every link up.
	if !m.Up(9999) {
		t.Error("an unknown interface's verdict is down")
	}
}

// TestMonitorSessionSurvivesSwap checks the generation swap: the session is
// keyed by interface ID, so the generation that rebinds the link's stable
// local address re-attaches its writer through the same session — state and
// timers untouched, the verdict continuous.
func TestMonitorSessionSurvivesSwap(t *testing.T) {
	m, store := newTestMonitor(t)
	ctx := context.Background()
	entry := servingEntry(bfdPeer)
	if err := store.Insert(ctx, entry); err != nil {
		t.Fatal(err)
	}
	m.reconcile()
	s := m.Session(entry)

	// The first generation attaches its writer and the session runs.
	first := &fakeWriter{}
	s.SetRawWriter(first)
	s.tick()
	if s.Transmitted() == 0 {
		t.Fatal("the session never transmitted")
	}
	s.ReceiveMessage(peerMessage(3, 0x11223344, 0)) // peer Up

	// The swap: the store's entry is served again by a new generation, whose
	// link attaches a fresh writer to the same session.
	rebound := servingEntry(bfdPeer)
	rebound.IfID = entry.IfID
	second := &fakeWriter{}
	s.SetRawWriter(second)
	before := s.Transmitted()
	s.tick()
	if s != m.Session(rebound) {
		t.Fatal("the swap minted a second session for the interface")
	}
	if s.Transmitted() != before+1 {
		t.Error("the session did not transmit on the new writer")
	}
	if len(second.packets) != 1 || len(first.packets) != 1 {
		t.Errorf("transmissions after the swap = %d/%d, want the new writer carrying them",
			len(second.packets), len(first.packets))
	}
	if s.localStateOf() == 0 {
		t.Error("the swap reset the session's state")
	}
	if !m.Up(entry.IfID) {
		t.Error("the swap disturbed the verdict")
	}
}

// TestMonitorRetargetsSession checks that the session's frames follow the
// entry's current addresses — the store's entry, not the construction-time
// snapshot, is the truth.
func TestMonitorRetargetsSession(t *testing.T) {
	m, store := newTestMonitor(t)
	ctx := context.Background()
	entry := servingEntry(bfdPeer)
	if err := store.Insert(ctx, entry); err != nil {
		t.Fatal(err)
	}
	m.reconcile()

	// The peer's link address changed; the session's next frame carries it.
	entry.Remote = netip.MustParseAddrPort("127.0.0.9:40009")
	if err := store.Update(ctx, entry); err != nil {
		t.Fatal(err)
	}
	m.reconcile()
	w := &fakeWriter{}
	s := m.Session(entry)
	s.SetRawWriter(w)
	s.tick()
	scn, _ := decodeControl(t, lastPacket(t, w))
	dst, err := scn.DstAddr()
	if err != nil {
		t.Fatal(err)
	}
	if got := dst.IP().String(); got != "127.0.0.9" {
		t.Errorf("frame destination = %s, want the retargeted 127.0.0.9", got)
	}
}

// sessionsOf counts the monitor's live sessions.
func (m *HealthMonitor) sessionsOf() int {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	return len(m.sessions)
}
