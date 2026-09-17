package testnetwork

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/internal/services"
	"github.com/fancl20/cion/pkg/apps/ping"
	"github.com/fancl20/cion/pkg/links"
)

// TestBFDLivenessEpisode is proposal 0012's integration proof: a three-node
// line — the core A, the middle B, and C below — where killing B is the
// blackhole on the A–B link's sockets. A marks the link down within the
// window while its BFD keeps leaving on the link's own socket; a ping from
// A toward B's far side receives the type-5 signal and A's interface cache
// records it; the selection loop, its neighbor now verdict-down, promotes
// the reachable C to hold the floor; lifting the blackhole — B restarted —
// returns the link up with no generation swap: the serving instance's
// session continuous across the episode.
func TestBFDLivenessEpisode(t *testing.T) {
	wpki := NewWebPKI(t)
	ipA, ipB, ipC := addrIP(0x61), addrIP(0x62), addrIP(0x63)

	a := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.State = t.TempDir()
		cfg.Internal = FreeUDPAddrOn(t, ipA)
		cfg.Control = FreeUDPAddrOn(t, ipA)
		cfg.CertFile = wpki.certFile
		cfg.KeyFile = wpki.keyFile
	})
	b := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.State = t.TempDir()
		cfg.Internal = FreeUDPAddrOn(t, ipB)
		cfg.Control = FreeUDPAddrOn(t, ipB)
		cfg.Neighbors = []string{a.rendezvousOf()}
		cfg.RootCAs = wpki.pool
	})
	c := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.State = t.TempDir()
		cfg.Internal = FreeUDPAddrOn(t, ipC)
		cfg.Control = FreeUDPAddrOn(t, ipC)
		cfg.Neighbors = []string{b.rendezvousOf()}
		cfg.RootCAs = wpki.pool
	})
	ctx := context.Background()

	// The line stands: A–B and B–C established, everyone enrolled and
	// answering end to end.
	Poll(t, "the line to stand", func() bool {
		return establishedOf(a, b.app.IA()) && establishedOf(b, a.app.IA()) &&
			establishedOf(b, c.app.IA()) && establishedOf(c, b.app.IA())
	})
	Poll(t, "A reaches C through B", func() bool {
		return pingFrom(ctx, a, c.app.IA(), c.host)
	})

	abEntry := entryOf(a, b.app.IA())
	abIfID := abEntry.IfID
	session := a.app.Monitor().Session(abEntry)
	if session == nil {
		t.Fatal("no BFD session on A's link to B")
	}

	// The blackhole: kill B.
	b.cancel()
	b.app.Close()

	// A marks the link down within the window while its BFD keeps leaving
	// on the link's own socket — the stream survives its own verdict.
	sent := session.Transmitted()
	Poll(t, "A to mark the A–B link down", func() bool {
		return !a.app.Monitor().Up(abIfID)
	})
	if now := session.Transmitted(); now <= sent {
		t.Error("A's BFD stopped transmitting on the down link")
	}
	// The serving instance is untouched: the entry stays established on the
	// same interface — no generation swap for a verdict flip.
	if e := entryOf(a, b.app.IA()); e.State != links.StateEstablished || e.IfID != abIfID {
		t.Errorf("A's entry = %v/%d, want established on %d", e.State, e.IfID, abIfID)
	}
	if a.app.Monitor().Session(entryOf(a, b.app.IA())) != session {
		t.Error("the verdict flip minted a new session")
	}

	// A ping from A toward B's far side — C — rides the path through the
	// dead link: the egress-down branch answers with the type-5 signal, and
	// A's conn records the signaled interface in the shared cache.
	pingLossy(ctx, t, a, c.app.IA(), c.host)
	Poll(t, "the interface-down signal to land in A's cache", func() bool {
		return a.app.InterfaceDown().Holds(a.app.IA(), abIfID)
	})

	// The selection loop, its neighbor now verdict-down below the up-link
	// floor, promotes the reachable C from the directory.
	Poll(t, "A to promote C to hold the floor", func() bool {
		return establishedOf(a, c.app.IA())
	})
	Poll(t, "A to reach C directly", func() bool {
		return pingFrom(ctx, a, c.app.IA(), c.host)
	})

	// Lift the blackhole: B restarted on the same state serves its persisted
	// link, and A's verdict returns up on the next answered arrival — the
	// same session, no generation swap.
	b2 := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.State = b.stateDir
		cfg.Internal = FreeUDPAddrOn(t, ipB)
		cfg.Control = FreeUDPAddrOn(t, ipB)
		cfg.RootCAs = wpki.pool
	})
	_ = b2
	Poll(t, "A's link to B to return up", func() bool {
		return a.app.Monitor().Up(abIfID)
	})
	if a.app.Monitor().Session(entryOf(a, b.app.IA())) != session {
		t.Error("the recovery minted a new session")
	}
	Poll(t, "A to reach B again", func() bool {
		return pingFrom(ctx, a, b.app.IA(), b.host)
	})
	if e := entryOf(a, b.app.IA()); e.State != links.StateEstablished || e.IfID != abIfID {
		t.Errorf("A's entry after recovery = %v/%d, want established on %d",
			e.State, e.IfID, abIfID)
	}
}

// TestBFDStaticLabEpisode runs the same episode on the static lab: three
// nodes paired by link-set files — the monitor is the core's, and the file
// provider's links carry BFD like any other's. No selection loop runs
// anywhere; the verdict gates forwarding and the signal reaches the source.
func TestBFDStaticLabEpisode(t *testing.T) {
	wpki := NewWebPKI(t)
	ipA, ipB, ipC := addrIP(0x71), addrIP(0x72), addrIP(0x73)

	abA, abB := FreeUDPAddrOn(t, ipA), FreeUDPAddrOn(t, ipB)
	bcB, bcC := FreeUDPAddrOn(t, ipB), FreeUDPAddrOn(t, ipC)
	newLinkSet := func(t *testing.T) string {
		path := linkSetPath(t)
		writeStaticSet(t, path)
		return path
	}
	bootStatic := func(t *testing.T, ip netip.Addr, core bool, state, linkSet string) *staticNode {
		t.Helper()
		n := &staticNode{linkSet: linkSet}
		n.assemblyNode = bootAssembly(t, func(cfg *services.NodeConfig) {
			cfg.Core = core
			cfg.LinkSet = linkSet
			cfg.State = state
			cfg.Internal = FreeUDPAddrOn(t, ip)
			cfg.Control = FreeUDPAddrOn(t, ip)
			if core {
				cfg.CertFile = wpki.certFile
				cfg.KeyFile = wpki.keyFile
			} else {
				cfg.RootCAs = wpki.pool
			}
		})
		return n
	}

	aState := t.TempDir()
	aSet := newLinkSet(t)
	a := bootStatic(t, ipA, true, aState, aSet)
	bState := t.TempDir()
	bSet := newLinkSet(t)
	writeStaticSet(t, bSet, staticLink{IA: a.app.IA().String(), Local: abB, Remote: abA})
	b := bootStatic(t, ipB, false, bState, bSet)
	cState := t.TempDir()
	cSet := newLinkSet(t)
	writeStaticSet(t, cSet, staticLink{IA: b.app.IA().String(), Local: bcC, Remote: bcB})
	c := bootStatic(t, ipC, false, cState, cSet)

	ifID := uint16(1)
	writeStaticSet(t, aSet, staticLink{IA: b.app.IA().String(), Local: abA, Remote: abB,
		Interface: &ifID})
	writeStaticSet(t, bSet,
		staticLink{IA: a.app.IA().String(), Local: abB, Remote: abA},
		staticLink{IA: c.app.IA().String(), Local: bcB, Remote: bcC})

	ctx := context.Background()
	Poll(t, "the static line to stand", func() bool {
		return establishedOf(a.assemblyNode, b.app.IA()) &&
			establishedOf(b.assemblyNode, a.app.IA()) &&
			establishedOf(c.assemblyNode, b.app.IA())
	})
	Poll(t, "A reaches C through B", func() bool {
		return pingFrom(ctx, a.assemblyNode, c.app.IA(), c.host)
	})

	// The blackhole: B dies, and A's monitor marks the file provider's link
	// down exactly as the measured provider's.
	b.cancel()
	b.app.Close()
	Poll(t, "A to mark the static link down", func() bool {
		return !a.app.Monitor().Up(ifID)
	})
	// The dead route answers the source with the signal; A's cache holds it.
	pingLossy(ctx, t, a.assemblyNode, c.app.IA(), c.host)
	Poll(t, "the interface-down signal to land in A's cache", func() bool {
		return a.app.InterfaceDown().Holds(a.app.IA(), ifID)
	})

	// Lift the blackhole: B restarted from its link-set returns the link up.
	b2 := bootStatic(t, ipB, false, bState, bSet)
	_ = b2
	Poll(t, "A's static link to B to return up", func() bool {
		return a.app.Monitor().Up(ifID)
	})
	Poll(t, "A to reach C through B again", func() bool {
		return pingFrom(ctx, a.assemblyNode, c.app.IA(), c.host)
	})
}

// establishedOf reports whether the node's entry of the neighbor is
// established.
func establishedOf(n *assemblyNode, ia addr.IA) bool {
	e := entryOf(n, ia)
	return e != nil && e.State == links.StateEstablished
}

// pingLossy runs one ping whose request is expected to die on a down egress:
// what matters is the SCMP error the slow path sends back, which the conn's
// receive path recognizes into the node's shared cache while the ping waits.
func pingLossy(ctx context.Context, t *testing.T, n *assemblyNode, dst addr.IA, host netip.Addr) {
	t.Helper()
	conn, err := n.app.Conn(0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = ping.Run(ctx, ping.Config{
		Conn:     conn,
		Provider: n.app.Provider(),
		Dst:      dst,
		DstHost:  host,
		Count:    1,
		Interval: 100 * time.Millisecond,
		Wait:     2 * time.Second,
	})
}

// linkSetPath names a fresh link-set file.
func linkSetPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "link-set.json")
}
