package testnetwork

import (
	"context"
	"net/netip"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/internal/services"
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/segment"
	"github.com/fancl20/cion/pkg/libs/underlay"
	"github.com/fancl20/cion/pkg/modules/links"
)

// bfdSelection paces the BFD lab's selection windows. The episode holds A's
// dead link established through its steps after the down verdict, which take
// seconds at the production BFD interval, and the selection retires a link
// whose verdict stays down for DemoteWindows windows. A neighbor missing
// from the selection's directory snapshot is never probed, so the windows
// run at the bare interval.
const bfdSelection = 5 * time.Second

// bfdPacing gives a BFD lab node the lab's selection windows.
func bfdPacing(cfg *services.NodeConfig) {
	cfg.Pacing.Selection = bfdSelection
}

// TestBFDLivenessEpisode is the BFD integration proof: a three-node
// line — the core A, the middle B, and C below — where killing B is the
// blackhole on the A–B link's sockets. A holds the floor of up links through
// a direct link to C and reaches C over it. A marks the A–B link down within
// the window while its BFD keeps leaving on the link's own socket; an echo
// from A across the dead link toward B's far side receives the type-5 signal
// and A's interface cache records it; lifting the blackhole — B restarted —
// returns the link up with no generation swap: the serving instance's
// session continuous across the episode. The selection loop retires a link
// whose verdict stays down for DemoteWindows windows, so every wait on path
// convergence comes before B dies.
func TestBFDLivenessEpisode(t *testing.T) {
	t.Parallel()
	wpki := webpkitest.New(t)
	ipA, ipB, ipC := hostSlot(t), hostSlot(t), hostSlot(t)
	a, b, c := bootRendezvousLine(t, wpki, ipA, ipB, ipC, bfdPacing)
	ctx := t.Context()

	// The line stands: A–B and B–C established, everyone enrolled and
	// answering end to end.
	Poll(t, "the line to stand", func() bool {
		return establishedOf(ctx, a, b.app.IA()) && establishedOf(ctx, b, a.app.IA()) &&
			establishedOf(ctx, b, c.app.IA()) && establishedOf(ctx, c, b.app.IA())
	})
	abEntry := entryOf(ctx, a, b.app.IA())
	abIfID := abEntry.IfID
	// The path through B is kept for the episode's echo across the dead
	// link, which no composition offers once A's verdict on it is down.
	var throughB *spath.Decoded
	Poll(t, "A reaches C through B", func() bool {
		throughB = pathVia(ctx, t, a, c.app.IA(), abIfID)
		return throughB != nil && echoOver(t, a, c.app.IA(), c.host, throughB, time.Second)
	})

	// A holds the floor of up links through a direct link to C — a line of
	// three leaves both ends below the floor, so one end's selection loop
	// promotes the other — and reaches C over it.
	Poll(t, "A to hold a direct link to C", func() bool {
		return establishedOf(ctx, a, c.app.IA())
	})
	acIfID := entryOf(ctx, a, c.app.IA()).IfID
	Poll(t, "A to reach C directly", func() bool {
		return echoVia(ctx, t, a, c.app.IA(), c.host, acIfID, time.Second)
	})

	session := a.app.Monitor().Session(abEntry)
	if session == nil {
		t.Fatal("no BFD session on A's link to B")
	}

	// The blackhole: kill B.
	b.stop(t)

	// A marks the link down within the window while its BFD keeps leaving
	// on the link's own socket — the stream survives its own verdict.
	Poll(t, "A to mark the A–B link down", func() bool {
		return !a.app.Monitor().Up(abIfID)
	})
	sent := session.Transmitted()
	Poll(t, "A's BFD to keep transmitting on the down link", func() bool {
		return session.Transmitted() > sent
	})
	// The serving instance is untouched: the entry stays established on the
	// same interface — no generation swap for a verdict flip.
	if e := entryOf(ctx, a, b.app.IA()); e.State != links.StateEstablished || e.IfID != abIfID {
		t.Errorf("A's entry = %v/%d, want established on %d", e.State, e.IfID, abIfID)
	}
	if a.app.Monitor().Session(entryOf(ctx, a, b.app.IA())) != session {
		t.Error("the verdict flip minted a new session")
	}

	// An echo from A toward B's far side — C — over the path through the
	// dead link: the egress-down branch answers with the type-5 signal, and
	// A's conn records the signaled interface in the shared cache.
	echoAcrossDownLink(t, a, c.app.IA(), c.host, abIfID, throughB)

	// Lift the blackhole: B restarted on the same state serves its persisted
	// link, and A's verdict returns up on the next answered arrival — the
	// same session, no generation swap.
	b2 := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.State = b.stateDir
		cfg.Internal = PinnedUDPAddrOn(t, ipB)
		cfg.Control = FreeUDPAddrOn(t, ipB)
		cfg.RootCAs = wpki.Pool
		bfdPacing(cfg)
	})
	_ = b2
	Poll(t, "A's link to B to return up", func() bool {
		return a.app.Monitor().Up(abIfID)
	})
	if a.app.Monitor().Session(entryOf(ctx, a, b.app.IA())) != session {
		t.Error("the recovery minted a new session")
	}
	Poll(t, "A to reach B again", func() bool {
		return pingFrom(ctx, a, b.app.IA(), b.host)
	})
	if e := entryOf(ctx, a, b.app.IA()); e.State != links.StateEstablished || e.IfID != abIfID {
		t.Errorf("A's entry after recovery = %v/%d, want established on %d",
			e.State, e.IfID, abIfID)
	}
}

// TestBFDStaticLabEpisode runs the same episode on the static lab: three
// nodes paired by link-set files — the monitor is the core's, and the file
// provider's links carry BFD like any other's. No selection loop runs
// anywhere; the verdict gates forwarding and the signal reaches the source.
func TestBFDStaticLabEpisode(t *testing.T) {
	t.Parallel()
	wpki := webpkitest.New(t)
	ipB := hostSlot(t)
	a, b, c := bootStaticLine(t, wpki, hostSlot(t), ipB, hostSlot(t))
	// The interface the core's file named its link to B.
	ifID := uint16(1)

	ctx := t.Context()
	Poll(t, "the static line to stand", func() bool {
		return establishedOf(ctx, a.assemblyNode, b.app.IA()) &&
			establishedOf(ctx, b.assemblyNode, a.app.IA()) &&
			establishedOf(ctx, c.assemblyNode, b.app.IA())
	})
	// The path through B is kept for the echo across the dead link, which
	// no composition offers once A's verdict on it is down.
	var throughB *spath.Decoded
	Poll(t, "A reaches C through B", func() bool {
		throughB = pathVia(ctx, t, a.assemblyNode, c.app.IA(), ifID)
		return throughB != nil &&
			echoOver(t, a.assemblyNode, c.app.IA(), c.host, throughB, time.Second)
	})

	// The blackhole: B dies, and A's monitor marks the file provider's link
	// down exactly as the measured provider's.
	b.stop(t)
	Poll(t, "A to mark the static link down", func() bool {
		return !a.app.Monitor().Up(ifID)
	})
	// The dead route answers the source with the signal; A's cache holds it.
	echoAcrossDownLink(t, a.assemblyNode, c.app.IA(), c.host, ifID, throughB)

	// Lift the blackhole: B restarted from its link-set returns the link up.
	b2 := bootStaticNode(t, wpki, ipB, false, b.stateDir, b.linkSet, nil)
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
func establishedOf(ctx context.Context, n *assemblyNode, ia addr.IA) bool {
	e := entryOf(ctx, n, ia)
	return e != nil && e.State == links.StateEstablished
}

// echoAcrossDownLink sends echoes toward the destination over a path
// through the node's down interface — captured while the link was up, for
// the provider composes no path through an interface the node cannot send
// over — until the node's shared cache holds the egress-down branch's
// type-5 signal, which the receive path records while each echo goes
// unanswered.
func echoAcrossDownLink(t *testing.T, n *assemblyNode, dst addr.IA,
	host netip.Addr, ifID uint16, path *spath.Decoded) {

	t.Helper()
	Poll(t, "the interface-down signal to land in the cache", func() bool {
		echoOver(t, n, dst, host, path, 100*time.Millisecond)
		return n.app.InterfaceDown().Holds(n.app.IA(), ifID)
	})
}

// pathVia returns a composed path toward the destination that leaves
// through the node's interface; nil while none is composed.
func pathVia(ctx context.Context, t *testing.T, n *assemblyNode, dst addr.IA,
	ifID uint16) *spath.Decoded {

	t.Helper()
	candidates, err := n.app.Provider().Enumerate(ctx, dst)
	if err != nil {
		t.Fatal(err)
	}
	via := segment.LinkID{IA: n.app.IA(), IfID: ifID}
	i := slices.IndexFunc(candidates, func(c scion.Candidate) bool {
		return slices.Contains(c.Links, via)
	})
	if i < 0 {
		return nil
	}
	return candidates[i].Path
}

// echoVia sends an echo request toward the destination over a composed
// path leaving through the node's interface and reports whether the reply
// arrived within the wait; while no such path is composed it reports false
// at once.
func echoVia(ctx context.Context, t *testing.T, n *assemblyNode, dst addr.IA,
	host netip.Addr, ifID uint16, wait time.Duration) bool {

	t.Helper()
	path := pathVia(ctx, t, n, dst, ifID)
	return path != nil && echoOver(t, n, dst, host, path, wait)
}

// echoOver sends an echo request toward the destination over the path and
// reads the socket until the reply arrives or the wait elapses, reporting
// whether the reply arrived. The receive path records an interface-down
// signal in the node's shared cache as it reads.
func echoOver(t *testing.T, n *assemblyNode, dst addr.IA, host netip.Addr,
	path *spath.Decoded, wait time.Duration) bool {

	t.Helper()
	conn, err := n.app.Conn(0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.WriteEchoRequestTo(&scion.Addr{
		IA:   dst,
		Addr: netip.AddrPortFrom(host, underlay.EndhostPort),
		Path: path,
	}, 0, nil); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(wait)); err != nil {
		t.Fatal(err)
	}
	for {
		echo, _, err := conn.ReadEchoFrom()
		if err != nil {
			return false // the wait elapsed
		}
		if echo.Reply && echo.Identifier == conn.LocalPort() {
			return true
		}
	}
}

// linkSetPath names a fresh link-set file.
func linkSetPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "link-set.json")
}
