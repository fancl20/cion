package testnetwork

import (
	"encoding/json/v2"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/internal/services"
	"github.com/fancl20/cion/pkg/modules/links"
	"github.com/fancl20/cion/pkg/webpki/webpkitest"
)

// staticNode is a node of the static lab: the run command's own assembly
// under the file provider, with its link-set file's path kept for edits.
type staticNode struct {
	*assemblyNode
	linkSet string
}

// staticLink is one link-set entry the lab writes.
type staticLink struct {
	IA        string  `json:"ia"`
	Local     string  `json:"local"`
	Remote    string  `json:"remote"`
	Interface *uint16 `json:"interface,omitempty"`
}

// writeStaticSet writes the link-set file's JSON.
func writeStaticSet(t *testing.T, path string, entries ...staticLink) {
	t.Helper()
	raw, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// newStaticSet names a fresh, empty link-set file.
func newStaticSet(t *testing.T) string {
	t.Helper()
	path := linkSetPath(t)
	writeStaticSet(t, path)
	return path
}

// bootStaticNode boots one node of the static lab on its loopback host: the
// run command's own assembly under the file provider, its state directory
// and link-set file the caller's.
func bootStaticNode(t *testing.T, wpki *webpkitest.CA, ip netip.Addr, core bool,
	state, linkSet string, mutate func(*services.NodeConfig)) *staticNode {

	t.Helper()
	n := &staticNode{linkSet: linkSet}
	n.assemblyNode = bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.Core = core
		cfg.LinkSet = linkSet
		cfg.State = state
		cfg.Internal = PinnedUDPAddrOn(t, ip)
		cfg.Control = FreeUDPAddrOn(t, ip)
		if core {
			cfg.CertFile = wpki.CertFile
			cfg.KeyFile = wpki.KeyFile
		} else {
			cfg.RootCAs = wpki.Pool
		}
		if mutate != nil {
			mutate(cfg)
		}
	})
	return n
}

// bootStaticLine brings up the static lab's three-node line — the founding
// core A, the middle B, and C below — paired by link-set files only: the
// two links' underlay addresses picked up front, the files' entries
// completing as each node's name turns final, the founding core started
// first.
func bootStaticLine(t *testing.T, wpki *webpkitest.CA,
	ipA, ipB, ipC netip.Addr) (a, b, c *staticNode) {

	t.Helper()
	abA, abB := PinnedUDPAddrOn(t, ipA), PinnedUDPAddrOn(t, ipB)
	bcB, bcC := PinnedUDPAddrOn(t, ipB), PinnedUDPAddrOn(t, ipC)

	// The founding core starts first, its link-set empty: its draw names
	// the ISD the other files' entries complete with. B's file names the
	// core — final already — before B's first start; C's names B, final
	// once B's first start completed from A's entry.
	a = bootStaticNode(t, wpki, ipA, true, t.TempDir(), newStaticSet(t), nil)
	bFile := newStaticSet(t)
	writeStaticSet(t, bFile, staticLink{IA: a.app.IA().String(), Local: abB, Remote: abA})
	b = bootStaticNode(t, wpki, ipB, false, t.TempDir(), bFile, nil)
	cFile := newStaticSet(t)
	writeStaticSet(t, cFile, staticLink{IA: b.app.IA().String(), Local: bcC, Remote: bcB})
	c = bootStaticNode(t, wpki, ipC, false, t.TempDir(), cFile, nil)

	// The core's file gains B's entry — B's name is final now, and the
	// entry's interface ID names one — and B's gains C's, the
	// modification-time poll reconciling each into the store as a
	// generation swap.
	ifID := uint16(1)
	writeStaticSet(t, a.linkSet,
		staticLink{IA: b.app.IA().String(), Local: abA, Remote: abB, Interface: &ifID})
	writeStaticSet(t, b.linkSet,
		staticLink{IA: a.app.IA().String(), Local: abB, Remote: abA},
		staticLink{IA: c.app.IA().String(), Local: bcB, Remote: bcC})
	return a, b, c
}

// staticTopology is a lab topology on the file provider: its nodes by
// ISD-AS, the founding core among them, the links between neighbors, the
// interface IDs a lab crafts hop fields against, each keyed by the node
// whose entry pins it and the neighbor the entry names, and, when set, a
// mutation every node's run arguments take last. A zero core leaves every
// node non-core.
type staticTopology struct {
	core   addr.IA
	nodes  []addr.IA
	links  [][2]addr.IA
	pins   map[[2]addr.IA]uint16
	mutate func(*services.NodeConfig)
}

// bootTopology boots a static topology through the node's own assembly.
// Each node's ISD-AS is written to its state before any boot, so every
// node's link set names its neighbors up front, each link's addresses drawn
// from its two nodes' hosts; the founding core, if any, boots first.
func bootTopology(t *testing.T, wpki *webpkitest.CA, topo staticTopology) map[addr.IA]*staticNode {
	t.Helper()
	hosts := make(map[addr.IA]netip.Addr, len(topo.nodes))
	states := make(map[addr.IA]string, len(topo.nodes))
	for _, ia := range topo.nodes {
		hosts[ia] = hostSlot(t)
		states[ia] = t.TempDir()
		persistIAFile(t, states[ia], ia)
	}
	entry := func(local, neighbor addr.IA, atLocal, atNeighbor string) staticLink {
		e := staticLink{IA: neighbor.String(), Local: atLocal, Remote: atNeighbor}
		if ifID, ok := topo.pins[[2]addr.IA{local, neighbor}]; ok {
			e.Interface = &ifID
		}
		return e
	}
	entries := make(map[addr.IA][]staticLink, len(topo.nodes))
	for _, l := range topo.links {
		x, y := l[0], l[1]
		atX, atY := PinnedUDPAddrOn(t, hosts[x]), PinnedUDPAddrOn(t, hosts[y])
		entries[x] = append(entries[x], entry(x, y, atX, atY))
		entries[y] = append(entries[y], entry(y, x, atY, atX))
	}
	sets := make(map[addr.IA]string, len(topo.nodes))
	for _, ia := range topo.nodes {
		sets[ia] = linkSetPath(t)
		writeStaticSet(t, sets[ia], entries[ia]...)
	}
	nodes := make(map[addr.IA]*staticNode, len(topo.nodes))
	if !topo.core.IsZero() {
		nodes[topo.core] = bootStaticNode(t, wpki, hosts[topo.core], true,
			states[topo.core], sets[topo.core], topo.mutate)
	}
	for _, ia := range topo.nodes {
		if ia != topo.core {
			nodes[ia] = bootStaticNode(t, wpki, hosts[ia], false, states[ia], sets[ia], topo.mutate)
		}
	}
	return nodes
}

// TestStaticLabByLinkSet is the file provider's integration proof: a
// three-node line — the founding core A, the middle B, and C below — paired by
// link-set files only: no rendezvous acceptor, no node directory, no selection
// loop runs anywhere. They beacon, forward, and answer echo end to end;
// identity completes from the files, the founding core started first; and
// removing an entry from B's file retires the link as a generation swap the
// surviving traffic rides through.
func TestStaticLabByLinkSet(t *testing.T) {
	t.Parallel()
	wpki := webpkitest.New(t)
	a, b, c := bootStaticLine(t, wpki, hostSlot(t), hostSlot(t), hostSlot(t))

	// The identity completed from the files: one ISD, each AS its own draw.
	for _, n := range []*staticNode{b, c} {
		if got := n.app.IA().ISD(); got != a.app.IA().ISD() {
			t.Errorf("a joiner's ISD = %d, want the files' %d", got, a.app.IA().ISD())
		}
	}

	ctx := t.Context()
	// The links stand: both sides of each hold an established entry, the
	// core's on the interface its file named.
	Poll(t, "A's link to B", func() bool {
		e := entryOf(ctx, a.assemblyNode, b.app.IA())
		return e != nil && e.State == links.StateEstablished && e.IfID == 1
	})
	Poll(t, "B's link to A", func() bool {
		e := entryOf(ctx, b.assemblyNode, a.app.IA())
		return e != nil && e.State == links.StateEstablished
	})
	Poll(t, "B's link to C", func() bool {
		e := entryOf(ctx, b.assemblyNode, c.app.IA())
		return e != nil && e.State == links.StateEstablished
	})
	Poll(t, "C's link to B", func() bool {
		e := entryOf(ctx, c.assemblyNode, b.app.IA())
		return e != nil && e.State == links.StateEstablished
	})

	// They beacon, forward, and answer echo end to end: B enrolls with the
	// core, C enrolls through B, and the core's echo to C rides the
	// composed two-hop path — the responder in every node's assembly
	// answering on its reversed arrival path.
	Poll(t, "B enrolled", func() bool { return pingFrom(ctx, b.assemblyNode, a.app.IA(), a.host) })
	Poll(t, "C enrolled", func() bool { return pingFrom(ctx, c.assemblyNode, a.app.IA(), a.host) })
	Poll(t, "the core reaches C", func() bool { return pingFrom(ctx, a.assemblyNode, c.app.IA(), c.host) })

	// Removing C's entry from B's file retires the link — a generation swap
	// the surviving traffic rides through. The A–B entry keeps the
	// addresses the standing link holds.
	ab := entryOf(ctx, b.assemblyNode, a.app.IA())
	writeStaticSet(t, b.linkSet, staticLink{
		IA: a.app.IA().String(), Local: ab.Local.String(), Remote: ab.Remote.String()})
	Poll(t, "B retired the link to C", func() bool {
		e := entryOf(ctx, b.assemblyNode, c.app.IA())
		return e != nil && e.State == links.StateRetired
	})
	Poll(t, "A and B still answer each other", func() bool {
		return pingFrom(ctx, a.assemblyNode, b.app.IA(), b.host)
	})
}

// TestStaticEnrollmentByAuthorizer checks the admission boundary the
// enrollment authorizer now is: the file provider's operator vouch admits the
// link — no acceptor reads any policy — while the core's CIDR authorizer
// bounds enrollment, a joiner whose source address no listed prefix contains
// never enrolling. No allowlist exists anywhere.
func TestStaticEnrollmentByAuthorizer(t *testing.T) {
	t.Parallel()
	wpki := webpkitest.New(t)
	ipA, ipB := hostSlot(t), hostSlot(t)
	abA, abB := PinnedUDPAddrOn(t, ipA), PinnedUDPAddrOn(t, ipB)

	// A prefix list that admits nothing on the lab's loopback addressing:
	// the vouch below still admits the link, the authorizer still bounds
	// the enrollment.
	a := bootStaticNode(t, wpki, ipA, true, t.TempDir(), newStaticSet(t),
		func(cfg *services.NodeConfig) {
			cfg.EnrollAuth = "cidrs=10.0.0.0/8"
		})
	bFile := newStaticSet(t)
	writeStaticSet(t, bFile, staticLink{IA: a.app.IA().String(), Local: abB, Remote: abA})
	b := bootStaticNode(t, wpki, ipB, false, t.TempDir(), bFile, nil)
	ifID := uint16(1)
	writeStaticSet(t, a.linkSet,
		staticLink{IA: b.app.IA().String(), Local: abA, Remote: abB, Interface: &ifID})

	Poll(t, "the link stands by the operator's vouch", func() bool {
		e := entryOf(t.Context(), b.assemblyNode, a.app.IA())
		return e != nil && e.State == links.StateEstablished
	})
	Poll(t, "the core's vouched link stands", func() bool {
		e := entryOf(t.Context(), a.assemblyNode, b.app.IA())
		return e != nil && e.State == links.StateEstablished
	})
	// The authorizer bounds enrollment: no chain ever names the joiner, on
	// either side, however long the joiner's retries run.
	time.Sleep(30 * fastPacing.Enrollment)
	if holdsChain(t.Context(), b.assemblyNode) {
		t.Error("a joiner outside the prefix list enrolled over the vouched link")
	}
	if !holdsNoChainFor(t.Context(), a.assemblyNode, b.assemblyNode) {
		t.Error("the core issued a chain naming a joiner outside the prefix list")
	}
}
