package testnetwork

import (
	"encoding/json/v2"
	"net/netip"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	spath "github.com/scionproto/scion/pkg/slayers/path/scion"

	"github.com/fancl20/cion/internal/services"
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
	"github.com/fancl20/cion/pkg/libs/scion"
	"github.com/fancl20/cion/pkg/libs/segment"
	"github.com/fancl20/cion/pkg/modules/links"
)

// staticNode is a node of the static lab: the run command's own assembly
// under the file provider, with its link-set file's path kept for edits.
type staticNode struct {
	*Node
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
	n.Node = bootAssembly(t, func(cfg *services.NodeConfig) {
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
// first. mutate, when set, takes every node's run arguments last.
func bootStaticLine(t *testing.T, wpki *webpkitest.CA, mutate func(*services.NodeConfig),
	ipA, ipB, ipC netip.Addr) (a, b, c *staticNode) {

	t.Helper()
	abA, abB := PinnedUDPAddrOn(t, ipA), PinnedUDPAddrOn(t, ipB)
	bcB, bcC := PinnedUDPAddrOn(t, ipB), PinnedUDPAddrOn(t, ipC)

	// The founding core starts first, its link-set empty: its draw names
	// the ISD the other files' entries complete with. B's file names the
	// core — final already — before B's first start; C's names B, final
	// once B's first start completed from A's entry.
	a = bootStaticNode(t, wpki, ipA, true, t.TempDir(), newStaticSet(t), mutate)
	bFile := newStaticSet(t)
	writeStaticSet(t, bFile, staticLink{IA: a.app.IA().String(), Local: abB, Remote: abA})
	b = bootStaticNode(t, wpki, ipB, false, t.TempDir(), bFile, mutate)
	cFile := newStaticSet(t)
	writeStaticSet(t, cFile, staticLink{IA: b.app.IA().String(), Local: bcC, Remote: bcB})
	c = bootStaticNode(t, wpki, ipC, false, t.TempDir(), cFile, mutate)

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

// entries returns each node's link-set entries, each link's addresses drawn
// by at from its two nodes, and each pinned interface named in the entry of
// the node whose pin it is.
func (topo staticTopology) entries(at func(addr.IA) string) map[addr.IA][]staticLink {
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
		atX, atY := at(x), at(y)
		entries[x] = append(entries[x], entry(x, y, atX, atY))
		entries[y] = append(entries[y], entry(y, x, atY, atX))
	}
	return entries
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
		hosts[ia] = HostSlot(t)
		states[ia] = t.TempDir()
		persistIAFile(t, states[ia], ia)
	}
	entries := topo.entries(func(ia addr.IA) string { return PinnedUDPAddrOn(t, hosts[ia]) })
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
	a, b, c := bootStaticLine(t, wpki, nil, HostSlot(t), HostSlot(t), HostSlot(t))

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
		e := entryOf(ctx, a.Node, b.app.IA())
		return e != nil && e.State == links.StateEstablished && e.IfID == 1
	})
	Poll(t, "B's link to A", func() bool {
		e := entryOf(ctx, b.Node, a.app.IA())
		return e != nil && e.State == links.StateEstablished
	})
	Poll(t, "B's link to C", func() bool {
		e := entryOf(ctx, b.Node, c.app.IA())
		return e != nil && e.State == links.StateEstablished
	})
	Poll(t, "C's link to B", func() bool {
		e := entryOf(ctx, c.Node, b.app.IA())
		return e != nil && e.State == links.StateEstablished
	})

	// They beacon, forward, and answer echo end to end: B enrolls with the
	// core, C enrolls through B, and the core's echo to C rides the
	// composed two-hop path — the responder in every node's assembly
	// answering on its reversed arrival path.
	Poll(t, "B enrolled", func() bool { return pingFrom(ctx, b.Node, a.app.IA(), a.host) })
	Poll(t, "C enrolled", func() bool { return pingFrom(ctx, c.Node, a.app.IA(), a.host) })
	Poll(t, "the core reaches C", func() bool { return pingFrom(ctx, a.Node, c.app.IA(), c.host) })

	// Removing C's entry from B's file retires the link — a generation swap
	// the surviving traffic rides through. The A–B entry keeps the
	// addresses the standing link holds.
	ab := entryOf(ctx, b.Node, a.app.IA())
	writeStaticSet(t, b.linkSet, staticLink{
		IA: a.app.IA().String(), Local: ab.Local.String(), Remote: ab.Remote.String()})
	Poll(t, "B retired the link to C", func() bool {
		e := entryOf(ctx, b.Node, c.app.IA())
		return e != nil && e.State == links.StateRetired
	})
	Poll(t, "A and B still answer each other", func() bool {
		return pingFrom(ctx, a.Node, b.app.IA(), b.host)
	})
}

// TestStaticLineWithoutMemberships is the none method's proof: the static
// lab's line, every node run without memberships, enrolls and answers echo
// end to end, and the founder lists every node by its chain, none with an
// expiry.
func TestStaticLineWithoutMemberships(t *testing.T) {
	t.Parallel()
	wpki := webpkitest.New(t)
	a, b, c := bootStaticLine(t, wpki, func(cfg *services.NodeConfig) {
		cfg.Membership = "none"
	}, HostSlot(t), HostSlot(t), HostSlot(t))

	ctx := t.Context()
	Poll(t, "B enrolled", func() bool { return pingFrom(ctx, b.Node, a.app.IA(), a.host) })
	Poll(t, "C enrolled", func() bool { return pingFrom(ctx, c.Node, a.app.IA(), a.host) })
	Poll(t, "the core reaches C", func() bool { return pingFrom(ctx, a.Node, c.app.IA(), c.host) })
	Poll(t, "the founder to list every node without an expiry", func() bool {
		list, err := a.app.Memberships(ctx)
		if err != nil {
			t.Fatal(err)
		}
		listed := make(map[addr.IA]bool, len(list))
		for _, m := range list {
			if !m.Expires.IsZero() {
				t.Fatalf("the founder lists %v with an expiry", m.IA)
			}
			listed[m.IA] = true
		}
		return listed[a.app.IA()] && listed[b.app.IA()] && listed[c.app.IA()]
	})
}

// TestRetiredLinkAnswersInterfaceDown is the retired link's proof on the
// static lab: the core A reaches D over two branches — B, and C then E —
// and its chosen path crosses B's link to D, the branch of fewer hops.
// Removing D's entry from B's file retires the link while the segments
// through it stay fresh for minutes: B's data plane answers an echo over
// them with the interface-down signal, A's interface-down topic holds B's
// interface, and A reaches D over C and E at once.
func TestRetiredLinkAnswersInterfaceDown(t *testing.T) {
	t.Parallel()
	iaD := addr.MustIAFrom(20, 0xff0000000091)
	iaE := addr.MustIAFrom(20, 0xff0000000092)
	// B's interface toward D, pinned so the lab names the signaled pair.
	const bd = uint16(7)
	nodes := bootTopology(t, webpkitest.New(t), staticTopology{
		core:  coreIA,
		nodes: []addr.IA{coreIA, nodeIA, lineCIA, iaD, iaE},
		links: [][2]addr.IA{
			{coreIA, nodeIA}, {nodeIA, iaD},
			{coreIA, lineCIA}, {lineCIA, iaE}, {iaE, iaD},
		},
		pins: map[[2]addr.IA]uint16{{nodeIA, iaD}: bd},
	})
	a, b, d := nodes[coreIA], nodes[nodeIA], nodes[iaD]
	ctx := t.Context()
	viaB := segment.LinkID{IA: nodeIA, IfID: bd}

	// A reaches D through B, and holds a fresh path around it.
	var throughB *spath.Decoded
	PollFor(t, RestartTimeout, "A to reach D through B", func() bool {
		c, err := a.app.Provider().Choose(ctx, iaD)
		if err != nil || !slices.Contains(c.Links, viaB) {
			return false
		}
		throughB = c.Path
		return pingFrom(ctx, a.Node, iaD, d.host)
	})
	Poll(t, "A to compose a fresh path around B", func() bool {
		candidates, err := a.app.Provider().Enumerate(ctx, iaD)
		return err == nil && slices.ContainsFunc(candidates, func(c scion.Candidate) bool {
			return !c.Stale && !slices.Contains(c.Links, viaB)
		})
	})

	// Removing D's entry from B's file retires the link. The A–B entry
	// keeps the addresses the standing link holds.
	ab := entryOf(ctx, b.Node, coreIA)
	writeStaticSet(t, b.linkSet, staticLink{
		IA: coreIA.String(), Local: ab.Local.String(), Remote: ab.Remote.String()})
	Poll(t, "B retired the link to D", func() bool {
		e := entryOf(ctx, b.Node, iaD)
		return e != nil && e.State == links.StateRetired
	})

	// B's data plane answers an echo over the path through the retired link
	// with the signal, and A, its topic holding the signal, reaches D over C
	// and E while the path through B still ranks first.
	echoAcrossDownLink(t, a.Node, iaD, d.host, viaB, throughB)
	Poll(t, "A to reach D around the retired link", func() bool {
		return pingFrom(ctx, a.Node, iaD, d.host)
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
	ipA, ipB := HostSlot(t), HostSlot(t)
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
		e := entryOf(t.Context(), b.Node, a.app.IA())
		return e != nil && e.State == links.StateEstablished
	})
	Poll(t, "the core's vouched link stands", func() bool {
		e := entryOf(t.Context(), a.Node, b.app.IA())
		return e != nil && e.State == links.StateEstablished
	})
	// The authorizer bounds enrollment: no chain ever names the joiner, on
	// either side, however long the joiner's retries run.
	time.Sleep(30 * fastPacing.Enrollment)
	if holdsChain(t.Context(), b.Node) {
		t.Error("a joiner outside the prefix list enrolled over the vouched link")
	}
	if !holdsNoChainFor(t.Context(), a.Node, b.Node) {
		t.Error("the core issued a chain naming a joiner outside the prefix list")
	}
}
