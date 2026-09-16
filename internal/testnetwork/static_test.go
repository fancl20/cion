package testnetwork

import (
	"context"
	"encoding/json/v2"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/fancl20/cion/internal/services"
	"github.com/fancl20/cion/pkg/links"
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

// TestStaticLabByLinkSet is the file provider's integration proof (ADR
// 0007): a three-node line — the founding core A, the middle B, and C below
// — paired by link-set files only: no rendezvous acceptor, no node
// directory, no selection loop runs anywhere. They beacon, forward, and
// answer echo end to end; identity completes from the files, the founding
// core started first; and removing an entry from B's file retires the link
// as a generation swap the surviving traffic rides through.
func TestStaticLabByLinkSet(t *testing.T) {
	wpki := NewWebPKI(t)
	ipA, ipB, ipC := addrIP(0x51), addrIP(0x52), addrIP(0x53)

	// The operator picks the two links' underlay addresses up front; only
	// the ISD-ASes wait for the nodes' names, the file provider's one
	// operational ceremony.
	abA, abB := FreeUDPAddrOn(t, ipA), FreeUDPAddrOn(t, ipB)
	bcB, bcC := FreeUDPAddrOn(t, ipB), FreeUDPAddrOn(t, ipC)
	newLinkSet := func(t *testing.T) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "link-set.json")
		writeStaticSet(t, path)
		return path
	}
	bootStatic := func(t *testing.T, ip netip.Addr, core bool, linkSet string) *staticNode {
		t.Helper()
		n := &staticNode{linkSet: linkSet}
		n.assemblyNode = bootAssembly(t, func(cfg *services.NodeConfig) {
			cfg.Core = core
			cfg.LinkSet = linkSet
			cfg.State = t.TempDir()
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

	// The founding core starts first, its link-set empty: its draw names
	// the ISD the other files' entries complete with. B's file names the
	// core — final already — before B's first start; C's names B, final
	// once B's first start completed from A's entry.
	a := bootStatic(t, ipA, true, newLinkSet(t))
	bFile := newLinkSet(t)
	writeStaticSet(t, bFile, staticLink{IA: a.app.IA().String(), Local: abB, Remote: abA})
	b := bootStatic(t, ipB, false, bFile)
	cFile := newLinkSet(t)
	writeStaticSet(t, cFile, staticLink{IA: b.app.IA().String(), Local: bcC, Remote: bcB})
	c := bootStatic(t, ipC, false, cFile)

	// The identity completed from the files: one ISD, each AS its own draw.
	for _, n := range []*staticNode{b, c} {
		if got := n.app.IA().ISD(); got != a.app.IA().ISD() {
			t.Errorf("a joiner's ISD = %d, want the files' %d", got, a.app.IA().ISD())
		}
	}

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

	ctx := context.Background()
	// The links stand: both sides of each hold an established entry.
	Poll(t, "A's link to B", func() bool {
		e := entryOf(a.assemblyNode, b.app.IA())
		return e != nil && e.State == links.StateEstablished && e.IfID == ifID
	})
	Poll(t, "B's link to A", func() bool {
		e := entryOf(b.assemblyNode, a.app.IA())
		return e != nil && e.State == links.StateEstablished
	})
	Poll(t, "B's link to C", func() bool {
		e := entryOf(b.assemblyNode, c.app.IA())
		return e != nil && e.State == links.StateEstablished
	})
	Poll(t, "C's link to B", func() bool {
		e := entryOf(c.assemblyNode, b.app.IA())
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
	// the surviving traffic rides through.
	writeStaticSet(t, b.linkSet, staticLink{IA: a.app.IA().String(), Local: abB, Remote: abA})
	Poll(t, "B retired the link to C", func() bool {
		e := entryOf(b.assemblyNode, c.app.IA())
		return e != nil && e.State == links.StateRetired
	})
	Poll(t, "A and B still answer each other", func() bool {
		return pingFrom(ctx, a.assemblyNode, b.app.IA(), b.host)
	})
}
