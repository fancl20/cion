package testnetwork

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/internal/services"
	"github.com/fancl20/cion/pkg/modules/trustdb"
	"github.com/fancl20/cion/pkg/trust"
)

// TestCoreJoinsBySensitiveUpdate is the join seam's integration proof: a
// founding core and a core joining it by rendezvous — the run command's own
// path, the core flag beside a neighbor — where the joiner completes its ISD
// from the neighbor's reply, enrolls with its voting certificate presented,
// submits its partially signed successor to the founder's voting
// application, and the founder's decision votes and pins; both pin the
// completed TRC, a third node discovers it from the founder's signed
// messages and enumerates two core ASes, and a node neighboring the joiner
// enrolls through the founder's endpoint — the issuer the route selects.
func TestCoreJoinsBySensitiveUpdate(t *testing.T) {
	t.Parallel()
	wpki := NewWebPKI(t)
	ipA, ipB, ipC, ipD := hostSlot(t), hostSlot(t), hostSlot(t), hostSlot(t)

	// The founding core.
	a := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.State = t.TempDir()
		cfg.Internal = PinnedUDPAddrOn(t, ipA)
		cfg.Control = FreeUDPAddrOn(t, ipA)
		cfg.CertFile = wpki.certFile
		cfg.KeyFile = wpki.keyFile
	})
	// The joining core: the core flag beside the founder's rendezvous
	// address, the network's core domain the bootstrap channel anchors to.
	b := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.State = t.TempDir()
		cfg.Internal = PinnedUDPAddrOn(t, ipB)
		cfg.Control = FreeUDPAddrOn(t, ipB)
		cfg.Neighbors = []string{a.rendezvousOf()}
		cfg.RootCAs = wpki.pool
	})
	// A third node joining the founder, to watch the successor spread.
	c := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.State = t.TempDir()
		cfg.Internal = PinnedUDPAddrOn(t, ipC)
		cfg.Control = FreeUDPAddrOn(t, ipC)
		cfg.Neighbors = []string{a.rendezvousOf()}
		cfg.RootCAs = wpki.pool
	})
	// A node neighboring the joining core alone, whose enrollments must
	// route past it to the founder.
	d := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.State = t.TempDir()
		cfg.Internal = PinnedUDPAddrOn(t, ipD)
		cfg.Control = FreeUDPAddrOn(t, ipD)
		cfg.Neighbors = []string{b.rendezvousOf()}
		cfg.RootCAs = wpki.pool
	})
	ctx := context.Background()

	// The joining core's identity completes from the neighbor's reply: the
	// founder's ISD, the drawn AS kept.
	Poll(t, "the joining core enrolled", func() bool { return holdsAssemblyChain(t, b, b.app.IA()) })
	if got := b.app.IA().ISD(); got != a.app.IA().ISD() {
		t.Fatalf("the joining core's ISD = %d, want the network's %d", got, a.app.IA().ISD())
	}

	// The cast lands: both sides pin the successor naming the joiner a core.
	successor := cppki.TRCID{ISD: a.app.IA().ISD(), Base: 1, Serial: 2}
	pollTRC := func(name string, app *services.App) cppki.SignedTRC {
		var trc cppki.SignedTRC
		Poll(t, name, func() bool {
			pinned, err := app.TrustDB().SignedTRC(ctx, successor)
			if err != nil {
				t.Fatal(err)
			}
			trc = pinned
			return !trc.IsZero()
		})
		return trc
	}
	founderPinned := pollTRC("the founder pinned the successor", a.app)
	joinerPinned := pollTRC("the joining core pinned the successor", b.app)
	for name, trc := range map[string]cppki.SignedTRC{
		"the founder's": founderPinned, "the joiner's": joinerPinned,
	} {
		if string(trc.Raw) != string(founderPinned.Raw) {
			t.Errorf("%s pinned successor differs from the founder's", name)
		}
		if err := trc.Verify(nil); err == nil {
			t.Errorf("%s successor verified without its predecessor", name)
		}
		named := false
		for _, as := range trc.TRC.CoreASes {
			if as == b.app.IA().AS() {
				named = true
			}
		}
		if !named {
			t.Errorf("%s successor names no core beside the founder", name)
		}
	}

	// The third node discovers the successor from the founder's signed
	// messages — the cited TRC the verifier reports — and enumerates two
	// core ASes off the newest TRC it holds.
	Poll(t, "the third node pinned the successor", func() bool {
		pinned, err := c.app.TrustDB().SignedTRC(ctx, successor)
		if err != nil {
			t.Fatal(err)
		}
		return !pinned.IsZero()
	})
	newest, err := c.app.TrustDB().SignedTRC(ctx, cppki.TRCID{
		ISD: a.app.IA().ISD(), Base: 1, Serial: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(newest.TRC.CoreASes) != 2 {
		t.Errorf("the third node enumerates %d core ASes off %v, want two",
			len(newest.TRC.CoreASes), newest.TRC.ID)
	}

	// The node below the joiner enrolls through the founder's endpoint: the
	// issuer set the core route selects skips the joiner, which issues
	// nothing, and lands on the founder.
	Poll(t, "the node below the joining core enrolled", func() bool {
		return holdsAssemblyChain(t, d, d.app.IA())
	})
}

// holdsAssemblyChain reports whether the assembly node holds a chain valid
// now for the IA.
func holdsAssemblyChain(t *testing.T, n *assemblyNode, ia addr.IA) bool {
	t.Helper()
	now := time.Now()
	chains, err := n.app.TrustDB().Chains(context.Background(), trustdb.ChainQuery{
		IA:       ia,
		Validity: cppki.Validity{NotBefore: now, NotAfter: now},
	})
	if err != nil {
		t.Fatal(err)
	}
	return len(chains) != 0
}

// TestJoinerStopsWithoutVotingApp checks the application's absence: a
// deliberate core — the empty applications list loads none — serves the
// network fine, and the joining core that seeks voting power through it
// stops itself with the reason, while a plain node keeps enrolling against
// the same core. The network is operational with or without the application;
// only the onboarding needs it.
func TestJoinerStopsWithoutVotingApp(t *testing.T) {
	t.Parallel()
	wpki := NewWebPKI(t)
	ipA, ipB, ipD := hostSlot(t), hostSlot(t), hostSlot(t)

	// The deliberate core: no application loads, the voting application
	// among them.
	a := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.Applications = []string{}
		cfg.State = t.TempDir()
		cfg.Internal = PinnedUDPAddrOn(t, ipA)
		cfg.Control = FreeUDPAddrOn(t, ipA)
		cfg.CertFile = wpki.certFile
		cfg.KeyFile = wpki.keyFile
	})
	// The joining core, run through the daemon's own body: its exit is the
	// assertion.
	bErr := make(chan error, 1)
	go func() {
		bErr <- services.Run(context.Background(), services.NodeConfig{
			Core:      true,
			Domain:    TestDomain,
			State:     t.TempDir(),
			Internal:  PinnedUDPAddrOn(t, ipB),
			Control:   FreeUDPAddrOn(t, ipB),
			Neighbors: []string{a.rendezvousOf()},
			RootCAs:   wpki.pool,
			Pacing:    fastPacing,
		}, services.DefaultDataplaneOptions())
	}()
	// A plain node keeps enrolling against the deliberate core.
	d := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.State = t.TempDir()
		cfg.Internal = PinnedUDPAddrOn(t, ipD)
		cfg.Control = FreeUDPAddrOn(t, ipD)
		cfg.Neighbors = []string{a.rendezvousOf()}
		cfg.RootCAs = wpki.pool
	})

	// The joiner enrolls, finds no voting application behind its submission,
	// and the node stops with the reason.
	var stopped error
	PollFor(t, RestartTimeout, "the joining core to stop itself", func() bool {
		select {
		case stopped = <-bErr:
			return true
		default:
			return false
		}
	})
	if !errors.Is(stopped, trust.ErrNoVotingApp) {
		t.Fatalf("the joining core's exit = %v, want the absent voting application",
			stopped)
	}

	// The network the exit leaves behind still serves enrollment.
	Poll(t, "the plain node enrolled against the deliberate core", func() bool {
		return holdsAssemblyChain(t, d, d.app.IA())
	})
}
