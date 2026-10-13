package testnetwork

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/fancl20/cion/internal/services"
	"github.com/fancl20/cion/pkg/core/trust"
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
	"github.com/fancl20/cion/pkg/modules/trustdb"
)

// votingAuth is the founder's admission policy in the labs that need its
// sensitive vote: every lab node sits on 127.0.x.y, and with no policy the
// founder casts its vote on no core's submission.
const votingAuth = "cidrs=127.0.0.0/8"

// TestCoreJoinsBySensitiveUpdate is the join seam's integration proof: a
// founding core and a core joining it by rendezvous — the run command's own
// path, the core flag beside a neighbor — where the joiner completes its ISD
// from the neighbor's reply, enrolls, submits the successor it signed to the
// founder's voting application, and the founder's decision votes on its
// admission policy's allow and pins; both pin the completed TRC, a third
// node discovers it from the founder's signed messages and enumerates two
// core ASes, and a node neighboring the joiner enrolls through the founder's
// endpoint — the issuer the route selects.
func TestCoreJoinsBySensitiveUpdate(t *testing.T) {
	t.Parallel()
	wpki := webpkitest.New(t)
	ipA, ipB, ipC, ipD := hostSlot(t), hostSlot(t), hostSlot(t), hostSlot(t)

	// The founding core.
	a := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.State = t.TempDir()
		cfg.Internal = PinnedUDPAddrOn(t, ipA)
		cfg.Control = FreeUDPAddrOn(t, ipA)
		cfg.CertFile = wpki.CertFile
		cfg.KeyFile = wpki.KeyFile
		cfg.EnrollAuth = votingAuth
	})
	// The joining core: the core flag beside the founder's rendezvous
	// address, the network's core domain the bootstrap channel anchors to.
	b := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.State = t.TempDir()
		cfg.Internal = PinnedUDPAddrOn(t, ipB)
		cfg.Control = FreeUDPAddrOn(t, ipB)
		cfg.Neighbors = []string{a.rendezvousOf()}
		cfg.RootCAs = wpki.Pool
	})
	// A third node joining the founder, to watch the successor spread.
	c := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.State = t.TempDir()
		cfg.Internal = PinnedUDPAddrOn(t, ipC)
		cfg.Control = FreeUDPAddrOn(t, ipC)
		cfg.Neighbors = []string{a.rendezvousOf()}
		cfg.RootCAs = wpki.Pool
	})
	// A node neighboring the joining core alone, whose enrollments must
	// route past it to the founder.
	d := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.State = t.TempDir()
		cfg.Internal = PinnedUDPAddrOn(t, ipD)
		cfg.Control = FreeUDPAddrOn(t, ipD)
		cfg.Neighbors = []string{b.rendezvousOf()}
		cfg.RootCAs = wpki.Pool
	})
	ctx := t.Context()

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

// TestCoreJoinsThroughAnAuthoritative checks the onboarding's route when a
// joining core's one neighbor is an onboarded authoritative core: the
// joiner holds both cores' beacons from before its pin, and its submission
// reaches the founder past the authoritative. The founder alone hosts the
// voting application, and a submission the authoritative refused would stop
// the joiner.
func TestCoreJoinsThroughAnAuthoritative(t *testing.T) {
	t.Parallel()
	wpki := webpkitest.New(t)
	ipA, ipB, ipE := hostSlot(t), hostSlot(t), hostSlot(t)

	// The founding core, and the authoritative onboarded through it.
	a := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.State = t.TempDir()
		cfg.Internal = PinnedUDPAddrOn(t, ipA)
		cfg.Control = FreeUDPAddrOn(t, ipA)
		cfg.CertFile = wpki.CertFile
		cfg.KeyFile = wpki.KeyFile
		cfg.EnrollAuth = votingAuth
	})
	b := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.State = t.TempDir()
		cfg.Internal = PinnedUDPAddrOn(t, ipB)
		cfg.Control = FreeUDPAddrOn(t, ipB)
		cfg.Neighbors = []string{a.rendezvousOf()}
		cfg.RootCAs = wpki.Pool
	})
	ctx := t.Context()
	// onboarded reports whether the node's newest pinned TRC names it a
	// core.
	onboarded := func(n *assemblyNode) bool {
		trc, err := n.app.TrustDB().SignedTRC(ctx, cppki.TRCID{
			ISD:    n.app.IA().ISD(),
			Base:   scrypto.LatestVer,
			Serial: scrypto.LatestVer,
		})
		if err != nil {
			t.Fatal(err)
		}
		return !trc.IsZero() && trust.CoreNamed(trc.TRC, n.app.IA())
	}
	Poll(t, "the authoritative onboarded", func() bool { return onboarded(b) })

	// The joining core, the authoritative its one neighbor.
	e := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.State = t.TempDir()
		cfg.Internal = PinnedUDPAddrOn(t, ipE)
		cfg.Control = FreeUDPAddrOn(t, ipE)
		cfg.Neighbors = []string{b.rendezvousOf()}
		cfg.RootCAs = wpki.Pool
	})
	stopped := make(chan error, 1)
	go func() { stopped <- e.app.Wait() }()
	Poll(t, "the joining core onboarded through the authoritative", func() bool {
		select {
		case err := <-stopped:
			t.Fatalf("the joining core stopped: %v", err)
		default:
		}
		return onboarded(e)
	})
}

// holdsAssemblyChain reports whether the assembly node holds a chain valid
// now for the IA.
func holdsAssemblyChain(t *testing.T, n *assemblyNode, ia addr.IA) bool {
	t.Helper()
	now := time.Now()
	chains, err := n.app.TrustDB().Chains(t.Context(), trustdb.ChainQuery{
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
// stops itself with the reason, whether run through the daemon's own body
// or booted for an application, whose Wait reports the same, while a plain
// node keeps enrolling against the same core. The network is operational
// with or without the application; only the onboarding needs it.
func TestJoinerStopsWithoutVotingApp(t *testing.T) {
	t.Parallel()
	wpki := webpkitest.New(t)
	ipA, ipB, ipD, ipE := hostSlot(t), hostSlot(t), hostSlot(t), hostSlot(t)

	// The deliberate core: no application loads, the voting application
	// among them.
	a := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.Applications = []string{}
		cfg.State = t.TempDir()
		cfg.Internal = PinnedUDPAddrOn(t, ipA)
		cfg.Control = FreeUDPAddrOn(t, ipA)
		cfg.CertFile = wpki.CertFile
		cfg.KeyFile = wpki.KeyFile
	})
	joiner := func(ip netip.Addr) services.NodeConfig {
		return services.NodeConfig{
			Core:      true,
			Domain:    webpkitest.Domain,
			State:     t.TempDir(),
			Internal:  PinnedUDPAddrOn(t, ip),
			Control:   FreeUDPAddrOn(t, ip),
			Neighbors: []string{a.rendezvousOf()},
			RootCAs:   wpki.Pool,
			Pacing:    fastPacing,
		}
	}
	// The joining core, run through the daemon's own body: its exit is the
	// assertion.
	bErr := make(chan error, 1)
	go func() {
		bErr <- services.Run(t.Context(), joiner(ipB), services.DefaultDataplaneOptions())
	}()
	// The same joining core booted for an application: its Wait is the
	// assertion.
	e, err := services.BootApp(t.Context(), joiner(ipE))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	eErr := make(chan error, 1)
	go func() { eErr <- e.Wait() }()
	// A plain node keeps enrolling against the deliberate core.
	d := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.State = t.TempDir()
		cfg.Internal = PinnedUDPAddrOn(t, ipD)
		cfg.Control = FreeUDPAddrOn(t, ipD)
		cfg.Neighbors = []string{a.rendezvousOf()}
		cfg.RootCAs = wpki.Pool
	})

	// Each joiner enrolls, finds no voting application behind its
	// submission, and the node stops with the reason.
	for name, stop := range map[string]chan error{"run": bErr, "booted": eErr} {
		var stopped error
		PollFor(t, RestartTimeout, "the "+name+" joining core to stop itself", func() bool {
			select {
			case stopped = <-stop:
				return true
			default:
				return false
			}
		})
		if !errors.Is(stopped, trust.ErrNoVotingApp) {
			t.Fatalf("the %s joining core's stop = %v, want the absent voting application",
				name, stopped)
		}
	}

	// The network the exit leaves behind still serves enrollment.
	Poll(t, "the plain node enrolled against the deliberate core", func() bool {
		return holdsAssemblyChain(t, d, d.app.IA())
	})
}

// TestJoiningCoreMeshesWithTheFounder checks the applications follow the
// founding tier: a core joining by rendezvous under the inference runs
// what a local node runs — its WireGuard application publishing to the
// founder's directory instead of serving one of its own and meshing with
// the founder, neither the coordination nor the voting application beside
// it — while the founder serves the directory and the voting application
// the joining core's submission needs.
func TestJoiningCoreMeshesWithTheFounder(t *testing.T) {
	t.Parallel()
	wpki := webpkitest.New(t)
	ipA, ipB := hostSlot(t), hostSlot(t)
	// The shared host ports are drawn from the pinned band, for a WireGuard
	// interface on the test host may hold the default. The two need not
	// match: the mesh rides SCION, and each host dials its own node.
	hostPort := func(ip netip.Addr) uint16 {
		return netip.MustParseAddrPort(PinnedUDPAddrOn(t, ip)).Port()
	}

	a := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.Applications = []string{"wireguard", "voting"}
		cfg.AppArguments.Wireguard.HostPort = hostPort(ipA)
		cfg.State = t.TempDir()
		cfg.Internal = PinnedUDPAddrOn(t, ipA)
		cfg.Control = FreeUDPAddrOn(t, ipA)
		cfg.CertFile = wpki.CertFile
		cfg.KeyFile = wpki.KeyFile
		cfg.EnrollAuth = votingAuth
	})
	b := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.AppArguments.Wireguard.HostPort = hostPort(ipB)
		cfg.State = t.TempDir()
		cfg.Internal = PinnedUDPAddrOn(t, ipB)
		cfg.Control = FreeUDPAddrOn(t, ipB)
		cfg.Neighbors = []string{a.rendezvousOf()}
		cfg.RootCAs = wpki.Pool
	})

	for _, resident := range []string{"coordination", "voting"} {
		if b.app.Application(resident) != nil {
			t.Errorf("the joining core loaded the %s application", resident)
		}
	}
	if wireguardOf(b).Registry() != nil {
		t.Fatal("the joining core opened a directory store of its own")
	}

	// The joining core's slice is the founder's assignment: the founder's
	// directory lists the slice the joining core's publication was answered.
	ctx, cancel := context.WithTimeout(t.Context(), TestTimeout)
	defer cancel()
	subnet, err := wireguardOf(b).Subnet(ctx)
	if err != nil {
		t.Fatalf("the joining core's slice: %v", err)
	}
	directory, err := wireguardOf(a).Directory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var listed netip.Prefix
	for _, entry := range directory.Nodes {
		if entry.IA.Equal(b.app.IA()) {
			listed = entry.Overlay
		}
	}
	if listed != subnet {
		t.Errorf("the founder's directory lists the joining core's slice as %v, want %v",
			listed, subnet)
	}

	Poll(t, "the founder's mesh peer", func() bool {
		return hasMeshPeer(wireguardOf(a), b.app.IA())
	})
	Poll(t, "the joining core's mesh peer", func() bool {
		return hasMeshPeer(wireguardOf(b), a.app.IA())
	})
}
