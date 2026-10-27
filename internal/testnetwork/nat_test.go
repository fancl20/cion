package testnetwork

import (
	"net/netip"
	"testing"
	"time"

	"github.com/fancl20/cion/internal/services"
	"github.com/fancl20/cion/internal/testnetwork/fabric"
	"github.com/fancl20/cion/pkg/core/webpki/webpkitest"
	"github.com/fancl20/cion/pkg/modules/links"
	"github.com/fancl20/cion/pkg/modules/topology/impl/measured"
)

// natBudget bounds each of the NAT labs' waits in virtual
// time, at the daemon's own pacing: a join, or a retirement's detection and
// down windows.
const natBudget = 5 * time.Minute

// bootNATLine boots the NAT lab's two nodes on a bubble's
// fabric: the founding core A beyond the NAT, and the joiner J inside
// it, whose every packet leaves through the gateway and never names its own
// host. The joiner's neighbor is the gateway — the one address a node
// behind a NAT can dial.
func bootNATLine(t *testing.T, f *fabric.Fabric, wpki *webpkitest.CA) (
	b *fabric.NAT, a, j *Node, gw netip.Addr,
) {

	t.Helper()
	ipA, gw, ipJ := HostSlot(t), HostSlot(t), HostSlot(t)
	b = f.ForwardingNAT(gw, ipA, measured.RendezvousPort, ipJ)
	a = BootInBubble(t, f, ipA, func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.CertFile = wpki.CertFile
		cfg.KeyFile = wpki.KeyFile
	})
	j = BootInBubble(t, f, ipJ, func(cfg *services.NodeConfig) {
		cfg.Neighbors = []string{gw.String()}
		cfg.RootCAs = wpki.Pool
	})
	return b, a, j, gw
}

// TestNATJoinerRecordsTheObservation is the NAT lab's
// exchange-level proof: a joiner whose rendezvous dials traverse a
// port-remapping NAT — every dial leaving through a mapping port the
// NAT drew, never the socket's own — joins, and the founder's entry
// for it records the observed mapping: the gateway's host under a drawn
// port, never the address the claim spells. The packets traverse the
// NAT without being addressed to it, so the link-level proofs the lab
// once deferred stand beside this one on the same fabric.
func TestNATJoinerRecordsTheObservation(t *testing.T) {
	if !solo(t) {
		return
	}
	InBubble(t, func(t *testing.T, f *fabric.Fabric, wpki *webpkitest.CA) {
		_, a, j, gw := bootNATLine(t, f, wpki)
		ctx := t.Context()

		// The joiner's identity completes through the NAT, and the
		// founder's entry for it appears aimed at a drawn mapping — the
		// address the exchange itself proved answers, not the claim.
		PollVirtual(t, natBudget, "A's entry for the joiner behind a NAT", func() bool {
			e := entryOf(ctx, a, j.app.IA())
			return e != nil && e.Live() && e.Remote.Addr() == gw &&
				fabric.MappingPort(e.Remote)
		})
		// The join completes over the link the exchange seeded.
		PollVirtual(t, natBudget, "the joiner's link to A", func() bool {
			e := entryOf(ctx, j, a.app.IA())
			return e != nil && e.State == links.StateEstablished
		})
	})
}

// TestNATLinkRidesTheMapping is the first of the two link-level proofs the
// exchange-level lab deferred: the link of a joiner behind a NAT carries its
// BFD stream and data through the mapping, holding Established past idle
// timeouts the mapping outlives only because the stream refreshes it — and
// under silence the link falls with the BFD detection, the founder retires
// it, and the mapping expires after the retirement.
func TestNATLinkRidesTheMapping(t *testing.T) {
	if !solo(t) {
		return
	}
	InBubble(t, func(t *testing.T, f *fabric.Fabric, wpki *webpkitest.CA) {
		b, a, j, _ := bootNATLine(t, f, wpki)
		ctx := t.Context()
		PollVirtual(t, natBudget, "the joiner's link to A", func() bool {
			e := entryOf(ctx, j, a.app.IA())
			return e != nil && e.State == links.StateEstablished
		})

		// Several mapping idle windows pass with the link Established: the
		// BFD stream, one packet per interval in both directions, refreshes
		// the mapping each window, and the data rides the same mapping.
		for range 3 {
			time.Sleep(fabric.MappingTimeout)
			if e := entryOf(ctx, j, a.app.IA()); e == nil || e.State != links.StateEstablished {
				t.Fatal("the link fell inside the mapping's idle ride")
			}
			if !pingFrom(ctx, j, a.app.IA(), a.host) {
				t.Fatal("the link's data stopped riding the mapping")
			}
		}
		if mappings := b.Mappings(); len(mappings) == 0 {
			t.Fatalf("the NAT holds no mapping after %v of link", 3*fabric.MappingTimeout)
		}

		// Silence: the joiner stops and the founder's BFD runs out its
		// detection. The founder's stream outlives its down verdict and
		// refreshes the mapping until the founder retires the link; the
		// mapping — nothing crossing any more — expires after the
		// retirement.
		ifID := entryOf(ctx, a, j.app.IA()).IfID
		j.Stop(t)
		PollVirtual(t, natBudget, "A to mark the link down", func() bool {
			return markedDown(ctx, a, ifID)
		})
		PollVirtual(t, natBudget, "A to retire the link", func() bool {
			e := entryOf(ctx, a, j.app.IA())
			return e == nil || !e.Live()
		})
		PollVirtual(t, 4*fabric.MappingTimeout, "the mapping to expire under silence", func() bool {
			return len(b.Mappings()) == 0
		})
	})
}

// TestNATRestartDrawsAFreshMapping is the second deferred proof's
// deterministic core: a restart behind a NAT draws a fresh mapping —
// the stopped node's gone with its socket, the founder's entry and the
// NAT's mapping retired under the silence that follows — and the
// founder's fresh entry records the observed mapping the join spells, never
// the address the claim names and never the port the stopped node's socket
// drew. The re-aim of an entry still standing — the restart that waits out
// no retirement — is the relocation lab's own proof below.
func TestNATRestartDrawsAFreshMapping(t *testing.T) {
	if !solo(t) {
		return
	}
	InBubble(t, func(t *testing.T, f *fabric.Fabric, wpki *webpkitest.CA) {
		b, a, j, gw := bootNATLine(t, f, wpki)
		jHost, jState := j.host, j.stateDir
		ctx := t.Context()
		PollVirtual(t, natBudget, "the joiner's link to A", func() bool {
			e := entryOf(ctx, j, a.app.IA())
			return e != nil && e.State == links.StateEstablished
		})
		before := entryOf(ctx, a, j.app.IA())
		if before == nil || before.Remote.Addr() != gw || !fabric.MappingPort(before.Remote) {
			t.Fatalf("A's entry before the restart = %v, want the gateway under a drawn port", before)
		}

		// The joiner stops, and the outage runs its course: the founder's
		// BFD runs out its detection, the sweep retires the entry, and the
		// mapping — nothing crossing any more — expires with it.
		j.Stop(t)
		PollVirtual(t, natBudget, "the founder's entry for the joiner to retire", func() bool {
			e := entryOf(ctx, a, j.app.IA())
			return e == nil || !e.Live()
		})
		PollVirtual(t, natBudget, "the NAT's mapping to expire", func() bool {
			return len(b.Mappings()) == 0
		})

		// The restart: the same state directory and host, the node's stack
		// rebound — its first dial drawing a fresh mapping, the founder's
		// fresh entry recording it.
		j2 := BootInBubble(t, f, jHost, func(cfg *services.NodeConfig) {
			cfg.State = jState
			cfg.Neighbors = []string{gw.String()}
			cfg.RootCAs = wpki.Pool
		})
		PollVirtual(t, natBudget, "A's fresh entry to record the fresh mapping", func() bool {
			e := entryOf(ctx, a, j2.app.IA())
			return e != nil && e.Live() && e.Remote.Addr() == gw &&
				fabric.MappingPort(e.Remote) && e.Remote.Port() != before.Remote.Port()
		})
	})
}

// TestNATReturnReAimsTheStandingEntry checks a node's return at a
// fresh mapping while its former neighbor still holds the standing entry
// aimed at the dead one — no retirement waited out — and the returning
// node's confirm pass re-aims that very entry, the interface kept, no
// re-admission, the link's verdict recovering on the BFD stream itself.
// Three of the founder's selection windows hold the down entry long past
// the returning node's first confirm.
func TestNATReturnReAimsTheStandingEntry(t *testing.T) {
	if !solo(t) {
		return
	}
	InBubble(t, func(t *testing.T, f *fabric.Fabric, wpki *webpkitest.CA) {
		b, a, j, gw := bootNATLine(t, f, wpki)
		jHost, jState := j.host, j.stateDir
		ctx := t.Context()
		PollVirtual(t, natBudget, "the joiner's link to A", func() bool {
			e := entryOf(ctx, j, a.app.IA())
			return e != nil && e.State == links.StateEstablished
		})
		standing := entryOf(ctx, a, j.app.IA())
		if standing == nil || standing.Remote.Addr() != gw || !fabric.MappingPort(standing.Remote) {
			t.Fatalf("A's standing entry = %v, want the gateway under a drawn port", standing)
		}

		// The return: the joiner stops and boots again at once — the same
		// state and host, the node's stack rebound — while the founder's
		// entry still stands on the old mapping. The NAT retires that
		// mapping outright, the changed mapping a restart's proof needs: the
		// founder's own BFD stream would keep refreshing it past the node's
		// stop, and the returning node's sockets rebind the same inside
		// addresses.
		j.Stop(t)
		b.Rebind()
		j2 := BootInBubble(t, f, jHost, func(cfg *services.NodeConfig) {
			cfg.State = jState
			cfg.Neighbors = []string{gw.String()}
			cfg.RootCAs = wpki.Pool
		})
		PollVirtual(t, natBudget, "the founder's standing entry to re-aim on the confirm", func() bool {
			e := entryOf(ctx, a, j2.app.IA())
			return e != nil && e.Live() && e.IfID == standing.IfID &&
				e.Remote.Addr() == gw && fabric.MappingPort(e.Remote) &&
				e.Remote.Port() != standing.Remote.Port()
		})
		PollVirtual(t, natBudget, "the returning joiner's link to A", func() bool {
			e := entryOf(ctx, j2, a.app.IA())
			return e != nil && e.State == links.StateEstablished
		})
		PollVirtual(t, natBudget, "the re-aimed link's verdict to recover", func() bool {
			return !markedDown(ctx, a, standing.IfID)
		})
		PollVirtual(t, natBudget, "the data to ride the re-aimed mapping", func() bool {
			return pingFrom(ctx, j2, a.app.IA(), a.host)
		})
	})
}
