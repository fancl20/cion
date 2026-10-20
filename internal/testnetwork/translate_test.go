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

// bootTranslatedLine boots the translation lab's two nodes on the fabric:
// the founding core A beyond the boundary, and the joiner J inside it, whose
// every packet leaves through the gateway and never names its own host. The
// joiner's neighbor is the gateway — the one address a node behind a
// translation can dial. Each node's run arguments take their own mutation.
func bootTranslatedLine(
	t *testing.T, wpki *webpkitest.CA,
	mutateA, mutateJ func(*services.NodeConfig),
) (
	f *fabric.Fabric, b *fabric.Boundary, a, j *assemblyNode, gw netip.Addr,
) {

	t.Helper()
	f = fabric.New(t)
	ipA, gw, ipJ := hostSlot(t), hostSlot(t), hostSlot(t)
	b = f.Translate(gw, ipA, measured.RendezvousPort, ipJ)
	a = bootOnFabric(t, f, ipA, func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.CertFile = wpki.CertFile
		cfg.KeyFile = wpki.KeyFile
		if mutateA != nil {
			mutateA(cfg)
		}
	})
	j = bootOnFabric(t, f, ipJ, func(cfg *services.NodeConfig) {
		cfg.Neighbors = []string{gw.String()}
		cfg.RootCAs = wpki.Pool
		if mutateJ != nil {
			mutateJ(cfg)
		}
	})
	return f, b, a, j, gw
}

// TestTranslatedJoinerRecordsTheObservation is the translation lab's
// exchange-level proof: a joiner whose rendezvous dials traverse a
// port-remapping boundary — every dial leaving through a mapping port the
// boundary drew, never the socket's own — joins, and the founder's entry
// for it records the observed mapping: the gateway's host under a drawn
// port, never the address the claim spells. The packets traverse the
// boundary without being addressed to it, so the link-level proofs the lab
// once deferred stand beside this one on the same fabric.
func TestTranslatedJoinerRecordsTheObservation(t *testing.T) {
	if !solo(t) {
		return
	}
	wpki := webpkitest.New(t)
	_, _, a, j, gw := bootTranslatedLine(t, wpki, nil, nil)
	ctx := t.Context()

	// The joiner's identity completes through the translation, and the
	// founder's entry for it appears aimed at a drawn mapping — the address
	// the exchange itself proved answers, not the claim.
	PollFor(t, RestartTimeout, "A's entry for the translated joiner", func() bool {
		e := entryOf(ctx, a, j.app.IA())
		return e != nil && e.Live() && e.Remote.Addr() == gw &&
			fabric.MappingPort(e.Remote)
	})
	// The join completes over the link the exchange seeded.
	PollFor(t, RestartTimeout, "the translated joiner's link to A", func() bool {
		e := entryOf(ctx, j, a.app.IA())
		return e != nil && e.State == links.StateEstablished
	})
}

// TestTranslatedLinkRidesTheMapping is the first of the two link-level
// proofs the exchange-level lab deferred: a translated joiner's link
// carries its BFD stream and data through the mapping, holding Established
// past idle timeouts the mapping outlives only because the stream refreshes
// it — and under silence the link falls with the BFD detection and the
// mapping expires after it.
func TestTranslatedLinkRidesTheMapping(t *testing.T) {
	if !solo(t) {
		return
	}
	wpki := webpkitest.New(t)
	_, b, a, j, _ := bootTranslatedLine(t, wpki, nil, nil)
	ctx := t.Context()
	PollFor(t, RestartTimeout, "the translated joiner's link to A", func() bool {
		e := entryOf(ctx, j, a.app.IA())
		return e != nil && e.State == links.StateEstablished
	})

	// Several mapping idle windows pass with the link Established: the BFD
	// stream, one packet per interval in both directions, refreshes the
	// mapping each window, and the data rides the same mapping.
	for range 3 {
		time.Sleep(fabric.MappingIdle)
		if e := entryOf(ctx, j, a.app.IA()); e == nil || e.State != links.StateEstablished {
			t.Fatal("the translated link fell inside the mapping's idle ride")
		}
		if !pingFrom(ctx, j, a.app.IA(), a.host) {
			t.Fatal("the translated link's data stopped riding the mapping")
		}
	}
	if mappings := b.Mappings(); len(mappings) == 0 {
		t.Fatalf("the boundary holds no mapping after %v of link", 3*fabric.MappingIdle)
	}

	// Silence: the joiner stops, the founder's BFD runs out its detection,
	// and the mapping — nothing crossing any more — expires after it.
	ifID := entryOf(ctx, a, j.app.IA()).IfID
	j.stop(t)
	Poll(t, "A to mark the translated link down", func() bool {
		return markedDown(ctx, a, ifID)
	})
	PollFor(t, 4*fabric.MappingIdle, "the mapping to expire under silence", func() bool {
		return len(b.Mappings()) == 0
	})
}

// TestTranslatedRestartDrawsAFreshMapping is the second deferred proof's
// deterministic core: a translated node's restart draws a fresh mapping —
// the stopped node's gone with its socket, the founder's entry and the
// boundary's mapping retired under the silence that follows — and the
// founder's fresh entry records the observed mapping the join spells, never
// the address the claim names and never the port the stopped node's socket
// drew. The re-aim of an entry still standing — the restart that waits out
// no retirement — is the relocation lab's own proof below.
func TestTranslatedRestartDrawsAFreshMapping(t *testing.T) {
	if !solo(t) {
		return
	}
	wpki := webpkitest.New(t)
	f, b, a, j, gw := bootTranslatedLine(t, wpki, nil, nil)
	jHost, jState := j.host, j.stateDir
	ctx := t.Context()
	PollFor(t, RestartTimeout, "the translated joiner's link to A", func() bool {
		e := entryOf(ctx, j, a.app.IA())
		return e != nil && e.State == links.StateEstablished
	})
	before := entryOf(ctx, a, j.app.IA())
	if before == nil || before.Remote.Addr() != gw || !fabric.MappingPort(before.Remote) {
		t.Fatalf("A's entry before the restart = %v, want the gateway under a drawn port", before)
	}

	// The joiner stops, and the outage runs its course: the founder's BFD
	// runs out its detection, the sweep retires the entry, and the mapping
	// — nothing crossing any more — expires with it.
	j.stop(t)
	PollFor(t, RestartTimeout, "the founder's entry for the joiner to retire", func() bool {
		e := entryOf(ctx, a, j.app.IA())
		return e == nil || !e.Live()
	})
	PollFor(t, RestartTimeout, "the boundary's mapping to expire", func() bool {
		return len(b.Mappings()) == 0
	})

	// The restart: the same state directory and host, the node's stack
	// rebound — its first dial drawing a fresh mapping, the founder's fresh
	// entry recording it.
	j2 := bootOnFabric(t, f, jHost, func(cfg *services.NodeConfig) {
		cfg.State = jState
		cfg.Neighbors = []string{gw.String()}
		cfg.RootCAs = wpki.Pool
	})
	PollFor(t, RestartTimeout, "A's fresh entry to record the fresh mapping", func() bool {
		e := entryOf(ctx, a, j2.app.IA())
		return e != nil && e.Live() && e.Remote.Addr() == gw &&
			fabric.MappingPort(e.Remote) && e.Remote.Port() != before.Remote.Port()
	})
}

// TestTranslatedReturnReAimsTheStandingEntry checks a node's return at a
// fresh mapping while its former neighbor still holds the standing entry
// aimed at the dead one — no retirement waited out — and the returning
// node's confirm pass re-aims that very entry, the interface kept, no
// re-admission, the link's verdict recovering on the BFD stream itself. The
// founder's selection runs at the production window, for the labs'
// compressed one retires a down entry inside a loaded runner's boot time, a
// race production never sees: three production windows hold the entry long
// past the returning node's first confirm.
func TestTranslatedReturnReAimsTheStandingEntry(t *testing.T) {
	if !solo(t) {
		return
	}
	wpki := webpkitest.New(t)
	f, b, a, j, gw := bootTranslatedLine(t, wpki, func(cfg *services.NodeConfig) {
		cfg.Pacing.Selection = measured.SelectionInterval
	}, nil)
	jHost, jState := j.host, j.stateDir
	ctx := t.Context()
	Poll(t, "the translated joiner's link to A", func() bool {
		e := entryOf(ctx, j, a.app.IA())
		return e != nil && e.State == links.StateEstablished
	})
	standing := entryOf(ctx, a, j.app.IA())
	if standing == nil || standing.Remote.Addr() != gw || !fabric.MappingPort(standing.Remote) {
		t.Fatalf("A's standing entry = %v, want the gateway under a drawn port", standing)
	}

	// The return: the joiner stops and boots again at once — the same state
	// and host, the node's stack rebound — while the founder's entry still
	// stands on the old mapping. The boundary retires that mapping outright,
	// the changed mapping a restart's proof needs: the founder's own BFD
	// stream would keep refreshing it past the node's stop, and the
	// returning node's sockets rebind the same inside addresses.
	j.stop(t)
	b.Rebind()
	j2 := bootOnFabric(t, f, jHost, func(cfg *services.NodeConfig) {
		cfg.State = jState
		cfg.Neighbors = []string{gw.String()}
		cfg.RootCAs = wpki.Pool
	})
	Poll(t, "the founder's standing entry to re-aim on the confirm", func() bool {
		e := entryOf(ctx, a, j2.app.IA())
		return e != nil && e.Live() && e.IfID == standing.IfID &&
			e.Remote.Addr() == gw && fabric.MappingPort(e.Remote) &&
			e.Remote.Port() != standing.Remote.Port()
	})
	Poll(t, "the returning joiner's link to A", func() bool {
		e := entryOf(ctx, j2, a.app.IA())
		return e != nil && e.State == links.StateEstablished
	})
	Poll(t, "the re-aimed link's verdict to recover", func() bool {
		return !markedDown(ctx, a, standing.IfID)
	})
	Poll(t, "the data to ride the re-aimed mapping", func() bool {
		return pingFrom(ctx, j2, a.app.IA(), a.host)
	})
}
