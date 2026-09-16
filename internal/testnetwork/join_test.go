package testnetwork

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/internal/services"
	"github.com/fancl20/cion/pkg/apps/ping"
	"github.com/fancl20/cion/pkg/apps/topology"
	"github.com/fancl20/cion/pkg/links"
	"github.com/fancl20/cion/pkg/trust"
)

// fastPacing paces the assembly's loops for the integration tests.
var fastPacing = services.NodePacing{
	Discovery:       DiscoveryGap,
	Propagation:     Propagation,
	Registration:    Registration,
	Enrollment:      EnrollRetry,
	Selection:       300 * time.Millisecond,
	CandidateWindow: 5 * time.Second,
	Directory:       100 * time.Millisecond,
	RendezvousRate:  10 * time.Millisecond,
	LinkSetPoll:     100 * time.Millisecond,
}

// assemblyNode is a node booted through the run command's own assembly.
type assemblyNode struct {
	app       *services.App
	cancel    context.CancelFunc
	stateDir  string
	host      netip.Addr
	pingCount int
}

// rendezvousOf returns the node's advertised rendezvous address: the
// control address's host on the fixed rendezvous port.
func (n *assemblyNode) rendezvousOf() string {
	return netip.AddrPortFrom(n.host, topology.RendezvousPort).String()
}

// bootAssembly boots a full node assembly — the run command's own wiring —
// and serves it underneath the test.
func bootAssembly(t *testing.T, mutate func(*services.NodeConfig)) *assemblyNode {
	t.Helper()
	cfg := services.NodeConfig{
		Domain: TestDomain,
		Pacing: fastPacing,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	if cfg.State == "" {
		cfg.State = t.TempDir()
	}
	ctx, cancel := context.WithCancel(context.Background())
	app, err := services.BootApp(ctx, cfg)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	n := &assemblyNode{app: app, cancel: cancel, stateDir: cfg.State}
	ap, err := netip.ParseAddrPort(cfg.Control)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	n.host = ap.Addr()
	t.Cleanup(func() {
		cancel()
		app.Close()
	})
	return n
}

// pingFrom pings the destination once through the node's own assembly,
// reporting success. The responder runs beside every node's control
// endpoint, as the daemon serves it.
func pingFrom(ctx context.Context, n *assemblyNode, dst addr.IA, host netip.Addr) bool {
	conn, err := n.app.Conn(0)
	if err != nil {
		return false
	}
	defer conn.Close() //nolint:errcheck
	report, err := ping.Run(ctx, ping.Config{
		Conn:     conn,
		Provider: n.app.Provider(),
		Dst:      dst,
		DstHost:  host,
		Count:    1,
		Interval: 100 * time.Millisecond,
		Wait:     2 * time.Second,
	})
	return err == nil && report.Received == 1
}

// entryOf returns the node's link entry of a neighbor, retired ones
// included.
func entryOf(n *assemblyNode, ia addr.IA) *links.Link {
	entries, err := n.app.Links().All(context.Background())
	if err != nil {
		return nil
	}
	for _, l := range entries {
		if l.NeighborIA.Equal(ia) {
			return l
		}
	}
	return nil
}

// TestJoinByRendezvous is proposal 0008's integration proof: a three-node
// line — the core A, the middle B, and C below — where B and C join by
// rendezvous with one bootstrap neighbor and the core's domain, enroll,
// publish, and fetch the node directory; C probes A by rendezvous echo
// against the two-hop path and promotes the direct link below the
// redundancy floor; killing B leaves C connected through A; and a bare
// restart serves from the persisted link store without rendezvous.
func TestJoinByRendezvous(t *testing.T) {
	wpki := NewWebPKI(t)
	ipA, ipB, ipC := addrIP(0x31), addrIP(0x32), addrIP(0x33)

	// The founding core; its certificate files are the offline fallback the
	// tests always take.
	a := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.State = t.TempDir()
		cfg.Internal = FreeUDPAddrOn(t, ipA)
		cfg.Control = FreeUDPAddrOn(t, ipA)
		cfg.CertFile = wpki.certFile
		cfg.KeyFile = wpki.keyFile
	})
	// B joins the core by rendezvous.
	b := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.State = t.TempDir()
		cfg.Internal = FreeUDPAddrOn(t, ipB)
		cfg.Control = FreeUDPAddrOn(t, ipB)
		cfg.Neighbors = []string{a.rendezvousOf()}
		cfg.RootCAs = wpki.pool
	})
	// C joins B — a non-core neighbor — with the core's domain.
	c := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.State = t.TempDir()
		cfg.Internal = FreeUDPAddrOn(t, ipC)
		cfg.Control = FreeUDPAddrOn(t, ipC)
		cfg.Neighbors = []string{b.rendezvousOf()}
		cfg.RootCAs = wpki.pool
	})
	ctx := context.Background()

	// The joins land: both sides of each link hold an entry, the joiner's
	// adopting the acceptor's ISD-AS from its greetings.
	Poll(t, "B's link to A", func() bool {
		e := entryOf(b, a.app.IA())
		return e != nil && e.State == links.StateEstablished
	})
	Poll(t, "A's link to B", func() bool {
		e := entryOf(a, b.app.IA())
		return e != nil && e.State == links.StateEstablished
	})
	Poll(t, "C's link to B", func() bool {
		e := entryOf(c, b.app.IA())
		return e != nil && e.State == links.StateEstablished
	})

	// B and C enroll through the joined links.
	Poll(t, "B enrolled", func() bool { return pingFrom(ctx, b, a.app.IA(), a.host) })
	Poll(t, "C enrolled", func() bool { return pingFrom(ctx, c, a.app.IA(), a.host) })

	// C publishes and fetches the directory, probes A by rendezvous echo
	// against the two-hop path, and promotes the direct link — below the
	// floor of two, outright on reachability.
	Poll(t, "C's direct link to A", func() bool {
		e := entryOf(c, a.app.IA())
		return e != nil && e.State == links.StateEstablished
	})
	Poll(t, "A's link to C", func() bool {
		e := entryOf(a, c.app.IA())
		return e != nil && e.State == links.StateEstablished
	})

	// The traffic of the swap survives: echo runs before and after the
	// promotion answer across the swap's bounded loss burst — a request
	// landing inside it is retried, as QUIC retransmits through any
	// internet loss.
	pingDeadline := time.Now().Add(10 * time.Second)
	for !pingFrom(ctx, c, a.app.IA(), a.host) {
		if time.Now().After(pingDeadline) {
			t.Fatal("C's echo to A never answered after the generation swap")
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Killing B leaves C connected through A.
	b.cancel()
	b.app.Close()
	time.Sleep(3 * DiscoveryGap) // let C's greetings to B time out
	deadline := time.Now().Add(10 * time.Second)
	for !pingFrom(ctx, c, a.app.IA(), a.host) {
		// The freshest up segment — A's beacon over the direct link — takes
		// over from the one through the dead B.
		if time.Now().After(deadline) {
			t.Fatal("C lost its path to A after B died")
		}
		time.Sleep(100 * time.Millisecond)
	}

	// A bare restart — the same state directory, no rendezvous — serves from
	// the persisted link store.
	b2 := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.State = b.stateDir
		cfg.Internal = FreeUDPAddrOn(t, ipB)
		cfg.Control = FreeUDPAddrOn(t, ipB)
		cfg.RootCAs = wpki.pool
	})
	Poll(t, "the restarted B serves its persisted link", func() bool {
		e := entryOf(b2, a.app.IA())
		return e != nil && e.State == links.StateEstablished
	})
	Poll(t, "the restarted B reaches A", func() bool {
		return pingFrom(ctx, b2, a.app.IA(), a.host)
	})
}

// TestBootstrapWithoutAnswer checks the negative: a first start whose
// bootstrap neighbor never answers its rendezvous fails cleanly — no
// identity persists, nothing was allocated on any acceptor — and a retry
// once a neighbor exists draws a fresh identity and joins.
func TestBootstrapWithoutAnswer(t *testing.T) {
	wpki := NewWebPKI(t)
	ipA, ipD := addrIP(0x35), addrIP(0x36)
	dead := FreeUDPAddrOn(t, ipA) // reserved, then released: nothing answers
	state := t.TempDir()

	func() {
		ctx, cancel := context.WithCancel(context.Background())
		_, err := services.BootApp(ctx, services.NodeConfig{
			Domain:    TestDomain,
			State:     state,
			Internal:  FreeUDPAddrOn(t, ipD),
			Control:   FreeUDPAddrOn(t, ipD),
			Neighbors: []string{dead},
			RootCAs:   wpki.pool,
			Pacing:    fastPacing,
		})
		defer cancel()
		if err == nil {
			t.Fatal("a first start whose bootstrap neighbor never answered succeeded")
		}
	}()

	// Nothing persisted: the identity stays unset for a fresh draw.
	if ia, err := trust.LoadIA(state); err != nil || !ia.IsZero() {
		t.Fatalf("identity after the failed bootstrap = %v (%v), want unset", ia, err)
	}

	// A core comes up; the retry joins it and completes its identity.
	a := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.State = t.TempDir()
		cfg.Internal = FreeUDPAddrOn(t, ipA)
		cfg.Control = FreeUDPAddrOn(t, ipA)
		cfg.CertFile = wpki.certFile
		cfg.KeyFile = wpki.keyFile
	})
	d := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.State = state
		cfg.Internal = FreeUDPAddrOn(t, ipD)
		cfg.Control = FreeUDPAddrOn(t, ipD)
		cfg.Neighbors = []string{a.rendezvousOf()}
		cfg.RootCAs = wpki.pool
	})
	Poll(t, "the retried join to land", func() bool {
		e := entryOf(d, a.app.IA())
		return e != nil && e.State == links.StateEstablished
	})
	if got := d.app.IA().ISD(); got != a.app.IA().ISD() {
		t.Errorf("the joiner's ISD = %d, want the network's %d", got, a.app.IA().ISD())
	}
}
