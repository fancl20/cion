package testnetwork

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/fancl20/cion/internal/services"
	"github.com/fancl20/cion/pkg/apps"
	"github.com/fancl20/cion/pkg/apps/ping"
	"github.com/fancl20/cion/pkg/modules/links"
	"github.com/fancl20/cion/pkg/modules/pathdb"
	"github.com/fancl20/cion/pkg/modules/topology/impl/measured"
	"github.com/fancl20/cion/pkg/trust"
)

// fastPacing paces the assembly's loops for the integration tests.
var fastPacing = services.NodePacing{
	Propagation:     Propagation,
	Registration:    Registration,
	Enrollment:      EnrollRetry,
	Selection:       300 * time.Millisecond,
	CandidateWindow: 5 * time.Second,
	Directory:       100 * time.Millisecond,
	RendezvousRate:  10 * time.Millisecond,
	LinkSetPoll:     100 * time.Millisecond,
	BFD:             200 * time.Millisecond,
}

// assemblyNode is a node booted through the run command's own assembly.
type assemblyNode struct {
	app      *services.App
	cancel   context.CancelFunc
	stateDir string
	host     netip.Addr
}

// rendezvousOf returns the node's advertised rendezvous address: the
// control address's host on the fixed rendezvous port.
func (n *assemblyNode) rendezvousOf() string {
	return netip.AddrPortFrom(n.host, measured.RendezvousPort).String()
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
	defer func() { _ = conn.Close() }()
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

// bootRendezvousLine brings up the assembly's three-node line — the
// founding core A, the middle B joined to it by rendezvous, and C below
// joined to B — on the given loopback hosts.
func bootRendezvousLine(t *testing.T, wpki *WebPKI,
	ipA, ipB, ipC netip.Addr) (a, b, c *assemblyNode) {

	t.Helper()
	// The founding core; its certificate files are the offline fallback the
	// tests always take.
	a = bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.State = t.TempDir()
		cfg.Internal = FreeUDPAddrOn(t, ipA)
		cfg.Control = FreeUDPAddrOn(t, ipA)
		cfg.CertFile = wpki.certFile
		cfg.KeyFile = wpki.keyFile
	})
	// B joins the core by rendezvous.
	b = bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.State = t.TempDir()
		cfg.Internal = FreeUDPAddrOn(t, ipB)
		cfg.Control = FreeUDPAddrOn(t, ipB)
		cfg.Neighbors = []string{a.rendezvousOf()}
		cfg.RootCAs = wpki.pool
	})
	// C joins B — a non-core neighbor — with the core's domain.
	c = bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.State = t.TempDir()
		cfg.Internal = FreeUDPAddrOn(t, ipC)
		cfg.Control = FreeUDPAddrOn(t, ipC)
		cfg.Neighbors = []string{b.rendezvousOf()}
		cfg.RootCAs = wpki.pool
	})
	return a, b, c
}

// TestJoinByRendezvous is the rendezvous join's integration proof: a
// three-node line — the core A, the middle B, and C below — where B and C join by
// rendezvous with one bootstrap neighbor and the core's domain, enroll,
// publish, and fetch the node directory; C probes A by rendezvous echo
// against the two-hop path and promotes the direct link below the
// redundancy floor; killing B leaves C connected through A; and a bare
// restart serves from the persisted link store without rendezvous.
func TestJoinByRendezvous(t *testing.T) {
	t.Parallel()
	wpki := NewWebPKI(t)
	ipA, ipB, ipC := hostSlot(t), hostSlot(t), hostSlot(t)
	a, b, c := bootRendezvousLine(t, wpki, ipA, ipB, ipC)
	ctx := context.Background()

	// The joins land: both sides of each link hold an entry, each naming
	// its neighbor from the rendezvous exchange alone.
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

	// The precondition of the episode below: A's beacons over the direct
	// link have reached C and terminated into a direct up segment — the
	// route that takes over when B dies. Without it, the takeover races
	// the beaconing convergence.
	Poll(t, "C's direct up segment from A", func() bool {
		segs, err := c.app.PathDB().Get(ctx, pathdb.Query{
			Type:  pathdb.SegmentTypeUp,
			SrcIA: a.app.IA(),
		})
		if err != nil {
			return false
		}
		for _, s := range segs {
			if len(s.PCB.Entries) == 2 {
				return true
			}
		}
		return false
	})

	// Killing B leaves C connected through A.
	b.cancel()
	b.app.Close()
	// C's BFD verdict on its link to B turns down — the condition the wait
	// wants, not a fixed multiple of the transmission interval — so the
	// composed route crosses no link the monitor distrusts.
	cbEntry := entryOf(c, b.app.IA())
	Poll(t, "C to mark the C–B link down", func() bool {
		return !c.app.Monitor().Up(cbEntry.IfID)
	})
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
	t.Parallel()
	wpki := NewWebPKI(t)
	ipA, ipD := hostSlot(t), hostSlot(t)
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

// TestHeldHostPortRefusesBoot checks the default's failure mode: a boot
// against a shared port another socket already holds — the machine's
// existing WireGuard interface — fails loudly at the bind, the argument's
// override the remedy.
func TestHeldHostPortRefusesBoot(t *testing.T) {
	t.Parallel()
	wpki := NewWebPKI(t)
	ip := hostSlot(t)
	held, err := net.ListenUDP("udp",
		net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, apps.DefaultHostPort)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err = services.BootApp(ctx, services.NodeConfig{
		Core:     true,
		Domain:   TestDomain,
		State:    t.TempDir(),
		Internal: FreeUDPAddrOn(t, ip),
		Control:  FreeUDPAddrOn(t, ip),
		CertFile: wpki.certFile,
		KeyFile:  wpki.keyFile,
		AppArguments: apps.Arguments{
			Wireguard: apps.WireguardArguments{HostPort: apps.DefaultHostPort},
		},
	})
	if err == nil {
		t.Fatal("a boot against a held shared port succeeded")
	}
	if want := "binding the host port"; !strings.Contains(err.Error(), want) {
		t.Errorf("the boot's refusal = %v, want it to name %q", err, want)
	}
}

// TestDeliberateCore is the empty list's proof: a core and a joiner that
// name --applications empty — the deliberate core, no application loaded
// — join and enroll over the control endpoint's own services, and neither
// node binds any application surface: the pure forwarder a stated shape
// rather than an accident of unset arguments.
func TestDeliberateCore(t *testing.T) {
	t.Parallel()
	wpki := NewWebPKI(t)
	ipA, ipB := hostSlot(t), hostSlot(t)

	a := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.Core = true
		cfg.Applications = []string{}
		cfg.State = t.TempDir()
		cfg.Internal = FreeUDPAddrOn(t, ipA)
		cfg.Control = FreeUDPAddrOn(t, ipA)
		cfg.CertFile = wpki.certFile
		cfg.KeyFile = wpki.keyFile
	})
	b := bootAssembly(t, func(cfg *services.NodeConfig) {
		cfg.Applications = []string{}
		cfg.State = t.TempDir()
		cfg.Internal = FreeUDPAddrOn(t, ipB)
		cfg.Control = FreeUDPAddrOn(t, ipB)
		cfg.Neighbors = []string{a.rendezvousOf()}
		cfg.RootCAs = wpki.pool
	})

	Poll(t, "the joiner's link to the core", func() bool {
		e := entryOf(b, a.app.IA())
		return e != nil && e.State == links.StateEstablished
	})
	Poll(t, "the joiner enrolled", func() bool {
		return pingFrom(context.Background(), b, a.app.IA(), a.host)
	})
	for _, node := range []struct {
		name string
		app  *services.App
	}{{"the core", a.app}, {"the joiner", b.app}} {
		for _, resident := range []string{"wireguard", "coordination", "socks"} {
			if got := node.app.Application(resident); got != nil {
				t.Errorf("%s loaded the %s application beside an empty list",
					node.name, resident)
			}
		}
	}
}
